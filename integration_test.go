//go:build integration

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	dockerImageName = "sshx-test-sshd"       // Name for our test image
	dockerContext   = "./test/sshd"          // Path to the Dockerfile directory
	sshxBinaryName  = "sshx_test_binary.exe" // Name for the compiled binary used in tests (added .exe for Windows)
)

var (
	// Global variables to hold container info and binary path
	containerID    string
	sshHostPort    string // e.g., "localhost:2222"
	sshxBinaryPath string

	// Global variables to store host keys retrieved from container
	hostKeys map[string]string // Map key type (e.g., "ssh-rsa") to key data

	// Global variables for temporary key pair used in tests
	tempPrivateKeyPath string
	tempPublicKeyPath  string
)

// TestMain sets up the integration test environment (Docker, build) and tears it down.
func TestMain(m *testing.M) {
	log.Println("Setting up integration test environment...")
	var exitCode int

	// Use a cleanup function to ensure teardown happens even on panic/failure
	defer func() {
		log.Println("Tearing down integration test environment...")
		tearDown()
		os.Exit(exitCode)
	}()

	err := setup()
	if err != nil {
		log.Printf("!!! Failed to set up integration tests: %v", err)
		exitCode = 1 // Indicate setup failure
		return       // Exit without running tests
	}

	log.Println("Setup complete. Running tests...")
	exitCode = m.Run() // Run the actual tests
}

// setup builds the docker image, starts container, builds sshx
func setup() error {
	var err error
	// Build Docker Image
	log.Printf("Building Docker image %s from %s...", dockerImageName, dockerContext)
	buildCmd := exec.Command("docker", "build", "-t", dockerImageName, dockerContext)
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err = buildCmd.Run(); err != nil {
		return fmt.Errorf("failed to build docker image: %w", err)
	}
	log.Println("Docker image built.")

	// Start Docker Container
	log.Println("Starting SSHD container...")
	// -d: detached, -P: publish exposed ports to random host ports
	runCmd := exec.Command("docker", "run", "--rm", "-d", "-P", dockerImageName)
	containerBytes, err := runCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start docker container: %w\nOutput: %s", err, string(containerBytes))
	}
	containerID = strings.TrimSpace(string(containerBytes))
	if len(containerID) < 12 { // Basic sanity check
		return fmt.Errorf("got unexpected container ID: %s", containerID)
	}
	containerID = containerID[:12] // Use short ID for logging
	log.Printf("Container %s started.", containerID)

	// Find Mapped Port
	log.Println("Finding mapped SSH port...")
	portCmd := exec.Command("docker", "port", containerID, "22/tcp")
	portBytes, err := portCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get mapped port for container %s: %w\nOutput: %s", containerID, err, string(portBytes))
	}
	// Output looks like: 0.0.0.0:PORT
	portAddr := strings.TrimSpace(string(portBytes))
	parts := strings.Split(portAddr, ":")
	if len(parts) != 2 {
		return fmt.Errorf("unexpected output from docker port: %s", portAddr)
	}
	sshHostPort = "localhost:" + parts[1] // Use localhost for connection
	log.Printf("SSH server available at %s", sshHostPort)

	// Build sshx binary for testing
	log.Println("Building sshx binary for tests...")
	wd, _ := os.Getwd()
	sshxBinaryPath = filepath.Join(wd, sshxBinaryName) // Place it in current dir
	// Use -o to specify output name
	buildSshxCmd := exec.Command("go", "build", "-o", sshxBinaryPath, ".")
	buildSshxCmd.Stdout = os.Stdout
	buildSshxCmd.Stderr = os.Stderr
	if err = buildSshxCmd.Run(); err != nil {
		return fmt.Errorf("failed to build sshx binary: %w", err)
	}
	log.Printf("sshx binary built at %s", sshxBinaryPath)

	// Wait for sshd to be ready and get host keys
	err = waitForSSHAndGetHostKeys()
	if err != nil {
		return fmt.Errorf("failed to wait for SSH or get host keys: %w", err)
	}

	// Generate temporary SSH key pair for testing
	err = generateTempSSHKeys()
	if err != nil {
		return fmt.Errorf("failed to generate temporary SSH keys: %w", err)
	}

	// Add the temporary public key to the container's authorized_keys
	err = addTempPublicKeyToContainer()
	if err != nil {
		return fmt.Errorf("failed to add temporary public key to container: %w", err)
	}

	return nil
}

// waitForSSHAndGetHostKeys polls the container's SSH port and retrieves host keys.
func waitForSSHAndGetHostKeys() error {
	hostKeys = make(map[string]string)
	hostParts := strings.Split(sshHostPort, ":")
	if len(hostParts) != 2 {
		return fmt.Errorf("invalid sshHostPort format: %s", sshHostPort)
	}
	host := "localhost"
	port := hostParts[1]

	log.Println("Waiting for SSH server to become available...")
	maxAttempts := 20
	attempt := 0
	for attempt < maxAttempts {
		attempt++
		log.Printf("Attempt %d/%d: Trying to connect to %s:%s...", attempt, maxAttempts, host, port)
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 1*time.Second)
		if err == nil {
			conn.Close()
			log.Println("SSH server is listening.")
			break // Port is open
		}
		log.Printf("  - Connection attempt failed: %v", err)
		if attempt == maxAttempts {
			return fmt.Errorf("timed out waiting for SSH server at %s:%s", host, port)
		}
		time.Sleep(2 * time.Second) // Wait before retrying
	}

	// Now that the port is open, run keyscan inside the container ONCE, forcing IPv4.
	log.Println("SSH port is open. Running ssh-keyscan -4 inside the container...")
	scanCmd := exec.Command("docker", "exec", containerID, "ssh-keyscan", "-4", "localhost")
	keyScanOutBytes, err := scanCmd.CombinedOutput()
	if err != nil {
		// Failure here likely indicates sshd isn't ready or crashed.
		// Check docker logs for the containerID if this happens.
		return fmt.Errorf("docker exec ssh-keyscan -4 failed: %w\nOutput (if any):\n%s", err, string(keyScanOutBytes))
	}

	keyScanOut := string(keyScanOutBytes)
	log.Printf("Internal ssh-keyscan successful. Output:\n%s", keyScanOut)

	// Parse the keys and store them in the global map
	scanner := bufio.NewScanner(strings.NewReader(keyScanOut))
	foundKeys := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 3 { // Need at least host, key_type, key_data
			keyType := parts[1]
			keyData := parts[2]
			hostKeys[keyType] = keyData
			log.Printf("  - Found host key: Type=%s", keyType)
			foundKeys++
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error scanning ssh-keyscan output: %w", err)
	}
	if foundKeys == 0 {
		return fmt.Errorf("no valid host keys found in ssh-keyscan output")
	}
	log.Printf("Successfully retrieved %d host keys.", foundKeys)
	return nil
}

// generateTempSSHKeys creates a temporary ED25519 key pair for tests.
func generateTempSSHKeys() error {
	// Create a temporary directory for the keys
	tempDir, err := os.MkdirTemp("", "sshx-test-keys-")
	if err != nil {
		return fmt.Errorf("failed to create temp dir for keys: %w", err)
	}
	tempPrivateKeyPath = filepath.Join(tempDir, "id_test_ed25519")
	tempPublicKeyPath = tempPrivateKeyPath + ".pub"

	log.Printf("Generating temporary ED25519 key pair in %s...", tempDir)
	// Use ssh-keygen command
	// -t ed25519: key type
	// -f path: output private key file
	// -N "": empty passphrase
	// -C comment: optional comment
	keygenCmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", tempPrivateKeyPath, "-N", "", "-C", "sshx-integration-test")
	keygenOut, err := keygenCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ssh-keygen failed: %w\nOutput:\n%s", err, string(keygenOut))
	}
	log.Printf("Temporary key pair generated: %s, %s", tempPrivateKeyPath, tempPublicKeyPath)
	return nil
}

// addTempPublicKeyToContainer copies the generated public key into the container.
func addTempPublicKeyToContainer() error {
	if tempPublicKeyPath == "" {
		return fmt.Errorf("temporary public key path not set")
	}
	if containerID == "" {
		return fmt.Errorf("container ID not set")
	}

	// Target path inside the container
	targetPath := "/home/testuser/.ssh/authorized_keys"

	log.Printf("Copying %s to container %s:%s...", tempPublicKeyPath, containerID, targetPath)
	cpCmd := exec.Command("docker", "cp", tempPublicKeyPath, fmt.Sprintf("%s:%s", containerID, targetPath))
	cpOut, err := cpCmd.CombinedOutput()
	if err != nil {
		// docker cp might fail if the target directory doesn't exist, but our Dockerfile should create it.
		// It might also fail due to permissions, but chown in Dockerfile should handle it.
		return fmt.Errorf("docker cp failed: %w\nOutput:\n%s", err, string(cpOut))
	}

	// Additionally, ensure the permissions are correct inside the container
	// (docker cp sometimes messes them up or uses root ownership)
	chownCmd := exec.Command("docker", "exec", containerID, "chown", "testuser:testuser", targetPath)
	chownOut, err := chownCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker exec chown failed: %w\nOutput:\n%s", err, string(chownOut))
	}

	chmodCmd := exec.Command("docker", "exec", containerID, "chmod", "600", targetPath)
	chmodOut, err := chmodCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker exec chmod failed: %w\nOutput:\n%s", err, string(chmodOut))
	}

	log.Printf("Successfully copied and set permissions for %s in container.", targetPath)
	return nil
}

// tearDown stops/removes the container and cleans up the binary
func tearDown() {
	if containerID != "" {
		log.Printf("Stopping container %s...", containerID)
		stopCmd := exec.Command("docker", "stop", containerID)
		stopCmd.Stdout = os.Stdout
		stopCmd.Stderr = os.Stderr
		if err := stopCmd.Run(); err != nil {
			log.Printf("Warning: failed to stop container %s: %v", containerID, err)
		}
		// container was started with --rm, so stopping should remove it
		// rmCmd := exec.Command("docker", "rm", containerID)
		// if err := rmCmd.Run(); err != nil {
		// 	log.Printf("Warning: failed to remove container %s: %v", containerID, err)
		// }
	}
	if sshxBinaryPath != "" {
		log.Printf("Removing test binary %s...", sshxBinaryPath)
		if err := os.Remove(sshxBinaryPath); err != nil {
			log.Printf("Warning: failed to remove test binary %s: %v", sshxBinaryPath, err)
		}
	}
	// Clean up temporary keys directory
	if tempPrivateKeyPath != "" {
		tempDir := filepath.Dir(tempPrivateKeyPath)
		log.Printf("Removing temporary key directory %s...", tempDir)
		if err := os.RemoveAll(tempDir); err != nil {
			log.Printf("Warning: failed to remove temporary key directory %s: %v", tempDir, err)
		}
	}
}

// --- Test Cases ---

// TestIntegrationConnectKey tests basic connection and command execution using key auth.
func TestIntegrationConnectKey(t *testing.T) {
	// This test requires setup to have run successfully
	if sshHostPort == "" || tempPrivateKeyPath == "" {
		t.Fatal("Setup likely failed: SSH host/port or temp private key path not set")
	}

	t.Run("ConnectAndRunEcho", func(t *testing.T) {
		// Create a temporary directory for this specific test run (for known_hosts)
		tempDir := t.TempDir()
		knownHostsPath := filepath.Join(tempDir, "known_hosts")

		hostParts := strings.Split(sshHostPort, ":")
		if len(hostParts) != 2 {
			t.Fatalf("Invalid sshHostPort format: %s", sshHostPort)
		}

		// 1. Construct the known_hosts content from globally stored keys
		var formattedKeys strings.Builder
		for keyType, keyData := range hostKeys {
			formattedLine := fmt.Sprintf("[%s]:%s %s %s\n", "localhost", hostParts[1], keyType, keyData)
			formattedKeys.WriteString(formattedLine)
		}
		if formattedKeys.Len() == 0 {
			t.Fatal("No host keys were retrieved during setup")
		}

		err := os.WriteFile(knownHostsPath, []byte(formattedKeys.String()), 0600)
		if err != nil {
			t.Fatalf("Failed to write temporary known_hosts file: %v", err)
		}
		log.Printf("Wrote host keys to temporary known_hosts: %s", knownHostsPath)

		// 2. Prepare the sshx command to run 'echo hello' using the temp key
		connectTarget := fmt.Sprintf("testuser@%s", sshHostPort)
		commandToRun := "echo hello"
		cmdArgs := []string{
			"-i", tempPrivateKeyPath, // Specify the temporary private key
			connectTarget,
			commandToRun,
		}
		cmd := exec.Command(sshxBinaryPath, cmdArgs...)

		// 3. Set the SSH_KNOWN_HOSTS environment variable
		cmd.Env = append(os.Environ(), fmt.Sprintf("SSH_KNOWN_HOSTS=%s", knownHostsPath))

		// 4. Run the command and capture output
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output // Capture stderr too

		log.Printf("Running command: %s %s", sshxBinaryPath, strings.Join(cmdArgs, " "))
		err = cmd.Run() // Use Run, no stdin piping needed
		if err != nil {
			t.Fatalf("sshx command failed: %v\nOutput:\n%s", err, output.String())
		}

		// 5. Verify the output
		expectedOutput := "hello"
		actualOutput := strings.TrimSpace(output.String())

		log.Printf("sshx command output: %q", actualOutput)

		if actualOutput != expectedOutput {
			t.Errorf("Expected output %q, but got %q", expectedOutput, actualOutput)
		}
	})

	// TODO: Add back password test if needed, maybe using an expect-like library
	// TODO: Add copy-id test using key auth
}
