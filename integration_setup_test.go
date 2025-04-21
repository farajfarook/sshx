//go:build integration

package main

import (
	"bufio"
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
	portOut, err := portCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get mapped port for container %s: %w", containerID, err)
	}

	// Handle potential dual IPv4/IPv6 output like:
	// 0.0.0.0:32768
	// [::]:32768
	// We only need the port number, which should be the same.
	portMapping := strings.TrimSpace(string(portOut))
	lines := strings.Split(portMapping, "\n")
	if len(lines) == 0 {
		return fmt.Errorf("empty output from docker port: %q", portMapping)
	}

	// Parse the port from the first line
	firstLine := strings.TrimSpace(lines[0])
	parts := strings.Split(firstLine, ":")
	if len(parts) != 2 {
		return fmt.Errorf("unexpected format in first line of docker port output: %q", firstLine)
	}
	port := parts[1]

	sshHostPort = "localhost:" + port
	log.Printf("SSH server available at %s (parsed from %q)", sshHostPort, firstLine)

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
		if len(parts) < 2 {
			log.Printf("Skipping malformed host key line: %s", line)
			continue
		}
		// parts[0] is the hostname (ignore, we know it's localhost)
		keyType := parts[1]
		keyData := parts[2] // Assuming key data doesn't have spaces
		hostKeys[keyType] = keyData
		log.Printf("  - Found host key: Type=%s", keyType)
		foundKeys++
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading ssh-keyscan output: %w", err)
	}
	if foundKeys == 0 {
		return fmt.Errorf("no host keys found in ssh-keyscan output")
	}
	log.Printf("Successfully retrieved %d host keys.", foundKeys)
	return nil
}

// generateTempSSHKeys creates a temporary directory and ed25519 key pair within it.
func generateTempSSHKeys() error {
	// Create a temporary directory for the keys
	tempDir, err := os.MkdirTemp("", "sshx-test-keys-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir for keys: %w", err)
	}

	tempPrivateKeyPath = filepath.Join(tempDir, "id_test_ed25519")
	tempPublicKeyPath = tempPrivateKeyPath + ".pub"

	log.Printf("Generating temporary ED25519 key pair in %s...", tempDir)

	// Use the keygen logic from our own package!
	// Note: This directly calls the function, bypassing the command-line interface part.
	privKey, pubKey, err := generateKeyPair("ed25519", 0) // Assuming generateKeyPair is accessible
	if err != nil {
		return fmt.Errorf("failed to generate key pair using generateKeyPair: %w", err)
	}

	pemBytes, err := encodePrivateKeyToPEM(privKey, nil) // No passphrase
	if err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	sshBytes, err := encodePublicKeyToSSH(pubKey, "sshx-test-key")
	if err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	if err := os.WriteFile(tempPrivateKeyPath, pemBytes, 0600); err != nil {
		return fmt.Errorf("failed to write temp private key %s: %w", tempPrivateKeyPath, err)
	}
	if err := os.WriteFile(tempPublicKeyPath, sshBytes, 0644); err != nil {
		return fmt.Errorf("failed to write temp public key %s: %w", tempPublicKeyPath, err)
	}

	log.Printf("Temporary key pair generated: %s, %s", tempPrivateKeyPath, tempPublicKeyPath)
	return nil
}

// addTempPublicKeyToContainer copies the generated public key to authorized_keys in the container.
func addTempPublicKeyToContainer() error {
	if tempPublicKeyPath == "" {
		return fmt.Errorf("temporary public key path is not set")
	}
	if containerID == "" {
		return fmt.Errorf("container ID is not set")
	}

	// We only need the path, not the content, for docker cp.
	// // Read the public key content
	// pubKeyBytes, err := os.ReadFile(tempPublicKeyPath)
	// if err != nil {
	// 	return fmt.Errorf("failed to read temporary public key %s: %w", tempPublicKeyPath, err)
	// }

	// Target path in the container
	targetAuthKeysPath := "/home/testuser/.ssh/authorized_keys"

	log.Printf("Copying %s to container %s:%s...", tempPublicKeyPath, containerID, targetAuthKeysPath)

	// Use docker cp to copy the public key file into the container
	// We need to copy it to a temporary location first, then move and set permissions
	// because `docker cp` doesn't easily allow setting ownership/permissions directly.
	containerTempPath := "/tmp/temp_auth_key.pub"
	copyCmd := exec.Command("docker", "cp", tempPublicKeyPath, fmt.Sprintf("%s:%s", containerID, containerTempPath))
	if out, err := copyCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to copy public key to container /tmp: %w\nOutput: %s", err, string(out))
	}

	// Use docker exec to move the file and set permissions/ownership
	// Must run as root inside the container to chown
	// Using sh -c to chain commands
	// Ensure the directory exists first, then copy, then chown, then chmod
	commands := fmt.Sprintf("mkdir -p $(dirname %s) && cp %s %s && chown testuser:testuser %s && chmod 600 %s",
		targetAuthKeysPath, containerTempPath, targetAuthKeysPath, targetAuthKeysPath, targetAuthKeysPath)
	execCmd := exec.Command("docker", "exec", containerID, "sh", "-c", commands)
	if out, err := execCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to move/set permissions on authorized_keys in container: %w\nOutput: %s", err, string(out))
	}

	log.Printf("Successfully copied and set permissions for %s in container.", targetAuthKeysPath)
	return nil
}

// NOTE: TestIntegrationConnectKey moved to connect_integration_test.go

// NOTE: TestIntegrationKeygen moved to keygen_integration_test.go

// tearDown stops the docker container and removes the test binary.
func tearDown() {
	if containerID != "" {
		log.Printf("Stopping container %s...", containerID)
		stopCmd := exec.Command("docker", "stop", containerID)
		output, err := stopCmd.CombinedOutput()
		if err != nil {
			log.Printf("Warning: Failed to stop container %s: %v\nOutput: %s", containerID, err, string(output))
		} else {
			log.Printf("Container stopped: %s", string(output))
		}
	}
	if sshxBinaryPath != "" {
		log.Printf("Removing test binary %s...", sshxBinaryPath)
		if err := os.Remove(sshxBinaryPath); err != nil {
			if !os.IsNotExist(err) {
				log.Printf("Warning: Failed to remove test binary %s: %v", sshxBinaryPath, err)
			}
		}
	}
	// Clean up temporary keys directory created by generateTempSSHKeys
	if tempPrivateKeyPath != "" {
		tempDir := filepath.Dir(tempPrivateKeyPath)
		log.Printf("Removing temporary key directory %s...", tempDir)
		if err := os.RemoveAll(tempDir); err != nil {
			log.Printf("Warning: Failed to remove temporary key directory %s: %v", tempDir, err)
		}
	}
}
