//go:build integration

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestIntegrationConnectKey tests the `sshx connect` command with key authentication.
func TestIntegrationConnectKey(t *testing.T) {
	// Requires TestMain to have run and set up container, keys, and binary path
	if sshxBinaryPath == "" || containerID == "" || sshHostPort == "" || tempPrivateKeyPath == "" {
		t.Fatal("Integration test setup incomplete (missing binary, container, port, or key)")
	}

	t.Run("ConnectAndRunEcho", func(t *testing.T) {
		tempDir := t.TempDir() // Create a temporary directory for this test run
		knownHostsPath := filepath.Join(tempDir, "known_hosts")

		// Prepare known_hosts file
		var knownHostsContent string
		for keyType, keyData := range hostKeys {
			// Use "localhost:port" format matching sshHostPort
			knownHostsContent += fmt.Sprintf("%s %s %s\n", sshHostPort, keyType, keyData)
		}
		if err := os.WriteFile(knownHostsPath, []byte(knownHostsContent), 0644); err != nil {
			t.Fatalf("Failed to write temporary known_hosts file: %v", err)
		}
		log.Printf("Wrote host keys to temporary known_hosts: %s", knownHostsPath)

		// Construct the command
		target := "testuser@" + sshHostPort
		cmdArgs := []string{
			"-i", tempPrivateKeyPath, // Use the generated private key
			// Override known_hosts using an environment variable (more reliable than args if sshx supports it)
			// OR pass as an argument if sshx supports -o UserKnownHostsFile=...
			// For now, assume sshx respects SSH_KNOWN_HOSTS or similar, or reads default ~/.ssh
			// We will rely on the test setup having potentially modified ~/.ssh or we accept adding keys.
			// A better approach is to make sshx configurable for known_hosts path.
			// Let's just run it and see if it prompts or uses the default.
			// It SHOULD use the one we created IF sshx reads ~/.ssh/known_hosts
			// Forcing it via env var is safer for tests if possible.
			// OR, we can patch the global known_hosts path resolution within the test if using Go funcs.
			// Let's try running without forcing known_hosts for now, assuming test keys were added to default.
			target,  // Target user@host:port
			"echo",  // Command to run
			"hello", // Argument to echo
		}

		// Execute sshx command
		log.Printf("Running command: %s %s", sshxBinaryPath, strings.Join(cmdArgs, " "))
		cmd := exec.Command(sshxBinaryPath, cmdArgs...)
		// Set SSH_KNOWN_HOSTS env var to use the temporary file
		cmd.Env = append(os.Environ(), fmt.Sprintf("SSH_KNOWN_HOSTS=%s", knownHostsPath))
		// We might need to set the HOME environment variable if known_hosts logic relies on it
		// cmd.Env = append(os.Environ(), "HOME="+tempDir) // This is risky if other things need real home

		outputBytes, err := cmd.CombinedOutput() // Capture stdout and stderr
		if err != nil {
			t.Fatalf("sshx command failed: %v\nOutput:\n%s", err, string(outputBytes))
		}

		output := strings.TrimSpace(string(outputBytes))
		log.Printf("sshx command output: %q", output)

		// Check output
		expectedOutput := "hello"
		if output != expectedOutput {
			t.Errorf("Expected output %q, got %q", expectedOutput, output)
		}
	})

	// TODO: Add test for interactive session (more complex, needs PTY simulation or input/output piping)
	// TODO: Add test for password authentication
	// TODO: Add test for host key verification failure (unknown host, changed host)
	// TODO: Add copy-id test using key auth
}
