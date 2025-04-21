//go:build integration

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestIntegrationKeygen tests the `sshx keygen` command end-to-end.
func TestIntegrationKeygen(t *testing.T) {
	if sshxBinaryPath == "" {
		t.Fatal("sshxBinaryPath not set, setup likely failed")
	}

	t.Run("Default Keygen (ed25519)", func(t *testing.T) {
		tempDir := t.TempDir()
		keyPath := filepath.Join(tempDir, "test_id_ed25519")

		args := []string{"keygen", "-f", keyPath}
		cmd := exec.Command(sshxBinaryPath, args...)

		// Capture output
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err != nil {
			t.Fatalf("'sshx keygen -f %s' failed: %v\nStderr: %s", keyPath, err, stderr.String())
		}

		// Check output messages
		stdoutStr := stdout.String()
		expectedPrivMsg := fmt.Sprintf("Your identification has been saved in %s", keyPath)
		expectedPubMsg := fmt.Sprintf("Your public key has been saved in %s.pub", keyPath)
		if !strings.Contains(stdoutStr, expectedPrivMsg) {
			t.Errorf("Stdout missing expected private key message.\nGot:\n%s\nWant containing:\n%s", stdoutStr, expectedPrivMsg)
		}
		if !strings.Contains(stdoutStr, expectedPubMsg) {
			t.Errorf("Stdout missing expected public key message.\nGot:\n%s\nWant containing:\n%s", stdoutStr, expectedPubMsg)
		}

		// Check private key file existence
		privFileInfo, err := os.Stat(keyPath)
		if err != nil {
			t.Fatalf("Failed to stat private key file '%s': %v", keyPath, err)
		}
		if privFileInfo.IsDir() {
			t.Errorf("Private key path '%s' is a directory, expected a file.", keyPath)
		}
		// Check private key permissions (best effort for cross-platform)
		// Expect 0600 or equivalent. Windows permissions are complex.
		if perm := privFileInfo.Mode().Perm(); perm&0077 != 0 {
			t.Logf("[Warning] Private key '%s' permissions are %o, expected 0600 (group/other permissions detected). This might be permissive.", keyPath, perm)
			// On non-Windows, we can be stricter:
			// if runtime.GOOS != "windows" && perm != 0600 { ... }
		}

		// Check public key file existence
		pubKeyPath := keyPath + ".pub"
		pubFileInfo, err := os.Stat(pubKeyPath)
		if err != nil {
			t.Fatalf("Failed to stat public key file '%s': %v", pubKeyPath, err)
		}
		if pubFileInfo.IsDir() {
			t.Errorf("Public key path '%s' is a directory, expected a file.", pubKeyPath)
		}
		// Optionally check public key permissions (e.g., 0644)
		// pubPerm := pubFileInfo.Mode().Perm()
		// if pubPerm != 0644 { ... }
	})

	// TODO: Add more subtests:
	// t.Run("RSA Keygen", ...)
	// t.Run("Keygen with Passphrase", ...)
	// t.Run("Keygen Refuse Overwrite", ...)
	// t.Run("Keygen Invalid Type", ...)
	// t.Run("Keygen Default Path (~/.ssh)", ...) // This might be harder/riskier
}
