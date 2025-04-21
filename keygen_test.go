package main

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestGenerateKeyPair tests the generateKeyPair function.
func TestGenerateKeyPair(t *testing.T) {
	t.Run("RSA Key Pair", func(t *testing.T) {
		priv, pub, err := generateKeyPair("rsa", rsaMinBits) // Use min bits for speed
		if err != nil {
			t.Fatalf("generateKeyPair(rsa) error = %v", err)
		}
		if _, ok := priv.(*rsa.PrivateKey); !ok {
			t.Errorf("Expected RSA private key, got %T", priv)
		}
		if _, ok := pub.(*rsa.PublicKey); !ok {
			t.Errorf("Expected RSA public key, got %T", pub)
		}
	})

	t.Run("Ed25519 Key Pair", func(t *testing.T) {
		priv, pub, err := generateKeyPair("ed25519", 0) // Bits ignored for ed25519
		if err != nil {
			t.Fatalf("generateKeyPair(ed25519) error = %v", err)
		}
		if _, ok := priv.(ed25519.PrivateKey); !ok {
			t.Errorf("Expected Ed25519 private key, got %T", priv)
		}
		if _, ok := pub.(ed25519.PublicKey); !ok {
			t.Errorf("Expected Ed25519 public key, got %T", pub)
		}
	})

	t.Run("Unsupported Key Type", func(t *testing.T) {
		_, _, err := generateKeyPair("dsa", 0)
		if err == nil {
			t.Fatal("Expected error for unsupported key type, got nil")
		}
		if !strings.Contains(err.Error(), "unsupported key type") {
			t.Errorf("Expected error message containing 'unsupported key type', got %q", err.Error())
		}
	})
}

// TestEncodePrivateKeyToPEM tests the encodePrivateKeyToPEM function.
func TestEncodePrivateKeyToPEM(t *testing.T) {
	// Generate sample keys
	rsaPriv, _, _ := generateKeyPair("rsa", rsaMinBits)
	edPriv, _, _ := generateKeyPair("ed25519", 0)
	passphrase := []byte("testpass")

	tests := []struct {
		name        string
		privateKey  any
		passphrase  []byte
		expectType  string
		expectEnc   bool // Whether the PEM block should be encrypted
		expectError bool
	}{
		{"RSA Unencrypted", rsaPriv, nil, "PRIVATE KEY", false, false},
		{"RSA Encrypted", rsaPriv, passphrase, "ENCRYPTED PRIVATE KEY", true, false}, // Type might vary based on impl, check for ENCRYPTED
		{"Ed25519 Unencrypted", edPriv, nil, "PRIVATE KEY", false, false},
		{"Ed25519 Encrypted", edPriv, passphrase, "ENCRYPTED PRIVATE KEY", true, false}, // Type might vary based on impl, check for ENCRYPTED
		{"Unsupported Type", "not a key", nil, "", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pemBytes, err := encodePrivateKeyToPEM(tt.privateKey, tt.passphrase)
			if (err != nil) != tt.expectError {
				t.Fatalf("encodePrivateKeyToPEM() error = %v, expectError %v", err, tt.expectError)
			}
			if err != nil {
				return // Don't check PEM structure if error was expected
			}

			pemBlock, rest := pem.Decode(pemBytes)
			if pemBlock == nil {
				t.Fatalf("Failed to decode PEM block from output")
			}
			if len(rest) > 0 {
				t.Errorf("Unexpected trailing data after PEM block: %q", rest)
			}

			// Check type, accounting for potential encryption variations
			if tt.expectEnc {
				if !strings.Contains(pemBlock.Type, "ENCRYPTED") {
					t.Errorf("Expected encrypted PEM block type (containing ENCRYPTED), got %q", pemBlock.Type)
				}
				// Also check if it can be decrypted (optional but good)
				isEncrypted := x509.IsEncryptedPEMBlock(pemBlock)
				if !isEncrypted {
					t.Errorf("Expected IsEncryptedPEMBlock to return true, got false")
				}
				// Attempt decryption
				//nolint:staticcheck // SA1019: x509.DecryptPEMBlock is deprecated
				decryptedBytes, err := x509.DecryptPEMBlock(pemBlock, tt.passphrase)
				if err != nil {
					t.Fatalf("Failed to decrypt PEM block with correct passphrase: %v", err)
				}
				if len(decryptedBytes) == 0 {
					t.Errorf("Decrypted PEM block is empty")
				}
			} else {
				if pemBlock.Type != tt.expectType {
					t.Errorf("Expected PEM block type %q, got %q", tt.expectType, pemBlock.Type)
				}
				isEncrypted := x509.IsEncryptedPEMBlock(pemBlock)
				if isEncrypted {
					t.Errorf("Expected IsEncryptedPEMBlock to return false, got true")
				}
			}

			if len(pemBlock.Bytes) == 0 {
				t.Errorf("PEM block bytes are empty")
			}
		})
	}
}

// TestEncodePublicKeyToSSH tests the encodePublicKeyToSSH function.
func TestEncodePublicKeyToSSH(t *testing.T) {
	// Generate sample keys
	_, rsaPub, _ := generateKeyPair("rsa", rsaMinBits)
	_, edPub, _ := generateKeyPair("ed25519", 0)

	tests := []struct {
		name         string
		publicKey    any
		comment      string
		expectPrefix string
		expectError  bool
	}{
		{"RSA No Comment", rsaPub, "", "ssh-rsa", false},
		{"RSA With Comment", rsaPub, "rsa-key@test", "ssh-rsa", false},
		{"Ed25519 No Comment", edPub, "", "ssh-ed25519", false},
		{"Ed25519 With Comment", edPub, "ed-key@test", "ssh-ed25519", false},
		{"Unsupported Type", "not a key", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sshBytes, err := encodePublicKeyToSSH(tt.publicKey, tt.comment)
			if (err != nil) != tt.expectError {
				t.Fatalf("encodePublicKeyToSSH() error = %v, expectError %v", err, tt.expectError)
			}
			if err != nil {
				return // Don't check output if error was expected
			}

			output := string(sshBytes)

			// Basic validation: check prefix and suffix
			if !strings.HasPrefix(output, tt.expectPrefix+" ") {
				t.Errorf("Output %q does not start with expected prefix %q", output, tt.expectPrefix)
			}
			if !strings.HasSuffix(output, "\n") {
				t.Errorf("Output %q does not end with newline", output)
			}

			// Check comment presence/absence
			trimmedOutput := strings.TrimSpace(output)
			if tt.comment != "" {
				if !strings.HasSuffix(trimmedOutput, " "+tt.comment) {
					t.Errorf("Output %q does not end with expected comment %q", trimmedOutput, tt.comment)
				}
			} else {
				// Check if there's any comment when none is expected
				parts := strings.Fields(trimmedOutput) // Split by space
				if len(parts) > 2 {                    // Should only be type and key data if no comment
					t.Errorf("Output %q unexpectedly contains extra fields (comment?) when no comment was provided", trimmedOutput)
				}
			}

			// More robust check: Try parsing it back
			pubKey, commentOut, _, _, err := ssh.ParseAuthorizedKey(sshBytes)
			if err != nil {
				t.Fatalf("Failed to parse back generated SSH public key: %v. Output was: %q", err, output)
			}
			if commentOut != tt.comment {
				t.Errorf("Parsed comment %q does not match input comment %q", commentOut, tt.comment)
			}
			// Note: Direct comparison might fail due to type differences (e.g., *rsa.PublicKey vs ssh.PublicKey)
			// Compare fingerprints for equality check.
			// Need to convert input tt.publicKey to ssh.PublicKey first for fingerprinting.
			sshInputKey, _ := ssh.NewPublicKey(tt.publicKey)
			if ssh.FingerprintSHA256(pubKey) != ssh.FingerprintSHA256(sshInputKey) {
				t.Errorf("Fingerprint mismatch between parsed key and original key")
			}
		})
	}
}
