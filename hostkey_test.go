package main

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestFingerprintSHA256(t *testing.T) {
	// Example Ed25519 public key string (key part only)
	// Corresponds to: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK20d1cvXrMmoaY11aXk927q/LeQ1L87X/+40UqYpNuP user@example
	keyStr := "AAAAC3NzaC1lZDI1NTE5AAAAIK20d1cvXrMmoaY11aXk927q/LeQ1L87X/+40UqYpNuP"
	expectedFingerprint := "SHA256:OwaVjCRtY4tWSZZ0L+nNn2+7L+o4zCE4oQZQo7W0Iss" // Pre-calculated fingerprint

	// Parse the public key
	// Note: ssh.ParsePublicKey requires the full line format (type key comment),
	// but we can decode the base64 part and parse the wire format directly for testing fingerprint.
	// OR, parse the known authorized key line format.
	pubKeyLine := "ssh-ed25519 " + keyStr + " test"
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyLine))
	if err != nil {
		t.Fatalf("Failed to parse test public key line: %v", err)
	}

	// Calculate fingerprint using the function
	gotFingerprint := fingerprintSHA256(pubKey)

	// Compare
	if gotFingerprint != expectedFingerprint {
		t.Errorf("fingerprintSHA256() got = %v, want %v", gotFingerprint, expectedFingerprint)
	}

	// Add more test cases with different key types (RSA, ECDSA) if desired
}
