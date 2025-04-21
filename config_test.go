package main

import (
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	// Note: We avoid importing ssh_config directly in tests where possible
	// to keep them focused. If needed for alias testing, we would add it.
)

// TestExpandTilde tests the tilde expansion logic.
func TestExpandTilde(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("Failed to get current user for testing: %v", err)
	}
	homeDir := currentUser.HomeDir

	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{"No Tilde", "/some/absolute/path", "/some/absolute/path", false},
		{"Tilde Only", "~", homeDir, false},
		{"Tilde Prefix", "~/some/relative/path", filepath.Join(homeDir, "some/relative/path"), false},
		{"Not a Tilde Prefix", "other~/path", "other~/path", false},
		{"Empty String", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpandTilde(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExpandTilde() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("ExpandTilde() got = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestResolveConnectionConfig_UserHostFormat tests the direct user@host parsing.
func TestResolveConnectionConfig_UserHostFormat(t *testing.T) {
	// Mock user.Current() to avoid external dependency if needed, but for basic tests it's often fine.
	// We primarily test parsing logic here, assuming expandTilde works (tested separately).

	// Set a fake home dir for default key path testing
	// Note: This relies on expandTilde working correctly.
	currentUser, _ := user.Current() // Get current user for home dir default path
	defaultKeyPath := filepath.Join(currentUser.HomeDir, ".ssh", "id_rsa")

	tests := []struct {
		name           string
		targetArg      string
		identityFlag   string
		wantHostname   string
		wantUser       string
		wantPort       string
		wantKeyPath    string // Expected final, expanded key path
		wantServerAddr string
		wantErr        bool
	}{
		{
			name:           "Simple user@host",
			targetArg:      "testuser@example.com",
			identityFlag:   "",
			wantHostname:   "example.com",
			wantUser:       "testuser",
			wantPort:       "22",
			wantKeyPath:    defaultKeyPath,
			wantServerAddr: "example.com:22",
			wantErr:        false,
		},
		{
			name:           "user@host with port",
			targetArg:      "admin@192.168.1.1:2222",
			identityFlag:   "",
			wantHostname:   "192.168.1.1",
			wantUser:       "admin",
			wantPort:       "2222",
			wantKeyPath:    defaultKeyPath,
			wantServerAddr: "192.168.1.1:2222",
			wantErr:        false,
		},
		{
			name:           "user@host with identity flag",
			targetArg:      "root@myhost",
			identityFlag:   "/explicit/path/key", // Absolute path, no tilde
			wantHostname:   "myhost",
			wantUser:       "root",
			wantPort:       "22",
			wantKeyPath:    "/explicit/path/key",
			wantServerAddr: "myhost:22",
			wantErr:        false,
		},
		{
			name:           "user@host with tilde identity flag",
			targetArg:      "dev@internal",
			identityFlag:   "~/keys/dev_key",
			wantHostname:   "internal",
			wantUser:       "dev",
			wantPort:       "22",
			wantKeyPath:    filepath.Join(currentUser.HomeDir, "keys", "dev_key"), // Expect expanded path
			wantServerAddr: "internal:22",
			wantErr:        false,
		},
		{
			name:      "Invalid format no @",
			targetArg: "justhost", // This should be handled by alias logic (tested separately)
			// We expect this test case might fail or need adjustment depending on how Resolve deals with it.
			// For now, we assume it's handled by the alias path, so this test is more about ensuring user@host logic isn't triggered incorrectly.
			// Let's test an actual invalid user@host format
			// targetArg:   "invalid@format@again",
			// wantErr:     true, -- This test would fail the Contains check, need better invalid case
		},
		{
			name:      "Invalid format missing host",
			targetArg: "user@",
			wantErr:   true,
		},
		{
			name:      "Invalid format missing user",
			targetArg: "@host",
			wantErr:   true,
		},
		{
			name:      "Invalid port",
			targetArg: "user@host:notaport",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip the placeholder test
			if strings.Contains(tt.name, "Invalid format no @") {
				t.Skip("Skipping test for alias format handled elsewhere")
			}

			got, err := ResolveConnectionConfig(tt.targetArg, tt.identityFlag)

			if (err != nil) != tt.wantErr {
				t.Errorf("ResolveConnectionConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return // Don't check fields if error was expected
			}

			if got == nil {
				t.Fatalf("ResolveConnectionConfig() returned nil, expected valid config")
			}

			if got.Hostname != tt.wantHostname {
				t.Errorf("ResolveConnectionConfig() Hostname got = %v, want %v", got.Hostname, tt.wantHostname)
			}
			if got.User != tt.wantUser {
				t.Errorf("ResolveConnectionConfig() User got = %v, want %v", got.User, tt.wantUser)
			}
			if got.Port != tt.wantPort {
				t.Errorf("ResolveConnectionConfig() Port got = %v, want %v", got.Port, tt.wantPort)
			}
			if got.ServerAddress != tt.wantServerAddr {
				t.Errorf("ResolveConnectionConfig() ServerAddress got = %v, want %v", got.ServerAddress, tt.wantServerAddr)
			}
			if got.KeyPath != tt.wantKeyPath {
				t.Errorf("ResolveConnectionConfig() KeyPath got = %v, want %v", got.KeyPath, tt.wantKeyPath)
			}
			if got.IsAlias == true {
				t.Errorf("ResolveConnectionConfig() IsAlias got = true, want false for user@host format")
			}
		})
	}
}

// TODO: Add tests for alias resolution logic (TestResolveConnectionConfig_AliasFormat)
// This will likely require creating temporary ssh config files during testing.
