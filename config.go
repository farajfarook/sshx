package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kevinburke/ssh_config"
)

// getUserCurrentFunc allows mocking user.Current in tests
var getUserCurrentFunc = user.Current

// ResolvedConfig holds the final parameters needed for an SSH connection.
type ResolvedConfig struct {
	Hostname      string
	User          string
	Port          string
	KeyPath       string
	ServerAddress string // Combined Hostname:Port
	IsAlias       bool
	TargetArg     string // Original target argument for logging
}

// ExpandTilde resolves paths like "~/.ssh/config" relative to the current user's home directory.
func ExpandTilde(path string) (string, error) {
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}
	currentUser, err := getUserCurrentFunc()
	if err != nil {
		return "", fmt.Errorf("failed to get current user for tilde expansion: %w", err)
	}
	return filepath.Join(currentUser.HomeDir, path[1:]), nil
}

// loadSshConfig loads and parses the ~/.ssh/config file.
func loadSshConfig() (*ssh_config.Config, error) {
	currentUser, err := getUserCurrentFunc()
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %w", err)
	}
	sshConfigPath := filepath.Join(currentUser.HomeDir, ".ssh", "config")
	sshConfigFile, err := os.Open(sshConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Warning: SSH config file not found at %s. Using defaults.", sshConfigPath)
			return &ssh_config.Config{}, nil // Return empty config, not an error
		} else {
			return nil, fmt.Errorf("failed to open SSH config file %s: %w", sshConfigPath, err)
		}
	}
	defer sshConfigFile.Close()

	cfg, err := ssh_config.Decode(sshConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH config file %s: %w", sshConfigPath, err)
	}
	return cfg, nil
}

// ResolveConnectionConfig determines the connection parameters based on user input and ssh config.
func ResolveConnectionConfig(targetArg string, identityFilePathFlag string) (*ResolvedConfig, error) {
	cfg, err := loadSshConfig()
	if err != nil {
		return nil, err
	}

	currentUser, err := getUserCurrentFunc()
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %w", err)
	}

	var res ResolvedConfig
	res.TargetArg = targetArg
	var hostname, sshUser, portStr, keyPathFromConfig string

	if strings.Contains(targetArg, "@") {
		res.IsAlias = false
		log.Printf("Parsing target as user@host[:port]: %s", targetArg)
		parts := strings.SplitN(targetArg, "@", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("invalid user@host format: %s", targetArg)
		}
		sshUser = parts[0]
		hostPort := parts[1]

		host, port, err := net.SplitHostPort(hostPort)
		if err != nil {
			if addrErr, ok := err.(*net.AddrError); ok && strings.Contains(addrErr.Err, "missing port") {
				hostname = hostPort
				portStr = "22"
			} else {
				return nil, fmt.Errorf("failed to parse host/port from '%s': %w", hostPort, err)
			}
		} else {
			hostname = host
			portStr = port
			_, err = strconv.Atoi(portStr)
			if err != nil {
				return nil, fmt.Errorf("invalid port number '%s' in target '%s'", portStr, targetArg)
			}
		}

		if hostname == "" {
			return nil, fmt.Errorf("could not determine hostname from target: %s", targetArg)
		}

		keyPathFromConfig, _ = cfg.Get(hostname, "IdentityFile")

	} else {
		res.IsAlias = true
		hostAlias := targetArg
		log.Printf("Resolving parameters for host alias: %s", hostAlias)

		hostname, err = cfg.Get(hostAlias, "Hostname")
		if err != nil || hostname == "" {
			hostname = hostAlias
		}
		sshUser, err = cfg.Get(hostAlias, "User")
		if err != nil || sshUser == "" {
			sshUser = currentUser.Username
		}
		portStr, err = cfg.Get(hostAlias, "Port")
		if err != nil || portStr == "" {
			portStr = "22"
		}
		_, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid Port '%s' found in SSH config for host '%s': %w", portStr, hostAlias, err)
		}
		keyPathFromConfig, _ = cfg.Get(hostAlias, "IdentityFile")
	}

	res.Hostname = hostname
	res.User = sshUser
	res.Port = portStr
	res.ServerAddress = net.JoinHostPort(res.Hostname, res.Port)

	// Determine the key path: prioritize flag, then config, then defaults
	finalKeyPath := identityFilePathFlag
	if finalKeyPath == "" {
		finalKeyPath = keyPathFromConfig
	}

	// If still no key path, check default locations in preferred order
	if finalKeyPath == "" {
		log.Println("No identity file specified via flag or config, checking defaults...")
		defaultKeyFiles := []string{
			"~/.ssh/id_ed25519",
			"~/.ssh/id_ecdsa",
			"~/.ssh/id_rsa",
		}
		for _, defaultPath := range defaultKeyFiles {
			expandedDefaultPath, err := ExpandTilde(defaultPath)
			if err != nil {
				log.Printf("Warning: could not expand tilde for default key path %s: %v", defaultPath, err)
				continue // Try next default
			}
			if _, err := os.Stat(expandedDefaultPath); err == nil {
				log.Printf("Found default identity file: %s", expandedDefaultPath)
				finalKeyPath = defaultPath // Use the path with the tilde for ExpandTilde below
				break
			} else if !os.IsNotExist(err) {
				// Log unexpected errors checking default key, but continue (might not have permission)
				log.Printf("Warning: error checking default key file %s: %v", expandedDefaultPath, err)
			}
		}
	}

	// If still no key path after checking defaults, log and proceed (will likely fallback to password)
	if finalKeyPath == "" {
		log.Println("No identity file specified or found in default locations. Authentication might require password.")
		// Set KeyPath to empty string; PrepareAuthMethods handles this
		res.KeyPath = ""
	} else {
		// Expand the final chosen path (could be from flag, config, or default)
		expandedKeyPath, err := ExpandTilde(finalKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to expand tilde in key path '%s': %w", finalKeyPath, err)
		}
		res.KeyPath = expandedKeyPath
	}

	log.Printf("Resolved connection parameters: User=%s, Host=%s, Port=%s, KeyPath='%s'", res.User, res.Hostname, res.Port, res.KeyPath) // Added KeyPath to log

	return &res, nil
}
