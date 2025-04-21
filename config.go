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
	currentUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("failed to get current user for tilde expansion: %w", err)
	}
	return filepath.Join(currentUser.HomeDir, path[1:]), nil
}

// loadSshConfig loads and parses the ~/.ssh/config file.
func loadSshConfig() (*ssh_config.Config, error) {
	currentUser, err := user.Current()
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

	currentUser, err := user.Current()
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

	finalKeyPath := identityFilePathFlag
	if finalKeyPath == "" {
		finalKeyPath = keyPathFromConfig
	}
	if finalKeyPath == "" {
		finalKeyPath = "~/.ssh/id_rsa"
	}

	expandedKeyPath, err := ExpandTilde(finalKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to expand tilde in key path '%s': %w", finalKeyPath, err)
	}
	res.KeyPath = expandedKeyPath

	return &res, nil
}
