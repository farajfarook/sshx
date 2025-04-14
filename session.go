package main

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

// createKnownHostsCallback creates a HostKeyCallback function using the default known_hosts file.
func createKnownHostsCallback() (ssh.HostKeyCallback, error) {
	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("failed to get current user for known_hosts path: %w", err)
	}
	knownHostsPath := filepath.Join(currentUser.HomeDir, ".ssh", "known_hosts")

	// knownhosts.New also handles file creation if it doesn't exist, but
	// standard behavior is usually to error if the file can't be read.
	// Let's try creating it with default permissions if it's missing first.
	if _, err := os.Stat(knownHostsPath); os.IsNotExist(err) {
		log.Printf("Warning: known_hosts file not found at %s. Attempting to create.", knownHostsPath)
		file, createErr := os.OpenFile(knownHostsPath, os.O_CREATE|os.O_WRONLY, 0600)
		if createErr != nil {
			return nil, fmt.Errorf("failed to create known_hosts file at %s: %w", knownHostsPath, createErr)
		}
		file.Close() // Close the empty file immediately
		log.Printf("Created empty known_hosts file. Please populate it (e.g., using standard ssh or ssh-keyscan).")
		// Even if created, knownhosts.New might fail if directory permissions are bad,
		// but it handles the 'file not found' aspect internally if we let it.
	}

	hostKeyCallback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		// This catches errors reading the file (permissions etc.)
		return nil, fmt.Errorf("failed to load known_hosts file '%s': %w", knownHostsPath, err)
	}

	// Optional: Log successful loading
	log.Printf("Loaded known_hosts file from %s", knownHostsPath)
	return hostKeyCallback, nil
}

// ConnectAndRunSession dials the SSH server, sets up the interactive session, and waits for it to complete.
func ConnectAndRunSession(resolvedConfig *ResolvedConfig, authMethods []ssh.AuthMethod) error {
	// Create the host key callback
	hostKeyCallback, err := createKnownHostsCallback()
	if err != nil {
		// If we can't establish a trust mechanism, it's a fatal error for secure connection.
		return fmt.Errorf("could not create host key callback: %w", err)
	}

	log.Printf("Connecting to %s (%s) as user %s...", resolvedConfig.ServerAddress, resolvedConfig.Hostname, resolvedConfig.User)

	// Configure SSH client with secure host key verification
	config := &ssh.ClientConfig{
		User:            resolvedConfig.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,  // Use the known_hosts callback
		Timeout:         15 * time.Second, // Added a connection timeout
	}

	// Dial the server
	client, err := ssh.Dial("tcp", resolvedConfig.ServerAddress, config)
	if err != nil {
		// Error here will include host key verification failures
		return fmt.Errorf("failed to dial %s: %w", resolvedConfig.ServerAddress, err)
	}
	defer client.Close()
	log.Println("Connected successfully. Starting interactive session...")

	// Create a new session
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// --- Setup Interactive Session ---
	fd := int(os.Stdin.Fd())

	// Put the terminal into raw mode
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		// Don't Fatalf here, return the error to main
		return fmt.Errorf("failed to put terminal into raw mode: %w", err)
	}
	// Restore terminal state on exit (even if other errors occur)
	defer term.Restore(fd, oldState)

	// Get terminal dimensions
	width, height, err := term.GetSize(fd)
	if err != nil {
		log.Printf("Warning: Failed to get terminal size: %v. Using default 80x24.", err)
		width = 80
		height = 24
	}

	// Request pseudo terminal (PTY)
	termType := os.Getenv("TERM")
	if termType == "" {
		termType = "xterm-256color"
	}

	if err := session.RequestPty(termType, height, width, ssh.TerminalModes{}); err != nil {
		return fmt.Errorf("request for PTY failed: %w", err)
	}

	// Connect session stdin, stdout, stderr
	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	// Start the remote shell
	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %w", err)
	}

	// Wait for the session to finish.
	// Log the exit error, but don't return it as a fatal error from this function,
	// as a non-zero exit status from the remote shell is not necessarily a client error.
	waitErr := session.Wait()
	if waitErr != nil {
		log.Printf("Remote command exited with error: %v", waitErr)
	} else {
		log.Printf("Session finished.")
	}

	return nil // Successful execution of the session itself
}
