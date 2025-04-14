package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// ConnectAndRunSession dials the SSH server, sets up the interactive session, and waits for it to complete.
func ConnectAndRunSession(resolvedConfig *ResolvedConfig, authMethods []ssh.AuthMethod) error {
	log.Printf("Connecting to %s (%s) as user %s...", resolvedConfig.ServerAddress, resolvedConfig.Hostname, resolvedConfig.User)

	// Configure SSH client
	// NOTE: HostKeyCallback is still insecure!
	config := &ssh.ClientConfig{
		User:            resolvedConfig.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Replace with secure callback later
		// Consider adding a timeout: Timeout: 15 * time.Second,
	}

	// Dial the server
	client, err := ssh.Dial("tcp", resolvedConfig.ServerAddress, config)
	if err != nil {
		// Error here likely includes authentication failures
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
