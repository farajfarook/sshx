package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// NOTE: All host key related functions and ErrUnknownHostKey moved to hostkey.go

// ConnectAndRunSession dials the SSH server, sets up the interactive session, and waits for it to complete.
func ConnectAndRunSession(resolvedConfig *ResolvedConfig, authMethods []ssh.AuthMethod) error {
	// Get the initial interactive callback from hostkey.go
	interactiveCallback, _, err := CreateInteractiveHostKeyCallback() // Assuming hostkey.go exports this
	if err != nil {
		return fmt.Errorf("could not create initial host key callback: %w", err)
	}

	log.Printf("Connecting to %s (%s) as user %s...", resolvedConfig.ServerAddress, resolvedConfig.Hostname, resolvedConfig.User)

	// --- First Dial Attempt ---
	config := &ssh.ClientConfig{
		User:            resolvedConfig.User,
		Auth:            authMethods,
		HostKeyCallback: interactiveCallback, // Use the interactive callback initially
		Timeout:         15 * time.Second,
	}

	client, err := ssh.Dial("tcp", resolvedConfig.ServerAddress, config)

	// --- Handle Dial Result ---
	if err != nil {
		var unknownHostErr *ErrUnknownHostKey // Use the type defined in hostkey.go
		if errors.As(err, &unknownHostErr) {
			// It's our specific 'unknown host' error, call prompt function from hostkey.go
			added, promptErr := PromptAndAddHostKey(unknownHostErr)
			if promptErr != nil {
				return fmt.Errorf("error during host key prompt: %w", promptErr)
			}
			if !added {
				return errors.New("connection aborted by user: host key not trusted")
			}

			// --- Second Dial Attempt (after adding key) ---
			log.Println("Retrying connection with updated known_hosts...")
			// Get standard strict callback from hostkey.go now
			// Assuming createKnownHostsCallback is NOT exported, or maybe we need it exported?
			// Let's assume we only need the interactive one again, which handles known keys now.
			// OR better: Get the strict callback directly if Prompt succeeded.
			// Re-creating the interactive one might be simpler code-wise, it falls back to strict check anyway.
			// Let's stick to re-creating interactive for now.
			retryCallback, _, cbErr := CreateInteractiveHostKeyCallback()
			if cbErr != nil {
				// This shouldn't fail if the first one succeeded, but check anyway
				return fmt.Errorf("could not create host key callback for retry: %w", cbErr)
			}
			config.HostKeyCallback = retryCallback // Use the callback again

			client, err = ssh.Dial("tcp", resolvedConfig.ServerAddress, config)
			if err != nil {
				// If it still fails (e.g., key mismatch on second try - unlikely but possible, or other error)
				return fmt.Errorf("failed to dial %s on retry: %w", resolvedConfig.ServerAddress, err)
			}
			// Successfully connected on retry

		} else {
			// It was some other error during the first dial (network, auth, key mismatch already logged etc.)
			return fmt.Errorf("failed to dial %s: %w", resolvedConfig.ServerAddress, err)
		}
	}

	// --- Connection Successful (either first or second attempt) ---
	defer client.Close()
	log.Println("Connected successfully. Starting interactive session...")

	// --- Session Setup (Remains the Same) ---
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("failed to put terminal into raw mode: %w", err)
	}
	defer term.Restore(fd, oldState)

	width, height, err := term.GetSize(fd)
	if err != nil {
		log.Printf("Warning: Failed to get terminal size: %v. Using default 80x24.", err)
		width = 80
		height = 24
	}

	termType := os.Getenv("TERM")
	if termType == "" {
		termType = "xterm-256color"
	}

	if err := session.RequestPty(termType, height, width, ssh.TerminalModes{}); err != nil {
		return fmt.Errorf("request for PTY failed: %w", err)
	}

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %w", err)
	}

	waitErr := session.Wait()
	if waitErr != nil {
		log.Printf("Remote command exited with error: %v", waitErr)
	} else {
		log.Printf("Session finished.")
	}

	return nil
}

// ConnectAndRunCommand dials the SSH server, runs a single command, and returns the combined output.
// It handles host key verification using the interactive callback.
func ConnectAndRunCommand(resolvedConfig *ResolvedConfig, authMethods []ssh.AuthMethod, command string) (string, error) {
	// Get the initial interactive callback from hostkey.go
	interactiveCallback, _, err := CreateInteractiveHostKeyCallback()
	if err != nil {
		return "", fmt.Errorf("could not create initial host key callback: %w", err)
	}

	log.Printf("Connecting to %s (%s) as user %s to run command...", resolvedConfig.ServerAddress, resolvedConfig.Hostname, resolvedConfig.User)

	// --- First Dial Attempt ---
	config := &ssh.ClientConfig{
		User:            resolvedConfig.User,
		Auth:            authMethods,
		HostKeyCallback: interactiveCallback, // Use the interactive callback initially
		Timeout:         15 * time.Second,
	}

	var client *ssh.Client // Declare client outside the retry block
	client, err = ssh.Dial("tcp", resolvedConfig.ServerAddress, config)

	// --- Handle Dial Result (including retry for unknown host) ---
	if err != nil {
		var unknownHostErr *ErrUnknownHostKey // Use the type defined in hostkey.go
		if errors.As(err, &unknownHostErr) {
			added, promptErr := PromptAndAddHostKey(unknownHostErr)
			if promptErr != nil {
				return "", fmt.Errorf("error during host key prompt: %w", promptErr)
			}
			if !added {
				return "", errors.New("connection aborted by user: host key not trusted")
			}

			// --- Second Dial Attempt ---
			log.Println("Retrying connection with updated known_hosts...")
			retryCallback, _, cbErr := CreateInteractiveHostKeyCallback()
			if cbErr != nil {
				return "", fmt.Errorf("could not create host key callback for retry: %w", cbErr)
			}
			config.HostKeyCallback = retryCallback

			client, err = ssh.Dial("tcp", resolvedConfig.ServerAddress, config)
			if err != nil {
				return "", fmt.Errorf("failed to dial %s on retry: %w", resolvedConfig.ServerAddress, err)
			}
		} else {
			return "", fmt.Errorf("failed to dial %s: %w", resolvedConfig.ServerAddress, err)
		}
	}

	// --- Connection Successful ---
	defer client.Close()
	log.Println("Connected successfully.")

	// --- Create Session and Run Command ---
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	log.Printf("Running remote command: %s", command)
	// Use CombinedOutput to get stdout and stderr
	outputBytes, err := session.CombinedOutput(command)
	if err != nil {
		// Command potentially failed. Log it, but return the raw error
		// so the caller can inspect ExitStatus if needed.
		log.Printf("Remote command finished with error: %v", err)
		return string(outputBytes), err // Return raw error
	}

	log.Println("Remote command completed successfully.")
	return string(outputBytes), nil // Return nil error on exit status 0
}
