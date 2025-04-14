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

// dialWithHostkeyHandling attempts to connect, handles unknown host keys interactively,
// and retries the connection if a key is added. Returns the established client or an error.
func dialWithHostkeyHandling(resolvedConfig *ResolvedConfig, authMethods []ssh.AuthMethod) (*ssh.Client, error) {
	// Get the initial interactive callback from hostkey.go
	interactiveCallback, _, err := CreateInteractiveHostKeyCallback()
	if err != nil {
		return nil, fmt.Errorf("could not create initial host key callback: %w", err)
	}

	// --- First Dial Attempt ---
	config := &ssh.ClientConfig{
		User:            resolvedConfig.User,
		Auth:            authMethods,
		HostKeyCallback: interactiveCallback,
		Timeout:         15 * time.Second,
	}

	log.Printf("Connecting to %s (%s) as user %s...", resolvedConfig.ServerAddress, resolvedConfig.Hostname, resolvedConfig.User)
	client, err := ssh.Dial("tcp", resolvedConfig.ServerAddress, config)

	// --- Handle Dial Result ---
	if err != nil {
		var unknownHostErr *ErrUnknownHostKey // Use the type defined in hostkey.go
		if errors.As(err, &unknownHostErr) {
			// It's our specific 'unknown host' error, call prompt function from hostkey.go
			added, promptErr := PromptAndAddHostKey(unknownHostErr)
			if promptErr != nil {
				return nil, fmt.Errorf("error during host key prompt: %w", promptErr)
			}
			if !added {
				return nil, errors.New("connection aborted by user: host key not trusted")
			}

			// --- Second Dial Attempt (after adding key) ---
			log.Println("Retrying connection with updated known_hosts...")
			// Re-create the callback; it will now find the key in known_hosts
			retryCallback, _, cbErr := CreateInteractiveHostKeyCallback()
			if cbErr != nil {
				return nil, fmt.Errorf("could not create host key callback for retry: %w", cbErr)
			}
			config.HostKeyCallback = retryCallback // Use the callback again

			client, err = ssh.Dial("tcp", resolvedConfig.ServerAddress, config)
			if err != nil {
				// If it still fails (e.g., key mismatch on second try, auth error, etc.)
				return nil, fmt.Errorf("failed to dial %s on retry: %w", resolvedConfig.ServerAddress, err)
			}
			// Successfully connected on retry

		} else {
			// It was some other error during the first dial (network, auth, key mismatch already logged etc.)
			return nil, fmt.Errorf("failed to dial %s: %w", resolvedConfig.ServerAddress, err)
		}
	}

	// Connection successful (either first or second attempt)
	log.Println("Connected successfully.")
	return client, nil
}

// ConnectAndRunSession dials the SSH server, sets up the interactive session, and waits for it to complete.
func ConnectAndRunSession(resolvedConfig *ResolvedConfig, authMethods []ssh.AuthMethod) error {
	// Use the helper function to establish the connection
	client, err := dialWithHostkeyHandling(resolvedConfig, authMethods)
	if err != nil {
		return err // Return connection error directly
	}
	defer client.Close()
	log.Println("Starting interactive session...") // Connection success logged in helper

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
func ConnectAndRunCommand(resolvedConfig *ResolvedConfig, authMethods []ssh.AuthMethod, command string) (string, error) {
	// Use the helper function to establish the connection
	client, err := dialWithHostkeyHandling(resolvedConfig, authMethods)
	if err != nil {
		return "", err // Return connection error directly
	}
	defer client.Close()
	// Connection success logged in helper

	// --- Create Session and Run Command ---
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	log.Printf("Running remote command: %s", command)
	outputBytes, err := session.CombinedOutput(command)
	if err != nil {
		log.Printf("Remote command finished with error: %v", err)
		return string(outputBytes), err // Return raw error
	}

	log.Println("Remote command completed successfully.")
	return string(outputBytes), nil
}
