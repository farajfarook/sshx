package main

import (
	"bufio" // For reading user input
	// For formatting known_hosts line
	"crypto/sha256"   // For fingerprint
	"encoding/base64" // For fingerprint
	"errors"
	"fmt"
	"log"
	"net" // Required again for net.Addr
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

// -- Custom Error for Unknown Host Key --
type ErrUnknownHostKey struct {
	Host           string
	Remote         net.Addr
	Key            ssh.PublicKey
	KnownHostsPath string
}

func (e *ErrUnknownHostKey) Error() string {
	// Provide a distinctive error message
	return fmt.Sprintf("ssh: unknown host key for %s", e.Host)
}

// Helper function for SHA256 fingerprint (matching ssh output)
func fingerprintSHA256(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	// Note: Using RawStdEncoding to avoid padding '=' characters, like standard ssh fingerprint.
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
}

// -- Host Key Handling Logic --

// createKnownHostsCallback creates the standard strict host key callback.
func createKnownHostsCallback() (ssh.HostKeyCallback, string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get current user for known_hosts path: %w", err)
	}
	knownHostsPath := filepath.Join(currentUser.HomeDir, ".ssh", "known_hosts")

	// Ensure the .ssh directory exists
	sshDir := filepath.Dir(knownHostsPath)
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		log.Printf("Creating SSH directory: %s", sshDir)
		if err := os.MkdirAll(sshDir, 0700); err != nil {
			return nil, "", fmt.Errorf("failed to create ssh directory %s: %w", sshDir, err)
		}
	}

	hostKeyCallback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, knownHostsPath, fmt.Errorf("failed to load known_hosts file '%s': %w", knownHostsPath, err)
	}

	log.Printf("Using known_hosts file: %s", knownHostsPath)
	return hostKeyCallback, knownHostsPath, nil
}

// createInteractiveHostKeyCallback creates a callback that returns a custom error for unknown keys.
func createInteractiveHostKeyCallback() (ssh.HostKeyCallback, string, error) {
	standardCallback, knownHostsPath, err := createKnownHostsCallback()
	if err != nil {
		return nil, knownHostsPath, err
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := standardCallback(hostname, remote, key)
		if err == nil {
			return nil
		}

		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) {
			if len(keyErr.Want) == 0 {
				return &ErrUnknownHostKey{
					Host:           hostname,
					Remote:         remote,
					Key:            key,
					KnownHostsPath: knownHostsPath,
				}
			} else {
				// Key mismatch error formatting (similar to OpenSSH)
				log.Printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
				log.Printf("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @")
				log.Printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
				log.Printf("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!")
				log.Printf("Someone could be eavesdropping on you right now (man-in-the-middle attack)!")
				log.Printf("It is also possible that a host key has just been changed.")
				log.Printf("The fingerprint for the %s key sent by the remote host %s is:", key.Type(), hostname)
				log.Printf(fingerprintSHA256(key))
				log.Printf("Please contact your system administrator.")
				// You would typically include the path to known_hosts and maybe the line number from keyErr
				log.Printf("Add correct host key in %s to get rid of this message.", knownHostsPath)
				for _, k := range keyErr.Want {
					log.Printf("Offending key found in %s:%d", k.Filename, k.Line)
					log.Printf("%s key fingerprint is %s", k.Key.Type(), fingerprintSHA256(k.Key))
				}
				return err
			}
		} else {
			return err
		}
	}, knownHostsPath, nil
}

// promptAndAddHostKey asks the user to confirm a new host key and appends it.
func promptAndAddHostKey(unknownHostErr *ErrUnknownHostKey) (bool, error) {
	reader := bufio.NewReader(os.Stdin)
	fingerprint := fingerprintSHA256(unknownHostErr.Key)
	host := unknownHostErr.Host

	// Remove the unnecessary backslash before the single quote
	fmt.Fprintf(os.Stderr, "The authenticity of host '%s (%s)' can't be established.\n", host, unknownHostErr.Remote.String())
	fmt.Fprintf(os.Stderr, "%s key fingerprint is %s.\n", unknownHostErr.Key.Type(), fingerprint)
	fmt.Fprintf(os.Stderr, "Are you sure you want to continue connecting (yes/no)? ")

	answer, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read user input: %w", err)
	}

	answer = strings.TrimSpace(strings.ToLower(answer))

	if answer == "yes" {
		// Format the line for known_hosts
		// Use Normalize() for the address part to handle CIDR etc. if needed, or just hostname
		// Address format: host[,ip] key_type base64_key
		addr := knownhosts.Normalize(unknownHostErr.Remote.String())
		hosts := []string{host}
		// Add IP address only if it's different from hostname
		if host != addr && host != unknownHostErr.Remote.String() {
			hosts = append(hosts, addr)
		}
		line := knownhosts.Line(hosts, unknownHostErr.Key)

		file, err := os.OpenFile(unknownHostErr.KnownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return false, fmt.Errorf("failed to open known_hosts '%s' for appending: %w", unknownHostErr.KnownHostsPath, err)
		}
		defer file.Close()

		_, err = file.WriteString(line + "\n")
		if err != nil {
			return false, fmt.Errorf("failed to append key to known_hosts '%s': %w", unknownHostErr.KnownHostsPath, err)
		}
		log.Printf("Warning: Permanently added '%s' (%s) to the list of known hosts.", strings.Join(hosts, ","), unknownHostErr.Key.Type())
		return true, nil
	} else {
		fmt.Fprintln(os.Stderr, "Host key verification failed. Connection aborted.")
		return false, nil
	}
}

// ConnectAndRunSession dials the SSH server, sets up the interactive session, and waits for it to complete.
func ConnectAndRunSession(resolvedConfig *ResolvedConfig, authMethods []ssh.AuthMethod) error {
	interactiveCallback, _, err := createInteractiveHostKeyCallback()
	if err != nil {
		return fmt.Errorf("could not create initial host key callback: %w", err)
	}

	log.Printf("Connecting to %s (%s) as user %s...", resolvedConfig.ServerAddress, resolvedConfig.Hostname, resolvedConfig.User)

	config := &ssh.ClientConfig{
		User:            resolvedConfig.User,
		Auth:            authMethods,
		HostKeyCallback: interactiveCallback,
		Timeout:         15 * time.Second,
	}

	client, err := ssh.Dial("tcp", resolvedConfig.ServerAddress, config)

	if err != nil {
		var unknownHostErr *ErrUnknownHostKey
		if errors.As(err, &unknownHostErr) {
			added, promptErr := promptAndAddHostKey(unknownHostErr)
			if promptErr != nil {
				return fmt.Errorf("error during host key prompt: %w", promptErr)
			}
			if !added {
				return errors.New("connection aborted by user: host key not trusted")
			}

			log.Println("Retrying connection with updated known_hosts...")
			standardCallback, _, cbErr := createKnownHostsCallback()
			if cbErr != nil {
				return fmt.Errorf("could not create standard host key callback for retry: %w", cbErr)
			}
			config.HostKeyCallback = standardCallback

			client, err = ssh.Dial("tcp", resolvedConfig.ServerAddress, config)
			if err != nil {
				return fmt.Errorf("failed to dial %s on retry: %w", resolvedConfig.ServerAddress, err)
			}
		} else {
			// Handle other dial errors (e.g., key mismatch already logged by callback, auth failure, network error)
			return fmt.Errorf("failed to dial %s: %w", resolvedConfig.ServerAddress, err)
		}
	}

	// Connection successful
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
