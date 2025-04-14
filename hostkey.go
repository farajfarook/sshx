package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// -- Custom Error for Unknown Host Key --
// ErrUnknownHostKey signals that the host key was not found in known_hosts.
// It contains the necessary details to prompt the user.
type ErrUnknownHostKey struct {
	Host           string
	Remote         net.Addr
	Key            ssh.PublicKey
	KnownHostsPath string
}

func (e *ErrUnknownHostKey) Error() string {
	return fmt.Sprintf("ssh: unknown host key for %s", e.Host)
}

// Helper function for SHA256 fingerprint (matching ssh output)
func fingerprintSHA256(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
}

// createKnownHostsCallback creates the standard strict host key callback.
// It returns the callback, the path to the known_hosts file, and any error encountered.
func createKnownHostsCallback() (ssh.HostKeyCallback, string, error) {
	var knownHostsPath string
	// Check environment variable first
	envPath := os.Getenv("SSH_KNOWN_HOSTS")
	if envPath != "" {
		knownHostsPath = envPath
		log.Printf("Using known_hosts path from environment variable SSH_KNOWN_HOSTS: %s", knownHostsPath)
	} else {
		// Fall back to default path
		currentUser, err := user.Current()
		if err != nil {
			return nil, "", fmt.Errorf("failed to get current user for known_hosts path: %w", err)
		}
		knownHostsPath = filepath.Join(currentUser.HomeDir, ".ssh", "known_hosts")
	}

	// Ensure the directory exists if we need to create the file later
	sshDir := filepath.Dir(knownHostsPath)
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		log.Printf("Creating directory for known_hosts: %s", sshDir)
		if err := os.MkdirAll(sshDir, 0700); err != nil {
			return nil, knownHostsPath, fmt.Errorf("failed to create directory %s for known_hosts: %w", sshDir, err)
		}
	} else if err != nil {
		// Handle potential errors checking the directory stat other than NotExist
		return nil, knownHostsPath, fmt.Errorf("failed to stat directory %s for known_hosts: %w", sshDir, err)
	}

	// Attempt to load the known_hosts file. It might not exist yet, which is okay for knownhosts.New
	// as long as the directory exists.
	hostKeyCallback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		// knownhosts.New can fail if the file exists but has bad permissions or format.
		// If it doesn't exist, it shouldn't fail here.
		return nil, knownHostsPath, fmt.Errorf("failed to initialize known_hosts mechanism with path '%s': %w", knownHostsPath, err)
	}

	log.Printf("Using known_hosts file: %s", knownHostsPath) // Log the final path being used
	return hostKeyCallback, knownHostsPath, nil
}

// CreateInteractiveHostKeyCallback creates a callback that returns ErrUnknownHostKey for unknown keys.
// This function is exported for use by session.go.
func CreateInteractiveHostKeyCallback() (ssh.HostKeyCallback, string, error) {
	standardCallback, knownHostsPath, err := createKnownHostsCallback()
	if err != nil {
		return nil, knownHostsPath, err
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := standardCallback(hostname, remote, key)
		if err == nil {
			return nil // Key is known and matches.
		}

		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) {
			if len(keyErr.Want) == 0 {
				// Host is unknown.
				return &ErrUnknownHostKey{
					Host:           hostname,
					Remote:         remote,
					Key:            key,
					KnownHostsPath: knownHostsPath,
				}
			} else {
				// Key mismatch error formatting.
				log.Printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
				log.Printf("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @")
				log.Printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
				log.Printf("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!")
				log.Printf("Someone could be eavesdropping on you right now (man-in-the-middle attack)!")
				log.Printf("It is also possible that a host key has just been changed.")
				log.Printf("The fingerprint for the %s key sent by the remote host %s is:", key.Type(), hostname)
				log.Printf("%s", fingerprintSHA256(key))
				log.Printf("Please contact your system administrator.")
				log.Printf("Add correct host key in %s to get rid of this message.", knownHostsPath)
				for _, k := range keyErr.Want {
					log.Printf("Offending key found in %s:%d", k.Filename, k.Line)
					log.Printf("%s key fingerprint is %s", k.Key.Type(), fingerprintSHA256(k.Key))
				}
				return err // Return the original knownhosts.KeyError.
			}
		} else {
			// Return other errors (e.g., parsing errors in known_hosts).
			return err
		}
	}, knownHostsPath, nil // Return the custom callback and the path.
}

// PromptAndAddHostKey asks the user to confirm a new host key and appends it.
// This function is exported for use by session.go.
func PromptAndAddHostKey(unknownHostErr *ErrUnknownHostKey) (bool, error) {
	reader := bufio.NewReader(os.Stdin)
	fingerprint := fingerprintSHA256(unknownHostErr.Key)
	host := unknownHostErr.Host

	fmt.Fprintf(os.Stderr, "The authenticity of host '%s (%s)' can't be established.\n", host, unknownHostErr.Remote.String())
	fmt.Fprintf(os.Stderr, "%s key fingerprint is %s.\n", unknownHostErr.Key.Type(), fingerprint)
	fmt.Fprintf(os.Stderr, "Are you sure you want to continue connecting (yes/no)? ")

	answer, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read user input: %w", err)
	}

	answer = strings.TrimSpace(strings.ToLower(answer))

	if answer == "yes" {
		addr := knownhosts.Normalize(unknownHostErr.Remote.String())
		hosts := []string{host}
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
		return false, nil // User chose not to add key, not an error state for this func.
	}
}
