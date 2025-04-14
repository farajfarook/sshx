package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// passwordCallback prompts the user for a password if required.
// Kept private to this package, used by PrepareAuthMethods.
func passwordCallbackFunc(user, host string) (string, error) {
	fmt.Printf("Password for %s@%s: ", user, host)
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Println() // Newline after password input
	return string(bytePassword), nil
}

// PrepareAuthMethods attempts to load the private key and sets up authentication methods.
// It returns a slice containing ssh.PublicKeys (if key loaded) and ssh.PasswordCallback.
func PrepareAuthMethods(resolvedConfig *ResolvedConfig) ([]ssh.AuthMethod, error) {
	var authMethods []ssh.AuthMethod

	keyPath := resolvedConfig.KeyPath
	logContext := keyPath
	if resolvedConfig.IsAlias {
		logContext = fmt.Sprintf("%s (Resolved from Alias: %s)", keyPath, resolvedConfig.TargetArg)
	}
	log.Printf("Attempting to load private key from: %s", logContext)

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Private key file not found: %s. Will proceed without key auth.", keyPath)
		} else {
			// Log non-fatal read error, but don't return error, allow password fallback
			log.Printf("Warning: Failed to read private key file '%s': %v. Will proceed without key auth.", keyPath, err)
		}
	} else {
		// Try parsing the private key without a passphrase
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			var passphraseError *ssh.PassphraseMissingError
			if errors.As(err, &passphraseError) {
				fmt.Printf("Enter passphrase for key '%s': ", keyPath)
				passphraseBytes, pErr := term.ReadPassword(int(os.Stdin.Fd()))
				if pErr != nil {
					// If we can't read passphrase, it's a fatal error for key auth
					return nil, fmt.Errorf("failed to read passphrase: %w", pErr)
				}
				fmt.Println()
				signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, passphraseBytes)
				if err != nil {
					// Failed parsing with passphrase, log warning and continue without key auth
					log.Printf("Warning: Failed to parse private key '%s' with passphrase: %v. Proceeding without key auth.", keyPath, err)
				} else {
					log.Println("Private key loaded and parsed successfully.")
					authMethods = append(authMethods, ssh.PublicKeys(signer))
				}
			} else {
				// Other parsing error, log warning and continue without key auth
				log.Printf("Warning: Failed to parse private key '%s': %v. Proceeding without key auth.", keyPath, err)
			}
		} else {
			// Parsed successfully without passphrase
			log.Println("Private key loaded and parsed successfully.")
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		}
	}

	// Add password callback as a fallback authentication method
	passwordAuthCallback := func() (string, error) {
		// Use the resolved user and hostname from the config struct
		return passwordCallbackFunc(resolvedConfig.User, resolvedConfig.Hostname)
	}
	authMethods = append(authMethods, ssh.PasswordCallback(passwordAuthCallback))

	if len(authMethods) == 1 {
		log.Println("No usable private key found or loaded. Will attempt password authentication.")
	}

	return authMethods, nil
}
