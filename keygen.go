package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	rsaDefaultBits = 4096
	rsaMinBits     = 2048
)

// handleKeygen implements the ssh-keygen functionality.
func handleKeygen(args []string) {
	keygenFlags := flag.NewFlagSet("keygen", flag.ExitOnError)

	// Define flags
	keyType := keygenFlags.String("t", "ed25519", "Specifies the type of key to create (rsa, ed25519)")
	keyBits := keygenFlags.Int("b", rsaDefaultBits, "Specifies the number of bits in the key to create (for RSA)")
	outputFile := keygenFlags.String("f", "", "Specifies the filename of the key file (default: ~/.ssh/id_TYPE)")
	passphrase := keygenFlags.String("N", "", "Provides the new passphrase")
	comment := keygenFlags.String("C", "", "Provides the comment")

	// Custom usage message for keygen
	keygenFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s keygen [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		keygenFlags.PrintDefaults()
	}

	// Parse the flags for the keygen subcommand
	keygenFlags.Parse(args)

	// --- Validate Flags ---
	*keyType = strings.ToLower(*keyType)
	if *keyType != "rsa" && *keyType != "ed25519" {
		log.Fatalf("Error: Invalid key type '%s'. Supported types are 'rsa' and 'ed25519'.", *keyType)
	}
	if *keyType == "rsa" && *keyBits < rsaMinBits {
		log.Fatalf("Error: RSA key bits must be at least %d.", rsaMinBits)
	}

	// --- Determine Default Values ---
	// Default comment
	if *comment == "" {
		currentUser, err := user.Current()
		if err != nil {
			log.Printf("Warning: could not get current user for default comment: %v", err)
		} else {
			hostname, err := os.Hostname()
			if err != nil {
				log.Printf("Warning: could not get hostname for default comment: %v", err)
			} else {
				*comment = fmt.Sprintf("%s@%s", currentUser.Username, hostname)
			}
		}
	}

	// Default output file path
	if *outputFile == "" {
		currentUser, err := user.Current()
		if err != nil {
			log.Fatalf("Error getting current user for default key file path: %v", err)
		}
		defaultFilename := fmt.Sprintf("id_%s", *keyType)
		*outputFile = filepath.Join(currentUser.HomeDir, ".ssh", defaultFilename)
	} else {
		// Expand tilde if present in user-provided path
		expandedPath, err := ExpandTilde(*outputFile)
		if err != nil {
			log.Fatalf("Error expanding path '%s': %v", *outputFile, err)
		}
		*outputFile = expandedPath
	}
	publicKeyFile := *outputFile + ".pub"

	log.Printf("Generating public/private %s key pair.", *keyType)

	// --- Generate Key Pair ---
	privKey, pubKey, err := generateKeyPair(*keyType, *keyBits)
	if err != nil {
		log.Fatalf("Error generating key pair: %v", err)
	}

	// --- Encode Private Key ---
	pemBlock, err := encodePrivateKeyToPEM(privKey, []byte(*passphrase))
	if err != nil {
		log.Fatalf("Error encoding private key: %v", err)
	}

	// --- Encode Public Key ---
	sshPubKeyBytes, err := encodePublicKeyToSSH(pubKey, *comment)
	if err != nil {
		log.Fatalf("Error encoding public key: %v", err)
	}

	// --- Write Files ---
	// Ensure the output directory exists
	outputDir := filepath.Dir(*outputFile)
	if err := os.MkdirAll(outputDir, 0700); err != nil { // Use 0700 for ~/.ssh
		log.Fatalf("Error creating output directory '%s': %v", outputDir, err)
	}

	// Write private key (permissions 0600)
	if err := writeFile(*outputFile, pemBlock, 0600); err != nil {
		log.Fatalf("Error writing private key file '%s': %v", *outputFile, err)
	}
	fmt.Printf("Your identification has been saved in %s\n", *outputFile)

	// Write public key (permissions 0644)
	if err := writeFile(publicKeyFile, sshPubKeyBytes, 0644); err != nil {
		log.Fatalf("Error writing public key file '%s': %v", publicKeyFile, err)
	}
	fmt.Printf("Your public key has been saved in %s\n", publicKeyFile)

	// TODO: Add fingerprint generation if desired
	fmt.Println("The key fingerprint is:")
	// Fingerprint generation would go here
	fmt.Println("The key's randomart image is:")
	// Randomart generation would go here
}

// generateKeyPair creates a new private/public key pair based on type and bits.
func generateKeyPair(keyType string, bits int) (any, any, error) {
	switch keyType {
	case "rsa":
		log.Printf("Generating RSA key with %d bits", bits)
		privateKey, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		return privateKey, &privateKey.PublicKey, nil
	case "ed25519":
		log.Println("Generating Ed25519 key")
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
		}
		return privateKey, publicKey, nil
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// encodePrivateKeyToPEM converts a private key to PEM format, optionally encrypted.
func encodePrivateKeyToPEM(privateKey any, passphrase []byte) ([]byte, error) {
	var pemBlock *pem.Block
	var err error

	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		// Use PKCS#8 format for better compatibility
		pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal RSA private key to PKCS#8: %w", err)
		}
		pemBlock = &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes} // Use generic "PRIVATE KEY" for PKCS#8
	case ed25519.PrivateKey:
		// Use PKCS#8 format
		pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Ed25519 private key to PKCS#8: %w", err)
		}
		pemBlock = &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes} // Use generic "PRIVATE KEY" for PKCS#8
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	// Encrypt the PEM block if a passphrase is provided
	if len(passphrase) > 0 {
		log.Println("Encrypting private key with passphrase.")
		// Note: Using DEK-Info headers is older; modern OpenSSH uses a different format.
		// This uses PEM encryption standards. Consider compatibility needs.
		// x509.EncryptPEMBlock is deprecated, but standard library alternatives are complex.
		// Using it for simplicity for now.
		//nolint:staticcheck // SA1019: x509.EncryptPEMBlock is deprecated
		pemBlock, err = x509.EncryptPEMBlock(rand.Reader, pemBlock.Type, pemBlock.Bytes, passphrase, x509.PEMCipherAES256)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt PEM block: %w", err)
		}
		// Ensure correct type after encryption
		if !strings.Contains(pemBlock.Type, "ENCRYPTED") {
			pemBlock.Type = "ENCRYPTED PRIVATE KEY" // Be explicit if encryption happened but type wasn't set
		}

	}

	return pem.EncodeToMemory(pemBlock), nil
}

// encodePublicKeyToSSH converts a public key to the authorized_keys format.
func encodePublicKeyToSSH(publicKey any, comment string) ([]byte, error) {
	sshPubKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create ssh public key: %w", err)
	}

	authorizedKeyBytes := ssh.MarshalAuthorizedKey(sshPubKey)

	// Append comment if provided
	if comment != "" {
		authorizedKeyBytes = append(authorizedKeyBytes[:len(authorizedKeyBytes)-1], []byte(" "+comment+"\n")...) // Replace trailing newline with comment + newline
	}

	return authorizedKeyBytes, nil
}

// writeFile writes data to a file with specific permissions, ensuring it doesn't overwrite.
func writeFile(filename string, data []byte, perm os.FileMode) error {
	// Check if the file already exists
	if _, err := os.Stat(filename); err == nil {
		return fmt.Errorf("file '%s' already exists, refusing to overwrite", filename)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to check if file '%s' exists: %w", filename, err) // Other error during stat
	}

	// Write the file
	err := os.WriteFile(filename, data, perm)
	if err != nil {
		return fmt.Errorf("failed to write file '%s': %w", filename, err)
	}
	log.Printf("Successfully wrote %s", filename)
	return nil
}

// NOTE: expandTilde needs to be available (exported from config.go or similar).
