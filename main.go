package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	// No longer needed: os/user, path/filepath, strings
	// No longer needed here: net, strconv, errors, ssh, term, ssh_config
)

// NOTE: expandTilde moved to config.go

func main() {
	// --- Top-level flags (e.g., -i for identity file, usable by multiple subcommands) ---
	// We parse flags first to make them available before deciding the subcommand.
	// Note: Flags defined here won't be automatically available to subcommands if we use flag.NewFlagSet later.
	// This structure might need adjustment if subcommands need complex shared flags, or use a CLI library.
	identityFilePathFlag := flag.String("i", "", "Path to the private key file (for connection auth or key to copy if applicable)")
	// It's important to parse *before* checking os.Args for subcommands
	flag.Parse()

	// --- Subcommand Dispatching ---
	args := flag.Args() // Get non-flag arguments

	if len(args) == 0 {
		// No arguments provided - show usage?
		// Or default to interactive session? Let's show usage for now.
		printUsage()
		os.Exit(1)
	}

	subcommand := args[0]
	subcommandArgs := args[1:] // Arguments specific to the subcommand

	switch subcommand {
	case "copy-id":
		// Call the function to handle copy-id (to be implemented)
		handleCopyId(subcommandArgs, *identityFilePathFlag)
	case "connect": // Optional: Add explicit 'connect' subcommand
		// Handle interactive connection (existing logic)
		handleConnect(subcommandArgs, *identityFilePathFlag)
	default:
		// Treat the first argument as the target for the default 'connect' action
		handleConnect(args, *identityFilePathFlag) // Pass all args including the 'subcommand' which is actually the target
	}
}

// printUsage displays help information.
func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [global options] <subcommand> [subcommand options] [arguments]\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Global options:\n")
	flag.PrintDefaults() // Prints flags defined in main (like -i)
	fmt.Fprintf(os.Stderr, "\nSubcommands:\n")
	fmt.Fprintf(os.Stderr, "  connect   Connect to a host and start an interactive session (default if no subcommand given).\n")
	fmt.Fprintf(os.Stderr, "            Usage: %s connect [-i key] <host_alias | user@host[:port]>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  copy-id   Copy a public key to a remote host's authorized_keys file.\n")
	fmt.Fprintf(os.Stderr, "            Usage: %s copy-id [-i pubkey] <host_alias | user@host[:port]>\n", os.Args[0])
	// Add more subcommands here
}

// handleConnect contains the original logic for the interactive session.
func handleConnect(args []string, identityFile string) {
	if len(args) != 1 {
		log.Printf("Error: 'connect' requires exactly one argument: <host_alias | user@host[:port]>\n")
		printUsage()
		os.Exit(1)
	}
	targetArg := args[0]

	// --- Resolve connection parameters ---
	resolvedConfig, err := ResolveConnectionConfig(targetArg, identityFile)
	if err != nil {
		log.Fatalf("Error resolving connection config: %v", err)
	}

	// --- Prepare authentication methods ---
	authMethods, err := PrepareAuthMethods(resolvedConfig)
	if err != nil {
		log.Fatalf("Error preparing authentication methods: %v", err)
	}

	// --- Connect and run the interactive session ---
	err = ConnectAndRunSession(resolvedConfig, authMethods)
	if err != nil {
		log.Fatalf("Error during SSH connection or session: %v", err)
	}

	log.Println("SSH client finished.")
}

// handleCopyId implements the ssh-copy-id functionality.
func handleCopyId(args []string, authIdentityFile string) { // Renamed identityFile -> authIdentityFile for clarity
	// 1. Parse Arguments
	if len(args) != 1 {
		log.Printf("Error: 'copy-id' requires exactly one argument: <host_alias | user@host[:port]>\n")
		printUsage()
		os.Exit(1)
	}
	targetArg := args[0]

	// TODO: Add specific flags for copy-id if needed, e.g., explicitly setting the public key path
	// For now, we try to find the default public key.

	// 2. Determine Public Key File Path
	// We prioritize ~/.ssh/id_ed25519.pub, then id_rsa.pub for defaults
	pubKeyPath := "" // We need to determine this
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("Error getting current user: %v", err)
	}
	homeDir := currentUser.HomeDir

	// Define potential default public key paths
	defaultPubKeys := []string{
		filepath.Join(homeDir, ".ssh", "id_ed25519.pub"),
		filepath.Join(homeDir, ".ssh", "id_ecdsa.pub"),
		filepath.Join(homeDir, ".ssh", "id_rsa.pub"),
	}

	// Check if a specific auth key was given AND it looks like a private key (no .pub)
	// If so, try deriving the .pub path from it.
	if authIdentityFile != "" && !strings.HasSuffix(strings.ToLower(authIdentityFile), ".pub") {
		derivedPubKeyPath := authIdentityFile + ".pub"
		if _, err := os.Stat(derivedPubKeyPath); err == nil {
			log.Printf("Using public key derived from -i flag: %s", derivedPubKeyPath)
			pubKeyPath = derivedPubKeyPath
		}
	}

	// If no key found yet, check the defaults
	if pubKeyPath == "" {
		for _, p := range defaultPubKeys {
			if _, err := os.Stat(p); err == nil {
				log.Printf("Found default public key: %s", p)
				pubKeyPath = p
				break
			}
		}
	}

	if pubKeyPath == "" {
		log.Fatalf("Error: Could not find a default public key file (e.g., ~/.ssh/id_rsa.pub, ~/.ssh/id_ed25519.pub).")
	}

	// 3. Read Public Key Content
	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		log.Fatalf("Error reading public key file '%s': %v", pubKeyPath, err)
	}
	// Trim whitespace/newlines from the key content
	pubKeyContent := strings.TrimSpace(string(pubKeyBytes))
	if pubKeyContent == "" {
		log.Fatalf("Error: Public key file '%s' is empty.", pubKeyPath)
	}

	log.Printf("Public key to copy from '%s':\n%s\n", pubKeyPath, pubKeyContent)

	// 4. Resolve connection parameters for the target host
	log.Printf("Resolving connection for target: %s", targetArg)
	resolvedConfig, err := ResolveConnectionConfig(targetArg, authIdentityFile)
	if err != nil {
		log.Fatalf("Error resolving connection config for target '%s': %v", targetArg, err)
	}

	// 5. Prepare authentication methods for connecting
	log.Println("Preparing authentication methods...")
	authMethods, err := PrepareAuthMethods(resolvedConfig)
	if err != nil {
		log.Fatalf("Error preparing authentication methods for target '%s': %v", targetArg, err)
	}

	// 6. & 7. Construct command and run it remotely
	log.Println("Constructing remote command...")
	// Ensure the key content is properly quoted for the shell command
	// Using single quotes around the key content handles most special characters.
	// If the key itself contains single quotes (highly unlikely), more complex quoting is needed.
	remoteCommand := fmt.Sprintf("mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '%s' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", pubKeyContent)

	log.Println("Connecting to remote host to run command...")
	output, err := ConnectAndRunCommand(resolvedConfig, authMethods, remoteCommand)

	// 8. Report success/failure
	if err != nil {
		// ConnectAndRunCommand already logs details
		// Output might contain useful error details from the server
		fmt.Fprintf(os.Stderr, "\nError running remote command: %v\n", err)
		if output != "" {
			fmt.Fprintf(os.Stderr, "Remote output on error:\n%s\n", output)
		}
		log.Fatalf("Failed to copy public key.")
	}

	log.Printf("Successfully copied public key to %s@%s.", resolvedConfig.User, resolvedConfig.Hostname)
	// Optional: Print remote output even on success?
	// if output != "" {
	// 	fmt.Printf("Remote output:\n%s\n", output)
	// }

}
