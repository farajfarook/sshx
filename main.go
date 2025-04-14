package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	// No longer needed: os/user, path/filepath, strings
	// No longer needed here: net, strconv, errors, ssh, term, ssh_config
)

// NOTE: expandTilde moved to config.go

func main() {
	// --- Define and parse command line flags ---
	identityFilePathFlag := flag.String("i", "", "Path to the private key file (overrides config and defaults)")
	flag.Parse()

	// --- Get target argument ---
	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-i /path/to/key] <host_alias | user@host[:port]>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       <host_alias> matches a Host entry in ~/.ssh/config\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	targetArg := flag.Arg(0)

	// --- Resolve connection parameters ---
	resolvedConfig, err := ResolveConnectionConfig(targetArg, *identityFilePathFlag)
	if err != nil {
		log.Fatalf("Error resolving connection config: %v", err)
	}

	// --- Prepare authentication methods ---
	authMethods, err := PrepareAuthMethods(resolvedConfig)
	if err != nil {
		// PrepareAuthMethods only returns fatal errors (e.g., cannot read passphrase)
		log.Fatalf("Error preparing authentication methods: %v", err)
	}

	// --- Connect and run the interactive session ---
	err = ConnectAndRunSession(resolvedConfig, authMethods)
	if err != nil {
		// ConnectAndRunSession returns fatal errors (dial, PTY setup, etc.)
		// Non-zero exit codes from the remote shell are logged within that function but not returned as errors here.
		log.Fatalf("Error during SSH connection or session: %v", err)
	}

	// If ConnectAndRunSession returned nil, the session completed (possibly with a remote error logged).
	// Main exits successfully.
	log.Println("SSH client finished.")
}
