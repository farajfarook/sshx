# Go SSH Client (sshx)

An interactive SSH client written in Go using the `golang.org/x/crypto/ssh` package. It aims to provide functionality similar to the standard OpenSSH client.

## Features

*   **Interactive Shell:** Provides a PTY for a full interactive session.
*   **Config Parsing:** Supports parsing `~/.ssh/config` for resolving host aliases and connection parameters (`Hostname`, `User`, `Port`, `IdentityFile`).
*   **Flexible Target:** Accepts host aliases (from `~/.ssh/config`) or direct `user@host[:port]` targets.
*   **Dual Authentication:** 
    *   Attempts Public Key authentication first (using key from `-i` flag, `IdentityFile` in config, or default `~/.ssh/id_rsa`).
    *   Supports passphrase-protected keys.
    *   Falls back to interactive Password authentication if key auth is unavailable or fails.
*   **Cross-Platform Builds:** Includes a GitHub Actions workflow (`.github/workflows/release.yml`) to automatically build binaries for Linux, macOS, and Windows upon tagging a release (e.g., `v1.0.0`).

## Build

Ensure you have Go installed and configured (version specified in `go.mod`).

1.  Fetch dependencies:
    ```bash
    go mod tidy
    ```
2.  Build the executable (named `sshx`):
    ```bash
    # For your current OS
    go build -o sshx .
    # Or specifically for Windows
    # go build -o sshx.exe .
    ```

## Usage

```bash
# Using a host alias defined in ~/.ssh/config
./sshx my-server-alias

# Using direct user@host
./sshx john.doe@192.168.1.100

# Using direct user@host with a specific port
./sshx admin@example.com:2222

# Overriding the identity file (key)
./sshx -i /path/to/my/private.key my-server-alias
./sshx -i C:\Keys\special.pem john.doe@192.168.1.100 
```

The client will attempt public key authentication using the resolved key. If the key requires a passphrase, it will prompt for it. If key authentication is not possible or fails, it will prompt for the user's password.

## Automated Releases

This repository uses GitHub Actions to build binaries for Linux (amd64), macOS (amd64), and Windows (amd64) whenever a Git tag matching `v*.*.*` is pushed. These binaries are automatically attached to a GitHub Release corresponding to the tag.

## CRITICAL SECURITY WARNING

**This client is NOT currently production-grade due to a critical security omission:**

*   **Missing Host Key Verification:** The client uses `ssh.InsecureIgnoreHostKey()`. This **disables verification of the remote server's identity**, making the connection **highly vulnerable to Man-in-the-Middle (MitM) attacks**. An attacker could impersonate the server and intercept your credentials or session.

**DO NOT use this client for connecting to sensitive systems or in untrusted networks until proper host key verification (e.g., checking against a `known_hosts` file) is implemented.** 