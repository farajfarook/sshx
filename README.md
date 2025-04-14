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
*   **Host Key Verification:** 
    *   Verifies the remote server's host key against the user's `~/.ssh/known_hosts` file.
    *   Prompts the user interactively (yes/no) to add the key if the host is unknown.
    *   Detects and warns about host key mismatches (potential Man-in-the-Middle attacks).
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

The client performs authentication and host key verification:
*   **Host Key:** Checks `~/.ssh/known_hosts`. If the host is unknown, it displays the key fingerprint and prompts for confirmation before adding it. If the key has changed, it aborts with a warning.
*   **Authentication:** Attempts public key authentication using the resolved key. If the key requires a passphrase, it prompts for it. If key authentication is not possible or fails, it falls back to prompting for the user's password.

## Automated Releases

This repository uses GitHub Actions to build binaries for Linux (amd64), macOS (amd64), and Windows (amd64) whenever a Git tag matching `v*.*.*` or `v*.*.*-*` (for pre-releases) is pushed. These binaries are automatically attached to a GitHub Release corresponding to the tag.

## Security Considerations

*   **Host Key Verification:** This client now implements standard host key verification against `~/.ssh/known_hosts`, significantly improving security against Man-in-the-Middle attacks compared to previous versions.
*   **Password Authentication:** While supported as a fallback, using Public Key authentication is generally recommended for better security.
*   **Dependencies:** Review the security posture of dependencies (`golang.org/x/crypto`, `golang.org/x/term`, `github.com/kevinburke/ssh_config`).

## Automated Releases

This repository uses GitHub Actions to build binaries for Linux (amd64), macOS (amd64), and Windows (amd64) whenever a Git tag matching `v*.*.*` or `v*.*.*-*` (for pre-releases) is pushed. These binaries are automatically attached to a GitHub Release corresponding to the tag.

## Security Considerations

*   **Host Key Verification:** This client now implements standard host key verification against `~/.ssh/known_hosts`, significantly improving security against Man-in-the-Middle attacks compared to previous versions.
*   **Password Authentication:** While supported as a fallback, using Public Key authentication is generally recommended for better security.
*   **Dependencies:** Review the security posture of dependencies (`golang.org/x/crypto`, `golang.org/x/term`, `github.com/kevinburke/ssh_config`). 