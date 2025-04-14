# Go SSH Client (sshx)

An interactive SSH client written in Go using the `golang.org/x/crypto/ssh` package. It aims to provide functionality similar to the standard OpenSSH client.

## Features

*   **Interactive Shell:** Provides a PTY for a full interactive session (`sshx <target>` or `sshx connect <target>`).
*   **Config Parsing:** Supports parsing `~/.ssh/config` for resolving host aliases and connection parameters (`Hostname`, `User`, `Port`, `IdentityFile`).
*   **Flexible Target:** Accepts host aliases (from `~/.ssh/config`) or direct `user@host[:port]` targets for both `connect` and `copy-id`.
*   **Dual Authentication:**
    *   Attempts Public Key authentication first (using key from `-i` flag, `IdentityFile` in config, or default `~/.ssh/id_rsa`).
    *   Supports passphrase-protected keys.
    *   Falls back to interactive Password authentication if key auth is unavailable or fails.
*   **Host Key Verification:**
    *   Verifies the remote server's host key against the user's `~/.ssh/known_hosts` file.
    *   Prompts the user interactively (yes/no) to add the key if the host is unknown.
    *   Detects and warns about host key mismatches (potential Man-in-the-Middle attacks).
*   **Public Key Installation (`copy-id`):** Includes an `sshx copy-id <target>` subcommand to install your default public key (`~/.ssh/id_ed25519.pub` or `id_rsa.pub` etc.) onto a remote server's `~/.ssh/authorized_keys` file, checking for duplicates.
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

### Connecting (Interactive Session)

The default action (or using the `connect` subcommand) starts an interactive SSH session.

```bash
# Default action: connect
./sshx my-server-alias
./sshx john.doe@192.168.1.100

# Explicitly using 'connect'
./sshx connect my-other-alias
./sshx connect admin@example.com:2222

# Overriding the authentication identity file
./sshx -i /path/to/my/private.key my-server-alias
./sshx connect -i C:\Keys\special.pem john.doe@192.168.1.100
```

Connection Process:
*   **Host Key:** Checks `~/.ssh/known_hosts`. If the host is unknown, it displays the key fingerprint and prompts for confirmation before adding it. If the key has changed, it aborts with a warning.
*   **Authentication:** Attempts public key authentication using the resolved key (from `-i`, config, or default). If the key requires a passphrase, it prompts for it. If key authentication is not possible or fails, it falls back to prompting for the user's password.

### Copying Public Key (`copy-id`)

The `copy-id` subcommand installs your public key for passwordless authentication.

```bash
# Copy default public key (~/.ssh/id_*.pub) to the target
./sshx copy-id my-server-alias
./sshx copy-id user@new-server.com

# Use a specific key for AUTHENTICATION when running copy-id
# (it still copies the default *public* key unless otherwise specified)
./sshx -i ~/.ssh/auth_key copy-id my-server-alias
```

Copy Process:
*   Finds your default public key (`~/.ssh/id_ed25519.pub`, `id_ecdsa.pub`, or `id_rsa.pub` preferred in that order). If `-i` points to a private key (e.g., `-i ~/.ssh/my_private`), it tries to find the corresponding `.pub` file (`~/.ssh/my_private.pub`).
*   Connects to the target host using standard authentication (keys/password, potentially prompting for host key verification).
*   Checks if the key already exists in `~/.ssh/authorized_keys` on the remote host.
*   If the key doesn't exist, it appends the public key content and sets appropriate file permissions.

## Automated Releases

This repository uses GitHub Actions to build binaries for Linux (amd64), macOS (amd64), and Windows (amd64) whenever a Git tag matching `v*.*.*` or `v*.*.*-*` (for pre-releases) is pushed. These binaries (`sshx-os-arch` or `sshx-windows-amd64.exe`) are automatically attached to a GitHub Release corresponding to the tag.

## Security Considerations

*   **Host Key Verification:** This client now implements standard host key verification against `~/.ssh/known_hosts`, significantly improving security against Man-in-the-Middle attacks compared to previous versions.
*   **Password Authentication:** While supported as a fallback, using Public Key authentication is generally recommended for better security.
*   **Dependencies:** Review the security posture of dependencies (`golang.org/x/crypto`, `golang.org/x/term`, `github.com/kevinburke/ssh_config`). 