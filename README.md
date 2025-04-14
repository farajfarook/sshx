# Go SSH Client Example

This is a simple interactive SSH client written in Go using the `golang.org/x/crypto/ssh` package.

## Features

*   Connects to an SSH server specified as `user@host[:port]`. 
*   Uses interactive password authentication.
*   Provides an interactive shell session.

## Build

Ensure you have Go installed and configured.

1.  Initialize modules (if not already done):
    ```bash
    go mod init sshclient # Or your desired module name
    go mod tidy
    ```
2.  Build the executable:
    ```bash
    go build 
    ```
    This will create `sshclient.exe` (on Windows) or `sshclient` (on Linux/macOS) based on your module name.

## Usage

```bash
./sshclient user@hostname
```

Replace `user@hostname` with your actual username and the server's hostname or IP address. You can optionally specify a port like `user@hostname:port`.

The program will prompt for your password.

## Security Warning

**This example is for educational purposes only and has significant security limitations:**

*   **Password Authentication:** It relies solely on passwords, which are less secure than public key authentication.
*   **Insecure Host Key Checking:** It uses `ssh.InsecureIgnoreHostKey()`, which bypasses verification of the server's host key. **This makes the connection vulnerable to Man-in-the-Middle (MitM) attacks.**

**DO NOT use this code in production environments without implementing proper public key authentication and host key verification.** 