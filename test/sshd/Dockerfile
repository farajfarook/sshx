# test/sshd/Dockerfile

# Use a minimal Debian base image
FROM debian:stable-slim AS builder

# Install OpenSSH server and utilities
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-server ssh && \
    rm -rf /var/lib/apt/lists/*

# Configure SSHD
# Allow PasswordAuthentication and PubkeyAuthentication
# Listen on all interfaces
# Disable UsePAM for simplicity in this environment
# Disable StrictModes to avoid permission issues with user homes in Docker
RUN sed -i 's/^#?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#?AuthorizedKeysFile.*/AuthorizedKeysFile\t.ssh\/authorized_keys/' /etc/ssh/sshd_config && \
    echo "ListenAddress 0.0.0.0" >> /etc/ssh/sshd_config && \
    echo "UsePAM no" >> /etc/ssh/sshd_config && \
    echo "StrictModes no" >> /etc/ssh/sshd_config && \
    # Optional: Allow root login with key (or set to prohibit-password or no)
    # sed -i 's/^#?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    # Ensure login is not blocked
    sed -i 's/^#?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config

# Generate host keys
RUN ssh-keygen -A

# Create a test user
ARG USERNAME=testuser
ARG USERPASS=testpass
RUN useradd -m -s /bin/bash ${USERNAME} && \
    echo "${USERNAME}:${USERPASS}" | chpasswd && \
    # Create .ssh directory and set permissions
    mkdir /home/${USERNAME}/.ssh && \
    chmod 700 /home/${USERNAME}/.ssh && \
    chown -R ${USERNAME}:${USERNAME} /home/${USERNAME}/.ssh

# Create /run/sshd needed by sshd (newer versions)
RUN mkdir -p /run/sshd && chmod 0755 /run/sshd

# Expose the SSH port
EXPOSE 22

# Run sshd as a foreground daemon, logging errors to stderr
# Use -D (daemon, foreground) instead of -d (debug, single connection)
CMD ["/usr/sbin/sshd", "-D", "-e"] 