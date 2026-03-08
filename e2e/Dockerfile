FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    openssh-server \
    sudo \
    iproute2 \
    curl \
    python3 \
    strace \
    net-tools \
    linux-tools-generic \
    kmod \
    && rm -rf /var/lib/apt/lists/*

# Install kernel modules matching the e2e VM kernel (6.8.0-49-generic from 22.04 HWE).
#
# The e2e/vmlinuz kernel is built from Ubuntu 22.04 HWE (vermagic includes
# "#49~22.04.1-Ubuntu"), so modules from Ubuntu 24.04's native repo have
# mismatched modversions CRCs — modprobe fails with "Invalid argument".
# We add the Jammy (22.04) HWE repo and install the matching modules.
RUN echo "deb http://archive.ubuntu.com/ubuntu jammy-updates main" > /etc/apt/sources.list.d/jammy-hwe.list && \
    apt-get update && \
    apt-get install -y --allow-downgrades linux-modules-6.8.0-49-generic && \
    depmod -a 6.8.0-49-generic && \
    rm -f /etc/apt/sources.list.d/jammy-hwe.list && \
    rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir /var/run/sshd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Ensure pam_loginuid is enabled (critical for auid tracking)
RUN grep -q 'pam_loginuid' /etc/pam.d/sshd || \
    echo 'session required pam_loginuid.so' >> /etc/pam.d/sshd

# Create test user with uid 1000.
# ⚠️  Ubuntu 24.04 Docker base image ships a pre-existing "ubuntu" user at uid 1000.
#     If we don't delete it, useradd assigns testuser uid 1001 instead.
#     The bloodhound daemon is configured with --uid 1000 (the target loginuid/auid),
#     so a uid mismatch means the daemon traces the wrong user → 0 events in NDJSON.
RUN echo "root:root" | chpasswd
RUN userdel -r ubuntu 2>/dev/null || true
RUN useradd -m -s /bin/bash -u 1000 testuser && \
    echo 'testuser:testpass' | chpasswd && \
    echo 'testuser ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Create test fixtures
RUN mkdir -p /opt/test-fixtures && \
    echo "test-hostname" > /opt/test-fixtures/hostname && \
    echo "#!/bin/bash" > /opt/test-fixtures/test-script.sh && \
    echo "echo hello" >> /opt/test-fixtures/test-script.sh && \
    chmod +x /opt/test-fixtures/test-script.sh

# Create directory for bloodhound binary
RUN mkdir -p /opt/bloodhound

# SSH host keys
RUN ssh-keygen -A

# Expose SSH port
EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
