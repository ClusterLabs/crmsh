# This Containerfile build the rootfs of the microvm, and will be converted to squashfs later
FROM docker.io/library/ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd \
    systemd-sysv \
    udev \
    dbus \
    podman \
    aardvark-dns \
    netavark \
    iptables \
    nftables \
    iproute2 \
    sudo \
    curl \
    python3 \
    tar \
    coreutils \
    util-linux \
    procps \
    ca-certificates \
    busybox-static \
    && rm -rf /var/lib/apt/lists/*

# As the `/` in a running microvm instance is an overlayfs,
# we mount /var/lib/containers as tmpfs so that podman can use it as the upperdir of another overlayfs there
RUN mkdir -p /var/lib/containers && \
    echo "tmpfs /var/lib/containers tmpfs defaults,mode=0755 0 0" >> /etc/fstab

# Mask non-essential systemd services for fast boot
RUN systemctl mask \
    systemd-networkd.service \
    systemd-resolved.service \
    systemd-timesyncd.service \
    systemd-udev-settle.service \
    systemd-journal-flush.service \
    getty@tty1.service \
    serial-getty@ttyS0.service \
    systemd-logind.service \
    multipathd.service \
    sys-kernel-config.mount \
    sys-kernel-debug.mount \
    sys-kernel-tracing.mount \
    networking.service \
    cron.service \
    rsyslog.service \
    motd-news.service \
    motd-news.timer

COPY crmsh-sandbox.service /etc/systemd/system/crmsh-sandbox.service
COPY guest-entrypoint.sh /usr/local/bin/guest-entrypoint.sh
RUN chmod +x /usr/local/bin/guest-entrypoint.sh && \
    systemctl enable crmsh-sandbox.service
