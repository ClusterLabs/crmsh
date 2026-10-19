# Sandboxed Functional Test Runner

This directory contains the Firecracker-based microVM sandbox for executing `crmsh` end-to-end functional and behave test suites in a secure, isolated, and reproducible environment.

## Rationale

Running crmsh functional tests directly on a developer's local machine is unsafe and intrusive because:

* They configure real networking, modify firewall rules (iptables/nftables), manage services (systemd), and run privileged operations that can disrupt the host system.
* Direct test execution on the host requires specific dependencies and system configurations that might differ from target deployment environments.
* Our container solution (Podman) does not share this risk entirely, but it still needs host root privileges to configure networking and kernel tunables.

A firecracker-based microVM sandbox allows developers to safely, reliably, and instantly run functional tests in an isolated guest environment with zero host pollution.

## Prerequisites

### Hardware & Kernel Requirements

- **CPU:** x86_64 processor with hardware virtualization.
- **KVM Access:** `/dev/kvm` must exist and be accessible with read and write permissions for the current user.

### Runtime Dependencies

* firecracker
* podman
* squashfs-tools
* e2fsprogs

## Building the Sandbox

```bash
test/sandbox-functional-tests/build
```

### What the build script does:

1. **Verifies Kernel:** Confirms `vmlinux` exists. Provides build instructions when it does not exists.
2. **Builds HA Container Image:** Builds `localhost/haleap:latest` from `test_container/Dockerfile` if not already present.
3. **Builds MicroVM Base Image:** Builds `crmsh-sandbox-base` using `test/sandbox-functional-tests/Dockerfile` (Ubuntu 24.04 with systemd, Podman, netavark, aardvark-dns).
4. **Packs Rootfs (`rootfs.squashfs`):** Caches `haleap.tar` inside `/var/lib/` and exports the container directly into a compressed zstd squashfs image using `sqfstar`.
5. **Generates Initrd (`initrd.img`):** Creates an initramfs with Busybox and a startup script that discovers `/dev/vda` (the squashfs root), overlays a tmpfs layer via overlayfs, and executes `/sbin/init`.

### Force Rebuilding

To force a rebuild of the nested `localhost/haleap:latest` container image along with the rootfs:

```bash
test/sandbox-functional-tests/build -f
```

## Usage

All functional test interactions are executed through the `run` script:

```bash
test/sandbox-functional-tests/run [OPTIONS] [FEATURE_ID...]
```

### Basic Command Syntax

Arguments passed to `run` are forwarded directly to `test/run-functional-tests` inside the sandbox environment.

#### Interactive Debugging Mode

Pass `-i` or `--interactive` to drop into an interactive bash shell inside the microVM.

```bash
# Boot directly into an interactive shell inside the sandbox
test/sandbox-functional-tests/run -i
```

### Code Coverage Reports

If the functional test run produces code coverage reports (`coverage*.xml`), the `run` script automatically extracts them from the microVM workspace disk and places them into the root of the repository before the temporary workspace is destroyed.
