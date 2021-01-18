CRM_H_OUTPUT = '''usage: crm [-h|--help] [OPTIONS] [SUBCOMMAND ARGS...]
or crm help SUBCOMMAND

For a list of available subcommands, use crm help.

Use crm without arguments for an interactive session.
Call a subcommand directly for a "single-shot" use.
Call crm with a level name as argument to start an interactive
session from that level.

See the crm(8) man page or call crm help for more details.

positional arguments:
  SUBCOMMAND

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -f FILE, --file FILE  Load commands from the given file. If a dash (-) is
                        used in place of a file name, crm will read commands
                        from the shell standard input (stdin).
  -c CIB, --cib CIB     Start the session using the given shadow CIB file.
                        Equivalent to `cib use <CIB>`.
  -D OUTPUT_TYPE, --display OUTPUT_TYPE
                        Choose one of the output options: plain, color-always,
                        color, or uppercase. The default is color if the
                        terminal emulation supports colors, else plain.
  -F, --force           Make crm proceed with applying changes where it would
                        normally ask the user to confirm before proceeding.
                        This option is mainly useful in scripts, and should be
                        used with care.
  -n, --no              Automatically answer no when prompted
  -w, --wait            Make crm wait for the cluster transition to finish
                        (for the changes to take effect) after each processed
                        line.
  -H DIR|FILE|SESSION, --history DIR|FILE|SESSION
                        A directory or file containing a cluster report to
                        load into history, or the name of a previously saved
                        history session.
  -d, --debug           Print verbose debugging information.
  -R, --regression-tests
                        Enables extra verbose trace logging used by the
                        regression tests. Logs all external calls made by
                        crmsh.
  --scriptdir DIR       Extra directory where crm looks for cluster scripts,
                        or a list of directories separated by semi-colons
                        (e.g. /dir1;/dir2;etc.).
  -X PROFILE            Collect profiling data and save in PROFILE.
  -o OPTION=VALUE, --opt OPTION=VALUE
                        Set crmsh option temporarily. If the options are saved
                        using+options save+ then the value passed here will
                        also be saved.Multiple options can be set by using
                        +-o+ multiple times.'''


CRM_CLUSTER_INIT_H_OUTPUT = '''usage: init [options] [STAGE]

optional arguments:
  -h, --help            Show this help message
  -q, --quiet           Be quiet (don't describe what's happening, just do it)
  -y, --yes             Answer "yes" to all prompts (use with caution, this is
                        destructive, especially during the "storage" stage.
                        The /root/.ssh/id_rsa key will be overwritten unless
                        the option "--no-overwrite-sshkey" is used)
  -t TEMPLATE, --template TEMPLATE
                        Optionally configure cluster with template "name"
                        (currently only "ocfs2" is valid here)
  -n NAME, --name NAME  Set the name of the configured cluster.
  -N NODES, --nodes NODES
                        Additional nodes to add to the created cluster. May
                        include the current node, which will always be the
                        initial cluster node.
  -S, --enable-sbd      Enable SBD even if no SBD device is configured
                        (diskless mode)
  -w WATCHDOG, --watchdog WATCHDOG
                        Use the given watchdog device or driver name
  --no-overwrite-sshkey
                        Avoid "/root/.ssh/id_rsa" overwrite if "-y" option is
                        used (False by default)

Network configuration:
  Options for configuring the network and messaging layer.

  -i IF, --interface IF
                        Bind to IP address on interface IF. Use -i second time
                        for second interface
  -u, --unicast         Configure corosync to communicate over unicast (UDP),
                        and not multicast. Default is multicast unless an
                        environment where multicast cannot be used is
                        detected.
  -A IP, --admin-ip IP  Configure IP address as an administration virtual IP
  -M, --multi-heartbeats
                        Configure corosync with second heartbeat line
  -I, --ipv6            Configure corosync use IPv6

QDevice configuration:
  Options for configuring QDevice and QNetd.

  --qnetd-hostname HOST
                        HOST or IP of the QNetd server to be used
  --qdevice-port PORT   TCP PORT of QNetd server(default:5403)
  --qdevice-algo ALGORITHM
                        QNetd decision ALGORITHM(ffsplit/lms, default:ffsplit)
  --qdevice-tie-breaker TIE_BREAKER
                        QNetd TIE_BREAKER(lowest/highest/valid_node_id,
                        default:lowest)
  --qdevice-tls TLS     Whether using TLS on QDevice/QNetd(on/off/required,
                        default:on)
  --qdevice-heuristics COMMAND
                        COMMAND to run with absolute path. For multiple
                        commands, use ";" to separate(details about heuristics
                        can see man 8 corosync-qdevice)
  --qdevice-heuristics-mode MODE
                        MODE of operation of heuristics(on/sync/off,
                        default:sync)

Storage configuration:
  Options for configuring shared storage.

  -p DEVICE, --partition-device DEVICE
                        Partition this shared storage device (only used in
                        "storage" stage)
  -s DEVICE, --sbd-device DEVICE
                        Block device to use for SBD fencing, use ";" as
                        separator or -s multiple times for multi path (up to 3
                        devices)
  -o DEVICE, --ocfs2-device DEVICE
                        Block device to use for OCFS2 (only used in "vgfs"
                        stage)

Stage can be one of:
    ssh         Create SSH keys for passwordless SSH between cluster nodes
    csync2      Configure csync2
    corosync    Configure corosync
    storage     Partition shared storage (ocfs2 template only)
    sbd         Configure SBD (requires -s <dev>)
    cluster     Bring the cluster online
    vgfs        Create volume group and filesystem (ocfs2 template only,
                requires -o <dev>)
    admin       Create administration virtual IP (optional)
    qdevice     Configure qdevice and qnetd

Note:
  - If stage is not specified, the script will run through each stage
    in sequence, with prompts for required information.
  - If using the ocfs2 template, the storage stage will partition a block
    device into two pieces, one for SBD, the remainder for OCFS2.  This is
    good for testing and demonstration, but not ideal for production.
    To use storage you have already configured, pass -s and -o to specify
    the block devices for SBD and OCFS2, and the automatic partitioning
    will be skipped.'''


CRM_CLUSTER_JOIN_H_OUTPUT = '''usage: join [options] [STAGE]

optional arguments:
  -h, --help            Show this help message
  -q, --quiet           Be quiet (don't describe what's happening, just do it)
  -y, --yes             Answer "yes" to all prompts (use with caution)
  -w WATCHDOG, --watchdog WATCHDOG
                        Use the given watchdog device

Network configuration:
  Options for configuring the network and messaging layer.

  -c HOST, --cluster-node HOST
                        IP address or hostname of existing cluster node
  -i IF, --interface IF
                        Bind to IP address on interface IF. Use -i second time
                        for second interface

Stage can be one of:
    ssh         Obtain SSH keys from existing cluster node (requires -c <host>)
    csync2      Configure csync2 (requires -c <host>)
    ssh_merge   Merge root's SSH known_hosts across all nodes (csync2 must
                already be configured).
    cluster     Start the cluster on this node

If stage is not specified, each stage will be invoked in sequence.'''


CRM_CLUSTER_ADD_H_OUTPUT = '''usage: add [options] [node ...]

optional arguments:
  -h, --help  Show this help message
  -y, --yes   Answer "yes" to all prompts (use with caution)'''


CRM_CLUSTER_REMOVE_H_OUTPUT = '''usage: remove [options] [<node> ...]

optional arguments:
  -h, --help            Show this help message
  -q, --quiet           Be quiet (don't describe what's happening, just do it)
  -y, --yes             Answer "yes" to all prompts (use with caution)
  -c HOST, --cluster-node HOST
                        IP address or hostname of cluster node which will be
                        deleted
  -F, --force           Remove current node
  --qdevice             Remove QDevice configuration and service from cluster'''


CRM_CLUSTER_GEO_INIT_H_OUTPUT = '''usage: geo-init [options]

optional arguments:
  -h, --help            Show this help message
  -q, --quiet           Be quiet (don't describe what's happening, just do it)
  -y, --yes             Answer "yes" to all prompts (use with caution)
  -a IP, --arbitrator IP
                        IP address of geo cluster arbitrator
  -s DESC, --clusters DESC
                        Geo cluster description (see details below)
  -t LIST, --tickets LIST
                        Tickets to create (space-separated)

Cluster Description

  This is a map of cluster names to IP addresses.
  Each IP address will be configured as a virtual IP
  representing that cluster in the geo cluster
  configuration.

  Example with two clusters named paris and amsterdam:

  --clusters "paris=192.168.10.10 amsterdam=192.168.10.11"

  Name clusters using the --name parameter to
  crm bootstrap init.'''


CRM_CLUSTER_GEO_JOIN_H_OUTPUT = '''usage: geo-join [options]

optional arguments:
  -h, --help            Show this help message
  -q, --quiet           Be quiet (don't describe what's happening, just do it)
  -y, --yes             Answer "yes" to all prompts (use with caution)
  -c IP, --cluster-node IP
                        IP address of an already-configured geo cluster or
                        arbitrator
  -s DESC, --clusters DESC
                        Geo cluster description (see geo-init for details)'''


CRM_CLUSTER_GEO_INIT_ARBIT_H_OUTPUT = '''usage: geo-init-arbitrator [options]

optional arguments:
  -h, --help            Show this help message
  -q, --quiet           Be quiet (don't describe what's happening, just do it)
  -y, --yes             Answer "yes" to all prompts (use with caution)
  -c IP, --cluster-node IP
                        IP address of an already-configured geo cluster'''
