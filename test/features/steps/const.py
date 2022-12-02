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


CRM_CLUSTER_INIT_H_OUTPUT = '''Initializes a new HA cluster

usage: init [options] [STAGE]

Initialize a cluster from scratch. This command configures
a complete cluster, and can also add additional cluster
nodes to the initial one-node cluster using the --nodes
option.

optional arguments:
  -h, --help            Show this help message
  -q, --quiet           Be quiet (don't describe what's happening, just do it)
  -y, --yes             Answer "yes" to all prompts (use with caution, this is
                        destructive, especially those storage related
                        configurations and stages.)
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
                        used (False by default; Deprecated)

Network configuration:
  Options for configuring the network and messaging layer.

  -i IF, --interface IF
                        Bind to IP address on interface IF. Use -i second time
                        for second interface
  -u, --unicast         Configure corosync to communicate over unicast(udpu).
                        This is the default transport type
  -U, --multicast       Configure corosync to communicate over multicast.
                        Default is unicast
  -A IP, --admin-ip IP  Configure IP address as an administration virtual IP
  -M, --multi-heartbeats
                        Configure corosync with second heartbeat line
  -I, --ipv6            Configure corosync use IPv6

QDevice configuration:
  QDevice participates in quorum decisions. With the assistance of 
  a third-party arbitrator Qnetd, it provides votes so that a cluster 
  is able to sustain more node failures than standard quorum rules 
  allow. It is recommended for clusters with an even number of nodes 
  and highly recommended for 2 node clusters.
  
  Options for configuring QDevice and QNetd.

  --qnetd-hostname HOST
                        HOST or IP of the QNetd server to be used
  --qdevice-port PORT   TCP PORT of QNetd server (default:5403)
  --qdevice-algo ALGORITHM
                        QNetd decision ALGORITHM (ffsplit/lms,
                        default:ffsplit)
  --qdevice-tie-breaker TIE_BREAKER
                        QNetd TIE_BREAKER (lowest/highest/valid_node_id,
                        default:lowest)
  --qdevice-tls TLS     Whether using TLS on QDevice/QNetd (on/off/required,
                        default:on)
  --qdevice-heuristics COMMAND
                        COMMAND to run with absolute path. For multiple
                        commands, use ";" to separate (details about
                        heuristics can see man 8 corosync-qdevice)
  --qdevice-heuristics-mode MODE
                        MODE of operation of heuristics (on/sync/off,
                        default:sync)

Storage configuration:
  Options for configuring shared storage.

  -s DEVICE, --sbd-device DEVICE
                        Block device to use for SBD fencing, use ";" as
                        separator or -s multiple times for multi path (up to 3
                        devices)
  -o DEVICE, --ocfs2-device DEVICE
                        Block device to use for OCFS2; When using Cluster LVM2
                        to manage the shared storage, user can specify one or
                        multiple raw disks, use ";" as separator or -o
                        multiple times for multi path (must specify -C option)
                        NOTE: this is a Technical Preview
  -C, --cluster-lvm2    Use Cluster LVM2 (only valid together with -o option)
                        NOTE: this is a Technical Preview
  -m MOUNT, --mount-point MOUNT
                        Mount point for OCFS2 device (default is
                        /srv/clusterfs, only valid together with -o option)
                        NOTE: this is a Technical Preview

Stage can be one of:
    ssh         Create SSH keys for passwordless SSH between cluster nodes
    csync2      Configure csync2
    corosync    Configure corosync
    sbd         Configure SBD (requires -s <dev>)
    cluster     Bring the cluster online
    ocfs2       Configure OCFS2 (requires -o <dev>) NOTE: this is a Technical Preview
    vgfs        Create volume group and filesystem (ocfs2 template only,
                    requires -o <dev>) NOTE: this stage is an alias of ocfs2 stage
    admin       Create administration virtual IP (optional)
    qdevice     Configure qdevice and qnetd

Note:
  - If stage is not specified, the script will run through each stage
    in sequence, with prompts for required information.

Examples:
  # Setup the cluster on the current node
  crm cluster init -y

  # Setup the cluster with multiple nodes
  (NOTE: the current node will be part of the cluster even not listed in the -N option as below)
  crm cluster init -N node1 -N node2 -N node3 -y

  # Setup the cluster on the current node, with two network interfaces
  crm cluster init -i eth1 -i eth2 -y

  # Setup the cluster on the current node, with disk-based SBD
  crm cluster init -s <share disk> -y

  # Setup the cluster on the current node, with diskless SBD
  crm cluster init -S  -y

  # Setup the cluster on the current node, with QDevice
  crm cluster init --qnetd-hostname <qnetd addr> -y

  # Setup the cluster on the current node, with SBD+OCFS2
  crm cluster init -s <share disk1> -o <share disk2> -y

  # Setup the cluster on the current node, with SBD+OCFS2+Cluster LVM
  crm cluster init -s <share disk1> -o <share disk2> -o <share disk3> -C -y

  # Add SBD on a running cluster
  crm cluster init sbd -s <share disk> -y

  # Add QDevice on a running cluster
  crm cluster init qdevice --qnetd-hostname <qnetd addr> -y

  # Add OCFS2+Cluster LVM on a running cluster
  crm cluster init ocfs2 -o <share disk1> -o <share disk2> -C -y'''


CRM_CLUSTER_JOIN_H_OUTPUT = '''Join existing cluster

usage: join [options] [STAGE]

Join the current node to an existing cluster. The
current node cannot be a member of a cluster already.
Pass any node in the existing cluster as the argument
to the -c option.

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

If stage is not specified, each stage will be invoked in sequence.

Examples:
  # Join with a cluster node
  crm cluster join -c <node> -y

  # Join with a cluster node, with the same network interface used by that node
  crm cluster join -c <node> -i eth1 -i eth2 -y'''


CRM_CLUSTER_ADD_H_OUTPUT = '''Add a new node to the cluster

usage: add [options] [node ...]

Add a new node to the cluster. The new node will be
configured as a cluster member.

optional arguments:
  -h, --help  Show this help message
  -y, --yes   Answer "yes" to all prompts (use with caution)'''


CRM_CLUSTER_REMOVE_H_OUTPUT = '''Remove node(s) from the cluster

usage: remove [options] [<node> ...]

Remove one or more nodes from the cluster.

This command can remove the last node in the cluster,
thus effectively removing the whole cluster. To remove
the last node, pass --force argument to crm or set
the config.core.force option.

optional arguments:
  -h, --help            Show this help message
  -q, --quiet           Be quiet (don't describe what's happening, just do it)
  -y, --yes             Answer "yes" to all prompts (use with caution)
  -c HOST, --cluster-node HOST
                        IP address or hostname of cluster node which will be
                        deleted
  -F, --force           Remove current node
  --qdevice             Remove QDevice configuration and service from cluster'''


CRM_CLUSTER_GEO_INIT_H_OUTPUT = '''Configure cluster as geo cluster

usage: geo-init [options]

Create a new geo cluster with the current cluster as the
first member. Pass the complete geo cluster topology as
arguments to this command, and then use geo-join and
geo-init-arbitrator to add the remaining members to
the geo cluster.

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


CRM_CLUSTER_GEO_JOIN_H_OUTPUT = '''Join cluster to existing geo cluster

usage: geo-join [options]

This command should be run from one of the nodes in a cluster
which is currently not a member of a geo cluster. The geo
cluster configuration will be fetched from the provided node,
and the cluster will be added to the geo cluster.

Note that each cluster in a geo cluster needs to have a unique
name set. The cluster name can be set using the --name argument
to init, or by configuring corosync with the cluster name in
an existing cluster.

optional arguments:
  -h, --help            Show this help message
  -q, --quiet           Be quiet (don't describe what's happening, just do it)
  -y, --yes             Answer "yes" to all prompts (use with caution)
  -c IP, --cluster-node IP
                        IP address of an already-configured geo cluster or
                        arbitrator
  -s DESC, --clusters DESC
                        Geo cluster description (see geo-init for details)'''


CRM_CLUSTER_GEO_INIT_ARBIT_H_OUTPUT = '''Initialize node as geo cluster arbitrator

usage: geo-init-arbitrator [options]

Configure the current node as a geo arbitrator. The command
requires an existing geo cluster or geo arbitrator from which
to get the geo cluster configuration.

optional arguments:
  -h, --help            Show this help message
  -q, --quiet           Be quiet (don't describe what's happening, just do it)
  -y, --yes             Answer "yes" to all prompts (use with caution)
  -c IP, --cluster-node IP
                        IP address of an already-configured geo cluster'''
