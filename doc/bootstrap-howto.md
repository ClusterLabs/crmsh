# How to use the Bootstrap commands

## Introduction

`crmsh` includes a set of cluster bootstrapping commands, both for
setting up an initial cluster, adding and removing nodes in the
cluster and for setting up geo clusters including arbitrators.

This document is a simplified guide to using these commands. There are
a lot of optional features that won't be fully covered by this guide,
but it should serve as a basic introduction to the bootstrap commands.

*Note:* These commands currently work correctly only on SUSE Linux
 Enterprise or openSUSE, and only if the `csync2` command is installed
 on all cluster nodes. For users of other distributions, please see
 the  documentation included with your operating system.

## Commands

First, here is the list of commands and a brief description of each
one. Each command is available in the `crm cluster` namespace, so to
run the `init` command, either call `crm cluster init` from the shell
command line or navigate to the `cluster` level in the interactive
`crm` shell and call the `init` command directly:

* `init` - Initialize a new cluster from scratch.
* `add` - Add a node to the current cluster.
* `join` - Add the current node to a cluster.
* `remove` - Remove a node from the cluster.
* `geo-init` - Create a new geo cluster with the current cluster as its first member.
* `geo-init-arbitrator` - Make the current node a geo cluster arbitrator.
* `geo-join` - Join the current cluster to an existing geo cluster.

## Initializing a basic cluster

For the full documentation of the `init` command, see
`crm help cluster init` in the interactive shell, or refer to the
online documentation at [crmsh.github.io](https://crmsh.github.io/).

### Using csync2 to synchronize configuration files

By default, the bootstrap commands make some assumptions about the
configuration to apply in order to simplify the process. One such
assumption is that the `csync2` command is installed and available for
use to synchronize the cluster configuration files across the
cluster. When initializing the basic cluster, `init` will configure
SSH access to all cluster nodes, open the necessary ports in the
firewall, and configure `csync2` so that configuration files can be
mirrored securely across the cluster.

### Configuring SBD

`SBD` is the storage based fencing mechanism recommended for use with
pacemaker. Using a storage based fencing method simplifies
configuration, as access to external hardware such as a lights-out
device or UPS doesn't have to be configured, and nodes can self-fence
if they detect reduced connectivity and loss of quorum.

`init` will optionally configure SBD for you. To do this, pass the
device to use as the SBD shared storage device using the
`--sbd-device=<device>` argument. It is also possible to configure
both SBD and a shared storage device formatted with the OCFS2 file
system, using the `--partition-device=<device>` argument. To use this
option, enable the `ocfs2` template using `-t ocfs2`.

### Basic Example

This command line when run on the uninitialized node `alice` will
configure and start a basic cluster on the three nodes `alice`, `bob`
and `carol`.

```
init --name basic-cluster --nodes "alice bob carol"
```

The `--name` argument is optional for regular clusters, but required
when configuring a geo cluster.

### Non-interactive configuration

To run the initialization steps non-interactively, pass the `-y` or
`--yes` flag to `init`. The default option will be chosen wherever the
command would otherwise have prompted for user input. If no default
option is available and user input is required, the command will
abort.

### Configuring shared storage

To configure shared storage using the `init` command, make sure that
you have a storage device accessible from all cluster nodes. This can
be an iSCSI device provided by a SAN, or a shared storage volume as
provided by your virtualization platform. To partition this device
into two volumes, one for use by SBD and one as a shared OCFS2 device,
use a command line like the following:

```
init --name storage-cluster --nodes "alice bob carol" -t ocfs2 -p /dev/shared
```

### Configuring an administration IP

To immediately configure a virtual IP address resource in the cluster,
use the `-A` argument: `init -A 1.2.3.4`.

The common use case for this virtual IP is to have a single point of
entry to [Hawk](https://hawk-ui.github.io), the cluster web
interface. It is also useful as a first example of a cluster
resource.

## Adding a new node to a cluster

There are two commands for adding a node to a cluster. When running
the command from one of the existing cluster nodes, use the `add`
form. For example, if there is an existing cluster consisting of the
nodes `alice` and `bob`, the following command will add `carol` as the
third node in the cluster when run from `alice` or `bob`:

```
alice# crm cluster add carol
```

It is also possible to add `carol` to the cluster from `carol`
directly, using the `join` form:

```
carol# crm cluster join -c alice
```

Note that `join` takes an argument `-c <node>`.

## Removing a node from a cluster

To remove a node from the cluster, run

```
crm cluster remove <node>
```

To remove the last node in a cluster (thereby destroying the cluster),
it is required to pass the `--force` flag to `crm`:

```
crm --force cluster remove $(hostname)
```

## Creating a geo cluster

Once you have a cluster up and running and you made sure to give it a
sensible name using `--name` (or by editing `corosync.conf` on all
cluster nodes and restarting the cluster), you can turn that cluster
into the first member in a geo cluster. Geo clusters are managed by
the `booth` daemon, so to use these commands, `booth` needs to be
installed on all cluster nodes.

The `geo-init` command takes as its arguments a complete description
of the geo cluster. This is because `booth` does not share its
configuration across the cluster, instead each cluster node in each
cluster needs to have a copy of the `booth` configuration.

As an example, we will configure a geo cluster consisting of five
nodes in total: The nodes `alice` and `bob` are members of the
`amsterdam` cluster. `carol` and `dave` are members of the `london`
cluster. Finally, `eve` is the arbitrator node located at a third
site. The `amsterdam` cluster is identified by the virtual IP
`192.168.100.8`, while the `london` cluster is identified by the
virtual IP `192.168.100.9`.

The `geo-init` command will configure these virtual IPs in each
cluster, so there is no need to configure them before-hand.

This geo cluster will share a single ticket, called `mcguffin`.

To create this configuration, run

```
crm cluster geo-init \
    --arbitrator eve \
    --tickets mcguffin \
    --clusters "amsterdam=192.168.100.8 london=192.168.100.9"
```

This will configure both the required cluster resources and the booth
daemon itself in the initial cluster.

## Adding an arbitrator to a geo cluster

This example uses the same basic setup as the `geo-init` example.

To configure the arbitrator `eve`, run the `geo-init-arbitrator`
command on `eve`, passing the cluster IP of the existing `amsterdam`
geo cluster member:

```
crm cluster geo-init-arbitrator \
    --cluster-node 192.168.100.8
```

## Adding a second cluster to a geo cluster

To add the `london` cluster to the existing geo cluster described in
the previous two sections, run the `geo-join` command from one of the
nodes in the cluster:

```
crm cluster geo-join --cluster-node 192.168.100.8
```
