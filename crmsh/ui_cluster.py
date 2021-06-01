# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import sys
import re
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from . import command
from . import utils
from . import scripts
from . import completers as compl
from . import bootstrap
from . import corosync
from .cibconfig import cib_factory
from . import constants


from . import log
logger = log.setup_logger(__name__)


class ArgParser(ArgumentParser):
    def format_epilog(self, formatter):
        return self.epilog or ""


def parse_options(parser, args):
    try:
        options, args = parser.parse_known_args(list(args))
    except:
        return None, None
    if hasattr(options, 'help') and options.help:
        parser.print_help()
        return None, None
    utils.check_space_option_value(options)
    return options, args


def parse_option_for_nodes(context, *args):
    """
    Parse option for nodes
    Return a node list
    """
    action_type = context.get_command_name()
    action_target = "node" if action_type in ["standby", "online"] else "cluster service"
    action = "{} {}".format(action_type, action_target)
    usage_template = """
Specify node(s) on which to {action}.
If no nodes are specified, {action} on the local node.
If --all is specified, {action} on all nodes."""
    addtion_usage = ""
    if action_type == "standby":
        usage_template += """
\n\nAdditionally, you may specify a lifetime for the standby---if set to
"reboot", the node will be back online once it reboots. "forever" will
keep the node in standby after reboot. The life time defaults to
"forever"."""
        addtion_usage = " [lifetime]"

    parser = ArgParser(description=usage_template.format(action=action),
            usage="{} [--all | <node>... ]{}".format(action_type, addtion_usage),
            add_help=False,
            formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument("-h", "--help", action="store_true", dest="help", help="Show this help message")
    parser.add_argument("--all", help="To {} on all nodes".format(action), action="store_true", dest="all")

    options, args = parse_options(parser, args)
    if options is None or args is None:
        raise utils.TerminateSubCommand
    if options.all and args:
        context.fatal_error("Should either use --all or specific node(s)")

    # return local node
    if not options.all and not args:
        return [utils.this_node()]
    member_list = utils.list_cluster_nodes()
    if not member_list:
        context.fatal_error("Cannot get the node list from cluster")
    for node in args:
        if node not in member_list:
            context.fatal_error("Node \"{}\" is not a cluster node".format(node))
    # return node list
    return member_list if options.all else args


def _remove_completer(args):
    try:
        n = utils.list_cluster_nodes()
    except:
        n = []
    for node in args[1:]:
        if node in n:
            n.remove(node)
    return scripts.param_completion_list('remove') + n


def script_printer():
    from .ui_script import ConsolePrinter
    return ConsolePrinter()


def script_args(args):
    from .ui_script import _nvpairs2parameters
    return _nvpairs2parameters(args)


def get_cluster_name():
    cluster_name = None
    if not utils.service_is_active("corosync.service"):
        name = corosync.get_values('totem.cluster_name')
        if name:
            cluster_name = name[0]
    else:
        cluster_name = cib_factory.get_property('cluster-name')
    return cluster_name


class Cluster(command.UI):
    '''
    Whole cluster management.

    - Package installation
    - System configuration
    - Network troubleshooting
    - Perform other callouts/cluster-wide devops operations
    '''
    name = "cluster"

    def requires(self):
        return True

    def __init__(self):
        command.UI.__init__(self)
        # ugly hack to allow overriding the node list
        # for the cluster commands that operate before
        # there is an actual cluster
        self._inventory_nodes = None
        self._inventory_target = None

    @command.skill_level('administrator')
    def do_start(self, context, *args):
        '''
        Starts the cluster services on all nodes or specific node(s)
        '''
        node_list = parse_option_for_nodes(context, *args)
        for node in node_list[:]:
            if utils.service_is_active("pacemaker.service", remote_addr=node):
                logger.info("Cluster services already started on {}".format(node))
                node_list.remove(node)
        if not node_list:
            return

        if utils.is_qdevice_configured():
            utils.start_service("corosync-qdevice", node_list=node_list)
        bootstrap.start_pacemaker(node_list)
        for node in node_list:
            logger.info("Cluster services started on {}".format(node))

    @command.skill_level('administrator')
    def do_stop(self, context, *args):
        '''
        Stops the cluster services on all nodes or specific node(s)
        '''
        node_list = parse_option_for_nodes(context, *args)
        for node in node_list[:]:
            if not utils.service_is_active("corosync.service", remote_addr=node) and \
                    not utils.service_is_active("sbd.service", remote_addr=node):
                logger.info("Cluster services already stopped on {}".format(node))
                node_list.remove(node)
        if not node_list:
            return

        # Stop pacemaker since it can make sure cluster has quorum until stop corosync
        utils.stop_service("pacemaker", node_list=node_list)
        # Then, stop qdevice if is active
        if utils.service_is_active("corosync-qdevice.service"):
            utils.stop_service("corosync-qdevice.service", node_list=node_list)
        # Last, stop corosync
        utils.stop_service("corosync", node_list=node_list)

        for node in node_list:
            logger.info("Cluster services stopped on {}".format(node))

    @command.skill_level('administrator')
    def do_restart(self, context, *args):
        '''
        Restarts the cluster services on all nodes or specific node(s)
        '''
        parse_option_for_nodes(context, *args)
        self.do_stop(context, *args)
        self.do_start(context, *args)

    def _enable_disable_common(self, context, *args):
        '''
        Common part for enable and disable
        '''
        node_list = parse_option_for_nodes(context, *args)
        action = context.get_command_name()
        utils.cluster_run_cmd("systemctl {} pacemaker.service".format(action), node_list)
        if utils.is_qdevice_configured():
            utils.cluster_run_cmd("systemctl {} corosync-qdevice.service".format(action), node_list)
        for node in node_list:
            logger.info("Cluster services %s on %s", action+'d', node)

    @command.skill_level('administrator')
    def do_enable(self, context, *args):
        '''
        Enable the cluster services on this node
        '''
        self._enable_disable_common(context, *args)

    @command.skill_level('administrator')
    def do_disable(self, context, *args):
        '''
        Disable the cluster services on this node
        '''
        self._enable_disable_common(context, *args)

    def _args_implicit(self, context, args, name):
        '''
        handle early non-nvpair arguments as
        values in an implicit list
        '''
        args = list(args)
        vals = []
        while args and args[0].find('=') == -1:
            vals.append(args[0])
            args = args[1:]
        if vals:
            return args + ['%s=%s' % (name, ','.join(vals))]
        return args

    # @command.completers_repeating(compl.call(scripts.param_completion_list, 'init'))
    @command.skill_level('administrator')
    def do_init(self, context, *args):
        '''
        Initialize a cluster.
        '''
        def looks_like_hostnames(lst):
            sectionlist = bootstrap.INIT_STAGES
            return all(not (l.startswith('-') or l in sectionlist) for l in lst)
        if len(args) > 0:
            if '--dry-run' in args or looks_like_hostnames(args):
                args = ['--yes', '--nodes'] + [arg for arg in args if arg != '--dry-run']
        parser = ArgParser(description="""
Initialize a cluster from scratch. This command configures
a complete cluster, and can also add additional cluster
nodes to the initial one-node cluster using the --nodes
option.""", usage="init [options] [STAGE]", epilog="""

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
""", add_help=False, formatter_class=RawDescriptionHelpFormatter)

        parser.add_argument("-h", "--help", action="store_true", dest="help", help="Show this help message")
        parser.add_argument("-q", "--quiet", action="store_true", dest="quiet",
                            help="Be quiet (don't describe what's happening, just do it)")
        parser.add_argument("-y", "--yes", action="store_true", dest="yes_to_all",
                            help='Answer "yes" to all prompts (use with caution, this is destructive, especially those storage related configurations and stages. The /root/.ssh/id_rsa key will be overwritten unless the option "--no-overwrite-sshkey" is used)')
        parser.add_argument("-n", "--name", metavar="NAME", dest="cluster_name", default="hacluster",
                            help='Set the name of the configured cluster.')
        parser.add_argument("-N", "--nodes", metavar="NODES", dest="nodes",
                            help='Additional nodes to add to the created cluster. May include the current node, which will always be the initial cluster node.')
        # parser.add_argument("--quick-start", dest="quickstart", action="store_true", help="Perform basic system configuration (NTP, watchdog, /etc/hosts)")
        parser.add_argument("-S", "--enable-sbd", dest="diskless_sbd", action="store_true",
                            help="Enable SBD even if no SBD device is configured (diskless mode)")
        parser.add_argument("-w", "--watchdog", dest="watchdog", metavar="WATCHDOG",
                            help="Use the given watchdog device or driver name")
        parser.add_argument("--no-overwrite-sshkey", action="store_true", dest="no_overwrite_sshkey",
                            help='Avoid "/root/.ssh/id_rsa" overwrite if "-y" option is used (False by default)')

        network_group = parser.add_argument_group("Network configuration", "Options for configuring the network and messaging layer.")
        network_group.add_argument("-i", "--interface", dest="nic_list", metavar="IF", action="append", choices=utils.interface_choice(),
                                   help="Bind to IP address on interface IF. Use -i second time for second interface")
        network_group.add_argument("-u", "--unicast", action="store_true", dest="unicast",
                                   help="Configure corosync to communicate over unicast (UDP), and not multicast. " +
                                   "Default is multicast unless an environment where multicast cannot be used is detected.")
        network_group.add_argument("-A", "--admin-ip", dest="admin_ip", metavar="IP",
                                   help="Configure IP address as an administration virtual IP")
        network_group.add_argument("-M", "--multi-heartbeats", action="store_true", dest="second_heartbeat",
                                   help="Configure corosync with second heartbeat line")
        network_group.add_argument("-I", "--ipv6", action="store_true", dest="ipv6",
                                   help="Configure corosync use IPv6")

        qdevice_group = parser.add_argument_group("QDevice configuration", re.sub('  ', '', constants.QDEVICE_HELP_INFO) + "\n\nOptions for configuring QDevice and QNetd.")
        qdevice_group.add_argument("--qnetd-hostname", dest="qnetd_addr", metavar="HOST",
                                   help="HOST or IP of the QNetd server to be used")
        qdevice_group.add_argument("--qdevice-port", dest="qdevice_port", metavar="PORT", type=int, default=5403,
                                   help="TCP PORT of QNetd server (default:5403)")
        qdevice_group.add_argument("--qdevice-algo", dest="qdevice_algo", metavar="ALGORITHM", default="ffsplit", choices=['ffsplit', 'lms'],
                                   help="QNetd decision ALGORITHM (ffsplit/lms, default:ffsplit)")
        qdevice_group.add_argument("--qdevice-tie-breaker", dest="qdevice_tie_breaker", metavar="TIE_BREAKER", default="lowest",
                                   help="QNetd TIE_BREAKER (lowest/highest/valid_node_id, default:lowest)")
        qdevice_group.add_argument("--qdevice-tls", dest="qdevice_tls", metavar="TLS", default="on", choices=['on', 'off', 'required'],
                                   help="Whether using TLS on QDevice/QNetd (on/off/required, default:on)")
        qdevice_group.add_argument("--qdevice-heuristics", dest="qdevice_heuristics", metavar="COMMAND",
                                   help="COMMAND to run with absolute path. For multiple commands, use \";\" to separate (details about heuristics can see man 8 corosync-qdevice)")
        qdevice_group.add_argument("--qdevice-heuristics-mode", dest="qdevice_heuristics_mode", metavar="MODE", choices=['on', 'sync', 'off'],
                                   help="MODE of operation of heuristics (on/sync/off, default:sync)")

        storage_group = parser.add_argument_group("Storage configuration", "Options for configuring shared storage.")
        storage_group.add_argument("-s", "--sbd-device", dest="sbd_devices", metavar="DEVICE", action="append",
                                   help="Block device to use for SBD fencing, use \";\" as separator or -s multiple times for multi path (up to 3 devices)")
        storage_group.add_argument("-o", "--ocfs2-device", dest="ocfs2_devices", metavar="DEVICE", action="append", default=[],
                help="Block device to use for OCFS2; When using Cluster LVM2 to manage the shared storage, user can specify one or multiple raw disks, use \";\" as separator or -o multiple times for multi path (must specify -C option) NOTE: this is a Technical Preview")
        storage_group.add_argument("-C", "--cluster-lvm2", action="store_true", dest="use_cluster_lvm2",
                help="Use Cluster LVM2 (only valid together with -o option) NOTE: this is a Technical Preview")
        storage_group.add_argument("-m", "--mount-point", dest="mount_point", metavar="MOUNT", default="/srv/clusterfs",
                help="Mount point for OCFS2 device (default is /srv/clusterfs, only valid together with -o option) NOTE: this is a Technical Preview")

        options, args = parse_options(parser, args)
        if options is None or args is None:
            return

        stage = ""
        if len(args):
            stage = args[0]
        if stage == "vgfs":
            stage = "ocfs2"
            logger.warning("vgfs stage was deprecated and is an alias of ocfs2 stage now")
        if stage not in bootstrap.INIT_STAGES and stage != "":
            parser.error("Invalid stage (%s)" % (stage))

        if options.qnetd_addr:
            if options.qdevice_heuristics_mode and not options.qdevice_heuristics:
                parser.error("Option --qdevice-heuristics is required if want to configure heuristics mode")
            options.qdevice_heuristics_mode = options.qdevice_heuristics_mode or "sync"
        elif re.search("--qdevice-.*", ' '.join(sys.argv)) or (stage == "qdevice" and options.yes_to_all):
            parser.error("Option --qnetd-hostname is required if want to configure qdevice")

        # if options.geo and options.name == "hacluster":
        #    parser.error("For a geo cluster, each cluster must have a unique name (use --name to set)")
        boot_context = bootstrap.Context.set_context(options)
        boot_context.ui_context = context
        boot_context.stage = stage
        boot_context.args = args
        boot_context.cluster_is_running = utils.service_is_active("pacemaker.service")
        boot_context.type = "init"

        bootstrap.bootstrap_init(boot_context)

        # if options.geo:
        #    bootstrap.bootstrap_init_geo()

        if options.nodes is not None:
            nodelist = [n for n in re.split('[ ,;]+', options.nodes)]
            for node in nodelist:
                if node == utils.this_node():
                    continue
                logger.info("\n\nAdd node {} (may prompt for root password):".format(node))
                if not self._add_node(node, yes_to_all=options.yes_to_all):
                    return False

        return True

    @command.skill_level('administrator')
    def do_join(self, context, *args):
        '''
        Join this node to an existing cluster
        '''
        parser = ArgParser(description="""
Join the current node to an existing cluster. The
current node cannot be a member of a cluster already.
Pass any node in the existing cluster as the argument
to the -c option.""",usage="join [options] [STAGE]", epilog="""

Stage can be one of:
    ssh         Obtain SSH keys from existing cluster node (requires -c <host>)
    csync2      Configure csync2 (requires -c <host>)
    ssh_merge   Merge root's SSH known_hosts across all nodes (csync2 must
                already be configured).
    cluster     Start the cluster on this node

If stage is not specified, each stage will be invoked in sequence.
""", add_help=False, formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument("-h", "--help", action="store_true", dest="help", help="Show this help message")
        parser.add_argument("-q", "--quiet", help="Be quiet (don't describe what's happening, just do it)", action="store_true", dest="quiet")
        parser.add_argument("-y", "--yes", help='Answer "yes" to all prompts (use with caution)', action="store_true", dest="yes_to_all")
        parser.add_argument("-w", "--watchdog", dest="watchdog", metavar="WATCHDOG", help="Use the given watchdog device")

        network_group = parser.add_argument_group("Network configuration", "Options for configuring the network and messaging layer.")
        network_group.add_argument("-c", "--cluster-node", dest="cluster_node", help="IP address or hostname of existing cluster node", metavar="HOST")
        network_group.add_argument("-i", "--interface", dest="nic_list", metavar="IF", action="append", choices=utils.interface_choice(),
                help="Bind to IP address on interface IF. Use -i second time for second interface")
        options, args = parse_options(parser, args)
        if options is None or args is None:
            return

        stage = ""
        if len(args) == 1:
            stage = args[0]
        if stage not in ("ssh", "csync2", "ssh_merge", "cluster", ""):
            parser.error("Invalid stage (%s)" % (stage))

        join_context = bootstrap.Context.set_context(options)
        join_context.ui_context = context
        join_context.stage = stage
        join_context.type = "join"

        bootstrap.bootstrap_join(join_context)

        return True

    def _add_node(self, node, yes_to_all=False):
        '''
        Adds the given node to the cluster.
        '''
        me = utils.this_node()
        cmd = "crm cluster join{} -c {}".format(" -y" if yes_to_all else "", me)
        rc = utils.ext_cmd_nosudo("ssh{} root@{} -o StrictHostKeyChecking=no '{}'".format("" if yes_to_all else " -t", node, cmd))
        return rc == 0

    @command.completers_repeating(compl.call(scripts.param_completion_list, 'add'))
    @command.skill_level('administrator')
    def do_add(self, context, *args):
        '''
        Add the given node(s) to the cluster.
        Installs packages, sets up corosync and pacemaker, etc.
        Must be executed from a node in the existing cluster.
        '''
        parser = ArgParser(description="""
Add a new node to the cluster. The new node will be
configured as a cluster member.""",
                usage="add [options] [node ...]", add_help=False, formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument("-h", "--help", action="store_true", dest="help", help="Show this help message")
        parser.add_argument("-y", "--yes", help='Answer "yes" to all prompts (use with caution)', action="store_true", dest="yes_to_all")
        options, args = parse_options(parser, args)
        if options is None or args is None:
            return

        for node in args:
            if not self._add_node(node, yes_to_all=options.yes_to_all):
                return False

    @command.alias("delete")
    @command.completers_repeating(_remove_completer)
    @command.skill_level('administrator')
    def do_remove(self, context, *args):
        '''
        Remove the given node(s) from the cluster.
        '''
        parser = ArgParser(description="""
Remove one or more nodes from the cluster.

This command can remove the last node in the cluster,
thus effectively removing the whole cluster. To remove
the last node, pass --force argument to crm or set
the config.core.force option.""",
                usage="remove [options] [<node> ...]", add_help=False, formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument("-h", "--help", action="store_true", dest="help", help="Show this help message")
        parser.add_argument("-q", "--quiet", help="Be quiet (don't describe what's happening, just do it)", action="store_true", dest="quiet")
        parser.add_argument("-y", "--yes", help='Answer "yes" to all prompts (use with caution)', action="store_true", dest="yes_to_all")
        parser.add_argument("-c", "--cluster-node", dest="cluster_node", help="IP address or hostname of cluster node which will be deleted", metavar="HOST")
        parser.add_argument("-F", "--force", dest="force", help="Remove current node", action="store_true")
        parser.add_argument("--qdevice", dest="qdevice_rm_flag", help="Remove QDevice configuration and service from cluster", action="store_true")
        options, args = parse_options(parser, args)
        if options is None or args is None:
            return

        if options.cluster_node is not None and options.cluster_node not in args:
            args = list(args) + [options.cluster_node]

        rm_context = bootstrap.Context.set_context(options)
        rm_context.ui_context = context

        if len(args) == 0:
            bootstrap.bootstrap_remove(rm_context)
        else:
            for node in args:
                rm_context.cluster_node = node
                bootstrap.bootstrap_remove(rm_context)
        return True

    @command.skill_level('administrator')
    def do_rename(self, context, new_name):
        '''
        Rename the cluster.
        '''
        if not utils.service_is_active("corosync.service"):
            context.fatal_error("Can't rename cluster when cluster service is stopped")
        old_name = cib_factory.get_property('cluster-name')
        if old_name and new_name == old_name:
            context.fatal_error("Expected a different name")

        # Update config file with the new name on all nodes
        nodes = utils.list_cluster_nodes()
        corosync.set_value('totem.cluster_name', new_name)
        if len(nodes) > 1:
            nodes.remove(utils.this_node())
            context.info("Copy cluster config file to \"{}\"".format(' '.join(nodes)))
            corosync.push_configuration(nodes)

        # Change the cluster-name property in the CIB
        cib_factory.create_object("property", "cluster-name={}".format(new_name))
        if not cib_factory.commit():
            context.fatal_error("Change property cluster-name failed!")

        # it's a safe way to give user a hints that need to restart service
        context.info("To apply the change, restart the cluster service at convenient time")

    def _parse_clustermap(self, clusters):
        '''
        Helper function to parse the cluster map into a dictionary:

        name=ip; name2=ip2 -> { name: ip, name2: ip2 }
        '''
        if clusters is None:
            return None
        try:
            return dict([re.split('[=:]+', o) for o in re.split('[ ,;]+', clusters)])
        except TypeError:
            return None
        except ValueError:
            return None

    @command.name("geo_init")
    @command.alias("geo-init")
    @command.skill_level('administrator')
    def do_geo_init(self, context, *args):
        '''
        Make this cluster a geo cluster.
        Needs some information to set up.

        * cluster map: "cluster-name=ip cluster-name=ip"
        * arbitrator IP / hostname (optional)
        * list of tickets (can be empty)
        '''
        parser = ArgParser(description="""
Create a new geo cluster with the current cluster as the
first member. Pass the complete geo cluster topology as
arguments to this command, and then use geo-join and
geo-init-arbitrator to add the remaining members to
the geo cluster.""",
        usage="geo-init [options]", epilog="""

Cluster Description

  This is a map of cluster names to IP addresses.
  Each IP address will be configured as a virtual IP
  representing that cluster in the geo cluster
  configuration.

  Example with two clusters named paris and amsterdam:

  --clusters "paris=192.168.10.10 amsterdam=192.168.10.11"

  Name clusters using the --name parameter to
  crm bootstrap init.
""", add_help=False, formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument("-h", "--help", action="store_true", dest="help", help="Show this help message")
        parser.add_argument("-q", "--quiet", help="Be quiet (don't describe what's happening, just do it)", action="store_true", dest="quiet")
        parser.add_argument("-y", "--yes", help='Answer "yes" to all prompts (use with caution)', action="store_true", dest="yes_to_all")
        parser.add_argument("-a", "--arbitrator", help="IP address of geo cluster arbitrator", dest="arbitrator", metavar="IP")
        parser.add_argument("-s", "--clusters", help="Geo cluster description (see details below)", dest="clusters", metavar="DESC")
        parser.add_argument("-t", "--tickets", help="Tickets to create (space-separated)", dest="tickets", metavar="LIST")
        options, args = parse_options(parser, args)
        if options is None or args is None:
            return

        if options.clusters is None:
            errs = []
            if options.clusters is None:
                errs.append("The --clusters argument is required.")
            parser.error(" ".join(errs))

        clustermap = self._parse_clustermap(options.clusters)
        if clustermap is None:
            parser.error("Invalid cluster description format")
        ticketlist = []
        if options.tickets is not None:
            try:
                ticketlist = [t for t in re.split('[ ,;]+', options.tickets)]
            except ValueError:
                parser.error("Invalid ticket list")

        geo_context = bootstrap.Context.set_context(options)
        geo_context.clusters = clustermap
        geo_context.tickets = ticketlist
        geo_context.ui_context = context

        bootstrap.bootstrap_init_geo(geo_context)
        return True

    @command.name("geo_join")
    @command.alias("geo-join")
    @command.skill_level('administrator')
    def do_geo_join(self, context, *args):
        '''
        Join this cluster to a geo configuration.
        '''
        parser = ArgParser(description="""
This command should be run from one of the nodes in a cluster
which is currently not a member of a geo cluster. The geo
cluster configuration will be fetched from the provided node,
and the cluster will be added to the geo cluster.

Note that each cluster in a geo cluster needs to have a unique
name set. The cluster name can be set using the --name argument
to init, or by configuring corosync with the cluster name in
an existing cluster.""",
                usage="geo-join [options]", add_help=False, formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument("-h", "--help", action="store_true", dest="help", help="Show this help message")
        parser.add_argument("-q", "--quiet", help="Be quiet (don't describe what's happening, just do it)", action="store_true", dest="quiet")
        parser.add_argument("-y", "--yes", help='Answer "yes" to all prompts (use with caution)', action="store_true", dest="yes_to_all")
        parser.add_argument("-c", "--cluster-node", help="IP address of an already-configured geo cluster or arbitrator", dest="cluster_node", metavar="IP")
        parser.add_argument("-s", "--clusters", help="Geo cluster description (see geo-init for details)", dest="clusters", metavar="DESC")
        options, args = parse_options(parser, args)
        if options is None or args is None:
            return
        errs = []
        if options.cluster_node is None:
            errs.append("The --cluster-node argument is required.")
        if options.clusters is None:
            errs.append("The --clusters argument is required.")
        if len(errs) > 0:
            parser.error(" ".join(errs))
        clustermap = self._parse_clustermap(options.clusters)
        if clustermap is None:
            parser.error("Invalid cluster description format")

        geo_context = bootstrap.Context.set_context(options)
        geo_context.clusters = clustermap
        geo_context.ui_context = context

        bootstrap.bootstrap_join_geo(geo_context)
        return True

    @command.name("geo_init_arbitrator")
    @command.alias("geo-init-arbitrator")
    @command.skill_level('administrator')
    def do_geo_init_arbitrator(self, context, *args):
        '''
        Make this node a geo arbitrator.
        '''
        parser = ArgParser(description="""
Configure the current node as a geo arbitrator. The command
requires an existing geo cluster or geo arbitrator from which
to get the geo cluster configuration.""",
                usage="geo-init-arbitrator [options]", add_help=False, formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument("-h", "--help", action="store_true", dest="help", help="Show this help message")
        parser.add_argument("-q", "--quiet", help="Be quiet (don't describe what's happening, just do it)", action="store_true", dest="quiet")
        parser.add_argument("-y", "--yes", help='Answer "yes" to all prompts (use with caution)', action="store_true", dest="yes_to_all")
        parser.add_argument("-c", "--cluster-node", help="IP address of an already-configured geo cluster", dest="cluster_node", metavar="IP")
        options, args = parse_options(parser, args)
        if options is None or args is None:
            return

        geo_context = bootstrap.Context.set_context(options)
        geo_context.ui_context = context

        bootstrap.bootstrap_arbitrator(geo_context)
        return True

    @command.completers_repeating(compl.call(scripts.param_completion_list, 'health'))
    def do_health(self, context, *args):
        '''
        Extensive health check.
        '''
        params = self._args_implicit(context, args, 'nodes')
        script = scripts.load_script('health')
        if script is None:
            raise ValueError("health script failed to load")
        return scripts.run(script, script_args(params), script_printer())

    def _node_in_cluster(self, node):
        return node in utils.list_cluster_nodes()

    def do_status(self, context):
        '''
        Quick cluster health status. Corosync status, DRBD status...
        '''
        print("Name: {}\n".format(get_cluster_name()))
        print("Services:")
        for svc in ["corosync", "pacemaker"]:
            info = utils.service_info(svc)
            if info:
                print("%-16s %s" % (svc, info))
            else:
                print("%-16s unknown" % (svc))

        rc, outp = utils.get_stdout(['corosync-cfgtool', '-s'], shell=False)
        if rc == 0:
            print("")
            print(outp)
        else:
            print("Failed to get corosync status")

    @command.completers_repeating(compl.choice(['10', '60', '600']))
    def do_wait_for_startup(self, context, timeout='10'):
        "usage: wait_for_startup [<timeout>]"
        import time
        t0 = time.time()
        timeout = float(timeout)
        cmd = 'crm_mon -bD1 2&>1 >/dev/null'
        ret = utils.ext_cmd(cmd)
        while ret in (107, 64) and time.time() < t0 + timeout:
            time.sleep(1)
            ret = utils.ext_cmd(cmd)
        if ret != 0:
            context.fatal_error("Timed out waiting for cluster (rc = %s)" % (ret))

    @command.skill_level('expert')
    def do_run(self, context, cmd, *nodes):
        '''
        Execute the given command on all nodes/specific node(s), report outcome
        '''
        try:
            import parallax
            _has_parallax = True
        except ImportError:
            _has_parallax = False

        if not _has_parallax:
            context.fatal_error("python package parallax is needed for this command")

        if nodes:
            hosts = list(nodes)
        else:
            hosts = utils.list_cluster_nodes()
            if hosts is None:
                context.fatal_error("failed to get node list from cluster")

        opts = parallax.Options()
        opts.ssh_options = ['StrictHostKeyChecking=no']
        for host in hosts:
            res = utils.check_ssh_passwd_need(host)
            if res:
                opts.askpass = True
                break
        for host, result in parallax.call(hosts, cmd, opts).items():
            if isinstance(result, parallax.Error):
                logger.error("[%s]: %s" % (host, result))
            else:
                if result[0] != 0:
                    logger.error("[%s]: rc=%s\n%s\n%s" % (host, result[0], utils.to_ascii(result[1]), utils.to_ascii(result[2])))
                else:
                    if not result[1]:
                        logger.info("[%s]" % host)
                    else:
                        logger.info("[%s]\n%s" % (host, utils.to_ascii(result[1])))

    def do_copy(self, context, local_file, *nodes):
        '''
        usage: copy <filename> [nodes ...]
        Copy file to other cluster nodes.
        If given no nodes as arguments, copy to all other cluster nodes.
        '''
        return utils.cluster_copy_file(local_file, nodes)

    def do_diff(self, context, filename, *nodes):
        "usage: diff <filename> [--checksum] [nodes...]. Diff file across cluster."
        nodes = list(nodes)
        this_node = utils.this_node()
        checksum = False
        if len(nodes) and nodes[0] == '--checksum':
            nodes = nodes[1:]
            checksum = True
        if not nodes:
            nodes = utils.list_cluster_nodes()
        if checksum:
            utils.remote_checksum(filename, nodes, this_node)
        elif len(nodes) == 1:
            utils.remote_diff_this(filename, nodes, this_node)
        elif this_node in nodes:
            nodes.remove(this_node)
            utils.remote_diff_this(filename, nodes, this_node)
        elif len(nodes):
            utils.remote_diff(filename, nodes)

    def do_crash_test(self, context, *args):
        """
        """
        from .crash_test import main
        sys.argv[1:] = args
        main.ctx.process_name = context.command_name
        main.run(main.ctx)
        return True
