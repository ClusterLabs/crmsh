# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import sys
import re
import argparse
import typing
from argparse import ArgumentParser, RawDescriptionHelpFormatter

import crmsh.parallax
from . import command, sh, healthcheck, migration
from . import utils
from . import scripts
from . import completers as compl
from . import bootstrap
from . import corosync
from . import qdevice
from . import xmlutil
from .cibconfig import cib_factory
from .prun import prun
from .service_manager import ServiceManager
from .sh import ShellUtils
from .ui_node import parse_option_for_nodes
from . import constants


from . import log
from .utils import TerminateSubCommand

logger = log.setup_logger(__name__)


def parse_options(parser, args):
    try:
        options, args = parser.parse_known_args(list(args))
    except Exception:
        return None, None
    if hasattr(options, 'help') and options.help:
        parser.print_help()
        raise TerminateSubCommand(success=True)
    utils.check_empty_option_value(options)
    return options, args


def script_printer():
    from .ui_script import ConsolePrinter
    return ConsolePrinter()


def script_args(args):
    from .ui_script import _nvpairs2parameters
    return _nvpairs2parameters(args)


def get_cluster_name():
    cluster_name = None
    if not ServiceManager(sh.ClusterShellAdaptorForLocalShell(sh.LocalShell())).service_is_active("corosync.service"):
        name = corosync.get_values('totem.cluster_name')
        if name:
            cluster_name = name[0]
    else:
        cluster_name = cib_factory.get_property('cluster-name')
    return cluster_name


class ArgparseCustomizableAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        previous_value = getattr(namespace, self.dest, None)
        parsed_value = self.parse(parser, previous_value, value, option_string=None)
        self.validate(parser, parsed_value, option_string)
        setattr(namespace, self.dest, parsed_value)

    def parse(self, parser, previous_value, raw_value, option_string):
        """Parse one argument and return the parsed value.

        Arguments:
            previous_value: The previous value hold in the destinating attribute.
            raw_value: The string value to be parse.
            option_string: The command-line option string associated with this action.
        """
        raise NotImplementedError

    def validate(self, parser, parsed_value, option_string):
        pass


class ArgparseActionSplitAndAppendParseMixin(ArgparseCustomizableAction):
    """Parse `--foo a;b --foo "c d" --foo e` into ['a', 'b', 'c', 'd', 'e']"""
    def parse(self, parser, previous_value, raw_value, option_string):
        items = previous_value if previous_value is not None else []
        items.extend([x for x in re.split("[; ]", raw_value) if x])
        return items


class ArgparseActionUniqueListItemValidateMixin(ArgparseCustomizableAction):
    """Validate te uniqueness of parsed list items."""
    def validate(self, parser, parsed_value, option_string):
        if len(parsed_value) != len(set(parsed_value)):
            parser.error(f"Duplicated input for '{'/'.join(self.option_strings)}' option")


class CustomAppendAction(ArgparseActionSplitAndAppendParseMixin, ArgparseActionUniqueListItemValidateMixin):
    """
    Custom class for argparse append action:
    - Flatten the value like '-s "/dev/sda1;/dev/sda2"'
    - Detect duplicated input
    """
    pass


class ArgparseActionUniqueHostInListItemValidateMixin(ArgparseCustomizableAction):
    """Validate the uniqueness of hosts in a parsed list in the format of 'user@host'"""
    def validate(self, parser, parsed_value, option_string):
        known_hosts = set()
        for item in parsed_value:
            match = re.match("^(?:[^@]+@)?([^@]+)$", item)
            if match is None:
                parser.error("Malformed value for option {} [<user>@]<host>: {}.".format(
                    '/'.join(self.option_strings), parsed_value
                ))
            host = match.group(1)
            if host in known_hosts:
                parser.error("Duplicated host in option {}: {}".format(
                    '/'.join(self.option_strings), parsed_value
                ))
            known_hosts.add(host)


class ArgparseUserAtHostAppendAction(
    ArgparseActionSplitAndAppendParseMixin,
    ArgparseActionUniqueHostInListItemValidateMixin,
):
    pass



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
        Starts the cluster stack on all nodes or specific node(s)
        '''
        service_check_list = ["pacemaker.service"]
        start_qdevice = False
        if utils.is_qdevice_configured():
            start_qdevice = True
            service_check_list.append("corosync-qdevice.service")

        service_manager = ServiceManager()
        node_list = parse_option_for_nodes(context, *args)
        try:
            for node in node_list[:]:
                if all([service_manager.service_is_active(srv, remote_addr=node) for srv in service_check_list]):
                    logger.info("The cluster stack already started on {}".format(node))
                    node_list.remove(node)
        except utils.NoSSHError as msg:
            logger.error('%s', msg)
            logger.info("Please try 'crm cluster start' on each node")
            return
        if not node_list:
            return

        if start_qdevice:
            service_manager.start_service("corosync-qdevice", node_list=node_list)
        node_list = bootstrap.start_pacemaker(node_list)
        if start_qdevice:
            qdevice.QDevice.check_qdevice_vote()
        for node in node_list:
            logger.info("The cluster stack started on {}".format(node))

    @staticmethod
    def _node_ready_to_stop_cluster_service(node):
        """
        Check if the specific node is ready to stop cluster service

        If both corosync.service and pacemaker.service is active, return True
        If some services started, stop them first and return False
        """
        service_manager = ServiceManager()

        corosync_active = service_manager.service_is_active("corosync.service", remote_addr=node)
        sbd_active = service_manager.service_is_active("sbd.service", remote_addr=node)
        pacemaker_active = service_manager.service_is_active("pacemaker.service", remote_addr=node)

        if not corosync_active:
            if sbd_active:
                service_manager.stop_service("corosync", remote_addr=node)
                logger.info(f"The cluster stack stopped on {node}")
            else:
                logger.info(f"The cluster stack already stopped on {node}")
            return False

        elif not pacemaker_active:
            service_manager.stop_service("corosync", remote_addr=node)
            logger.info("The cluster stack stopped on {}".format(node))
            return False

        return True

    @staticmethod
    def _wait_for_dc(node=None):
        """
        Wait for the cluster's DC to become available
        """
        if not ServiceManager().service_is_active("pacemaker.service", remote_addr=node):
            return

        dc_deadtime = utils.get_property("dc-deadtime", peer=node) or str(constants.DC_DEADTIME_DEFAULT)
        dc_timeout = int(dc_deadtime.strip('s')) + 5
        try:
            utils.check_function_with_timeout(utils.get_dc, wait_timeout=dc_timeout, peer=node)
        except TimeoutError:
            logger.error("No DC found currently, please wait if the cluster is still starting")
            raise utils.TerminateSubCommand

    @staticmethod
    def _set_dlm(node=None):
        """
        When dlm running and quorum is lost, before stop cluster service, should set
        enable_quorum_fencing=0, enable_quorum_lockspace=0 for dlm config option
        """
        if utils.is_dlm_running(node) and not utils.is_quorate(node):
            logger.debug("Quorum is lost; Set enable_quorum_fencing=0 and enable_quorum_lockspace=0 for dlm")
            utils.set_dlm_option(peer=node, enable_quorum_fencing=0, enable_quorum_lockspace=0)

    @command.skill_level('administrator')
    def do_stop(self, context, *args):
        '''
        Stops the cluster stack on all nodes or specific node(s)
        '''
        node_list = parse_option_for_nodes(context, *args)
        try:
            node_list = [n for n in node_list if self._node_ready_to_stop_cluster_service(n)]
        except utils.NoSSHError as msg:
            logger.error('%s', msg)
            logger.info("Please try 'crm cluster stop' on each node")
            return
        if not node_list:
            return
        logger.debug(f"stop node list: {node_list}")

        self._wait_for_dc(node_list[0])

        self._set_dlm(node_list[0])

        service_manager = ServiceManager()
        # Stop pacemaker since it can make sure cluster has quorum until stop corosync
        node_list = service_manager.stop_service("pacemaker", node_list=node_list)
        # Then, stop qdevice if is active
        if service_manager.service_is_active("corosync-qdevice.service"):
            service_manager.stop_service("corosync-qdevice.service", node_list=node_list)
        # Last, stop corosync
        node_list = service_manager.stop_service("corosync", node_list=node_list)

        for node in node_list:
            logger.info("The cluster stack stopped on {}".format(node))

    @command.skill_level('administrator')
    def do_restart(self, context, *args):
        '''
        Restarts the cluster stack on all nodes or specific node(s)
        '''
        parse_option_for_nodes(context, *args)
        self.do_stop(context, *args)
        self.do_start(context, *args)

    @command.skill_level('administrator')
    def do_enable(self, context, *args):
        '''
        Enable the cluster services on this node
        '''
        node_list = parse_option_for_nodes(context, *args)
        service_manager = ServiceManager()
        node_list = service_manager.enable_service("pacemaker.service", node_list=node_list)
        if service_manager.service_is_available("corosync-qdevice.service") and utils.is_qdevice_configured():
            service_manager.enable_service("corosync-qdevice.service", node_list=node_list)
        for node in node_list:
            logger.info("Cluster services enabled on %s", node)

    @command.skill_level('administrator')
    def do_disable(self, context, *args):
        '''
        Disable the cluster services on this node
        '''
        node_list = parse_option_for_nodes(context, *args)
        service_manager = ServiceManager()
        node_list = service_manager.disable_service("pacemaker.service", node_list=node_list)
        service_manager.disable_service("corosync-qdevice.service", node_list=node_list)
        for node in node_list:
            logger.info("Cluster services disabled on %s", node)

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

    @command.skill_level('administrator')
    def do_init(self, context, *args):
        '''
        Initialize a cluster.
        '''
        parser = ArgumentParser(description="""
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
    gfs2        Configure GFS2 (requires -g <dev>) NOTE: this is a Technical Preview
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

  # Setup the cluster on the current node, with SBD+GFS2
  crm cluster init -s <share disk1> -g <share disk2> -y

  # Setup the cluster on the current node, with SBD+OCFS2+Cluster LVM
  crm cluster init -s <share disk1> -o <share disk2> -o <share disk3> -C -y

  # Setup the cluster on the current node, with SBD+GFS2+Cluster LVM
  crm cluster init -s <share disk1> -g <share disk2> -g <share disk3> -C -y

  # Add SBD on a running cluster
  crm cluster init sbd -s <share disk> -y

  # Replace SBD device on a running cluster which already configured SBD
  crm -F cluster init sbd -s <share disk> -y

  # Add diskless SBD on a running cluster
  crm cluster init sbd -S -y

  # Add QDevice on a running cluster
  crm cluster init qdevice --qnetd-hostname <qnetd addr> -y

  # Add OCFS2+Cluster LVM on a running cluster
  crm cluster init ocfs2 -o <share disk1> -o <share disk2> -C -y

  # Add GFS2+Cluster LVM on a running cluster
  crm cluster init gfs2 -g <share disk1> -g <share disk2> -C -y
""", add_help=False, formatter_class=RawDescriptionHelpFormatter)

        parser.add_argument("-h", "--help", action="store_true", dest="help", help="Show this help message")
        parser.add_argument("-q", "--quiet", action="store_true", dest="quiet",
                            help="Be quiet (don't describe what's happening, just do it)")
        parser.add_argument("-y", "--yes", action="store_true", dest="yes_to_all",
                            help='Answer "yes" to all prompts (use with caution, this is destructive, especially those storage related configurations and stages.)')
        parser.add_argument("-n", "--name", metavar="NAME", dest="cluster_name", default="hacluster",
                            help='Set the name of the configured cluster.')
        parser.add_argument("-N", "--node", metavar="[USER@]HOST", dest="user_at_node_list", action=ArgparseUserAtHostAppendAction, default=[],
                            help='The member node of the cluster. Note: the current node is always get initialized during bootstrap in the beginning.')
        parser.add_argument("-S", "--enable-sbd", dest="diskless_sbd", action="store_true",
                            help="Enable SBD even if no SBD device is configured (diskless mode)")
        parser.add_argument("-w", "--watchdog", dest="watchdog", metavar="WATCHDOG",
                            help="Use the given watchdog device or driver name")
        parser.add_argument("-x", "--skip-csync2-sync", dest="skip_csync2", action="store_true",
                            help="Skip csync2 initialization (an experimental option)")
        parser.add_argument("--no-overwrite-sshkey", action="store_true", dest="no_overwrite_sshkey",
                            help='Avoid "/root/.ssh/id_rsa" overwrite if "-y" option is used (False by default; Deprecated)')
        parser.add_argument('--use-ssh-agent', action='store_true', dest='use_ssh_agent',
                            help="Use an existing key from ssh-agent instead of creating new key pairs")

        network_group = parser.add_argument_group("Network configuration", "Options for configuring the network and messaging layer.")
        network_group.add_argument("-i", "--interface", dest="nic_list", metavar="IF", action=CustomAppendAction, choices=utils.interface_choice(), default=[],
                                   help="Bind to IP address on interface IF. Use -i second time for second interface")
        network_group.add_argument("-u", "--unicast", action="store_true", dest="unicast",
                                   help="Configure corosync to communicate over unicast(udpu). This is the default transport type")
        network_group.add_argument("-U", "--multicast", action="store_true", dest="multicast",
                                   help="Configure corosync to communicate over multicast. Default is unicast")
        network_group.add_argument("-A", "--admin-ip", dest="admin_ip", metavar="IP",
                                   help="Configure IP address as an administration virtual IP")
        network_group.add_argument("-M", "--multi-heartbeats", action="store_true", dest="second_heartbeat",
                                   help="Configure corosync with second heartbeat line")
        network_group.add_argument("-I", "--ipv6", action="store_true", dest="ipv6",
                                   help="Configure corosync use IPv6")

        qdevice_group = parser.add_argument_group("QDevice configuration", re.sub('  ', '', constants.QDEVICE_HELP_INFO) + "\n\nOptions for configuring QDevice and QNetd.")
        qdevice_group.add_argument("--qnetd-hostname", dest="qnetd_addr_input", metavar="[USER@]HOST",
                                   help="User and host of the QNetd server. The host can be specified in either hostname or IP address.")
        qdevice_group.add_argument("--qdevice-port", dest="qdevice_port", metavar="PORT", type=int, default=5403,
                                   help="TCP PORT of QNetd server (default:5403)")
        qdevice_group.add_argument("--qdevice-algo", dest="qdevice_algo", metavar="ALGORITHM", default="ffsplit", choices=['ffsplit', 'lms'],
                                   help="QNetd decision ALGORITHM (ffsplit/lms, default:ffsplit)")
        qdevice_group.add_argument("--qdevice-tie-breaker", dest="qdevice_tie_breaker", metavar="TIE_BREAKER", default="lowest",
                                   help="QNetd TIE_BREAKER (lowest/highest/valid_node_id, default:lowest)")
        qdevice_group.add_argument("--qdevice-tls", dest="qdevice_tls", metavar="TLS", default="on", choices=['on', 'off', 'required'],
                                   help="Whether using TLS on QDevice (on/off/required, default:on)")
        qdevice_group.add_argument("--qdevice-heuristics", dest="qdevice_heuristics", metavar="COMMAND",
                                   help="COMMAND to run with absolute path. For multiple commands, use \";\" to separate (details about heuristics can see man 8 corosync-qdevice)")
        qdevice_group.add_argument("--qdevice-heuristics-mode", dest="qdevice_heuristics_mode", metavar="MODE", choices=['on', 'sync', 'off'],
                                   help="MODE of operation of heuristics (on/sync/off, default:sync)")

        storage_group = parser.add_argument_group("Storage configuration", "Options for configuring shared storage.")
        storage_group.add_argument("-s", "--sbd-device", dest="sbd_devices", metavar="DEVICE", action=CustomAppendAction, default=[],
                                   help="Block device to use for SBD fencing, use \";\" as separator or -s multiple times for multi path (up to 3 devices)")
        storage_group.add_argument("-o", "--ocfs2-device", dest="ocfs2_devices", metavar="DEVICE", action=CustomAppendAction, default=[],
                help="Block device to use for OCFS2; When using Cluster LVM2 to manage the shared storage, user can specify one or multiple raw disks, use \";\" as separator or -o multiple times for multi path (must specify -C option) NOTE: this is a Technical Preview")
        storage_group.add_argument("-g", "--gfs2-device", dest="gfs2_devices", metavar="DEVICE", action=CustomAppendAction, default=[],
                help="Block device to use for GFS2; When using Cluster LVM2 to manage the shared storage, user can specify one or multiple raw disks, use \";\" as separator or -g multiple times for multi path (must specify -C option) NOTE: this is a Technical Preview")
        storage_group.add_argument("-C", "--cluster-lvm2", action="store_true", dest="use_cluster_lvm2",
                help="Use Cluster LVM2 (only valid together with -o or -g option) NOTE: this is a Technical Preview")
        storage_group.add_argument("-m", "--mount-point", dest="mount_point", metavar="MOUNT", default="/srv/clusterfs",
                help="Mount point for OCFS2 or GFS2 device (default is /srv/clusterfs, only valid together with -o or -g option) NOTE: this is a Technical Preview")

        options, args = parse_options(parser, args)
        if options is None or args is None:
            return

        stage = ""
        if len(args):
            stage = args[0]
        if stage == "vgfs":
            stage = "ocfs2"
            logger.warning("vgfs stage was deprecated and is an alias of ocfs2 stage now")

        if options.qnetd_addr_input:
            if not ServiceManager().service_is_available("corosync-qdevice.service"):
                utils.fatal("corosync-qdevice.service is not available")
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
        boot_context.cluster_is_running = ServiceManager(sh.ClusterShellAdaptorForLocalShell(sh.LocalShell())).service_is_active("pacemaker.service")
        boot_context.type = "init"
        boot_context.initialize_qdevice()
        boot_context.validate_option()

        bootstrap.bootstrap_init(boot_context)
        bootstrap.bootstrap_add(boot_context)

        return True

    @command.skill_level('administrator')
    def do_join(self, context, *args):
        '''
        Join this node to an existing cluster
        '''
        parser = ArgumentParser(description="""
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

Examples:
  # Join with a cluster node
  crm cluster join -c <node> -y

  # Join with a cluster node, with the same network interface used by that node
  crm cluster join -c <node> -i eth1 -i eth2 -y
""", add_help=False, formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument("-h", "--help", action="store_true", dest="help", help="Show this help message")
        parser.add_argument("-q", "--quiet", help="Be quiet (don't describe what's happening, just do it)", action="store_true", dest="quiet")
        parser.add_argument("-y", "--yes", help='Answer "yes" to all prompts (use with caution)', action="store_true", dest="yes_to_all")
        parser.add_argument("-w", "--watchdog", dest="watchdog", metavar="WATCHDOG", help="Use the given watchdog device")
        parser.add_argument('--use-ssh-agent', action='store_true', dest='use_ssh_agent',
                            help="Use an existing key from ssh-agent instead of creating new key pairs")

        network_group = parser.add_argument_group("Network configuration", "Options for configuring the network and messaging layer.")
        network_group.add_argument(
            "-c", "--cluster-node", metavar="[USER@]HOST", dest="cluster_node",
            help="User and host to login to an existing cluster node. The host can be specified with either a hostname or an IP.",
        )
        network_group.add_argument("-i", "--interface", dest="nic_list", metavar="IF", action=CustomAppendAction, choices=utils.interface_choice(), default=[],
                help="Bind to IP address on interface IF. Use -i second time for second interface")
        options, args = parse_options(parser, args)
        if options is None or args is None:
            return

        stage = ""
        if len(args) == 1:
            stage = args[0]

        join_context = bootstrap.Context.set_context(options)
        join_context.ui_context = context
        join_context.stage = stage
        join_context.cluster_is_running = ServiceManager(sh.ClusterShellAdaptorForLocalShell(sh.LocalShell())).service_is_active("pacemaker.service")
        join_context.type = "join"
        join_context.validate_option()

        bootstrap.bootstrap_join(join_context)

        return True

    @command.alias("delete")
    @command.completers_repeating(compl.nodes)
    @command.skill_level('administrator')
    def do_remove(self, context, *args):
        '''
        Remove the given node(s) from the cluster.
        '''
        parser = ArgumentParser(description="""
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
                print()
        return True

    @command.skill_level('administrator')
    def do_rename(self, context, new_name):
        '''
        Rename the cluster.
        '''
        service_manager = ServiceManager()
        if not service_manager.service_is_active("corosync.service"):
            context.fatal_error("Can't rename cluster when cluster service is stopped")
        if service_manager.service_is_active("corosync-qdevice.service"):
            logger.error("Can't rename cluster when QDevice service is running")
            suggestion = '''Please run `crm cluster remove --qdevice` on any node in the cluster to remove the QDevice configuration;
Then rename the cluster;
Finally run `crm cluster init qdevice` on any node in the cluster to re-deploy the QDevice.'''
            logger.info(suggestion)
            return

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

        if xmlutil.CrmMonXmlParser().is_any_resource_running():
            context.info("To apply the change, restart the cluster service at convenient time")
        else:
            bootstrap.restart_cluster()


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
        parser = ArgumentParser(description="""
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
        parser.add_argument(
            "-a", "--arbitrator", dest="arbitrator", metavar="[USER@]HOST",
            help="Geo cluster arbitrator",
        )
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
        parser = ArgumentParser(description="""
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
        parser.add_argument("-c", "--cluster-node", metavar="[USER@]HOST", help="An already-configured geo cluster or arbitrator", dest="cluster_node")
        parser.add_argument("-s", "--clusters", help="Geo cluster description (see geo-init for details)", dest="clusters", metavar="DESC")
        parser.add_argument('--use-ssh-agent', action='store_true', dest='use_ssh_agent',
                            help="Use an existing key from ssh-agent instead of creating new key pairs")
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
        parser = ArgumentParser(description="""
Configure the current node as a geo arbitrator. The command
requires an existing geo cluster or geo arbitrator from which
to get the geo cluster configuration.""",
                usage="geo-init-arbitrator [options]", add_help=False, formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument("-h", "--help", action="store_true", dest="help", help="Show this help message")
        parser.add_argument("-q", "--quiet", help="Be quiet (don't describe what's happening, just do it)", action="store_true", dest="quiet")
        parser.add_argument("-y", "--yes", help='Answer "yes" to all prompts (use with caution)', action="store_true", dest="yes_to_all")
        parser.add_argument("-c", "--cluster-node", metavar="[USER@]HOST", help="An already-configured geo cluster", dest="cluster_node")
        parser.add_argument('--use-ssh-agent', action='store_true', dest='use_ssh_agent',
                            help="Use an existing key from ssh-agent instead of creating new key pairs")
        options, args = parse_options(parser, args)
        if options is None or args is None:
            return

        geo_context = bootstrap.Context.set_context(options)
        geo_context.ui_context = context

        bootstrap.bootstrap_arbitrator(geo_context)
        return True

    @command.completers(compl.choice(['hawk2']))
    def do_health(self, context, *args):
        '''
        Extensive health check.
        '''
        if not args:
            return self._do_health_legacy(context, *args)
        parser = argparse.ArgumentParser()
        parser.add_argument('component', choices=['hawk2', 'sles16'])
        parser.add_argument('-f', '--fix', action='store_true')
        parsed_args, remaining_args = parser.parse_known_args(args)
        match parsed_args.component:
            case 'hawk2':
                if remaining_args:
                    logger.error('Known arguments: %s', ' '.join(remaining_args))
                    return False
                nodes = utils.list_cluster_nodes()
                if parsed_args.fix:
                    if not healthcheck.feature_full_check(healthcheck.PasswordlessPrimaryUserAuthenticationFeature(), nodes):
                        try:
                            healthcheck.feature_fix(
                                healthcheck.PasswordlessPrimaryUserAuthenticationFeature(),
                                nodes,
                                utils.ask,
                            )
                        except healthcheck.FixFailure:
                            logger.error('Cannot fix automatically.')
                            return False
                    try:
                        healthcheck.feature_fix(healthcheck.PasswordlessHaclusterAuthenticationFeature(), nodes, utils.ask)
                        logger.info("hawk2: passwordless ssh authentication: OK.")
                        return True
                    except healthcheck.FixFailure:
                        logger.error("hawk2: passwordless ssh authentication: FAIL.")
                        return False
                else:
                    if healthcheck.feature_full_check(healthcheck.PasswordlessHaclusterAuthenticationFeature(), nodes):
                        logger.info("hawk2: passwordless ssh authentication: OK.")
                        return True
                    else:
                        logger.error("hawk2: passwordless ssh authentication: FAIL.")
                        logger.warning('Please run "crm cluster health hawk2 --fix"')
                        return False
            case 'sles16':
                try:
                    if parsed_args.fix:
                        logger.error('"--fix" is only available in SLES 16.')
                        return False
                    else:
                        return 0 == migration.check(remaining_args)
                except migration.MigrationFailure as e:
                    logger.error('%s', e)
                    return False
            case _:
                logger.error('Unknown component: %s', parsed_args.component)
                return False

    def _do_health_legacy(self, context, *args):
        params = self._args_implicit(context, args, 'nodes')
        script = scripts.load_script('health')
        if script is None:
            raise ValueError("health script failed to load")
        return scripts.run(script, script_args(params), script_printer())

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

        rc, outp = ShellUtils().get_stdout(['corosync-cfgtool', '-s'], shell=False)
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
        cmd = 'crm_mon -bD1 >/dev/null 2>&1'
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
        if nodes:
            hosts = list(nodes)
        else:
            hosts = utils.list_cluster_nodes()
            if hosts is None:
                context.fatal_error("failed to get node list from cluster")

        for host, result in prun.prun({x: cmd for x in hosts}).items():
            if isinstance(result, prun.PRunError):
                logger.error("[%s]: %s", host, result)
            else:
                if result.returncode != 0:
                    logger.error(
                        "[%s]: Exited with error code %s. Error output: %s",
                        host, result.returncode, utils.to_ascii(result.stderr),
                    )
                else:
                    if not result.stdout:
                        logger.info("[%s]", host)
                    else:
                        logger.info("[%s]\n%s", host, utils.to_ascii(result.stdout))

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
