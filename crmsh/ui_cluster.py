# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import optparse
import re
from . import command
from . import utils
from .msg import err_buf
from . import scripts
from . import completers as compl
from . import bootstrap


class OptParser(optparse.OptionParser):
    def format_epilog(self, formatter):
        return self.epilog or ""


def _remove_completer(args):
    try:
        n = utils.list_cluster_nodes()
    except:
        n = []
    return scripts.param_completion_list('remove') + n


def script_printer():
    from .ui_script import ConsolePrinter
    return ConsolePrinter()


def script_args(args):
    from .ui_script import _nvpairs2parameters
    return _nvpairs2parameters(args)


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
        stack = utils.cluster_stack()
        if len(stack) > 0 and stack != 'corosync':
            err_buf.warning("Unsupported cluster stack %s detected." % (stack))
        return True

    def __init__(self):
        command.UI.__init__(self)
        # ugly hack to allow overriding the node list
        # for the cluster commands that operate before
        # there is an actual cluster
        self._inventory_nodes = None
        self._inventory_target = None

    @command.skill_level('administrator')
    def do_start(self, context):
        '''
        Starts the cluster services on this node
        '''
        rc, out, err = utils.get_stdout_stderr('service pacemaker start')
        if rc != 0:
            context.fatal_error("Failed to start pacemaker service: %s" % (err))
        err_buf.info("Cluster services started")

        # TODO: optionally start services on all nodes or specific node

    @command.skill_level('administrator')
    def do_stop(self, context):
        '''
        Stops the cluster services on this node
        '''
        rc, out, err = utils.get_stdout_stderr('service pacemaker stop')
        if rc != 0:
            context.fatal_error("Failed to stop pacemaker service: %s" % (err))
        err_buf.info("Cluster services stopped")

        # TODO: optionally stop services on all nodes or specific node

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
        if '--dry-run' in args or looks_like_hostnames(args):
            args = ['--yes', '--nodes'] + [arg for arg in args if arg != '--dry-run']
        parser = OptParser(usage="usage: init [options] [STAGE]", epilog="""

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

Note:
  - If stage is not specified, the script will run through each stage
    in sequence, with prompts for required information.
  - If using the ocfs2 template, the storage stage will partition a block
    device into two pieces, one for SBD, the remainder for OCFS2.  This is
    good for testing and demonstration, but not ideal for production.
    To use storage you have already configured, pass -s and -o to specify
    the block devices for SBD and OCFS2, and the automatic partitioning
    will be skipped.
""")
        parser.add_option("-q", "--quiet", action="store_true", dest="quiet",
                          help="Be quiet (don't describe what's happening, just do it)")
        parser.add_option("-y", "--yes", action="store_true", dest="yes_to_all",
                          help='Answer "yes" to all prompts (use with caution, this is destructive, especially during the "storage" stage)')
        parser.add_option("-t", "--template", dest="template",
                          help='Optionally configure cluster with template "name" (currently only "ocfs2" is valid here)')
        parser.add_option("-n", "--name", metavar="NAME", dest="name", default="hacluster",
                          help='Set the name of the configured cluster.')
        parser.add_option("-N", "--nodes", metavar="NODES", dest="nodes", help='Additional nodes to add to the created cluster. May include the current node, which will always be the initial cluster node.')
        # parser.add_option("--quick-start", dest="quickstart", action="store_true", help="Perform basic system configuration (NTP, watchdog, /etc/hosts)")
        parser.add_option("-w", "--watchdog", dest="watchdog", metavar="WATCHDOG",
                          help="Use the given watchdog device")

        network_group = optparse.OptionGroup(parser, "Network configuration", "Options for configuring the network and messaging layer.")
        network_group.add_option("-i", "--interface", dest="nic", metavar="IF",
                                 help="Bind to IP address on interface IF")
        network_group.add_option("-u", "--unicast", action="store_true", dest="unicast",
                                 help="Configure corosync to communicate over unicast (UDP), and not multicast. Default is multicast unless an environment where multicast cannot be used is detected.")
        network_group.add_option("-A", "--admin-ip", dest="admin_ip", metavar="IP",
                                 help="Configure IP address as an administration virtual IP")
        parser.add_option_group(network_group)

        storage_group = optparse.OptionGroup(parser, "Storage configuration", "Options for configuring shared storage.")
        storage_group.add_option("-p", "--partition-device", dest="shared_device", metavar="DEVICE",
                                 help='Partition this shared storage device (only used in "storage" stage)')
        storage_group.add_option("-s", "--sbd-device", dest="sbd_device", metavar="DEVICE",
                                 help="Block device to use for SBD fencing")
        storage_group.add_option("-o", "--ocfs2-device", dest="ocfs2_device", metavar="DEVICE",
                                 help='Block device to use for OCFS2 (only used in "vgfs" stage)')
        parser.add_option_group(storage_group)

        options, args = parser.parse_args(list(args))

        stage = ""
        if len(args):
            stage = args[0]
        if stage not in bootstrap.INIT_STAGES and stage != "":
            parser.error("Invalid stage (%s)" % (stage))
            return False

        if options.template and options.template != "ocfs2":
            parser.error("Invalid template (%s)" % (options.template))
            return False

        # if options.geo and options.name == "hacluster":
        #    parser.error("For a geo cluster, each cluster must have a unique name (use --name to set)")
        #    return False

        bootstrap.bootstrap_init(
            cluster_name=options.name,
            nic=options.nic,
            ocfs2_device=options.ocfs2_device,
            shared_device=options.shared_device,
            sbd_device=options.sbd_device,
            quiet=options.quiet,
            template=options.template,
            admin_ip=options.admin_ip,
            yes_to_all=options.yes_to_all,
            unicast=options.unicast,
            watchdog=options.watchdog,
            stage=stage)

        # if options.geo:
        #    bootstrap.bootstrap_init_geo()

        nodelist = [n for n in re.split('[ ,;]+', options.nodes)]
        for node in nodelist:
            if node == utils.this_node():
                continue
            bootstrap.status("Add node {} (may prompt for root password):".format(node))
            if not self._add_node(node, yes_to_all=options.yes_to_all):
                return False

        return True

    @command.skill_level('administrator')
    def do_join(self, context, *args):
        '''
        Join this node to an existing cluster
        '''
        parser = OptParser(usage="usage: join [options] [STAGE]", epilog="""

Stage can be one of:
    ssh         Obtain SSH keys from existing cluster node (requires -c <host>)
    csync2      Configure csync2 (requires -c <host>)
    ssh_merge   Merge root's SSH known_hosts across all nodes (csync2 must
                already be configured).
    cluster     Start the cluster on this node

If stage is not specified, each stage will be invoked in sequence.
""")
        parser.add_option("-q", "--quiet", help="Be quiet (don't describe what's happening, just do it)", action="store_true", dest="quiet")
        parser.add_option("-y", "--yes", help='Answer "yes" to all prompts (use with caution)', action="store_true", dest="yes_to_all")
        parser.add_option("-w", "--watchdog", dest="watchdog", metavar="WATCHDOG", help="Use the given watchdog device")

        network_group = optparse.OptionGroup(parser, "Network configuration", "Options for configuring the network and messaging layer.")
        network_group.add_option("-c", "--cluster-node", dest="cluster_node", help="IP address or hostname of existing cluster node", metavar="HOST")
        network_group.add_option("-i", "--interface", dest="nic", help="Bind to IP address on interface IF", metavar="IF")
        parser.add_option_group(network_group)

        options, args = parser.parse_args(list(args))

        stage = ""
        if len(args) == 1:
            stage = args[0]
        if stage not in ("ssh", "csync2", "ssh_merge", "cluster", ""):
            parser.error("Invalid stage (%s)" % (stage))
            return False

        bootstrap.bootstrap_join(
            cluster_node=options.cluster_node,
            nic=options.nic,
            quiet=options.quiet,
            yes_to_all=options.yes_to_all,
            watchdog=options.watchdog,
            stage=stage)

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
        parser = OptParser(usage="usage: add [options] [node ...]")
        parser.add_option("-y", "--yes", help='Answer "yes" to all prompts (use with caution)', action="store_true", dest="yes_to_all")
        options, args = parser.parse_args(list(args))
        for node in args:
            if not self._add_node(node, yes_to_all=options.yes_to_all):
                return False

    @command.completers_repeating(_remove_completer)
    @command.skill_level('administrator')
    def do_remove(self, context, *args):
        '''
        Remove the given node(s) from the cluster.
        '''
        parser = OptParser(usage="usage: remove [options] [<node> ...]")
        parser.add_option("-q", "--quiet", help="Be quiet (don't describe what's happening, just do it)", action="store_true", dest="quiet")
        parser.add_option("-y", "--yes", help='Answer "yes" to all prompts (use with caution)', action="store_true", dest="yes_to_all")
        parser.add_option("-c", "--cluster-node", dest="cluster_node", help="IP address or hostname of cluster node which will be deleted", metavar="HOST")

        options, args = parser.parse_args(list(args))
        if options.cluster_node is not None and options.cluster_node not in args:
            args.append(options.cluster_node)
        if len(args) == 0:
            bootstrap.bootstrap_remove(
                cluster_node=None,
                quiet=options.quiet,
                yes_to_all=options.yes_to_all)
        else:
            for node in args:
                bootstrap.bootstrap_remove(
                    cluster_node=node,
                    quiet=options.quiet,
                    yes_to_all=options.yes_to_all)
        return True

    @command.name("geo-init")
    @command.skill_level('administrator')
    def do_geo_init(self, context, *args):
        '''
        Make this cluster a geo cluster.
        Needs some information to set up.

        * arbitrator IP / hostname
        * cluster map: "cluster-name=ip cluster-name=ip"
        * list of tickets
        '''
        parser = OptParser(usage="usage: geo-init [options]", epilog="""

Cluster Description

  This is a map of cluster names to IP addresses.
  Each IP address will be configured as a virtual IP
  representing that cluster in the geo cluster
  configuration.

  Example with two clusters named paris and amsterdam:

  --clusters "paris=192.168.10.10 amsterdam=192.168.10.11"

  Name clusters using the --name parameter to
  crm bootstrap init.
""")
        parser.add_option("-q", "--quiet", help="Be quiet (don't describe what's happening, just do it)", action="store_true", dest="quiet")
        parser.add_option("-y", "--yes", help='Answer "yes" to all prompts (use with caution)', action="store_true", dest="yes_to_all")
        parser.add_option("--arbitrator", help="IP address of geo cluster arbitrator", dest="arbitrator", metavar="IP")
        parser.add_option("--clusters", help="Cluster description (see details below)", dest="clusters", metavar="DESC")
        parser.add_option("--tickets", help="Tickets to create (space-separated)", dest="tickets", metavar="LIST")
        options, args = parser.parse_args(list(args))

        if options.clusters is None or options.arbitrator is None:
            errs = []
            if options.clusters is None:
                errs.append("The --clusters argument is required.")
            if options.arbitrator is None:
                errs.append("The --arbitrator argument is required.")
            parser.error(" ".join(errs))

        try:
            clustermap = dict([re.split('[=:]+', o) for o in re.split('[ ,;]+', options.clusters)])
        except ValueError:
            parser.error("Invalid cluster description format")
        ticketlist = []
        if options.tickets is not None:
            try:
                ticketlist = [t for t in re.split('[ ,;]+', options.tickets)]
            except ValueError:
                parser.error("Invalid ticket list")
        bootstrap.bootstrap_init_geo(options.quiet, options.yes_to_all, options.arbitrator, clustermap, ticketlist)
        return True

    @command.name("geo-join")
    @command.skill_level('administrator')
    def do_geo_join(self, context, *args):
        '''
        Join this cluster to a geo configuration.
        '''
        parser = OptParser(usage="usage: geo-join [options]")
        parser.add_option("-c", "--cluster-node", help="IP address of an already-configured geo cluster or arbitrator", dest="node", metavar="IP")
        options, args = parser.parse_args(list(args))
        bootstrap.bootstrap_join_geo(options.quiet, options.yes_to_all, options.node)
        return True

    @command.name("geo-init-arbitrator")
    @command.skill_level('administrator')
    def do_geo_init_arbitrator(self, context, *args):
        '''
        Make this node a geo arbitrator.
        '''
        parser = OptParser(usage="usage: geo-init-arbitrator [options]")
        parser.add_option("-c", "--cluster-node", help="IP address of an already-configured geo cluster", dest="other", metavar="IP")
        options, args = parser.parse_args(list(args))
        bootstrap.bootstrap_arbitrator(options.quiet, options.yes_to_all, options.other)
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
        stack = utils.cluster_stack()
        if not stack:
            err_buf.error("No supported cluster stack found (tried heartbeat|openais|corosync)")
        if utils.cluster_stack() == 'corosync':
            print "Services:"
            for svc in ["corosync", "pacemaker"]:
                info = utils.service_info(svc)
                if info:
                    print "%-16s %s" % (svc, info)
                else:
                    print "%-16s unknown" % (svc)

            rc, outp = utils.get_stdout(['corosync-cfgtool', '-s'], shell=False)
            if rc == 0:
                print ""
                print outp
            else:
                print "Failed to get corosync status"

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
    def do_run(self, context, cmd):
        '''
        Execute the given command on all nodes, report outcome
        '''
        try:
            import parallax
            _has_parallax = True
        except ImportError:
            _has_parallax = False

        if not _has_parallax:
            context.fatal_error("python package parallax is needed for this command")

        hosts = utils.list_cluster_nodes()
        opts = parallax.Options()
        for host, result in parallax.call(hosts, cmd, opts).iteritems():
            if isinstance(result, parallax.Error):
                err_buf.error("[%s]: %s" % (host, result))
            else:
                if result[0] != 0:
                    err_buf.error("[%s]: rc=%s\n%s\n%s" % (host, result[0], result[1], result[2]))
                else:
                    err_buf.ok("[%s]\n%s" % (host, result[1]))

    def do_copy(self, context, local_file, *nodes):
        '''
        usage: copy <filename> [nodes ...]
        Copy file to other cluster nodes.
        If given no nodes as arguments, copy to all other cluster nodes.
        '''
        return utils.cluster_copy_file(local_file, nodes)

    def do_diff(self, context, filename, *nodes):
        "usage: diff <filename> [--checksum] [nodes...]. Diff file across cluster."
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
