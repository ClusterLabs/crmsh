# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

from . import command
from . import utils
from .msg import err_buf
from . import scripts
from . import completers as compl


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
            return False
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
        rc, out, err = utils.get_stdout_stderr('service corosync start')
        if rc != 0:
            context.fatal_error("Failed to start corosync service: %s" % (err))
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
        rc, out, err = utils.get_stdout_stderr('service corosync stop')
        if rc != 0:
            context.fatal_error("Failed to stop corosync service: %s" % (err))
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

    @command.completers_repeating(compl.call(scripts.param_completion_list, 'init'))
    @command.skill_level('administrator')
    def do_init(self, context, *args):
        '''
        Initialize a cluster with the given hosts as nodes.
        '''
        args = self._args_implicit(context, args, 'nodes')
        script = scripts.load_script('init')
        if script is None:
            raise ValueError("init script failed to load")
        return scripts.run(script, script_args(args), script_printer())

    @command.completers_repeating(compl.call(scripts.param_completion_list, 'add'))
    @command.skill_level('administrator')
    def do_add(self, context, *args):
        '''
        Add the given node(s) to the cluster.
        Installs packages, sets up corosync and pacemaker, etc.
        Must be executed from a node in the existing cluster.
        '''
        params = self._args_implicit(context, args, 'node')
        paramdict = utils.nvpairs2dict(params)
        node = paramdict.get('node')
        if node:
            node = node.replace(',', ' ').split()
        else:
            node = []
        nodes = paramdict.get('nodes')
        if not nodes:
            nodes = utils.list_cluster_nodes()
        nodes += node
        params += ['nodes=%s' % (','.join(nodes))]
        script = scripts.load_script('add')
        if script is None:
            raise ValueError("add script failed to load")
        return scripts.run(script, script_args(params), script_printer())

    @command.completers_repeating(_remove_completer)
    @command.skill_level('administrator')
    def do_remove(self, context, *args):
        '''
        Remove the given node(s) from the cluster.
        '''
        params = self._args_implicit(context, args, 'node')
        script = scripts.load_script('remove')
        if script is None:
            raise ValueError("remove script failed to load")
        return scripts.run(script, script_args(params), script_printer())

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
