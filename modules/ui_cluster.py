# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

import command
import utils
from msg import err_buf
import scripts


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
            err_buf.warn("Unsupported cluster stack %s detected." % (stack))
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

    @command.skill_level('administrator')
    def do_init(self, context, *args):
        '''
        Initialize a cluster with the given hosts as nodes.
        '''
        return scripts.run('init', self._args_implicit(context, args, 'nodes'))

    @command.skill_level('administrator')
    def do_add(self, context, *args):
        '''
        Add the given node(s) to the cluster.
        Installs packages, sets up corosync and pacemaker, etc.
        Must be executed from a node in the existing cluster.
        '''
        return scripts.run('add', self._args_implicit(context, args, 'node'))

    @command.skill_level('administrator')
    def do_remove(self, context, *args):
        '''
        Remove the given node(s) from the cluster.
        '''
        return scripts.run('remove', self._args_implicit(context, args, 'node'))

    def do_health(self, context, *args):
        '''
        Extensive health check.
        '''
        params = self._args_implicit(context, args, 'nodes')
        if not any(k.startswith('nodes=') for k in params):
            params += ['nodes=%s' % (','.join(utils.list_cluster_nodes()))]
        return scripts.run('health', params)

    def _node_in_cluster(self, node):
        return node in utils.list_cluster_nodes()

    def do_status(self, context):
        '''
        Quick cluster health status. Corosync status, DRBD status...
        '''
        stack = utils.cluster_stack()
        if not stack:
            err_buf.error("Cluster stack not detected!")
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

    def do_wait_for_startup(self, context, timeout='10'):
        "usage: wait_for_startup [<timeout>]"
        import time
        t0 = time.time()
        timeout = float(timeout)
        cmd = 'crm_mon -s -1 2&>1 >/dev/null'
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
            from psshlib import api as pssh
            _has_pssh = True
        except ImportError:
            _has_pssh = False

        if not _has_pssh:
            context.fatal_error("PSSH not found")

        hosts = utils.list_cluster_nodes()
        opts = pssh.Options()
        for host, result in pssh.call(hosts, cmd, opts).iteritems():
            if isinstance(result, pssh.Error):
                err_buf.error("[%s]: %s" % (host, result))
            else:
                if result[0] != 0:
                    err_buf.error("[%s]: rc=%s\n%s\n%s" % (host, result[0], result[1], result[2]))
                else:
                    err_buf.ok("[%s]\n%s" % (host, result[1]))
