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

    @command.skill_level('administrator')
    def do_init(self, context, *hosts):
        '''
        Initialize a cluster with the given hosts as nodes.
        '''
        dry_run = False
        if len(hosts) and hosts[0] == '--dry-run':
            dry_run = True
            hosts = hosts[1:]
        return scripts.run(hosts, 'init', [], dry_run=dry_run)

    @command.skill_level('administrator')
    def do_add(self, context, node):
        '''
        Add the given node to the cluster.
        Installs packages, sets up corosync and pacemaker, etc.
        Must be executed from a node in the existing cluster.
        '''
        if self._node_in_cluster(node):
            context.fatal_error("Node already in cluster: %s" % (node))
        return scripts.run(None, 'add', ['node=%s' % (node)])

    @command.skill_level('administrator')
    def do_remove(self, context, node):
        '''
        Remove the given node from the cluster.
        '''
        if not self._node_in_cluster(node):
            context.fatal_error("Node not in cluster: %s" % (node))
        return scripts.run(None, 'remove', ['node=%s' % (node)])

    def do_health(self, context, *hosts):
        '''
        Extensive health check.
        '''
        if len(hosts) and hosts[0] == '--dry-run':
            dry_run = True
            hosts = hosts[1:]
        return scripts.run(hosts, 'health', [], dry_run=dry_run)

    def _node_in_cluster(self, node):
        return node in utils.list_cluster_nodes()

    def do_status(self, context):
        '''
        Quick cluster health status. Corosync status, DRBD status...
        '''
        stack = utils.cluster_stack()
        if not stack:
            err_buf.error("Cluster stack not detected!")
        else:
            print "* Cluster stack: " + utils.cluster_stack()
        if utils.cluster_stack() == 'corosync':
            rc, outp = utils.get_stdout(['corosync-cfgtool', '-s'], shell=False)
            print outp
            rc, outp = utils.get_stdout(['corosync-quorumtool', '-s'], shell=False)
            print outp

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
