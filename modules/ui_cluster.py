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


class Cluster(command.UI):
    '''
    Whole cluster management.

    - Package installation
    - System configuration
    - Corosync configuration
    - Network troubleshooting
    - Perform other callouts/cluster-wide devops operations
    '''
    name = "cluster"

    @command.skill_level('administrator')
    def do_init(self, context):
        '''
        Cluster initialization, from scratch!

        Can assume that the dependencies for crmsh are installed on this node.

        Don't count on anything else.

        Automatic as far as possible.
        '''
        context.fatal_error("Not implemented.")

    @command.skill_level('administrator')
    def do_join(self, context, node):
        '''
        Join the given node to the cluster.
        Installs packages, sets up corosync and pacemaker, etc.
        Is assumed to be executed from a node in an existing cluster.
        '''
        # verify that localhost is in a cluster
        # check health of cluster
        # probe new node
        # install stuff on new node
        context.fatal_error("Not implemented.")

    def do_status(self, context):
        '''
        Quick cluster health status. Corosync status, DRBD status...
        '''
        context.fatal_error("Not implemented.")

    def do_doctor(self, context):
        '''
        Cluster extensive health monitoring.
        '''
        context.fatal_error("Not implemented.")

    def do_actions(self, context):
        '''
        List the available cluster actions.
        '''
        context.fatal_error("No cluster actions found.")

    @command.skill_level('administrator')
    def do_action(self, context, action, *args):
        '''
        Apply the given cluster action.
        '''
        context.fatal_error("Cluster action '%' not found." % (action))

    @command.skill_level('administrator')
    def do_shell(self, context, shellcmd):
        '''
        Execute the given shell command on
        all nodes in the cluster.
        '''
        context.fatal_error("Not implemented.")
