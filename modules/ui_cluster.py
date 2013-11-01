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
    @command.alias('create', 'setup')
    def do_init(self, context):
        '''
        Cluster initialization, from scratch!

        Can assume that the dependencies for crmsh are installed.

        Don't count on anything else.

        Automatic as far as possible.
        '''
        return True

    @command.skill_level('administrator')
    def do_join(self, context, node):
        '''
        Join the given node to the cluster.
        Installs packages, sets up corosync and pacemaker, etc.
        '''
        return True

    def do_status(self, context):
        '''
        Quick cluster health status. Corosync status, DRBD status...
        '''
        return True

    def do_doctor(self, context):
        '''
        Cluster extensive health monitoring.
        '''
        return True

    @command.skill_level('administrator')
    def do_apply(self, context, playbook, *args):
        '''
        Apply the given playbook (cluster script)
        '''
        return True

    @command.skill_level('administrator')
    def do_shell(self, context, shellcmd):
        '''
        Execute the given shell command on all nodes in the cluster
        '''
        return True

