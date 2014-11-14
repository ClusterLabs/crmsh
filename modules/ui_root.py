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

# Revised UI structure for crmsh
#
# Goals:
#
# - Modularity
# - Reduced global state
# - Separate static hierarchy from current context
# - Fix completion
# - Implement bash completion
# - Retain all previous functionality
# - Have per-level pre-requirements:
#   def requires(self): <- raise error if prereqs are not met
#   This is so that crmsh can be installed with minimal prereqs,
#   and use cluster sublevel to install all requirements

import command
import cmd_status
import ui_cib
import ui_corosync
import ui_resource
import ui_configure
import ui_history
import ui_ra
import ui_site
import ui_node
import ui_report
import ui_options


class Root(command.UI):
    """
    Root of the UI hierarchy.
    """

    # name is the user-visible name of this CLI level.
    name = 'root'

    @command.level(ui_corosync.Corosync)
    @command.help('''Corosync configuration management
Corosync is the underlying messaging layer for most HA clusters.
This level provides commands for editing and managing the corosync
configuration.
''')
    def do_corosync(self):
        pass

    @command.level(ui_cib.CibShadow)
    @command.help('''manage shadow CIBs
A shadow CIB is a regular cluster configuration which is kept in
a file. The CRM and the CRM tools may manage a shadow CIB in the
same way as the live CIB (i.e. the current cluster configuration).
A shadow CIB may be applied to the cluster in one step.
''')
    def do_cib(self):
        pass

    @command.level(ui_resource.RscMgmt)
    @command.help('''resources management
Everything related to resources management is available at this
level. Most commands are implemented using the crm_resource(8)
program.
''')
    def do_resource(self):
        pass

    @command.level(ui_configure.CibConfig)
    @command.help('''CRM cluster configuration
The configuration level.

Note that you can change the working CIB at the cib level. It is
advisable to configure shadow CIBs and then commit them to the
cluster.
''')
    def do_configure(self):
        pass

    @command.level(ui_node.NodeMgmt)
    @command.help('''nodes management
A few node related tasks such as node standby are implemented
here.
''')
    def do_node(self):
        pass

    @command.level(ui_options.CliOptions)
    @command.help('''user preferences
Several user preferences are available. Note that it is possible
to save the preferences to a startup file.
''')
    def do_options(self):
        pass

    @command.level(ui_history.History)
    @command.help('''CRM cluster history
The history level.

Examine Pacemaker's history: node and resource events, logs.
''')
    def do_history(self):
        pass

    @command.level(ui_site.Site)
    @command.help('''Geo-cluster support
The site level.

Geo-cluster related management.
''')
    def do_site(self):
        pass

    @command.level(ui_ra.RA)
    @command.help('''resource agents information center
This level contains commands which show various information about
the installed resource agents. It is available both at the top
level and at the `configure` level.
''')
    def do_ra(self):
        pass

    @command.help('''Utility to collect logs and other information
`report` is a utility to collect all information (logs,
configuration files, system information, etc) relevant to
crmsh over the given period of time.
''')
    def do_report(self, context, *args):
        return ui_report.create_report(context, args)

    @command.help('''show cluster status
Show cluster status. The status is displayed by `crm_mon`. Supply
additional arguments for more information or different format.
See `crm_mon(8)` for more details.

Usage:
...............
status [<option> ...]

option :: bynode | inactive | ops | timing | failcounts
...............
''')
    def do_status(self, context, *args):
        return cmd_status.cmd_status(args)

# this will initialize _children for all levels under the root
Root.init_ui()


# vim:ts=4:sw=4:et:
