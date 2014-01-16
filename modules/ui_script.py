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
import scripts

from msg import err_buf


class Script(command.UI):
    '''
    Cluster scripts can perform cluster-wide configuration,
    validation and management. See the `list` command for
    an overview of available scripts.

    The script UI is a thin veneer over the scripts
    backend module.
    '''
    name = "script"

    def do_list(self, context):
        '''
        List available scripts.
        '''
        for name in scripts.list_scripts():
            main = scripts.load_script(name)
            print "%-16s %s" % (name, main.get('name', ''))

    def do_verify(self, context, name):
        '''
        Verify the given script.
        '''
        if scripts.verify(name):
            err_buf.ok(name)

    def do_describe(self, context, name):
        '''
        Describe the given script.
        '''
        return scripts.describe(name)

    def do_steps(self, context, name):
        '''
        Print names of steps in script
        '''
        main = scripts.load_script(name)
        for step in main['steps']:
            print step['name']

    def do_run(self, context, name, *args):
        '''
        Run the given script.
        '''
        return scripts.run(name, args)
