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

from . import command
from . import scripts


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
            script = scripts.load_script(name)
            if script is not None:
                print("%-16s %s" (script.name, script.shortdesc))

    def do_describe(self, context, name):
        '''
        Describe the given script.
        '''
        script = scripts.load_script(name)
        if script is None:
            return False

        def describe_param(p):
            return "    %s" % (p.name)
        vals = {
            'name': script.name,
            'category': script.category,
            'shortdesc': script.shortdesc,
            'longdesc': script.longdesc,
            'parameters': "\n".join((describe_param(p) for p in script.params))}
        return """%(name)s (%(category)s)
%(shortdesc)s

%(longdesc)s

Parameters:

%(parameters)s
""" % vals

    def do_verify(self, context, name, *args):
        '''
        Verify the script parameters
        '''
        script = scripts.load_script(name)
        if script is None:
            return False
        ret = script.verify(args)
        if ret is None:
            return False
        for nodes, action in ret:
            print action

    def do_run(self, context, name, *args):
        '''
        Run the given script.
        '''
        try:
            import parallax
        except ImportError:
            raise ValueError("The parallax python package is missing")
        script = scripts.load_script(name)
        if script is not None:
            return script.run(name, args)
        return False
