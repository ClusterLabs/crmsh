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
        for fn in scripts.list_scripts():
            script = scripts.load_script(fn)
            if script is not None:
                print("%-16s %s" % (script['name'], script['shortdesc']))

    @command.alias('info')
    def do_describe(self, context, name):
        '''
        Describe the given script.
        '''
        script = scripts.load_script(name)
        if script is None:
            return False

        def describe_step(i, s):
            ret = "%s. %s\n" % (i, s['stepdesc'].strip() or 'Parameters')
            for p in s['parameters']:
                ret += "  %-16s %s\n" % (p['name'], p['shortdesc'])
            return ret
        vals = {
            'name': script['name'],
            'category': script['category'],
            'shortdesc': script['shortdesc'],
            'longdesc': script['longdesc'],
            'steps': "\n".join((describe_step(i + 1, s) for i, s in enumerate(script['steps'])))}
        print("""%(name)s (%(category)s)
%(shortdesc)s

%(longdesc)s

Steps:

%(steps)s
""" % vals)

    def do_verify(self, context, name, *args):
        '''
        Verify the script parameters
        '''
        script = scripts.load_script(name)
        if script is None:
            return False
        ret = scripts.verify(script, args)
        if ret is None:
            return False
        for i, action in enumerate(ret):
            print("%s. %s" % (i + 1, action['shortdesc']))

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
            return scripts.run(script, args)
        return False

    @command.name('_print')
    @command.skill_level('administrator')
    def do_print(self, context, name):
        '''
        Debug print the given script.
        '''
        script = scripts.load_script(name)
        if script is not None:
            import pprint
            pprint.pprint(script)
        return False
