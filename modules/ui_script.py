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
from . import utils
from . import completers as compl


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
                print("%-16s %s" % (script['name'], script['shortdesc'].strip()))

    @command.completers_repeating(compl.call(scripts.list_scripts))
    @command.alias('info')
    def do_describe(self, context, name):
        '''
        Describe the given script.
        '''
        script = scripts.load_script(name)
        if script is None:
            return False

        def describe_step(i, s):
            ret = "%s. %s\n\n" % (i, s['stepdesc'].strip() or 'Parameters')
            if s.get('name'):
                for p in s['parameters']:
                    ret += "  %-16s %s\n" % (':'.join((s['name'], p['name'])), p['shortdesc'].strip())
            else:
                for p in s['parameters']:
                    ret += "  %-16s %s\n" % (p['name'], p['shortdesc'].strip())
            return ret
        vals = {
            'name': script['name'],
            'category': script['category'],
            'shortdesc': script['shortdesc'].strip(),
            'longdesc': script['longdesc'].strip(),
            'steps': "\n".join((describe_step(i + 1, s) for i, s in enumerate(script['steps'])))}
        print("""%(name)s (%(category)s)
%(shortdesc)s

%(longdesc)s

%(steps)s
""" % vals)

    @command.completers(compl.call(scripts.list_scripts))
    def do_verify(self, context, name, *args):
        '''
        Verify the script parameters
        '''
        script = scripts.load_script(name)
        if script is None:
            return False
        ret = scripts.verify(script, utils.nvpairs2dict(args))
        if ret is None:
            return False
        if not ret:
            print("OK (no actions)")
        for i, action in enumerate(ret):
            shortdesc = action.get('shortdesc', '')
            text = action.get('text') or action.get('longdesc', '')
            print("%s. %s\n" % (i + 1, shortdesc))
            if text:
                for line in text.split('\n'):
                    print("\t%s" % (line))
                print('')

    @command.completers(compl.call(scripts.list_scripts))
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
            return scripts.run(script, utils.nvpairs2dict(args))
        return False

    @command.name('_print')
    @command.skill_level('administrator')
    @command.completers(compl.call(scripts.list_scripts))
    def do_print(self, context, name):
        '''
        Debug print the given script.
        '''
        script = scripts.load_script(name)
        if script is not None:
            import pprint
            pprint.pprint(script)
        return False
