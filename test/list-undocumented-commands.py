#!/usr/bin/env python
#
# Script to discover and report undocumented commands.

import os
import sys

parent, bindir = os.path.split(os.path.dirname(os.path.abspath(sys.argv[0])))
if os.path.exists(os.path.join(parent, 'modules')):
    sys.path.insert(0, parent)


from modules.ui_root import Root
import modules.help

modules.help.HELP_FILE = "doc/crm.8.adoc"
modules.help._load_help()

_IGNORED_COMMANDS = ('help', 'quit', 'cd', 'up', 'ls')

def check_help(ui):
    for name, child in ui._children.iteritems():
        if child.type == 'command':
            try:
                h = modules.help.help_command(ui.name, name)
                if h.generated and name not in _IGNORED_COMMANDS:
                    print "Undocumented: %s %s" % (ui.name, name)
            except:
                print "Undocumented: %s %s" % (ui.name, name)
        elif child.type == 'level':
            h = modules.help.help_level(name)
            if h.generated:
                print "Undocumented: %s %s" % (ui.name, name)
            check_help(child.level)

check_help(Root())
