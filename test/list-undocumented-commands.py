#!/usr/bin/env python
#
# Script to discover and report undocumented commands.

from crmsh.ui_root import Root
from crmsh import help

help.HELP_FILE = "doc/crm.8.adoc"
help._load_help()

_IGNORED_COMMANDS = ('help', 'quit', 'cd', 'up', 'ls')


def check_help(ui):
    for name, child in ui.children().iteritems():
        if child.type == 'command':
            try:
                h = help.help_command(ui.name, name)
                if h.generated and name not in _IGNORED_COMMANDS:
                    print("Undocumented: %s %s" % (ui.name, name))
            except:
                print("Undocumented: %s %s" % (ui.name, name))
        elif child.type == 'level':
            h = help.help_level(name)
            if h.generated:
                print("Undocumented: %s %s" % (ui.name, name))
            check_help(child.level)

check_help(Root())
