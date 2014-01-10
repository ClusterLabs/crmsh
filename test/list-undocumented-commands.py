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

modules.help.HELP_FILE = "doc/crm.8.txt"
modules.help._load_help()


def check_help(ui):
    for name, child in ui._children.iteritems():
        if modules.help.help_contextual(ui.name, name, None) == modules.help._DEFAULT:
            print "Undocumented: %s %s" % (ui.name, name)
        if child.type == 'level':
            check_help(child.level)

check_help(Root())
