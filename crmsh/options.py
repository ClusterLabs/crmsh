# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
'''
Session-only options (not saved).
'''

batch = False
ask_no = False
regression_tests = False
profile = ""
history = "live"
input_file = ""
shadow = ""
scriptdir = ""
# set to true when completing non-interactively
shell_completion = False
force = False

_in_repl = False


def in_repl():
    '''Return True if running in the interactive REPL shell.'''
    return _in_repl


def set_in_repl(val=True):
    global _in_repl
    _in_repl = bool(val)

