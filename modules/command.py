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

# Decorators and other helper functions for the UI
#
# Mostly, what these functions do is store extra metadata
# inside the functions.

#from functools import wraps
import inspect
import help as help_module


def name(n):
    def inner(fn):
        setattr(fn, '_name', n)
        return fn
    return inner


def alias(*aliases):
    def inner(fn):
        setattr(fn, '_aliases', aliases)
        return fn
    return inner


def level(level_class):
    def inner(fn):
        # check signature of given level function
        _check_args(fn, ('self',))

        setattr(fn, '_ui_type', 'level')
        setattr(fn, '_level', level_class)

        def default(arg, val):
            if not hasattr(fn, arg):
                setattr(fn, arg, val)

        default('_aliases', tuple())
        default('_short_help', None)
        default('_long_help', None)
        return fn
    return inner


def help(doc):
    '''
    Use to set a help text for a command or level
    which isn't documented in crm.8.txt.

    The first line of the doc string will be used as
    the short help, the rest will be used as the full
    help message.
    '''
    doc_split = doc.split('\n', 1)

    def inner(fn):
        setattr(fn, '_short_help', doc_split[0])
        if len(doc_split) > 1:
            setattr(fn, '_long_help', doc_split[1])
        else:
            setattr(fn, '_long_help', '')
        return fn
    return inner


def skill_level(level):
    '''
    Use to set the required skill level of a command:

        @command
        @skill_level('administrator')
        def do_rmrf(self, cmd, args):
            ...
    '''
    if isinstance(level, basestring):
        levels = {'operator': 0, 'administrator': 1, 'expert': 2}
        if level.lower() not in levels:
            raise ValueError("Unknown skill level: " + level)
        level = levels[level.lower()]

    def inner(fn):
        setattr(fn, '_skill_level', level)
        return fn
    return inner


def wait(fn):
    '''
    A command with this decorator will
    force the interactive shell to wait
    for the command to complete.

        @command
        @wait
        def do_bigop(self, cmd, args):
            ...
    '''
    setattr(fn, '_wait', True)
    return fn


def completers(*fns):
    '''
    Use to set a list of tab completers for the command.
    The completer gets as its argument the command line entered so far,
    and returns a list of possible completions.
    '''
    def inner(fn):
        setattr(fn, '_completers', fns)
        return fn
    return inner


class UI(object):
    '''
    Base class for all ui levels.
    Things that I need to solve:
      - Error handling
      - Help
      - Completion
    '''
    name = None

    def requires(self):
        '''
        Returns False if requirements for level are
        not met. Checked before entering the level.
        '''
        return True

    def end_game(self, no_questions_asked=False):
        '''
        Overriding end_game() allows levels to ask
        for confirmation before exiting.
        '''
        pass

    def should_wait(self):
        '''
        A kludge to allow in-transit configuration changes to
        make us wait on transition to finish. Needs to be
        implemented in the level (currently, just configure).
        '''
        return False

    @alias('end', 'back')
    @help('Go back to previous level')
    def do_up(self, context):
        '''
        TODO: Implement full cd navigation. cd ../configure, for example
        Also implement ls to list commands / levels from current location
        '''
        self.end_game()
        context.up()

    @help('Navigate the level structure')
    def do_cd(self, context, optarg='..'):
        '''
        TODO: Implement full cd navigation. cd ../configure, for example
        Also implement ls to list commands / levels from current location
        '''
        if optarg == '..':
            self.end_game()
            context.up()
        elif optarg == '.':
            pass

    @alias('bye', 'exit')
    @help('Exit the interactive shell')
    def do_quit(self, context):
        self.end_game()
        context.quit()

    @alias('?')
    @help('''show help (help topics for list of topics)
    The help subsystem consists of the command reference and a list
    of topics. The former is what you need in order to get the
    details regarding a specific command. The latter should help with
    concepts and examples.

    Examples:

        help Introduction
        help quit
    ''')
    def do_help(self, context, arg=None):
        """usage: help topic|level|command"""
        help_module.help_contextual(context.level_name(), arg).paginate()

    def get_completions(self):
        '''
        return tab completions
        '''
        return self._children.keys()

    def get_child(self, name):
        return self._children.get(name)

    @classmethod
    def init_ui(self):
        children = {}
        for child_name in dir(self):
            child = getattr(self, child_name)
            iscommand = child_name.startswith('do_') and inspect.ismethod(child)
            if iscommand:
                info = ChildInfo(child, self)
                if info.type == 'command' and not is_valid_command_function(info.function):
                    raise ValueError("Invalid command function: %s.%s" %
                                     (self.__name__, info.function.__name__))
                children[info.name] = info

                # Set up aliases
                for alias in info.aliases:
                    children[alias] = info

                # Add static help to the help system
                if info.short_help:
                    entry = help.HelpEntry(info.short_help, info.long_help)
                    if info.type == 'command':
                        help.add_help(entry, level=self.name, command=info.name)
                    elif info.type == 'level':
                        help.add_help(entry, level=info.name)
        setattr(self, '_children', children)
        return children


def make_name(name):
    '''
    Generate command name from command function name.
    '''
    if name.startswith('do_'):
        return name[3:]
    return name


class ChildInfo(object):
    '''
    Declares the given method a command method.
    Sets extra attributes in the function itself,
    which are picked up by the UILevel class and used
    to generate ChildInfo data.

    The given method is expected to take a first parameter
    (after self) which is a UI context, which holds information
    about where the user came from when calling the command, controls
    for manipulating the current level (up(), quit(), etc),
    the name used when calling the command, error reporting and warning
    methods.

    The rest of the parameters are the actual arguments to the method. These
    are tokenized using shlex and then matched to the actual arguments of the
    method.

    Information about a child node in the hierarchy:
    A node is either a level or a command.
    '''
    def __init__(self, fn, parent):
        def maybe(attr, default):
            if hasattr(fn, attr):
                return getattr(fn, attr)
            return default

        self.function = fn
        self.name = maybe('_name', make_name(fn.__name__))
        self.type = maybe('_ui_type', 'command')
        self.aliases = maybe('_aliases', tuple())
        self.short_help = maybe('_short_help', None)
        self.long_help = maybe('_long_help', None)
        self.skill_level = maybe('_skill_level', 0)
        self.wait = maybe('_wait', False)
        self.level = maybe('_level', None)
        self.parent = parent
        self.children = {}
        if self.type == 'level' and self.level:
            self.children = self.level.init_ui()

    def complete(self, args):
        '''
        Execute the completer for this command with the given arguments.
        The completer mostly completes based on argument position, but
        some commands are context sensitive...
        '''
        return []

    def __repr__(self):
        return "%s:%s (%s)" % (self.type, self.name, self.short_help)


def is_valid_command_function(fn):
    '''
    Returns True if fn is a valid command function:
    named do_xxx, takes (self, context) as the first two parameters
    '''
    specs = inspect.getargspec(fn)
    return len(specs.args) >= 2 and specs.args[0] == 'self' and specs.args[1] == 'context'


def _check_args(fn, expected):
    argnames = fn.func_code.co_varnames[:fn.func_code.co_argcount]
    if argnames != expected:
        raise ValueError(fn.__name__ +
                         ": Expected method with signature " + repr(expected))
