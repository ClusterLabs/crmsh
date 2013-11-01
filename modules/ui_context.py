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

import shlex
import sys
import readline
from msg import common_err, common_info, common_warn
from msg import Options, UserPrefs
from utils import wait4dc
import ui_utils
import vars


class Context(object):
    """
    Context is a cursor that marks the current
    location of the user in the UI hierarchy.
    It maintains a stack of UILevel objects, so
    level_stack[-1] is the current level.

    The Context is passed as the first parameter
    to any command.
    """
    def __init__(self, tree):
        self.tree = tree
        self.stack = [tree.root]

        # holds information about the currently
        # executing command
        self.command_name = None
        self.command_args = None
        self.command_info = None

        # readline cache
        self._rl_line = None
        self._rl_words = None

    def run(self, line):
        '''
        Execute the given command line.
        '''
        line = line.strip()
        if not line or line.startswith('#'):
            return True

        try:
            tokens = shlex.split(line)
            while tokens:
                token, tokens = tokens[0], tokens[1:]
                self.command_name = token
                self.command_args = tokens
                self.command_info = self.current_level().get_child(token)
                if not self.command_info:
                    self.fatal_error("No such command: %s" % token)
                if self.command_info.type == 'level':
                    self.enter_level(self.command_info.level)
                else:
                    return self.execute_command()
            return True
        except ValueError, msg:
            common_err("%s: %s" % (self.get_qualified_name(), msg))
        except IOError, msg:
            common_err("%s: %s" % (self.get_qualified_name(), msg))
        return False

    def complete(self, line):
        '''
        Given a (partial) command line, returns
        a list of potential completions.
        A space at the end of the line is significant.
        '''
        complete_next = line.endswith(' ')
        #if complete_next:
        #    print >>sys.stderr, "complete_next is on"

        # copy current state
        prev_stack = list(self.stack)
        prev_name = self.command_name
        prev_args = self.command_args
        prev_info = self.command_info
        try:
            line = line.strip()
            if not line or line.startswith('#'):
                return self.current_level().get_completions()

            tokens = shlex.split(line)
            if complete_next:
                tokens += ['']
            while tokens:
                token, tokens = tokens[0], tokens[1:]
                self.command_name = token
                self.command_args = tokens
                self.command_info = self.current_level().get_child(token)

                if not self.command_info:
                    return self.current_level().get_completions()
                if self.command_info.type == 'level':
                    self.enter_level(self.command_info.level)
                else:
                    # use the completer for the command
                    return self.command_info.complete(tokens)
            # reached the end on a valid level.
            # return the completions for the previous level.
            if self.previous_level():
                return self.previous_level().get_completions()
            # not sure this is the right thing to do
            return self.current_level().get_completions()
        finally:
            # restore level stack
            self.stack = prev_stack
            self.command_name = prev_name
            self.command_args = prev_args
            self.command_info = prev_info

    def setup_readline(self):
        readline.set_history_length(100)
        readline.parse_and_bind("tab: complete")
        readline.set_completer(self.readline_completer)
        delims = readline.get_completer_delims()
        delims = delims.replace('-', '').replace('/', '').replace('=', '')
        readline.set_completer_delims(delims)
        try:
            readline.read_history_file(vars.hist_file)
        except IOError:
            pass

    def readline_completer(self, text, state):
        def matching(word):
            'we are only completing the last word in the line'
            return word.split()[-1].startswith(text)

        line = readline.get_line_buffer()
        if line != self._rl_line:
            self._rl_line = line
            self._rl_words = [w for w in self.complete(line) if matching(w)]
        try:
            return self._rl_words[state]
        except IndexError:
            return None

    def current_level(self):
        return self.stack[-1]

    def previous_level(self):
        if len(self.stack) > 1:
            return self.stack[-2]
        return None

    def enter_level(self, level):
        '''
        Pushes an instance of the given UILevel
        subclass onto self.stack. Checks prerequirements
        for the level (if any).
        '''
        # on entering new level we need to set the
        # interactive option _before_ creating the level
        if not options.interactive and not self.command_args:
            self._set_interactive()

        entry = level()
        if 'requires' in dir(entry) and not entry.requires():
            self.fatal_error("Missing requirements")
        self.stack.append(entry)

    def _set_interactive(self):
        '''Set the interactive option only if we're on a tty.'''
        if sys.stdin.isatty():
            options.interactive = True

    def execute_command(self):
        # build argument list
        arglist = [self.current_level(), self] + self.command_args
        # nskip = 2 to skip self and context when reporting errors
        ui_utils.validate_arguments(self.command_info.function, arglist, nskip=2)
        self.check_skill_level(self.command_info.skill_level)
        rv = self.command_info.function(*arglist)

        # should we wait till the command takes effect?
        if rv and self.should_wait():
            if not wait4dc(self.command_name, not options.batch):
                return False
        return rv

    def should_wait(self):
        if not user_prefs.wait or not self.command_info.wait:
            return False

        by_level = self.current_level().should_wait()
        transit_or_noninteractive = self.is_in_transit() or not options.interactive
        return by_level and transit_or_noninteractive

    def is_in_transit(self):
        '''
        TODO
        FIXME
        '''
        return False

    def check_skill_level(self, skill_level):
        if user_prefs.skill_level < skill_level:
            levels = {0: 'operator', 1: 'administrator', 2: 'expert'}
            self.fatal_error("ACL %s skill level required" %
                             (levels.get(skill_level, 'other')))

    def get_command_name(self):
        "Returns name used to call the current command"
        return self.command_name

    def get_qualified_name(self):
        "Returns level.command if level is not root"
        names = '.'.join([l.name for l in self.stack[1:]])
        if names:
            return "%s.%s" % (names, self.get_command_name())
        return self.get_command_name()

    def get_command_info(self):
        "Returns the ChildInfo object for the current command or level"
        return self.command_info

    def up(self):
        '''
        Navigate up in the levels hierarchy
        '''
        if len(self.stack) > 1:
            self.stack.pop()

    def quit(self, rc=0):
        '''
        Exit from the top level
        '''
        if options.interactive and not options.batch:
            print "bye"
        sys.exit(rc)

    def level_name(self):
        '''
        Returns the name of the current level.
        Returns '.' if at the root level.
        '''
        return self.current_level().name

    def prompt(self):
        'returns a prompt generated from the level stack'
        return ' '.join(l.name for l in self.stack[1:])

    def previous_level_is(self, level_name):
        '''
        Check call stack for previous level name
        '''
        prev = self.previous_level()
        return prev and prev.name == level_name

    def fatal_error(self, msg):
        """
        TODO: Better error messages, with full context information
        Raise exception to get thrown out to run()
        """
        raise ValueError(msg)

    def error_message(self, msg):
        """
        Error message only, don't cancel execution of command
        """
        common_err("%s: %s" % (self.get_qualified_name(), msg))

    def warning(self, msg):
        common_warn("%s: %s" % (self.get_qualified_name(), msg))

    def info(self, msg):
        common_info("%s: %s" % (self.get_qualified_name(), msg))


options = Options.getInstance()
user_prefs = UserPrefs.getInstance()

# vim:ts=4:sw=4:et:
