# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import shlex
import sys
from . import config
from . import utils
from . import options
from . import ui_utils
from . import userdir
from . import constants
from . import log
from . import main
from .service_manager import ServiceManager


logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)


class Context(object):
    """
    Context is a cursor that marks the current
    location of the user in the UI hierarchy.
    It maintains a stack of UILevel objects, so
    level_stack[-1] is the current level.

    The Context is passed as the first parameter
    to any command.
    """
    def __init__(self, root):
        self.stack = [root]
        self._mark = 0
        self._in_transit = False
        self._wait_for_dc = False

        # holds information about the currently
        # executing command
        self.command_name = None
        self.command_args = None
        self.command_info = None

        # readline cache
        self._rl_line = None
        self._rl_words = []

    def run(self, line):
        '''
        Execute the given command line.
        '''
        promptstr = "crm({}/{}){}# ".format(main.cib_prompt(), utils.this_node(), self.prompt())
        logger_utils.log_only_to_file("{}{}".format(promptstr, line))

        line = line.strip()
        if not line or line.startswith('#'):
            return True

        line = _try_redirect_help_argument_to_subcommand(line)

        self._mark = len(self.stack)
        self._in_transit = False
        self._wait_for_dc = False

        rv = True
        cmd = False
        try:
            tokens = shlex.split(line)
            while tokens:
                token, tokens = tokens[0], tokens[1:]
                self.command_name = token
                self.command_args = tokens
                self.command_info = self.current_level().get_child(token)
                if not self.command_info:
                    self.fatal_error("No such command")
                if self.command_name in self.command_info.aliases and self.command_name not in ["-h", "--help"]:
                    logger.warning("This command '%s' is deprecated, please use '%s'", self.command_name, self.command_info.name)
                if token != self.command_info.name:
                    logger.info("\"%s\" is accepted as \"%s\"", token, self.command_info.name)
                self.command_name = self.command_info.name
                if self.command_info.type == 'level':
                    self.enter_level(self.command_info.level)
                else:
                    cmd = True
                    break
            if cmd:
                if self.command_name not in constants.NON_FUNCTIONAL_COMMANDS\
                        and all(arg not in constants.NON_FUNCTIONAL_OPTIONS for arg in self.command_args):
                    entry = self.current_level()
                    if 'requires' in dir(entry) and not entry.requires():
                        self.fatal_error("Missing requirements")
                utils.check_user_access(self.current_level().name)
                rv = self.execute_command() is not False
        except (ValueError, IOError) as e:
            logger.error("%s: %s", self.get_qualified_name(), e, exc_info=e)
            rv = False
        except utils.TerminateSubCommand as terminate:
            if terminate.success:
                rv = True
            else:
                return False
        if cmd or (rv is False):
            rv = self._back_out() and rv

        # wait for dc if wait flag set
        if self._wait_for_dc:
            return utils.wait4dc(self.command_name, not options.batch)
        return rv

    def complete(self, line):
        '''
        Given a (partial) command line, returns
        a list of potential completions.
        A space at the end of the line is significant.
        '''
        complete_next = line.endswith(' ')
        # if complete_next:
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

            try:
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
                        ret = self.command_info.complete(self, tokens)
                        if tokens:
                            ret = [t for t in ret if t.startswith(tokens[-1])]

                        if not ret or self.command_info.aliases:
                            if not token in self.current_level().get_completions():
                                return self.current_level().get_completions()
                        if self.command_name in self.command_info.aliases and not self.command_args:
                            return [self.command_name]
                        return ret
                # reached the end on a valid level.
                # return the completions for the previous level.
                if self.previous_level():
                    return self.previous_level().get_completions()
                # not sure this is the right thing to do
                return self.current_level().get_completions()
            except ValueError:
                # logger.error("%s: %s" % (self.get_qualified_name(), msg))
                pass
            except IOError:
                # logger.error("%s: %s" % (self.get_qualified_name(), msg))
                pass
            return []
        finally:
            # restore level stack
            self.stack = prev_stack
            self.command_name = prev_name
            self.command_args = prev_args
            self.command_info = prev_info

    def setup_readline(self):
        import readline
        readline.set_history_length(100)
        for v in ('tab: complete',
                  # 'set bell-style visible',
                  # 'set menu-complete-display-prefix on',
                  # 'set show-all-if-ambiguous on',
                  # 'set show-all-if-unmodified on',
                  'set skip-completed-text on'):
            readline.parse_and_bind(v)
        readline.set_completer(self.readline_completer)
        readline.set_completer_delims(' \t\n,')
        try:
            readline.read_history_file(userdir.HISTORY_FILE)
        except IOError:
            pass

    def disable_completion(self):
        import readline
        readline.parse_and_bind('tab: complete')
        readline.set_completer(self.disable_completer)

    def disable_completer(self, text, state):
        # complete nothing
        return

    def clear_readline_cache(self):
        self._rl_line = None
        self._rl_words = []

    def readline_completer(self, text, state):
        import readline

        def matching(word):
            'we are only completing the last word in the line'
            return word.split()[-1].startswith(text)

        line = utils.get_line_buffer() + readline.get_line_buffer()
        if line != self._rl_line:
            try:
                self._rl_line = line
                completions = self.complete(line)
                if text:
                    self._rl_words = [w for w in completions if matching(w) and not w.startswith("_")]
                else:
                    self._rl_words = [w for w in completions if not w.startswith("_")]

            except Exception:  # , msg:
                # logging.exception(msg)
                self.clear_readline_cache()

        try:
            ret = self._rl_words[state]
        except IndexError:
            ret = None
        # logging.debug("line:%s, text:%s, ret:%s, state:%s", repr(line), repr(text), ret, state)
        if not text or (ret and line.split()[-1].endswith(ret)):
            if ret == "id=":
                return ret
            return ret + ' '
        return ret

    def current_level(self):
        return self.stack[-1]

    def previous_level(self):
        if len(self.stack) > 1:
            return self.stack[-2]
        return None

    def enter_level(self, level):
        '''
        Pushes an instance of the given UILevel
        subclass onto self.stack.
        '''
        # on entering new level we need to set the
        # interactive option _before_ creating the level
        if not options.interactive and not self.command_args:
            self._set_interactive()

        # not sure what this is all about
        self._in_transit = True

        entry = level()
        if ServiceManager().service_is_active("pacemaker.service"):
            if 'requires' in dir(entry) and not entry.requires():
                self.fatal_error("Missing requirements")
        self.stack.append(entry)
        self.clear_readline_cache()

    def _set_interactive(self):
        '''Set the interactive option only if we're on a tty.'''
        if utils.can_ask():
            options.interactive = True

    def execute_command(self):
        # build argument list
        arglist = [self.current_level(), self] + self.command_args
        # nskip = 2 to skip self and context when reporting errors
        ui_utils.validate_arguments(self.command_info.function, arglist, nskip=2)
        self.check_skill_level(self.command_info.skill_level)
        rv = self.command_info.function(*arglist)

        # should we wait till the command takes effect?
        if self.should_wait():
            self._wait_for_dc = True
        return rv

    def should_wait(self):
        if not config.core.wait:
            return False

        if self.command_info.wait:
            return True

        by_level = self.current_level().should_wait()
        transit_or_noninteractive = self.is_in_transit() or not options.interactive
        return by_level and transit_or_noninteractive

    def is_in_transit(self):
        '''
        TODO
        FIXME
        '''
        return self._in_transit

    def check_skill_level(self, skill_level):
        levels_to = {0: 'operator', 1: 'administrator', 2: 'expert'}
        levels_from = {'operator': 0, 'administrator': 1, 'expert': 2}
        if levels_from.get(config.core.skill_level, 0) < skill_level:
            self.fatal_error("ACL %s skill level required" %
                             (levels_to.get(skill_level, 'other')))

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
        ok = True
        if len(self.stack) > 1:
            if ServiceManager().service_is_active("pacemaker.service"):
                ok = self.current_level().end_game(no_questions_asked=self._in_transit) is not False
            self.stack.pop()
            self.clear_readline_cache()
        return ok

    def _back_out(self):
        '''
        Restore the stack to the marked position
        '''
        ok = True
        while self._mark > 0 and len(self.stack) > self._mark:
            ok = self.up() and ok
        return ok

    def save_stack(self):
        self._mark = len(self.stack)

    def quit(self, rc=0):
        '''
        Exit from the top level
        '''
        ok = True
        if self.command_name and self.command_name not in constants.NON_FUNCTIONAL_COMMANDS:
            ok = self.current_level().end_game()
        if options.interactive and not options.batch:
            if constants.need_reset:
                utils.ext_cmd("reset")
            else:
                print("bye")
        if ok is False and rc == 0:
            rc = 1
        sys.exit(rc)

    def level_name(self):
        '''
        Returns the name of the current level.
        Returns 'root' if at the root level.
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

    def error(self, msg):
        """
        Too easy to misremember and type error()
        when I meant fatal_error().
        """
        raise ValueError(msg)

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
        logger.error("%s: %s", self.get_qualified_name(), msg)

    def warning(self, msg):
        logger.warning("%s: %s", self.get_qualified_name(), msg)

    def info(self, msg):
        logger.info("%s: %s", self.get_qualified_name(), msg)


def _try_redirect_help_argument_to_subcommand(line):
    tokens = shlex.split(line)
    if "--help-without-redirect" in tokens:
        # Help text of some subcommands are read from `--help` generated by argparse.
        # They should not be redirected, or a circular redirect will be formed.
        # See crmsh.help._load_help.
        return ' '.join(("--help" if token == "--help-without-redirect" else token for token in tokens))
    elif tokens[-1] in ["-h", "--help"]:
        if len(tokens) == 2 and tokens[0] == 'report':
            # subcommand report has --help implementation, but _load_help doest not load from it.
            return line
        else:
            return 'help ' + ' '.join(tokens[:-1])
    else:
        return line


# vim:ts=4:sw=4:et:
