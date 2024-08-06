# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.

import sys
import os
import atexit
import random

from . import config
from . import options
from . import constants
from . import clidisplay
from . import term
from . import upgradeutil
from . import utils
from . import userdir

from . import ui_root
from . import ui_context
from . import log


logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)


random.seed()


def load_rc(context, rcfile):
    # only load the RC file if there is no new-style user config
    if config.has_user_config():
        return

    try:
        f = open(rcfile)
    except:
        return
    save_stdin = sys.stdin
    sys.stdin = f
    while True:
        inp = utils.multi_input()
        if inp is None:
            break
        try:
            if not context.run(inp):
                raise ValueError("Error in RC file: " + rcfile)
        except ValueError as msg:
            logger.error(msg)
    f.close()
    sys.stdin = save_stdin


def exit_handler():
    '''
    Write the history file. Remove tmp files.
    '''
    if options.interactive and not options.batch:
        try:
            from readline import write_history_file
            write_history_file(userdir.HISTORY_FILE)
        except:
            pass


# prefer the user set PATH
def envsetup():
    path = os.environ["PATH"].split(':')
    # always add these dirs to PATH if they exist
    libexec_dirs = ('/usr/lib64', '/usr/libexec', '/usr/lib',
                    '/usr/local/lib64', '/usr/local/libexec', '/usr/local/lib')
    pacemaker_dirs = set("{}/pacemaker".format(d) for d in libexec_dirs)
    pacemaker_dirs.add(config.path.crm_daemon_dir)
    pacemaker_dirs.add(os.path.dirname(sys.argv[0]))
    for p in pacemaker_dirs:
        if p not in path and os.path.isdir(p):
            os.environ['PATH'] = "%s:%s" % (os.environ['PATH'], p)


# three modes: interactive (no args supplied), batch (input from
# a file), half-interactive (args supplied, but not batch)
def cib_prompt():
    shadow = utils.get_cib_in_use()
    if not shadow:
        return constants.live_cib_prompt
    if constants.tmp_cib:
        return constants.tmp_cib_prompt
    return shadow


def make_option_parser():
    from argparse import ArgumentParser, REMAINDER
    parser = ArgumentParser(prog='crm', usage="""%(prog)s [-h|--help] [OPTIONS] [SUBCOMMAND ARGS...]
or %(prog)s help SUBCOMMAND

For a list of available subcommands, use %(prog)s help.

Use %(prog)s without arguments for an interactive session.
Call a subcommand directly for a "single-shot" use.
Call %(prog)s with a level name as argument to start an interactive
session from that level.

See the crm(8) man page or call %(prog)s help for more details.""")
    parser.add_argument('--version', action='version', version="%(prog)s " + config.CRM_VERSION)
    parser.add_argument("-f", "--file", dest="filename", metavar="FILE",
                        help="Load commands from the given file. If a dash (-) " +
                        "is used in place of a file name, crm will read commands " +
                        "from the shell standard input (stdin).")
    parser.add_argument("-c", "--cib", dest="cib", metavar="CIB",
                        help="Start the session using the given shadow CIB file. " +
                        "Equivalent to `cib use <CIB>`.")
    parser.add_argument("-D", "--display", dest="display", metavar="OUTPUT_TYPE",
                        help="Choose one of the output options: plain, color-always, color, or uppercase. " +
                        "The default is color if the terminal emulation supports colors, " +
                        "else plain.")
    parser.add_argument("-F", "--force", action="store_true", default=False, dest="force",
                        help="Make crm proceed with applying changes where it would normally " +
                        "ask the user to confirm before proceeding. This option is mainly useful " +
                        "in scripts, and should be used with care.")
    parser.add_argument("-n", "--no", action="store_true", default=False, dest="ask_no",
                        help="Automatically answer no when prompted")
    parser.add_argument("-w", "--wait", action="store_true", default=False, dest="wait",
                        help="Make crm wait for the cluster transition to finish " +
                        "(for the changes to take effect) after each processed line.")
    parser.add_argument("-H", "--history", dest="history", metavar="DIR|FILE|SESSION",
                        help="A directory or file containing a cluster report to load " +
                        "into history, or the name of a previously saved history session.")
    parser.add_argument("-d", "--debug", action="store_true", default=False, dest="debug",
                        help="Print verbose debugging information.")
    parser.add_argument("-R", "--regression-tests", action="store_true", default=False,
                        dest="regression_tests",
                        help="Enables extra verbose trace logging used by the regression " +
                        "tests. Logs all external calls made by crmsh.")
    parser.add_argument("--scriptdir", dest="scriptdir", metavar="DIR",
                        help="Extra directory where crm looks for cluster scripts, or a list " +
                        "of directories separated by semi-colons (e.g. /dir1;/dir2;etc.).")
    parser.add_argument("-X", dest="profile", metavar="PROFILE",
                        help="Collect profiling data and save in PROFILE.")
    parser.add_argument("-o", "--opt", action="append", type=str, metavar="OPTION=VALUE",
                        help="Set crmsh option temporarily. If the options are saved using" +
                        "+options save+ then the value passed here will also be saved." +
                        "Multiple options can be set by using +-o+ multiple times.")
    parser.add_argument("SUBCOMMAND", nargs=REMAINDER)
    return parser


option_parser = make_option_parser()


def usage(rc):
    option_parser.print_usage(file=(sys.stderr if rc != 0 else sys.stdout))
    sys.exit(rc)


def set_interactive():
    '''Set the interactive option only if we're on a tty.'''
    if utils.can_ask():
        options.interactive = True


def add_quotes(args):
    '''
    Add quotes if there's whitespace in one of the
    arguments; so that the user doesn't need to protect the
    quotes.

    If there are two kinds of quotes which actually _survive_
    the getopt, then we're _probably_ screwed.

    At any rate, stuff like ... '..."..."'
    as well as '...\'...\''  do work.
    '''
    l = []
    for s in args:
        if config.core.add_quotes and ' ' in s:
            q = '"' in s and "'" or '"'
            if q not in s:
                s = "%s%s%s" % (q, s, q)
        l.append(s)
    return l


def handle_noninteractive_use(context, user_args):
    """
    returns: either a status code of 0 or 1, or
    None to indicate that nothing was done here.
    """
    if options.shadow:
        if not context.run("cib use " + options.shadow):
            return 1

    # this special case is silly, but we have to keep it to
    # preserve the backward compatibility
    if len(user_args) == 1 and user_args[0].startswith("conf"):
        if not context.run("configure"):
            return 1
    elif len(user_args) > 0:
        # we're not sure yet whether it's an interactive session or not
        # (single-shot commands aren't)
        logger_utils.reset_lineno()
        options.interactive = False

        l = add_quotes(user_args)
        if context.run(' '.join(l)):
            # if the user entered a level, then just continue
            if not context.previous_level():
                return 0
            set_interactive()
            if options.interactive:
                logger_utils.reset_lineno(-1)
        else:
            return 1
    return None


def render_prompt(context):
    rendered_prompt = constants.prompt
    if options.interactive and not options.batch:
        # TODO: fix how color interacts with readline,
        # seems the color prompt messes it up
        promptstr = "crm(%s/%s)%s# " % (cib_prompt(), utils.this_node(), context.prompt())
        constants.prompt = promptstr
        if clidisplay.colors_enabled():
            rendered_prompt = term.render(clidisplay.prompt(promptstr))
        else:
            rendered_prompt = promptstr
    return rendered_prompt


def setup_context(context):
    if options.input_file and options.input_file != "-":
        try:
            sys.stdin = open(options.input_file)
        except IOError as msg:
            logger.error(msg)
            usage(2)

    if options.interactive and not options.batch:
        context.setup_readline()


def main_input_loop(context, user_args):
    """
    Main input loop for crmsh. Parses input
    line by line.
    """
    rc = handle_noninteractive_use(context, user_args)
    if rc is not None:
        return rc

    setup_context(context)

    rc = 0
    while True:
        try:
            inp = utils.multi_input(render_prompt(context))
            if inp is None:
                if options.interactive:
                    rc = 0
                context.quit(rc)
            try:
                if not context.run(inp):
                    rc = 1
            except ValueError as msg:
                rc = 1
                logger.error(msg)
        except KeyboardInterrupt:
            if options.interactive and not options.batch:
                print("Ctrl-C, leaving")
            context.quit(1)
    return rc


def compgen():
    args = sys.argv[2:]
    if len(args) < 2:
        return

    options.shell_completion = True

    # point = int(args[0])
    line = args[1]

    # remove [*]crm from commandline
    idx = line.find('crm')
    if idx >= 0:
        line = line[idx+3:].lstrip()

    options.interactive = False
    ui = ui_root.Root()
    context = ui_context.Context(ui)
    last_word = line.rsplit(' ', 1)
    if len(last_word) > 1 and ':' in last_word[1]:
        idx = last_word[1].rfind(':')
        for w in context.complete(line):
            print(w[idx+1:])
    else:
        for w in context.complete(line):
            print(w)


def parse_options():
    opts, args = option_parser.parse_known_args()
    utils.check_space_option_value(opts)
    config.core.debug = "yes" if opts.debug else config.core.debug
    options.profile = opts.profile or options.profile
    options.regression_tests = opts.regression_tests or options.regression_tests
    config.color.style = opts.display or config.color.style
    config.core.force = opts.force or config.core.force
    if opts.filename:
        logger_utils.reset_lineno()
        options.input_file, options.batch, options.interactive = opts.filename, True, False
    options.history = opts.history or options.history
    config.core.wait = opts.wait or config.core.wait
    options.shadow = opts.cib or options.shadow
    options.scriptdir = opts.scriptdir or options.scriptdir
    options.ask_no = opts.ask_no
    for opt in opts.opt or []:
        try:
            k, v = opt.split('=')
            s, n = k.split('.')
            config.set_option(s, n, v)
        except ValueError as e:
            raise ValueError("Expected -o <section>.<name>=<value>: %s" % (e))
    return opts.SUBCOMMAND


def profile_run(context, user_args):
    import cProfile
    cProfile.runctx('main_input_loop(context, user_args)',
                    globals(),
                    {'context': context, 'user_args': user_args},
                    filename=options.profile)
    # print how to use the profile file, but don't disturb
    # the regression tests
    if not options.regression_tests:
        stats_cmd = "; ".join(['import pstats',
                               's = pstats.Stats("%s")' % options.profile,
                               's.sort_stats("cumulative").print_stats()'])
        print("python -c '%s' | less" % (stats_cmd))
    return 0


def run():
    try:
        if len(sys.argv) >= 2 and sys.argv[1] == '--compgen':
            compgen()
            return 0
        envsetup()
        userdir.mv_user_files()

        ui = ui_root.Root()
        context = ui_context.Context(ui)

        load_rc(context, userdir.RC_FILE)
        atexit.register(exit_handler)
        options.interactive = utils.can_ask()
        if not options.interactive:
            logger_utils.reset_lineno()
            options.batch = True
        user_args = parse_options()
        if config.core.debug:
            logger.debug(utils.debug_timestamp())
        term.init()
        if options.profile:
            return profile_run(context, user_args)
        else:
            return main_input_loop(context, user_args)
    except KeyboardInterrupt:
        if config.core.debug:
            raise
        else:
            print("Ctrl-C, leaving")
            sys.exit(1)
    except ValueError as e:
        if config.core.debug:
            import traceback
            traceback.print_exc()
            sys.stdout.flush()
        logger.error(str(e))
        sys.exit(1)

# vim:ts=4:sw=4:et:
