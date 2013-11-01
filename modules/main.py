# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#

import sys
import os
import shlex
import getopt
import atexit

from utils import wait4dc, is_pcmk_118, is_program
from userprefs import Options, UserPrefs
import vars
from msg import ErrorBuffer, syntax_err, skill_err
from msg import common_warn, common_info, common_debug, common_err
from clidisplay import CliDisplay
from term import TerminalController

import ui_tree
import ui_context


def load_rc(rcfile):
    try:
        f = open(rcfile)
    except:
        return
    save_stdin = sys.stdin
    sys.stdin = f
    while True:
        inp = multi_input()
        if inp == None:
            break
        try:
            parse_line(levels, shlex.split(inp))
        except ValueError, msg:
            common_err(msg)
    f.close()
    sys.stdin = save_stdin


def multi_input(prompt=''):
    """
    Get input from user
    Allow multiple lines using a continuation character
    """
    line = []
    while True:
        try:
            text = raw_input(prompt)
        except EOFError:
            return None
        err_buf.incr_lineno()
        if options.regression_tests:
            print ".INP:", text
            sys.stdout.flush()
            sys.stderr.flush()
        stripped = text.strip()
        if stripped.endswith('\\'):
            stripped = stripped.rstrip('\\')
            line.append(stripped)
            if prompt:
                prompt = '> '
        else:
            line.append(stripped)
            break
    return ''.join(line)


def check_args(args, argsdim):
    if not argsdim:
        return True
    if len(argsdim) == 1:
        minargs = argsdim[0]
        return len(args) >= minargs
    else:
        minargs, maxargs = argsdim
        return len(args) >= minargs and len(args) <= maxargs

#
# Note on parsing
#
# Parsing tables are python dictionaries.
#
# Keywords are used as keys and the corresponding values are
# lists (actually tuples, since they should be read-only) or
# classes. In the former case, the keyword is a terminal and
# in the latter, a new object for the class is created. The class
# must have the cmd_table variable.
#
# The list has the following content:
#
# function: a function to handle this command
# numargs_list: number of minimum/maximum arguments; for example,
#   (0, 1) means one optional argument, (1, 1) one required; if the
#   list is empty then the function will parse arguments itself
# required minimum skill level: operator, administrator, expert
#   (encoded as a small integer from 0 to 2)
# can the command cause transition to start (0 or 1)
#   used to check whether to wait4dc to end the transition
#


def show_usage(cmd):
    p = None
    try:
        p = cmd.__doc__
    except:
        pass
    if p:
        print >> sys.stderr, p
    else:
        syntax_err(cmd.__name__)


def exit_handler():
    '''
    Write the history file. Remove tmp files.
    '''
    if options.interactive and not options.batch:
        try:
            from readline import write_history_file
            write_history_file(vars.hist_file)
        except:
            pass
    for f in vars.tmpfiles:
        try:
            os.unlink(f)
        except OSError:
            pass


# prefer the user set PATH
def envsetup():
    mybinpath = os.path.dirname(sys.argv[0])
    for p in mybinpath, vars.crm_daemon_dir:
        if p not in os.environ["PATH"].split(':'):
            os.environ['PATH'] = "%s:%s" % (os.environ['PATH'], p)


# three modes: interactive (no args supplied), batch (input from
# a file), half-interactive (args supplied, but not batch)
def cib_prompt():
    if not vars.cib_in_use:
        return vars.live_cib_prompt
    if vars.tmp_cib:
        return vars.tmp_cib_prompt
    return vars.cib_in_use


def usage(rc):
    f = sys.stderr
    if rc == 0:
        f = sys.stdout
    print >> f, """
usage:
    crm [-D display_type] [-f file] [-c cib] [-H hist_src] [-hFRDw] [--version] [args]

    -f, --file='FILE'::
        Load commands from the given file. If the file is - then
        use terminal stdin.

    -c, --cib='CIB'::
        Start the session with the given shadow CIB file.
        Equivalent to cib use.

    -D, --display='OUTPUT_TYPE'::
        Choose one of the output options: plain, color, or
        uppercase. The default is color if the terminal emulation
        supports colors. Otherwise, plain is used.

    -F, --force::
        Make crm proceed with doing changes even though it would
        normally ask user to confirm some of them. Mostly useful in
        scripts.

    -w, --wait::
        Make crm wait for the cluster transition to finish (for the
        changes to take effect) after each processed line.

    -H, --history='DIR|FILE'::
        The history commands can examine either live cluster
        (default) or a report generated by hb_report. Use this
        option to specify a directory or file containing the report.

    -h, --help::
        Print help page.

    --version::
        Print Pacemaker version and build information (Mercurial Hg
        changeset hash).

    -R, --regression-tests::
        Run in the regression test mode. Used mainly by the
        regression testing suite.

    -d, --debug::
        Print some debug information. Used by developers. [Not yet
        refined enough to print useful information for other users.]

    Use crm without arguments for an interactive session.
    Supply one or more arguments for a "single-shot" use.
    Supply level name to start working at that level.
    Specify with -f a file which contains a script. Use '-' for
    standard input or use pipe/redirection.

    Examples:

        # crm -f stopapp2.txt
        # crm -w resource stop global_www
        # echo stop global_www | crm resource
        # crm configure property no-quorum-policy=ignore
        # crm ra info pengine
        # crm status

    See the crm(8) man page or the crm help system for more details.
    """
    sys.exit(rc)

user_prefs = UserPrefs.getInstance()
options = Options.getInstance()
err_buf = ErrorBuffer.getInstance()
#levels = Levels.getInstance()


def set_interactive():
    '''Set the interactive option only if we're on a tty.'''
    if sys.stdin.isatty():
        options.interactive = True


def xdg_file(name, xdg_name, obj_type, semantics):
    if not name or not xdg_name:
        return name
    chk_fun = obj_type == "f" and os.path.isfile or os.path.isdir
    dir = semantics == "config" and \
        vars.config_home or vars.cache_home
    if not os.path.isdir(dir):
        os.makedirs(dir, 0700)
    new = os.path.join(dir, xdg_name)
    if semantics == "config" and chk_fun(new) and chk_fun(name):
        common_warn("both %s and %s exist, please cleanup" % (name, new))
        return name
    if chk_fun(name):
        if semantics == "config":
            common_info("moving %s to %s" % (name, new))
        else:
            common_debug("moving %s to %s" % (name, new))
        os.rename(name, new)
    return new


def mv_user_files():
    vars.hist_file = xdg_file(vars.hist_file,
                              vars.xdg_map["history"], "f", "cache")
    vars.rc_file = xdg_file(vars.rc_file,
                            vars.xdg_map["rc"], "f", "config")
    vars.index_file = xdg_file(vars.index_file,
                               vars.xdg_map["help_index"], "f", "cache")
    vars.tmpl_conf_dir = xdg_file(vars.tmpl_conf_dir,
                                  vars.xdg_map["crmconf"], "d", "config")


def compatibility_setup():
    if is_pcmk_118():
        vars.node_type_opt = True
        vars.attr_defaults["node"] = {"type": "normal"}
        vars.cib_no_section_rc = 6


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
        if user_prefs.add_quotes and ' ' in s:
            q = '"' in s and "'" or '"'
            if not q in s:
                s = "%s%s%s" % (q, s, q)
        l.append(s)
    return l


def do_work(user_args):
    compatibility_setup()

    tree = ui_tree.Tree()
    context = ui_context.Context(tree)

    if options.shadow:
        if not context.run("cib use " + options.shadow):
            sys.exit(1)

    # this special case is silly, but we have to keep it to
    # preserve the backward compatibility
    if len(user_args) == 1 and user_args[0].startswith("conf"):
        if not context.run("configure"):
            sys.exit(1)
    elif len(user_args) > 0:
        err_buf.reset_lineno()
        # we're not sure yet whether it's an interactive session or not
        # (single-shot commands aren't)
        options.interactive = False

        l = add_quotes(user_args)
        if context.run(' '.join(l)):
            # if the user entered a level, then just continue
            if not context.previous_level():
                sys.exit(0)
        else:
            sys.exit(1)

    if options.file and options.file != "-":
        try:
            sys.stdin = open(options.file)
        except IOError, msg:
            common_err(msg)
            usage(2)

    if options.interactive and not options.batch:
        context.setup_readline()

    rc = 0
    while True:
        if options.interactive and not options.batch:
            termctrl = TerminalController.getInstance()
            cli_display = CliDisplay.getInstance()
            promptstr = "crm(%s)%s# " % (cib_prompt(), context.prompt())
            vars.prompt = termctrl.render(cli_display.prompt(promptstr))
        inp = multi_input(vars.prompt)
        if inp is None:
            if options.interactive:
                rc = 0
            context.quit(rc)
        try:
            if not context.run(inp):
                rc = 1
        except ValueError, msg:
            rc = 1
            common_err(msg)


def compgen():
    args = sys.argv[2:]
    if len(args) < 2:
        return

    #point = int(args[0])
    line = args[1]

    # remove crm from commandline
    line = line.split(' ', 1)
    if len(line) == 1:
        return
    line = line[1].lstrip()

    options.interactive = False
    tree = ui_tree.Tree()
    context = ui_context.Context(tree)
    for w in context.complete(line):
        print w


def run():
    if len(sys.argv) >= 2 and sys.argv[1] == '--compgen':
        compgen()
        return

    envsetup()

    mv_user_files()
    load_rc(vars.rc_file)

    atexit.register(exit_handler)

    if not sys.stdin.isatty():
        err_buf.reset_lineno()
        options.batch = True
    else:
        options.interactive = True

    try:
        opts, user_args = getopt.getopt(
            sys.argv[1:],
            'whdc:f:FX:RD:H:',
            ("wait", "version", "help", "debug",
             "cib=", "file=", "force", "profile=",
             "regression-tests", "display=", "history="))
        for o, p in opts:
            if o in ("-h", "--help"):
                usage(0)
            elif o in ("--version"):
                print >> sys.stdout, ("%s" % vars.crm_version)
                sys.exit(0)
            elif o == "-d":
                user_prefs.debug = "yes"
            elif o == "-X":
                options.profile = p
            elif o == "-R":
                options.regression_tests = True
            elif o in ("-D", "--display"):
                user_prefs.output = p
            elif o in ("-F", "--force"):
                user_prefs.force = "yes"
            elif o in ("-f", "--file"):
                options.batch = True
                options.interactive = False
                err_buf.reset_lineno()
                options.file = p
            elif o in ("-H", "--history"):
                options.history = p
            elif o in ("-w", "--wait"):
                user_prefs.wait = "yes"
            elif o in ("-c", "--cib"):
                options.shadow = p
    except getopt.GetoptError, msg:
        print msg
        usage(1)

    if options.profile:
        import cProfile
        cProfile.runctx('main.do_work(user_args)',
                        globals(),
                        {'user_args': user_args},
                        filename=options.profile)
        # print how to use the profile file, but don't disturb
        # the regression tests
        if not options.regression_tests:
            stats_cmd = "; ".join(['import pstats',
                                   's = pstats.Stats("%s")' % options.profile,
                                   's.sort_stats("cumulative").print_stats()'])
            print "python -c '%s' | less" % (stats_cmd)

    else:
        do_work(user_args)

# vim:ts=4:sw=4:et:
