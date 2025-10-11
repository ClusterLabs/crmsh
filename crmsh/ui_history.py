# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import os
import sys
import time
import re
import bz2
from functools import cache
from . import config
from . import command
from . import completers as compl
from . import utils
from . import ui_utils
from . import xmlutil
from . import options
from .cibconfig import mkset_obj, cib_factory
from .sh import ShellUtils
from . import history
from . import cmd_status
from . import log


logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)


ptest_options = ["@v+", "nograph", "scores", "actions", "utilization"]


@cache
def crm_report():
    return history.Report()


class History(command.UI):
    '''
    The history class
    '''
    name = "history"

    def __init__(self):
        command.UI.__init__(self)
        self.current_session = None
        self._source_inited = False

    def _init_source(self):
        if self._source_inited:
            return True
        self._source_inited = True
        return self._set_source(options.history)

    def _set_period(self, from_time='', to_time=''):
        '''
        parse time specs and set period
        '''
        from_dt = to_dt = None
        if from_time:
            from_dt = utils.parse_time(from_time)
            if not from_dt:
                return False
        if to_time:
            to_dt = utils.parse_time(to_time)
            if not to_dt:
                return False
        if to_dt and from_dt:
            if to_dt < from_dt:
                from_dt, to_dt = to_dt, from_dt
            elif to_dt == from_dt:
                logger.error("%s - %s: To and from dates cannot be the same", from_time, to_time)
                return False
        return crm_report().set_period(from_dt, to_dt)

    def _set_source(self, src, live_from_time=None):
        '''
        Have the last history source survive the History
        and Report instances
        '''
        def _check_source():
            return (src == 'live') or os.path.isfile(src) or os.path.isdir(src)

        logger.debug("setting source to %s", src)
        if not _check_source():
            if os.path.exists(crm_report().get_session_dir(src)):
                logger.debug("Interpreting %s as session", src)
                if crm_report().load_state(crm_report().get_session_dir(src)):
                    options.history = crm_report().get_source()
                    crm_report().prepare_source()
                    self.current_session = src
                    return True
            else:
                logger.error("source %s doesn't exist", src)
            return False
        crm_report().set_source(src)
        options.history = src
        self.current_session = None
        to_time = ''
        if src == "live":
            from_time = time.ctime(live_from_time and live_from_time or (time.time() - 60*60))
        else:
            from_time = ''
        return self._set_period(from_time, to_time)

    @command.skill_level('administrator')
    def do_source(self, context, src=None):
        "usage: source {<dir>|<file>|live}"
        if src is None:
            print("Current source: %s" % (options.history))
            return True
        self._init_source()
        if src != options.history:
            return self._set_source(src)

    @command.skill_level('administrator')
    @command.alias('timeframe')
    def do_limit(self, context, from_time='', to_time=''):
        "usage: limit [<from_time> [<to_time>]]"
        self._init_source()
        if options.history == "live" and not from_time:
            from_time = time.ctime(time.time() - 60*60)
        return self._set_period(from_time, to_time)

    @command.skill_level('administrator')
    def do_refresh(self, context, force=''):
        "usage: refresh"
        self._init_source()
        if force:
            if force != "force" and force != "--force":
                context.fatal_error("Expected 'force' or '--force' (was '%s')" % (force))
            force = True
        return crm_report().refresh_source(force)

    @command.skill_level('administrator')
    def do_detail(self, context, detail_lvl):
        "usage: detail <detail_level>"
        self._init_source()
        detail_num = utils.convert2ints(detail_lvl)
        if detail_num is None or detail_num not in (0, 1):
            context.fatal_error("Expected '0' or '1' (was '%s')" % (detail_lvl))
        return crm_report().set_detail(detail_lvl)

    @command.skill_level('administrator')
    @command.completers_repeating(compl.call(lambda: crm_report().node_list()))
    def do_setnodes(self, context, *args):
        "usage: setnodes <node> [<node> ...]"
        self._init_source()
        if options.history != "live":
            logger.info("setting nodes not necessary for existing reports, proceeding anyway")
        return crm_report().set_nodes(*args)

    @command.skill_level('administrator')
    def do_info(self, context):
        "usage: info"
        self._init_source()
        return crm_report().info()

    @command.skill_level('administrator')
    def do_latest(self, context):
        "usage: latest"
        self._init_source()
        if not utils.wait_dc_stable("transition", not options.batch):
            return False
        self._set_source("live")
        crm_report().refresh_source()
        f = self._get_pe_byidx(-1)
        if not f:
            return False
        crm_report().show_transition_log(f)

    @command.skill_level('administrator')
    @command.completers_repeating(compl.call(lambda: crm_report().rsc_list()))
    def do_resource(self, context, *args):
        "usage: resource <rsc> [<rsc> ...]"
        self._init_source()
        return crm_report().resource(*args)

    @command.skill_level('administrator')
    @command.wait
    @command.completers_repeating(compl.call(lambda: crm_report().node_list()))
    def do_node(self, context, *args):
        "usage: node <node> [<node> ...]"
        self._init_source()
        return crm_report().node(*args)

    @command.skill_level('administrator')
    @command.completers_repeating(compl.call(lambda: crm_report().node_list()))
    def do_log(self, context, *args):
        "usage: log [<node> ...]"
        self._init_source()
        return crm_report().show_log(*args)

    def ptest(self, nograph, scores, utilization, actions, verbosity):
        'Send a decompressed self.pe_file to ptest'
        try:
            bits = bz2.decompress(open(self.pe_file, "rb").read())
        except IOError as msg:
            logger.error("open: %s", msg)
            return False
        return utils.run_ptest(bits, nograph, scores, utilization, actions, verbosity)

    @command.skill_level('administrator')
    def do_events(self, context):
        "usage: events"
        self._init_source()
        return crm_report().events()

    @command.skill_level('administrator')
    @command.completers_repeating(compl.join(compl.call(lambda: crm_report().peinputs_list()),
                                             compl.choice(['v'])))
    def do_peinputs(self, context, *args):
        """usage: peinputs [{<range>|<number>} ...] [v]"""
        self._init_source()
        argl = list(args)
        opt_l = utils.fetch_opts(argl, ["v"])
        if argl:
            l = []
            for s in argl:
                a = utils.convert2ints(s.split(':'))
                if a and len(a) == 2 and not utils.check_range(a):
                    logger.error("%s: invalid peinputs range", a)
                    return False
                l += crm_report().pelist(a, verbose=("v" in opt_l))
        else:
            l = crm_report().pelist(verbose=("v" in opt_l))
        if not l:
            return False
        s = '\n'.join(l)
        utils.page_string(s)

    def _get_pe_byname(self, s):
        l = crm_report().find_pe_files(s)
        if len(l) == 0:
            logger.error("%s: path not found", s)
            return None
        elif len(l) > 1:
            logger.error("%s: path ambiguous", s)
            return None
        return l[0]

    def _get_pe_byidx(self, idx):
        l = crm_report().pelist()
        if len(l) < abs(idx):
            if idx == -1:
                logger.error("no transitions found in the source")
            else:
                logger.error("PE input file for index %d not found", (idx+1))
            return None
        return l[idx]

    def _get_pe_bynum(self, n):
        l = crm_report().pelist([n])
        if len(l) == 0:
            logger.error("PE file %d not found", n)
            return None
        elif len(l) > 1:
            logger.error("PE file %d ambiguous", n)
            return None
        return l[0]

    def _get_pe_input(self, pe_spec):
        '''Get PE input file from the <number>|<index>|<file>
        spec.'''
        if re.search('pe-', pe_spec):
            f = self._get_pe_byname(pe_spec)
        elif utils.is_int(pe_spec):
            n = int(pe_spec)
            if n <= 0:
                f = self._get_pe_byidx(n-1)
            else:
                f = self._get_pe_bynum(n)
        else:
            f = self._get_pe_byidx(-1)
        return f

    def _show_pe(self, f, opt_l):
        self.pe_file = f  # self.pe_file needed by self.ptest
        ui_utils.ptestlike(self.ptest, 'vv', "transition", opt_l)
        return crm_report().show_transition_log(f)

    def _display_dot(self, f):
        if not config.core.dotty:
            logger.error("install graphviz to draw transition graphs")
            return False
        f = crm_report().pe2dot(f)
        if not f:
            logger.error("dot file not found in the report")
            return False
        utils.show_dot_graph(f, keep_file=True, desc="configuration graph")
        return True

    def _pe2shadow(self, f, argl):
        try:
            name = argl[0]
        except:
            name = os.path.basename(f).replace(".bz2", "")
        logger.info("transition %s saved to shadow %s", f, name)
        return xmlutil.pe2shadow(f, name)

    @command.skill_level('administrator')
    def do_transitions(self, context):
        self._init_source()
        s = '\n'.join(crm_report().show_transitions())
        utils.page_string(s)

    @command.skill_level('administrator')
    @command.completers(compl.join(compl.call(lambda: crm_report().peinputs_list()),
                                   compl.choice(['log', 'showdot', 'save'])))
    def do_transition(self, context, *args):
        """usage: transition [<number>|<index>|<file>] [nograph] [v...] [scores] [actions] [utilization]
        transition showdot [<number>|<index>|<file>]
        transition log [<number>|<index>|<file>]
        transition save [<number>|<index>|<file> [name]]"""
        self._init_source()
        argl = list(args)
        subcmd = "show"
        if argl and argl[0] in ("showdot", "log", "save", "tags"):
            subcmd = argl[0]
            del argl[0]
        if subcmd == "show":
            opt_l = utils.fetch_opts(argl, ptest_options)
        if argl:
            f = self._get_pe_input(argl[0])
            del argl[0]
        else:
            f = self._get_pe_byidx(-1)
        if (subcmd == "save" and len(argl) > 1) or \
                (subcmd in ("show", "showdot", "log") and argl):
            logger_utils.syntax_err(args, context="transition")
            return False
        if not f:
            return False
        if subcmd == "show":
            logger.info("running ptest with %s", f)
            rc = self._show_pe(f, opt_l)
        elif subcmd == "showdot":
            rc = self._display_dot(f)
        elif subcmd == "save":
            rc = self._pe2shadow(f, argl)
        elif subcmd == "tags":
            tags = crm_report().get_transition_tags(f)
            rc = tags is not None
            if rc:
                print(' '.join(tags) if len(tags) else "No tags.")
        else:
            rc = crm_report().show_transition_log(f, True)
        return rc

    def _save_cib_env(self):
        try:
            self._cib_f_save = os.environ["CIB_file"]
        except:
            self._cib_f_save = None

    def _reset_cib_env(self):
        if self._cib_f_save:
            os.environ["CIB_file"] = self._cib_f_save
        else:
            try:
                del os.environ["CIB_file"]
            except:
                pass

    def _setup_cib_env(self, pe_f):
        '''Setup the CIB_file environment variable.
        Alternatively, we could (or should) use shadows, but the
        file/shadow management would be a bit involved.'''
        if pe_f != "live":
            os.environ["CIB_file"] = pe_f
        else:
            self._reset_cib_env()

    def _pe_config_obj(self, pe_f):
        '''Return set_obj of the configuration. It can later be
        rendered using the repr() method.'''
        self._setup_cib_env(pe_f)
        if not cib_factory.refresh():
            set_obj = mkset_obj("NOOBJ")
        else:
            set_obj = mkset_obj()
        return set_obj

    def _pe_config_noclr(self, pe_f):
        '''Configuration with no formatting (no colors).'''
        return self._pe_config_obj(pe_f).repr_nopretty()

    def _pe_config_plain(self, pe_f):
        '''Configuration with no formatting (but with colors).'''
        return self._pe_config_obj(pe_f).repr(format_mode=0)

    def _pe_config(self, pe_f):
        '''Formatted configuration.'''
        return self._pe_config_obj(pe_f).repr()

    def _pe_status(self, pe_f):
        '''Return status as a string.'''
        self._setup_cib_env(pe_f)
        rc, s = cmd_status.crm_mon()
        if rc != 0:
            if s:
                logger.error("crm_mon exited with code %d and said: %s", rc, s)
            else:
                logger.error("crm_mon exited with code %d", rc)
            return None
        return s

    def _pe_status_nohdr(self, pe_f):
        '''Return status (without header) as a string.'''
        self._setup_cib_env(pe_f)
        rc, s = cmd_status.crm_mon()
        if rc != 0:
            logger.error("crm_mon exited with code %d and said: %s", rc, s)
            return None
        l = s.split('\n')
        while l and l[0] != "":
            l = l[1:]
        while l and l[0] == "":
            l = l[1:]
        return '\n'.join(l)

    def _get_diff_pe_input(self, t):
        if t != "live":
            return self._get_pe_input(t)
        if not utils.get_dc():
            logger.error("cluster not running")
            return None
        return "live"

    def _render_pe(self, pe_fun, t):
        pe_f = self._get_diff_pe_input(t)
        if not pe_f:
            return None
        self._save_cib_env()
        s = pe_fun(pe_f)
        self._reset_cib_env()
        return s

    def _diff(self, pe_fun, t1, t2, html=False, wdiff=False):
        def _diff_impl(s1, s2, cmd):
            s = None
            f1 = utils.str2tmp(s1)
            f2 = utils.str2tmp(s2)
            try:
                if f1 and f2:
                    _, s = ShellUtils().get_stdout(cmd.format(f1=f1, f2=f2))
            finally:
                for f in (f1, f2):
                    try:
                        os.unlink(f)
                    except os.error:
                        pass
            return s

        def _diffhtml(s1, s2, t1, t2):
            import difflib
            return ''.join(difflib.HtmlDiff(tabsize=2, wrapcolumn=120).make_table(s1.split('\n'), s2.split('\n'), t1, t2)).replace('&nbsp;&nbsp;', '&nbsp;')

        s1 = self._render_pe(pe_fun, t1)
        s2 = self._render_pe(pe_fun, t2)
        if not s1 or not s2:
            return None
        if html:
            s = _diffhtml(s1, s2, t1, t2)
        elif wdiff:
            s = _diff_impl(s1, s2, "wdiff {f1} {f2}")
        else:
            s = _diff_impl(s1, s2, "diff -U 0 -d -b --label %s --label %s {f1} {f2}" % (t1, t2))
        return s

    def _common_pe_render_check(self, context, opt_l, *args):
        if context.previous_level_is("cibconfig") and cib_factory.has_cib_changed():
            logger.error("please try again after committing CIB changes")
            return False
        argl = list(args)
        supported_l = ["status"]
        if context.get_command_name() == "diff":
            supported_l.append("html")
        opt_l += utils.fetch_opts(argl, supported_l)
        if argl:
            logger_utils.syntax_err(' '.join(argl), context=context.get_command_name())
            return False
        return True

    @command.skill_level('administrator')
    @command.name('_dump')
    def do_dump(self, context, t, *args):
        '''dump configuration or status to a file and print file
        name.
        NB: The configuration is color rendered, but note that
        that depends on the current value of the TERM variable.
        '''
        self._init_source()
        opt_l = []
        if not self._common_pe_render_check(context, opt_l, *args):
            return False
        if "status" in opt_l:
            s = self._render_pe(self._pe_status_nohdr, t)
        else:
            s = utils.term_render(self._render_pe(self._pe_config_plain, t))
        if context.previous_level_is("cibconfig"):
            cib_factory.refresh()
        if not s:
            return False
        print(utils.str2tmp(s))

    @command.skill_level('administrator')
    @command.completers(compl.join(compl.call(lambda: crm_report().peinputs_list()),
                                   compl.choice(['live'])),
                        compl.choice(['status']))
    def do_show(self, context, t, *args):
        "usage: show <pe> [status]"
        self._init_source()
        opt_l = []
        if not self._common_pe_render_check(context, opt_l, *args):
            return False
        showfun = self._pe_config
        if "status" in opt_l:
            showfun = self._pe_status
        s = self._render_pe(showfun, t)
        if context.previous_level_is("cibconfig"):
            cib_factory.refresh()
        if not s:
            return False
        utils.page_string(s)

    @command.skill_level('administrator')
    @command.completers(compl.join(compl.call(lambda: crm_report().peinputs_list()),
                                   compl.choice(['live'])))
    def do_graph(self, context, t, *args):
        "usage: graph <pe> [<gtype> [<file> [<img_format>]]]"
        self._init_source()
        pe_f = self._get_diff_pe_input(t)
        if not pe_f:
            return False
        set_obj = self._pe_config_obj(pe_f)
        rc = set_obj.query_graph(*args)
        if rc is None:
            return False
        if context.previous_level_is("cibconfig"):
            cib_factory.refresh()
        return rc

    @command.skill_level('administrator')
    @command.completers(compl.join(compl.call(lambda: crm_report().peinputs_list()),
                                   compl.choice(['live'])),
                        compl.join(compl.call(lambda: crm_report().peinputs_list()),
                                   compl.choice(['live'])))
    def do_diff(self, context, t1, t2, *args):
        "usage: diff <pe> <pe> [status] [html]"
        self._init_source()
        opt_l = []
        if not self._common_pe_render_check(context, opt_l, *args):
            return False
        showfun = self._pe_config_plain
        mkhtml = "html" in opt_l
        if "status" in opt_l:
            showfun = self._pe_status_nohdr
        elif mkhtml:
            showfun = self._pe_config_noclr
        s = self._diff(showfun, t1, t2, html=mkhtml)
        if context.previous_level_is("cibconfig"):
            cib_factory.refresh()
        if s is None:
            return False
        if not mkhtml:
            utils.page_string(s)
        else:
            sys.stdout.writelines(s)

    @command.skill_level('administrator')
    @command.completers(compl.join(compl.call(lambda: crm_report().peinputs_list()),
                                   compl.choice(['live'])),
                        compl.join(compl.call(lambda: crm_report().peinputs_list()),
                                   compl.choice(['live'])))
    def do_wdiff(self, context, t1, t2, *args):
        "usage: wdiff <pe> <pe> [status]"
        self._init_source()
        opt_l = []
        if not self._common_pe_render_check(context, opt_l, *args):
            return False
        showfun = self._pe_config_plain
        if "status" in opt_l:
            showfun = self._pe_status_nohdr
        s = self._diff(showfun, t1, t2, wdiff=True)
        if context.previous_level_is("cibconfig"):
            cib_factory.refresh()
        if s is None:
            return False
        utils.page_string(s)

    @command.skill_level('administrator')
    @command.completers(compl.call(lambda: crm_report().session_subcmd_list()),
                        compl.call(lambda: crm_report().session_list()))
    def do_session(self, context, subcmd=None, name=None):
        "usage: session [{save|load|delete} <name> | pack [<name>] | update | list]"
        self._init_source()
        if not subcmd:
            print("current session: %s" % self.current_session)
            return True
        # verify arguments
        if subcmd not in ("save", "load", "pack", "delete", "list", "update"):
            logger.error("unknown history session subcmd: %s", subcmd)
            return False
        if name:
            if subcmd not in ("save", "load", "pack", "delete"):
                logger_utils.syntax_err(subcmd, context='session')
                return False
            if not utils.is_filename_sane(name):
                return False
        elif subcmd not in ("list", "update", "pack"):
            logger_utils.syntax_err(subcmd, context='session')
            return False
        elif subcmd in ("update", "pack") and not self.current_session:
            logger.error("need to load a history session before update/pack")
            return False
        # do work
        if not name:
            # some commands work on the existing session
            name = self.current_session
        rc = crm_report().manage_session(subcmd, name)
        # set source appropriately
        if rc and subcmd in ("save", "load"):
            options.history = crm_report().get_source()
            crm_report().prepare_source()
            self.current_session = name
        elif rc and subcmd == "delete":
            if name == self.current_session:
                logger.info("current history session deleted, setting source to live")
                self._set_source("live")
        return rc

    @command.skill_level('administrator')
    @command.completers(compl.choice(['clear']))
    def do_exclude(self, context, arg=None):
        "usage: exclude [<regex>|clear]"
        self._init_source()
        if not arg:
            return crm_report().manage_excludes("show")
        elif arg == "clear":
            return crm_report().manage_excludes("clear")
        return crm_report().manage_excludes("add", arg)

# vim:ts=4:sw=4:et:
