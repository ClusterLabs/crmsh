# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
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

import sys
import re
import os
import shlex
import time
import bz2

from help import HelpSystem, load_init_help_tab, add_static_help
from vars import Vars
from levels import Levels
from cibconfig import mkset_obj, CibFactory
from cibstatus import CibStatus
from report import Report
from template import LoadTemplate
from cliformat import nvpairs2list, cli_format
from rsctest import test_resources
from msg import common_error, common_err, common_info, common_debug, common_warn
from msg import syntax_err, bad_usage, no_prog_err
from msg import UserPrefs, Options, ErrorBuffer
import utils
from utils import vars
import ra
import glob
import xmlutil
import config


def cmd_end(cmd, dir=".."):
    "Go up one level."
    levels.droplevel()


def cmd_exit(cmd, rc=0):
    "Exit the crm program"
    cmd_end(cmd)
    if options.interactive and not options.batch:
        print "bye"
    sys.exit(rc)

ptest_options = ["@v+", "nograph", "scores", "actions", "utilization"]


def fetch_opts(args, opt_l):
    '''
    Get and remove option keywords from args.
    They are always listed last, at the end of the line.
    Return a list of options found. The caller can do
    if keyw in optlist: ...
    '''
    re_opt = None
    if opt_l[0].startswith("@"):
        re_opt = re.compile("^%s$" % opt_l[0][1:])
        del opt_l[0]
    l = []
    for i in reversed(range(len(args))):
        if (args[i] in opt_l) or \
            (re_opt and re_opt.search(args[i])):
            l.append(args.pop())
        else:
            break
    return l

lifetime_options = ["reboot", "forever"]


def fetch_lifetime_opt(args, iso8601=True):
    '''
    Get and remove a lifetime option from args. It can be one of
    lifetime_options or an ISO 8601 formatted period/time. There
    is apparently no good support in python for this format, so
    we cheat a bit.
    '''
    if not args:
        return None
    if iso8601:
        iso8601_re = re.compile("(PT?[0-9]|[0-9]+.*[:-])")
    else:
        iso8601_re = None
    if (args[-1] in lifetime_options) or \
            (iso8601_re and iso8601_re.match(args[-1])):
        return args.pop()
    else:
        return None


class UserInterface(object):
    '''
    Stuff common to all user interface classes.
    '''

    lvl_name = ""  # this is just a template
    global_cmd_aliases = {
        "quit": ("bye", "exit"),
        "end": ("cd", "up"),
        "help": ("?"),
    }

    def __init__(self):
        self.help_table = utils.odict()
        self.cmd_table = utils.odict()
        self.rev_alias_table = utils.odict()
        self.cmd_table["help"] = (self.help, (0, 1), 0, 0)
        self.cmd_table["quit"] = (self.exit, (0, 0), 0, 0)
        self.cmd_table["end"] = (self.end, (0, 1), 0, 0)
        self.cmd_aliases = self.global_cmd_aliases.copy()
        if options.interactive:
            self.help_table = help_sys.load_level(self.lvl_name)
        self.topics = []

    def myname(self):
        '''Just return some id.'''
        return self.lvl_name

    def end_game(self, no_questions_asked=False):
        pass

    def should_wait(self):
        '''
        A kludge to allow in-transit configuration changes to
        make us wait on transition to finish. Needs to be
        implemented in the level (currently, just configure).
        '''
        return False

    def help(self, cmd, topic=''):
        "usage: help [<command>|<Topic>|topics]"
        if topic in ("?", "Help", "HELP", "HELP!"):
            topic = "help"
        if topic == "topics" or (topic and topic[0].isupper()):
            if not self.topics:
                self.topics = help_sys.load_topics()
            help_tab = self.topics
        else:
            if not self.help_table:
                self.help_table = help_sys.load_level(self.lvl_name)
            utils.setup_help_aliases(self)
            help_tab = self.help_table
        return help_sys.cmd_help(help_tab, topic)

    def end(self, cmd, dir=".."):
        "usage: end"
        self.end_game()
        cmd_end(cmd, dir)

    def exit(self, cmd):
        "usage: exit"
        self.end_game()
        cmd_exit(cmd)


class CliOptions(UserInterface):
    '''
    Manage user preferences
    '''
    lvl_name = "options"

    def __init__(self):
        UserInterface.__init__(self)
        self.cmd_table["skill-level"] = (self.set_skill_level, (1, 1), 0, 0)
        self.cmd_table["editor"] = (self.set_editor, (1, 1), 0, 0)
        self.cmd_table["pager"] = (self.set_pager, (1, 1), 0, 0)
        self.cmd_table["user"] = (self.set_crm_user, (0, 1), 0, 0)
        self.cmd_table["output"] = (self.set_output, (1, 1), 0, 0)
        self.cmd_table["colorscheme"] = (self.set_colors, (1, 1), 0, 0)
        self.cmd_table["check-frequency"] = (self.set_check_frequency, (1, 1), 0, 0)
        self.cmd_table["check-mode"] = (self.set_check_mode, (1, 1), 0, 0)
        self.cmd_table["sort-elements"] = (self.set_sort_elements, (1, 1), 0, 0)
        self.cmd_table["wait"] = (self.set_wait, (1, 1), 0, 0)
        self.cmd_table["add-quotes"] = (self.set_add_quotes, (1, 1), 0, 0)
        self.cmd_table["manage-children"] = (self.set_manage_children, (1, 1), 0, 0)
        self.cmd_table["save"] = (self.save_options, (0, 0), 0, 0)
        self.cmd_table["show"] = (self.show_options, (0, 0), 0, 0)
        self.cmd_table["reset"] = (self.reset_options, (0, 0), 0, 0)
        utils.setup_aliases(self)

    def set_skill_level(self, cmd, skill_level):
        """usage: skill-level <level>
        level: operator | administrator | expert"""
        return user_prefs.set_pref("skill-level", skill_level)

    def set_editor(self, cmd, prog):
        "usage: editor <program>"
        return user_prefs.set_pref("editor", prog)

    def set_pager(self, cmd, prog):
        "usage: pager <program>"
        return user_prefs.set_pref("pager", prog)

    def set_crm_user(self, cmd, user=''):
        "usage: user [<crm_user>]"
        return user_prefs.set_pref("user", user)

    def set_output(self, cmd, otypes):
        "usage: output <type>"
        return user_prefs.set_pref("output", otypes)

    def set_colors(self, cmd, scheme):
        "usage: colorscheme <colors>"
        return user_prefs.set_pref("colorscheme", scheme)

    def set_check_frequency(self, cmd, freq):
        "usage: check-frequency <freq>"
        return user_prefs.set_pref("check-frequency", freq)

    def set_check_mode(self, cmd, mode):
        "usage: check-mode <mode>"
        return user_prefs.set_pref("check-mode", mode)

    def set_sort_elements(self, cmd, opt):
        "usage: sort-elements {yes|no}"
        return user_prefs.set_pref("sort-elements", opt)

    def set_wait(self, cmd, opt):
        "usage: wait {yes|no}"
        return user_prefs.set_pref("wait", opt)

    def set_add_quotes(self, cmd, opt):
        "usage: add-quotes {yes|no}"
        return user_prefs.set_pref("add-quotes", opt)

    def set_manage_children(self, cmd, opt):
        "usage: manage-children <option>"
        return user_prefs.set_pref("manage-children", opt)

    def show_options(self, cmd):
        "usage: show"
        return user_prefs.write_rc(sys.stdout)

    def save_options(self, cmd):
        "usage: save"
        return user_prefs.save_options(vars.rc_file)

    def reset_options(self, cmd):
        "usage: reset"
        return user_prefs.reset_options()

    def end_game(self, no_questions_asked=False):
        if no_questions_asked and not options.interactive:
            self.save_options("save")


class CibShadow(UserInterface):
    '''
    CIB shadow management class
    '''
    lvl_name = "cib"
    extcmd = ">/dev/null </dev/null crm_shadow"
    extcmd_stdout = "</dev/null crm_shadow"

    def __init__(self):
        UserInterface.__init__(self)
        self.cmd_table["new"] = (self.new, (1, 3), 1, 0)
        self.cmd_table["delete"] = (self.delete, (1, 1), 1, 0)
        self.cmd_table["reset"] = (self.reset, (1, 1), 1, 0)
        self.cmd_table["commit"] = (self.commit, (1, 1), 1, 1)
        self.cmd_table["use"] = (self.use, (0, 2), 1, 0)
        self.cmd_table["diff"] = (self.diff, (0, 0), 1, 0)
        self.cmd_table["list"] = (self.list, (0, 0), 1, 0)
        self.cmd_table["import"] = (self.pe_import, (1, 2), 1, 0)
        self.cmd_table["cibstatus"] = StatusMgmt
        self.chkcmd()
        utils.setup_aliases(self)

    def chkcmd(self):
        try:
            utils.ext_cmd("%s 2>&1" % self.extcmd)
        except os.error:
            no_prog_err(self.extcmd)
            return False
        return True

    def new(self, cmd, name, *args):
        "usage: new <shadow_cib> [withstatus] [force] [empty]"
        if not utils.is_filename_sane(name):
            return False
        for par in args:
            if not par in ("force", "--force", "withstatus", "empty"):
                syntax_err((cmd, name, par), context='new')
                return False
        if "empty" in args:
            new_cmd = "%s -e '%s'" % (self.extcmd, name)
        else:
            new_cmd = "%s -c '%s'" % (self.extcmd, name)
        if user_prefs.force or "force" in args or "--force" in args:
            new_cmd = "%s --force" % new_cmd
        if utils.ext_cmd(new_cmd) == 0:
            common_info("%s shadow CIB created" % name)
            self.use("use", name)
            if "withstatus" in args:
                cib_status.load("shadow:%s" % name)

    def _find_pe(self, infile):
        'Find a pe input'
        for p in ("%s/%s", "%s/%s.bz2", "%s/pe-*-%s.bz2"):
            fl = glob.glob(p % (vars.pe_dir, infile))
            if fl:
                break
        if not fl:
            common_err("no %s pe input file" % infile)
            return ''
        if len(fl) > 1:
            common_err("more than one %s pe input file: %s" %
                       (infile, ' '.join(fl)))
            return ''
        return fl[0]

    def pe_import(self, cmd, infile, name=None):
        "usage: import {<file>|<number>} [<shadow>]"
        if name and not utils.is_filename_sane(name):
            return False
        # where's the input?
        if not os.access(infile, os.F_OK):
            if "/" in infile:
                common_err("%s: no such file" % infile)
                return False
            infile = self._find_pe(infile)
            if not infile:
                return False
        if not name:
            name = os.path.basename(infile).replace(".bz2", "")
        if not xmlutil.pe2shadow(infile, name):
            return False
        # use the shadow and load the status from there
        return self.use("use", name, "withstatus")

    def delete(self, cmd, name):
        "usage: delete <shadow_cib>"
        if not utils.is_filename_sane(name):
            return False
        if vars.cib_in_use == name:
            common_err("%s shadow CIB is in use" % name)
            return False
        if utils.ext_cmd("%s -D '%s' --force" % (self.extcmd, name)) == 0:
            common_info("%s shadow CIB deleted" % name)
        else:
            common_err("failed to delete %s shadow CIB" % name)
            return False

    def reset(self, cmd, name):
        "usage: reset <shadow_cib>"
        if not utils.is_filename_sane(name):
            return False
        if utils.ext_cmd("%s -r '%s'" % (self.extcmd, name)) == 0:
            common_info("copied live CIB to %s" % name)
        else:
            common_err("failed to copy live CIB to %s" % name)
            return False

    def commit(self, cmd, name):
        "usage: commit <shadow_cib>"
        if not utils.is_filename_sane(name):
            return False
        if utils.ext_cmd("%s -C '%s' --force" % (self.extcmd, name)) == 0:
            common_info("committed '%s' shadow CIB to the cluster" % name)
        else:
            common_err("failed to commit the %s shadow CIB" % name)
            return False
        return True

    def diff(self, cmd):
        "usage: diff"
        rc, s = utils.get_stdout(utils.add_sudo("%s -d" % self.extcmd_stdout))
        utils.page_string(s)

    def list(self, cmd):
        "usage: list"
        if options.regression_tests:
            for t in xmlutil.listshadows():
                print t
        else:
            utils.multicolumn(xmlutil.listshadows())

    def _use(self, name, withstatus):
        # Choose a shadow cib for further changes. If the name
        # provided is empty, then choose the live (cluster) cib.
        # Don't allow ' in shadow names
        if not name or name == "live":
            os.unsetenv(vars.shadow_envvar)
            vars.cib_in_use = ""
            if withstatus:
                cib_status.load("live")
        else:
            os.putenv(vars.shadow_envvar, name)
            vars.cib_in_use = name
            if withstatus:
                cib_status.load("shadow:%s" % name)

    def use(self, cmd, name='', withstatus=''):
        "usage: use [<shadow_cib>] [withstatus]"
        # check the name argument
        if name and not utils.is_filename_sane(name):
            return False
        if name and name != "live":
            if not os.access(xmlutil.shadowfile(name), os.F_OK):
                common_err("%s: no such shadow CIB" % name)
                return False
        if withstatus and withstatus != "withstatus":
            syntax_err((cmd, withstatus), context='use')
            return False
        # If invoked from configure
        # take special precautions
        try:
            prev_level = levels.previous().myname()
        except:
            prev_level = ''
        if prev_level != "cibconfig":
            self._use(name, withstatus)
            return True
        if not cib_factory.has_cib_changed():
            self._use(name, withstatus)
            # new CIB: refresh the CIB factory
            cib_factory.refresh()
            return True
        saved_cib = vars.cib_in_use
        self._use(name, '')  # don't load the status yet
        if not cib_factory.is_current_cib_equal(silent=True):
            # user made changes and now wants to switch to a
            # different and unequal CIB; we refuse to cooperate
            common_err("the requested CIB is different from the current one")
            if user_prefs.force:
                common_info("CIB overwrite forced")
            elif not utils.ask("All changes will be dropped. Do you want to proceed?"):
                self._use(saved_cib, '')  # revert to the previous CIB
                return False
        self._use(name, withstatus)  # now load the status too
        return True


def check_transition(inp, state, possible_l):
    if not state in possible_l:
        common_err("input (%s) in wrong state %s" % (inp, state))
        return False
    return True


class Template(UserInterface):
    '''
    Configuration templates.
    '''
    lvl_name = "template"

    def __init__(self):
        UserInterface.__init__(self)
        self.cmd_table["new"] = (self.new, (2,), 1, 0)
        self.cmd_table["load"] = (self.load, (0, 1), 1, 0)
        self.cmd_table["edit"] = (self.edit, (0, 1), 1, 0)
        self.cmd_table["delete"] = (self.delete, (1, 2), 1, 0)
        self.cmd_table["show"] = (self.show, (0, 1), 0, 0)
        self.cmd_table["apply"] = (self.apply, (0, 2), 1, 0)
        self.cmd_table["list"] = (self.list, (0, 1), 0, 0)
        utils.setup_aliases(self)
        self.init_dir()
        self.curr_conf = ''

    def init_dir(self):
        '''Create the conf directory, link to templates'''
        if not os.path.isdir(vars.tmpl_conf_dir):
            try:
                os.makedirs(vars.tmpl_conf_dir)
            except os.error, msg:
                common_err("makedirs: %s" % msg)
                return

    def get_depends(self, tmpl):
        '''return a list of required templates'''
        # Not used. May need it later.
        try:
            tf = open("%s/%s" % (vars.tmpl_dir, tmpl), "r")
        except IOError, msg:
            common_err("open: %s" % msg)
            return
        l = []
        for s in tf:
            a = s.split()
            if len(a) >= 2 and a[0] == '%depends_on':
                l += a[1:]
        tf.close()
        return l

    def replace_params(self, s, user_data):
        change = False
        for i in range(len(s)):
            word = s[i]
            for p in user_data:
                # is parameter in the word?
                pos = word.find('%' + p)
                if pos < 0:
                    continue
                endpos = pos + len('%' + p)
                # and it isn't part of another word?
                if re.match("[A-Za-z0-9]", word[endpos:endpos+1]):
                    continue
                # if the value contains a space or
                # it is a value of an attribute
                # put quotes around it
                if user_data[p].find(' ') >= 0 or word[pos-1:pos] == '=':
                    v = '"' + user_data[p] + '"'
                else:
                    v = user_data[p]
                word = word.replace('%' + p, v)
                change = True  # we did replace something
            if change:
                s[i] = word
        if 'opt' in s:
            if not change:
                s = []
            else:
                s.remove('opt')
        return s

    def generate(self, l, user_data):
        '''replace parameters (user_data) and generate output
        '''
        l2 = []
        for piece in l:
            piece2 = []
            for s in piece:
                s = self.replace_params(s, user_data)
                if s:
                    piece2.append(' '.join(s))
            if piece2:
                l2.append(cli_format(piece2, 1))
        return '\n'.join(l2)

    def process(self, config=''):
        '''Create a cli configuration from the current config'''
        try:
            f = open("%s/%s" % (vars.tmpl_conf_dir, config or self.curr_conf), 'r')
        except IOError, msg:
            common_err("open: %s" % msg)
            return ''
        l = []
        piece = []
        user_data = {}
        # states
        START = 0
        PFX = 1
        DATA = 2
        GENERATE = 3
        state = START
        err_buf.start_tmp_lineno()
        rc = True
        for inp in f:
            err_buf.incr_lineno()
            if inp.startswith('#'):
                continue
            if type(inp) == type(u''):
                inp = inp.encode('ascii')
            inp = inp.strip()
            try:
                s = shlex.split(inp)
            except ValueError, msg:
                common_err(msg)
                continue
            while '\n' in s:
                s.remove('\n')
            if not s:
                if state == GENERATE and piece:
                    l.append(piece)
                    piece = []
            elif s[0] in ("%name", "%depends_on", "%suggests"):
                continue
            elif s[0] == "%pfx":
                if check_transition(inp, state, (START, DATA)) and len(s) == 2:
                    pfx = s[1]
                    state = PFX
            elif s[0] == "%required":
                if check_transition(inp, state, (PFX,)):
                    state = DATA
                    data_reqd = True
            elif s[0] == "%optional":
                if check_transition(inp, state, (PFX, DATA)):
                    state = DATA
                    data_reqd = False
            elif s[0] == "%%":
                if state != DATA:
                    common_warn("user data in wrong state %s" % state)
                if len(s) < 2:
                    common_warn("parameter name missing")
                elif len(s) == 2:
                    if data_reqd:
                        common_err("required parameter %s not set" % s[1])
                        rc = False
                elif len(s) == 3:
                    user_data["%s:%s" % (pfx, s[1])] = s[2]
                else:
                    common_err("%s: syntax error" % inp)
            elif s[0] == "%generate":
                if check_transition(inp, state, (DATA,)):
                    state = GENERATE
                    piece = []
            elif state == GENERATE:
                if s:
                    piece.append(s)
            else:
                common_err("<%s> unexpected" % inp)
        if piece:
            l.append(piece)
        err_buf.stop_tmp_lineno()
        f.close()
        if not rc:
            return ''
        return self.generate(l, user_data)
    def new(self, cmd, name, *args):
        "usage: new <config> <template> [<template> ...] [params name=value ...]"
        if not utils.is_filename_sane(name):
            return False
        if os.path.isfile("%s/%s" % (vars.tmpl_conf_dir, name)):
            common_err("config %s exists; delete it first" % name)
            return False
        lt = LoadTemplate(name)
        rc = True
        mode = 0
        params = {}
        for s in args:
            if mode == 0 and s == "params":
                params["id"] = name
                mode = 1
            elif mode == 1:
                a = s.split('=')
                if len(a) != 2:
                    syntax_err(args, context='new')
                    rc = False
                else:
                    params[a[0]] = a[1]
            elif not lt.load_template(s):
                rc = False
        if rc:
            lt.post_process(params)
        if not rc or not lt.write_config(name):
            return False
        self.curr_conf = name

    def config_exists(self, name):
        if not utils.is_filename_sane(name):
            return False
        if not os.path.isfile("%s/%s" % (vars.tmpl_conf_dir, name)):
            common_err("%s: no such config" % name)
            return False
        return True

    def delete(self, cmd, name, force=''):
        "usage: delete <config> [force]"
        if force:
            if force != "force" and force != "--force":
                syntax_err((cmd, force), context='delete')
                return False
        if not self.config_exists(name):
            return False
        if name == self.curr_conf:
            if not force and not user_prefs.force and \
                    not utils.ask("Do you really want to remove config %s which is in use?" % self.curr_conf):
                return False
            else:
                self.curr_conf = ''
        os.remove("%s/%s" % (vars.tmpl_conf_dir, name))

    def load(self, cmd, name=''):
        "usage: load [<config>]"
        if not name:
            self.curr_conf = ''
            return True
        if not self.config_exists(name):
            return False
        self.curr_conf = name

    def edit(self, cmd, name=''):
        "usage: edit [<config>]"
        if not name and not self.curr_conf:
            common_err("please load a config first")
            return False
        if name:
            if not self.config_exists(name):
                return False
            utils.edit_file("%s/%s" % (vars.tmpl_conf_dir, name))
        else:
            utils.edit_file("%s/%s" % (vars.tmpl_conf_dir, self.curr_conf))

    def show(self, cmd, name=''):
        "usage: show [<config>]"
        if not name and not self.curr_conf:
            common_err("please load a config first")
            return False
        if name:
            if not self.config_exists(name):
                return False
            print self.process(name)
        else:
            print self.process()

    def apply(self, cmd, *args):
        "usage: apply [<method>] [<config>]"
        method = "replace"
        name = ''
        if len(args) > 0:
            i = 0
            if args[0] in ("replace", "update"):
                method = args[0]
                i += 1
            if len(args) > i:
                name = args[i]
        if not name and not self.curr_conf:
            common_err("please load a config first")
            return False
        if name:
            if not self.config_exists(name):
                return False
            s = self.process(name)
        else:
            s = self.process()
        if not s:
            return False
        tmp = utils.str2tmp(s)
        if not tmp:
            return False
        if method == "replace":
            if options.interactive and cib_factory.has_cib_changed():
                if not utils.ask("This operation will erase all changes. Do you want to proceed?"):
                    return False
            cib_factory.erase()
        set_obj = mkset_obj()
        rc = set_obj.import_file(method, tmp)
        try:
            os.unlink(tmp)
        except:
            pass
        return rc

    def list(self, cmd, templates=''):
        "usage: list [templates]"
        if templates == "templates":
            utils.multicolumn(utils.listtemplates())
        else:
            utils.multicolumn(utils.listconfigs())


def manage_attr(cmd, attr_ext_commands, *args):
    if len(args) < 3:
        bad_usage(cmd, ' '.join(args))
        return False
    attr_cmd = None
    try:
        attr_cmd = attr_ext_commands[args[1]]
    except KeyError:
        bad_usage(cmd, ' '.join(args))
        return False
    if not attr_cmd:
        bad_usage(cmd, ' '.join(args))
        return False
    if args[1] == 'set':
        if len(args) == 4:
            if not utils.is_name_sane(args[0]) \
                    or not utils.is_name_sane(args[2]) \
                    or not utils.is_value_sane(args[3]):
                return False
            return utils.ext_cmd(attr_cmd % (args[0], args[2], args[3])) == 0
        else:
            bad_usage(cmd, ' '.join(args))
            return False
    elif args[1] in ('delete', 'show') or \
            (cmd == "secret" and args[1] in ('stash', 'unstash', 'check')):
        if len(args) == 3:
            if not utils.is_name_sane(args[0]) \
                    or not utils.is_name_sane(args[2]):
                return False
            return utils.ext_cmd(attr_cmd % (args[0], args[2])) == 0
        else:
            bad_usage(cmd, ' '.join(args))
            return False
    else:
        bad_usage(cmd, ' '.join(args))
        return False


def rm_meta_attribute(node, attr, l, force_children=False):
    '''
    Build a list of nvpair nodes which contain attribute
    (recursively in all children resources)
    '''
    for c in node.iterchildren():
        if c.tag == "meta_attributes":
            nvpair = xmlutil.get_attr_in_set(c, attr)
            if nvpair is not None:
                l.append(nvpair)
        elif force_children or \
                (xmlutil.is_child_rsc(c) and not c.getparent().tag == "group"):
            rm_meta_attribute(c, attr, l, force_children=force_children)


def get_children_with_different_attr(node, attr, value):
    l = []
    for p in node.xpath(".//primitive"):
        diff_attr = False
        for meta_set in xmlutil.get_set_nodes(p, "meta_attributes", 0):
            p_value = xmlutil.get_attr_value(meta_set, attr)
            if p_value != None and p_value != value:
                diff_attr = True
                break
        if diff_attr:
            l.append(p)
    return l


def set_deep_meta_attr_node(target_node, attr, value):
    nvpair_l = []
    if xmlutil.is_clone(target_node):
        for c in target_node.iterchildren():
            if xmlutil.is_child_rsc(c):
                rm_meta_attribute(c, attr, nvpair_l)
    if user_prefs.manage_children != "never" and \
            (xmlutil.is_group(target_node) or
             (xmlutil.is_clone(target_node) and xmlutil.cloned_el(target_node) == "group")):
        odd_children = get_children_with_different_attr(target_node, attr, value)
        for c in odd_children:
            if user_prefs.manage_children == "always" or \
                    (user_prefs.manage_children == "ask" and
                     utils.ask("Do you want to override %s for child resource %s?" %
                               (attr, c.get("id")))):
                common_debug("force remove meta attr %s from %s" %
                             (attr, c.get("id")))
                rm_meta_attribute(c, attr, nvpair_l, force_children=True)
    xmlutil.rmnodes(list(set(nvpair_l)))
    xmlutil.xml_processnodes(target_node,
                             xmlutil.is_emptynvpairs, xmlutil.rmnodes)

    # work around issue with pcs interoperability
    # by finding exising nvpairs -- if there are any, just
    # set the value in those. Otherwise fall back to adding
    # to all meta_attributes tags
    nvpairs = target_node.xpath("./meta_attributes/nvpair[@name='%s']" % (attr))
    if len(nvpairs) > 0:
        for nvpair in nvpairs:
            nvpair.set("value", value)
    else:
        for n in xmlutil.get_set_nodes(target_node, "meta_attributes", create=True):
            xmlutil.set_attr(n, attr, value)
    return True


def set_deep_meta_attr(rsc, attr, value, commit=True):
    """
    If the referenced rsc is a primitive that belongs to a group,
    then set its attribute.
    Otherwise, go up to the topmost resource which contains this
    resource and set the attribute there (i.e. if the resource is
    cloned).
    If it's a group then check its children. If any of them has
    the attribute set to a value different from the one given,
    then ask the user whether to reset them or not (exact
    behaviour depends on the value of config.core.manage_children).
    """

    def update_obj(obj):
        """
        set the meta attribute in the given object
        """
        node = obj.node
        obj.updated = True
        obj.propagate_updated()
        if not (node.tag == "primitive" and
                node.getparent().tag == "group"):
            node = xmlutil.get_topmost_rsc(node)
        return set_deep_meta_attr_node(node, attr, value)

    def flatten(objs):
        for obj in objs:
            if isinstance(obj, list):
                for subobj in obj:
                    yield subobj
            else:
                yield obj

    def resolve(obj):
        if obj.obj_type == 'tag':
            ret = [cib_factory.find_object(o) for o in obj.node.xpath('./obj_ref/@id')]
            ret = [r for r in ret if r is not None]
            return ret
        return obj

    def is_resource(obj):
        return xmlutil.is_resource(obj.node)

    objs = cib_factory.find_objects(rsc)
    if objs is None:
        common_error("CIB is not valid!")
        return False
    while any(obj for obj in objs if obj.obj_type == 'tag'):
        objs = list(flatten(resolve(obj) for obj in objs))
    objs = filter(is_resource, objs)
    common_debug("set_deep_meta_attr: %s" % (', '.join([obj.obj_id for obj in objs])))
    if not objs:
        common_error("Resource not found: %s" % (rsc))
        return False

    ok = all(update_obj(obj) for obj in objs)
    if not ok:
        common_error("Failed to update meta attributes for %s" % (rsc))
        return False

    if not commit:
        return True

    ok = cib_factory.commit()
    if not ok:
        common_error("Failed to commit updates to %s" % (rsc))
        return False
    return True


def cleanup_resource(rsc, node=''):
    if not utils.is_name_sane(rsc) or not utils.is_name_sane(node):
        return False
    if not node:
        rc = utils.ext_cmd(RscMgmt.rsc_cleanup_all % (rsc)) == 0
    else:
        rc = utils.ext_cmd(RscMgmt.rsc_cleanup % (rsc, node)) == 0
    return rc


class RscMgmt(UserInterface):
    '''
    Resources management class
    '''
    lvl_name = "resource"
    rsc_status_all = "crm_resource -L"
    rsc_status = "crm_resource -W -r '%s'"
    rsc_showxml = "crm_resource -q -r '%s'"
    rsc_setrole = "crm_resource --meta -r '%s' -p target-role -v '%s'"
    rsc_migrate = "crm_resource -M -r '%s' %s"
    rsc_unmigrate = "crm_resource -U -r '%s'"
    rsc_cleanup = "crm_resource -C -r '%s' -H '%s'"
    rsc_cleanup_all = "crm_resource -C -r '%s'"
    rsc_param = {
        'set': "crm_resource -r '%s' -p '%s' -v '%s'",
        'delete': "crm_resource -r '%s' -d '%s'",
        'show': "crm_resource -r '%s' -g '%s'",
    }
    rsc_meta = {
        'set': "crm_resource --meta -r '%s' -p '%s' -v '%s'",
        'delete': "crm_resource --meta -r '%s' -d '%s'",
        'show': "crm_resource --meta -r '%s' -g '%s'",
    }
    rsc_failcount = {
        'set': "crm_attribute -t status -n 'fail-count-%s' -N '%s' -v '%s' -d 0",
        'delete': "crm_attribute -t status -n 'fail-count-%s' -N '%s' -D -d 0",
        'show': "crm_attribute -t status -n 'fail-count-%s' -N '%s' -G -d 0",
    }
    rsc_utilization = {
        'set': "crm_resource -z -r '%s' -p '%s' -v '%s'",
        'delete': "crm_resource -z -r '%s' -d '%s'",
        'show': "crm_resource -z -r '%s' -g '%s'",
    }
    rsc_secret = {
        'set': "cibsecret set '%s' '%s' '%s'",
        'stash': "cibsecret stash '%s' '%s'",
        'unstash': "cibsecret unstash '%s' '%s'",
        'delete': "cibsecret delete '%s' '%s'",
        'show': "cibsecret get '%s' '%s'",
        'check': "cibsecret check '%s' '%s'",
    }
    rsc_refresh = "crm_resource -R"
    rsc_refresh_node = "crm_resource -R -H '%s'"
    rsc_reprobe = "crm_resource -P"
    rsc_reprobe_node = "crm_resource -P -H '%s'"

    def __init__(self):
        UserInterface.__init__(self)
        self.cmd_table["status"] = (self.status, (0, 1), 0, 0)
        self.cmd_table["start"] = (self.start, (1, 1), 0, 1)
        self.cmd_table["stop"] = (self.stop, (1, 1), 0, 1)
        self.cmd_table["restart"] = (self.restart, (1, 1), 0, 1)
        self.cmd_table["promote"] = (self.promote, (1, 1), 0, 1)
        self.cmd_table["demote"] = (self.demote, (1, 1), 0, 1)
        self.cmd_table["manage"] = (self.manage, (1, 1), 0, 0)
        self.cmd_table["unmanage"] = (self.unmanage, (1, 1), 0, 0)
        self.cmd_table["migrate"] = (self.migrate, (1, 4), 0, 1)
        self.cmd_table["unmigrate"] = (self.unmigrate, (1, 1), 0, 1)
        self.cmd_table["param"] = (self.param, (3, 4), 1, 1)
        self.cmd_table["secret"] = (self.secret, (3, 4), 1, 1)
        self.cmd_table["meta"] = (self.meta, (3, 4), 1, 1)
        self.cmd_table["utilization"] = (self.utilization, (3, 4), 1, 1)
        self.cmd_table["failcount"] = (self.failcount, (3, 4), 0, 0)
        self.cmd_table["cleanup"] = (self.cleanup, (1, 2), 1, 1)
        self.cmd_table["refresh"] = (self.refresh, (0, 1), 0, 0)
        self.cmd_table["reprobe"] = (self.reprobe, (0, 1), 0, 1)
        self.cmd_table["trace"] = (self.trace, (2, 3), 0, 1)
        self.cmd_table["untrace"] = (self.untrace, (2, 3), 0, 1)
        self.cmd_aliases.update({
            "status": ("show", "list",),
            "migrate": ("move",),
            "unmigrate": ("unmove",),
        })
        utils.setup_aliases(self)

    def _commit_meta_attr(self, rsc, name, value):
        """
        Perform change to resource
        """
        if not utils.is_name_sane(rsc):
            return False
        commit = not cib_factory.has_cib_changed()
        if not commit:
            common_info("Currently editing the CIB, changes will not be committed")
        return set_deep_meta_attr(rsc, name, value, commit=commit)

    def status(self, cmd, rsc=None):
        "usage: status [<rsc>]"
        if rsc:
            if not utils.is_name_sane(rsc):
                return False
            return utils.ext_cmd(self.rsc_status % rsc) == 0
        else:
            return utils.ext_cmd(self.rsc_status_all) == 0

    def start(self, cmd, rsc):
        "usage: start <rsc>"
        return self._commit_meta_attr(rsc, "target-role", "Started")

    def restart(self, cmd, rsc):
        "usage: restart <rsc>"
        common_info("ordering %s to stop" % rsc)
        if not self.stop("stop", rsc):
            return False
        if not utils.wait4dc("stop", not options.batch):
            return False
        common_info("ordering %s to start" % rsc)
        return self.start("start", rsc)

    def stop(self, cmd, rsc):
        "usage: stop <rsc>"
        return self._commit_meta_attr(rsc, "target-role", "Stopped")

    def promote(self, cmd, rsc):
        "usage: promote <rsc>"
        if not utils.is_name_sane(rsc):
            return False
        if not xmlutil.RscState().is_ms(rsc):
            common_err("%s is not a master-slave resource" % rsc)
            return False
        return utils.ext_cmd(self.rsc_setrole % (rsc, "Master")) == 0

    def demote(self, cmd, rsc):
        "usage: demote <rsc>"
        if not utils.is_name_sane(rsc):
            return False
        if not xmlutil.RscState().is_ms(rsc):
            common_err("%s is not a master-slave resource" % rsc)
            return False
        return utils.ext_cmd(self.rsc_setrole % (rsc, "Slave")) == 0

    def manage(self, cmd, rsc):
        "usage: manage <rsc>"
        return self._commit_meta_attr(rsc, "is-managed", "true")

    def unmanage(self, cmd, rsc):
        "usage: unmanage <rsc>"
        return self._commit_meta_attr(rsc, "is-managed", "false")

    def migrate(self, cmd, *args):
        """usage: migrate <rsc> [<node>] [<lifetime>] [force]"""
        argl = list(args)
        rsc = argl[0]
        if not utils.is_name_sane(rsc):
            return False
        del argl[0]
        node = None
        opt_l = fetch_opts(argl, ["force"])
        lifetime = fetch_lifetime_opt(argl)
        if len(argl) == 1:
            if xmlutil.is_our_node(argl[0]):
                node = argl[0]
            else:
                common_err("Not our node: " + argl[0])
                return False
        opts = ''
        if node:
            opts = "--node='%s'" % node
        if lifetime:
            opts = "%s --lifetime='%s'" % (opts, lifetime)
        if "force" in opt_l or user_prefs.force:
            opts = "%s --force" % opts
        return utils.ext_cmd(self.rsc_migrate % (rsc, opts)) == 0

    def unmigrate(self, cmd, rsc):
        "usage: unmigrate <rsc>"
        if not utils.is_name_sane(rsc):
            return False
        return utils.ext_cmd(self.rsc_unmigrate % rsc) == 0

    def cleanup(self, cmd, *args):
        "usage: cleanup <rsc> [<node>]"
        # Cleanup a resource on a node. Omit node to cleanup on
        # all live nodes.
        if len(args) == 2:  # remove
            return cleanup_resource(args[0], args[1])
        else:
            return cleanup_resource(args[0])

    def failcount(self, cmd, *args):
        """usage:
        failcount <rsc> set <node> <value>
        failcount <rsc> delete <node>
        failcount <rsc> show <node>"""
        d = lambda: manage_attr(cmd, self.rsc_failcount, *args)
        return d()

    def param(self, cmd, *args):
        """usage:
        param <rsc> set <param> <value>
        param <rsc> delete <param>
        param <rsc> show <param>"""
        d = lambda: manage_attr(cmd, self.rsc_param, *args)
        return d()

    def secret(self, cmd, *args):
        """usage:
        secret <rsc> set <param> <value>
        secret <rsc> stash <param>
        secret <rsc> unstash <param>
        secret <rsc> delete <param>
        secret <rsc> show <param>
        secret <rsc> check <param>"""
        d = lambda: manage_attr(cmd, self.rsc_secret, *args)
        return d()

    def meta(self, cmd, *args):
        """usage:
        meta <rsc> set <attr> <value>
        meta <rsc> delete <attr>
        meta <rsc> show <attr>"""
        d = lambda: manage_attr(cmd, self.rsc_meta, *args)
        return d()

    def utilization(self, cmd, *args):
        """usage:
        utilization <rsc> set <attr> <value>
        utilization <rsc> delete <attr>
        utilization <rsc> show <attr>"""
        d = lambda: manage_attr(cmd, self.rsc_utilization, *args)
        return d()

    def refresh(self, cmd, *args):
        'usage: refresh [<node>]'
        if len(args) == 1:
            if not utils.is_name_sane(args[0]):
                return False
            return utils.ext_cmd(self.rsc_refresh_node % args[0]) == 0
        else:
            return utils.ext_cmd(self.rsc_refresh) == 0

    def reprobe(self, cmd, *args):
        'usage: reprobe [<node>]'
        if len(args) == 1:
            if not utils.is_name_sane(args[0]):
                return False
            return utils.ext_cmd(self.rsc_reprobe_node % args[0]) == 0
        else:
            return utils.ext_cmd(self.rsc_reprobe) == 0

    def _get_trace_rsc(self, rsc_id):
        cib_factory.refresh()
        if not cib_factory.is_cib_sane():
            return None
        rsc = cib_factory.find_object(rsc_id)
        if not rsc:
            common_err("resource %s does not exist" % rsc_id)
            return None
        if rsc.obj_type != "primitive":
            common_err("element %s is not a primitive resource" % rsc_id)
            return None
        return rsc

    def trace(self, cmd, rsc_id, op, interval=None):
        'usage: trace <rsc> <op> [<interval>]'
        rsc = self._get_trace_rsc(rsc_id)
        if not rsc:
            return False
        if not interval:
            interval = op == "monitor" and "non-0" or "0"
        if op == "probe":
            op = "monitor"
        op_node = xmlutil.find_operation(rsc.node, op, interval)
        if op_node is None and utils.crm_msec(interval) != 0:
            common_err("not allowed to create non-0 interval operation %s" % op)
            return False
        if op_node is None:
            head_pl = ["op", []]
            head_pl[1].append(["name", op])
            head_pl[1].append(["interval", interval])
            head_pl[1].append([vars.trace_ra_attr, "1"])
            cli_list = []
            cli_list.append(head_pl)
            if not rsc.add_operation(cli_list):
                return False
        else:
            op_node = rsc.set_op_attr(op_node, vars.trace_ra_attr, "1")
        if not cib_factory.commit():
            return False
        if op == "monitor" and utils.crm_msec(interval) != 0:
            common_warn("please CLEANUP the RA trace directory %s regularly!" %
                        vars.ha_varlib_dir)
        else:
            common_info("restart %s to get the trace" % rsc_id)
        return True

    def untrace(self, cmd, rsc_id, op, interval=None):
        'usage: untrace <rsc> <op> [<interval>]'
        rsc = self._get_trace_rsc(rsc_id)
        if not rsc:
            return False
        if not interval:
            interval = op == "monitor" and "non-0" or "0"
        if op == "probe":
            op = "monitor"
        op_node = xmlutil.find_operation(rsc.node, op, interval)
        if op_node is None:
            common_err("operation %s does not exist in %s" % (op, rsc.obj_id))
            return False
        op_node = rsc.del_op_attr(op_node, vars.trace_ra_attr)
        if rsc.is_dummy_operation(op_node):
            rsc.del_operation(op_node)
        return cib_factory.commit()


def print_node(uname, id, node_type, other, inst_attr, offline):
    """
    Try to pretty print a node from the cib. Sth like:
    uname(id): node_type
        attr1: v1
        attr2: v2
    """
    s_offline = offline and "(offline)" or ""
    if not node_type:
        node_type = "normal"
    if uname == id:
        print "%s: %s%s" % (uname, node_type, s_offline)
    else:
        print "%s(%s): %s%s" % (uname, id, node_type, s_offline)
    for a in other:
        print "\t%s: %s" % (a, other[a])
    for a, v in inst_attr:
        print "\t%s: %s" % (a, v)


class NodeMgmt(UserInterface):
    '''
    Nodes management class
    '''
    lvl_name = "node"
    node_standby = "crm_attribute -t nodes -N '%s' -n standby -v '%s' %s"
    node_maint = "crm_attribute -t nodes -N '%s' -n maintenance -v '%s'"
    node_delete = "cibadmin -D -o nodes -X '<node uname=\"%s\"/>'"
    node_delete_status = "cibadmin -D -o status -X '<node_state uname=\"%s\"/>'"
    node_clear_state = "cibadmin %s -o status --xml-text '<node_state id=\"%s\" uname=\"%s\" ha=\"active\" in_ccm=\"false\" crmd=\"offline\" join=\"member\" expected=\"down\" crm-debug-origin=\"manual_clear\" shutdown=\"0\"/>'"
    node_clear_state_118 = "stonith_admin --confirm %s"
    hb_delnode = config.DATADIR + "/heartbeat/hb_delnode '%s'"
    crm_node = "crm_node"
    node_fence = "crm_attribute -t status -U '%s' -n terminate -v true"
    dc = "crmadmin -D"
    node_attr = {
        'set': "crm_attribute -t nodes -U '%s' -n '%s' -v '%s'",
        'delete': "crm_attribute -D -t nodes -U '%s' -n '%s'",
        'show': "crm_attribute -G -t nodes -U '%s' -n '%s'",
    }
    node_status = {
        'set': "crm_attribute -t status -U '%s' -n '%s' -v '%s'",
        'delete': "crm_attribute -D -t status -U '%s' -n '%s'",
        'show': "crm_attribute -G -t status -U '%s' -n '%s'",
    }
    node_utilization = {
        'set': "crm_attribute -z -t nodes -U '%s' -n '%s' -v '%s'",
        'delete': "crm_attribute -z -D -t nodes -U '%s' -n '%s'",
        'show': "crm_attribute -z -G -t nodes -U '%s' -n '%s'",
    }

    def __init__(self):
        UserInterface.__init__(self)
        self.cmd_table["status"] = (self.status, (0, 1), 0, 0)
        self.cmd_table["show"] = (self.show, (0, 1), 0, 0)
        self.cmd_table["standby"] = (self.standby, (0, 2), 0, 1)
        self.cmd_table["online"] = (self.online, (0, 1), 0, 1)
        self.cmd_table["maintenance"] = (self.maintenance, (0, 1), 0, 1)
        self.cmd_table["ready"] = (self.ready, (0, 1), 0, 1)
        self.cmd_table["fence"] = (self.fence, (1, 1), 0, 1)
        self.cmd_table["delete"] = (self.delete, (1, 1), 0, 0)
        self.cmd_table["clearstate"] = (self.clearstate, (1, 1), 0, 1)
        self.cmd_table["attribute"] = (self.attribute, (3, 4), 0, 1)
        self.cmd_table["utilization"] = (self.utilization, (3, 4), 0, 1)
        self.cmd_table["status-attr"] = (self.status_attr, (3, 4), 0, 1)
        self.cmd_aliases.update({
            "show": ("list",),
        })
        utils.setup_aliases(self)

    def status(self, cmd, node=None):
        'usage: status [<node>]'
        a = node and ('--xpath "//nodes/node[@uname=\'%s\']"' % node) or \
            '-o nodes'
        return utils.ext_cmd("%s %s" % (xmlutil.cib_dump, a)) == 0

    def show(self, cmd, node=None):
        'usage: show [<node>]'
        cib_elem = xmlutil.cibdump2elem()
        if cib_elem is None:
            return False
        try:
            nodes_node = cib_elem.xpath("//configuration/nodes")[0]
            status = cib_elem.findall("status")[0]
        except:
            return False
        for c in nodes_node.iterchildren():
            if c.tag != "node":
                continue
            if node is not None and c.get("uname") != node:
                continue
            type = uname = id = ""
            inst_attr = []
            other = {}
            for attr in c.keys():
                v = c.get(attr)
                if attr == "type":
                    type = v
                elif attr == "uname":
                    uname = v
                elif attr == "id":
                    id = v
                else:
                    other[attr] = v
            for c2 in c.iterchildren():
                if c2.tag == "instance_attributes":
                    inst_attr += nvpairs2list(c2)
            offline = False
            for c2 in status.xpath(".//node_state"):
                if uname != c2.get("uname"):
                    continue
                offline = c2.get("crmd") == "offline"
            print_node(uname, id, type, other, inst_attr, offline)

    def standby(self, cmd, *args):
        'usage: standby [<node>] [<lifetime>]'
        argl = list(args)
        node = None
        lifetime = fetch_lifetime_opt(argl, iso8601=False)
        if not argl:
            node = vars.this_node
        elif len(argl) == 1:
            if xmlutil.is_our_node(args[0]):
                node = args[0]
            else:
                common_err("%s: node name not recognized" % args[0])
                return False
        else:
            syntax_err(args, context=cmd)
            return False
        opts = ''
        if lifetime:
            opts = "--lifetime='%s'" % lifetime
        else:
            opts = "--lifetime='forever'"
        return utils.ext_cmd(self.node_standby % (node, "on", opts)) == 0

    def online(self, cmd, node=None):
        'usage: online [<node>]'
        if not node:
            node = vars.this_node
        if not utils.is_name_sane(node):
            return False
        return utils.ext_cmd(self.node_standby % (node, "off", "--lifetime='forever'")) == 0

    def maintenance(self, cmd, node=None):
        'usage: maintenance [<node>]'
        if not node:
            node = vars.this_node
        if not utils.is_name_sane(node):
            return False
        return utils.ext_cmd(self.node_maint % (node, "on")) == 0

    def ready(self, cmd, node=None):
        'usage: ready [<node>]'
        if not node:
            node = vars.this_node
        if not utils.is_name_sane(node):
            return False
        return utils.ext_cmd(self.node_maint % (node, "off")) == 0

    def fence(self, cmd, node):
        'usage: fence <node>'
        if not node:
            node = vars.this_node
        if not utils.is_name_sane(node):
            return False
        if not user_prefs.force and \
                not utils.ask("Do you really want to shoot %s?" % node):
            return False
        return utils.ext_cmd(self.node_fence % (node)) == 0

    def clearstate(self, cmd, node):
        'usage: clearstate <node>'
        if not utils.is_name_sane(node):
            return False
        if not user_prefs.force and \
                not utils.ask("Do you really want to drop state for node %s?" % node):
            return False
        if utils.is_pcmk_118():
            return utils.ext_cmd(self.node_clear_state_118 % node) == 0
        else:
            return utils.ext_cmd(self.node_clear_state % ("-M -c", node, node)) == 0 and \
                utils.ext_cmd(self.node_clear_state % ("-R", node, node)) == 0

    def delete(self, cmd, node):
        'usage: delete <node>'
        if not utils.is_name_sane(node):
            return False
        if not xmlutil.is_our_node(node):
            common_err("node %s not found in the CIB" % node)
            return False
        rc = True
        if utils.cluster_stack() == "heartbeat":
            cmd = (self.hb_delnode % node)
        else:
            ec, s = utils.get_stdout("%s -p" % self.crm_node)
            if not s:
                common_err('%s -p could not list any nodes (rc=%d)' %
                           (self.crm_node, ec))
                rc = False
            else:
                partition_l = s.split()
                if node in partition_l:
                    common_err("according to %s, node %s is still active" %
                               (self.crm_node, node))
                    rc = False
            cmd = "%s --force -R %s" % (self.crm_node, node)
        if not rc:
            if user_prefs.force:
                common_info('proceeding with node %s removal' % node)
            else:
                return False
        ec = utils.ext_cmd(cmd)
        if ec != 0:
            common_warn('"%s" failed, rc=%d' % (cmd, ec))
            return False
        if utils.ext_cmd(self.node_delete % node) != 0 or \
                utils.ext_cmd(self.node_delete_status % node) != 0:
            common_err("%s removed from membership, but not from CIB!" % node)
            return False
        common_info("node %s deleted" % node)
        return True

    def attribute(self, cmd, *args):
        """usage:
        attribute <node> set <rsc> <value>
        attribute <node> delete <rsc>
        attribute <node> show <rsc>"""
        d = lambda: manage_attr(cmd, self.node_attr, *args)
        return d()

    def utilization(self, cmd, *args):
        """usage:
        utilization <node> set <rsc> <value>
        utilization <node> delete <rsc>
        utilization <node> show <rsc>"""
        d = lambda: manage_attr(cmd, self.node_utilization, *args)
        return d()

    def status_attr(self, cmd, *args):
        """usage:
        status-attr <node> set <rsc> <value>
        status-attr <node> delete <rsc>
        status-attr <node> show <rsc>"""
        d = lambda: manage_attr(cmd, self.node_status, *args)
        return d()


class RA(UserInterface):
    '''
    CIB shadow management class
    '''
    lvl_name = "ra"
    provider_classes = ["ocf"]

    def __init__(self):
        UserInterface.__init__(self)
        self.cmd_table["classes"] = (self.classes, (0, 0), 0, 0)
        self.cmd_table["list"] = (self.list, (1, 2), 1, 0)
        self.cmd_table["providers"] = (self.providers, (1, 2), 1, 0)
        self.cmd_table["meta"] = (self.meta, (1, 3), 1, 0)
        self.cmd_aliases.update({
            "meta": ("info",),
        })
        utils.setup_aliases(self)

    def classes(self, cmd):
        "usage: classes"
        for c in ra.ra_classes():
            if c in self.provider_classes:
                print "%s / %s" % (c, ' '.join(ra.ra_providers_all(c)))
            else:
                print "%s" % c

    def providers(self, cmd, ra_type, ra_class="ocf"):
        "usage: providers <ra> [<class>]"
        print ' '.join(ra.ra_providers(ra_type, ra_class))

    def list(self, cmd, c, p=None):
        "usage: list <class> [<provider>]"
        if not c in ra.ra_classes():
            common_err("class %s does not exist" % c)
            return False
        if p and not p in ra.ra_providers_all(c):
            common_err("there is no provider %s for class %s" % (p, c))
            return False
        if options.regression_tests:
            for t in ra.ra_types(c, p):
                print t
        else:
            utils.multicolumn(ra.ra_types(c, p))

    def meta(self, cmd, *args):
        "usage: meta [<class>:[<provider>:]]<type>"
        if len(args) > 1:  # obsolete syntax
            ra_type = args[0]
            ra_class = args[1]
            if len(args) < 3:
                ra_provider = "heartbeat"
            else:
                ra_provider = args[2]
        else:
            if args[0] in vars.meta_progs:
                ra_class = args[0]
                ra_provider = ra_type = None
            else:
                ra_class, ra_provider, ra_type = ra.disambiguate_ra_type(args[0])
        agent = ra.RAInfo(ra_class, ra_type, ra_provider)
        if agent.mk_ra_node() is None:
            return False
        try:
            utils.page_string(agent.meta_pretty())
        except Exception, msg:
            common_err(msg)
            return False


def ptestlike(simfun, def_verb, cmd, args):
    verbosity = def_verb  # default verbosity
    nograph = False
    scores = False
    utilization = False
    actions = False
    for p in args:
        if p == "nograph":
            nograph = True
        elif p == "scores":
            scores = True
        elif p == "utilization":
            utilization = True
        elif p == "actions":
            actions = True
        elif re.match("^vv*$", p):
            verbosity = p
        else:
            bad_usage(cmd, ' '.join(args))
            return False
    return simfun(nograph, scores, utilization, actions, verbosity)


class StatusMgmt(UserInterface):
    '''
    The CIB status section management user interface class
    '''
    lvl_name = "cibstatus"

    def __init__(self):
        UserInterface.__init__(self)
        self.cmd_table["show"] = (self.show, (0, 1), 1, 0)
        self.cmd_table["save"] = (self.save, (0, 1), 2, 0)
        self.cmd_table["load"] = (self.load, (1, 1), 2, 0)
        self.cmd_table["origin"] = (self.origin, (0, 0), 1, 0)
        self.cmd_table["node"] = (self.edit_node, (2, 2), 2, 0)
        self.cmd_table["op"] = (self.edit_op, (3, 5), 2, 0)
        self.cmd_table["run"] = (self.run, (0, 3), 1, 0)
        self.cmd_table["simulate"] = (self.simulate, (0, 3), 1, 0)
        self.cmd_table["quorum"] = (self.quorum, (1, 1), 1, 0)
        self.cmd_table["ticket"] = (self.edit_ticket, (2, 2), 2, 0)
        utils.setup_aliases(self)

    def load(self, cmd, org):
        "usage: load {<file>|shadow:<cib>|live}"
        return cib_status.load(org)

    def save(self, cmd, dest=None):
        "usage: save [<file>|shadow:<cib>]"
        return cib_status.save(dest)

    def origin(self, cmd):
        "usage: origin"
        state = cib_status.modified and " (modified)" or ""
        print "%s%s" % (cib_status.origin, state)

    def show(self, cmd, changed=""):
        "usage: show [changed]"
        if changed:
            if changed != "changed":
                syntax_err((cmd, changed))
                return False
            else:
                return cib_status.list_changes()
        return cib_status.show()

    def quorum(self, cmd, opt):
        "usage: quorum <bool>"
        if not utils.verify_boolean(opt):
            common_err("%s: bad boolean option" % opt)
            return False
        return cib_status.set_quorum(utils.is_boolean_true(opt))

    def edit_node(self, cmd, node, state):
        "usage: node <node> {online|offline|unclean}"
        return cib_status.edit_node(node, state)

    def edit_ticket(self, cmd, ticket, subcmd):
        "usage: ticket <ticket> {grant|revoke|activate|standby}"
        return cib_status.edit_ticket(ticket, subcmd)

    def edit_op(self, cmd, op, rsc, rc, op_status=None, node=''):
        "usage: op <operation> <resource> <exit_code> [<op_status>] [<node>]"
        if rc in vars.lrm_exit_codes:
            num_rc = vars.lrm_exit_codes[rc]
        else:
            num_rc = rc
        if not num_rc.isdigit():
            common_err("%s exit code invalid" % num_rc)
            return False
        num_op_status = op_status
        if op_status:
            if op_status in vars.lrm_status_codes:
                num_op_status = vars.lrm_status_codes[op_status]
            if not num_op_status.isdigit():
                common_err("%s operation status invalid" % num_op_status)
                return False
        return cib_status.edit_op(op, rsc, num_rc, num_op_status, node)

    def run(self, cmd, *args):
        "usage: run [nograph] [v...] [scores] [utilization]"
        return ptestlike(cib_status.run, '', cmd, args)

    def simulate(self, cmd, *args):
        "usage: simulate [nograph] [v...] [scores] [utilization]"
        return ptestlike(cib_status.simulate, '', cmd, args)


def _graph_args(args):
    '''
    Common parameters for two graph commands:
        configure graph [<gtype> [<file> [<img_format>]]]
        history graph <pe> [<gtype> [<file> [<img_format>]]]
    '''
    from crm_gv import gv_types
    gtype, outf, ftype = None, None, None
    try:
        gtype = args[0]
        if gtype not in gv_types:
            common_err("graph type %s is not supported" % gtype)
            return False, gtype, outf, ftype
    except:
        gtype = "dot"
    try:
        outf = args[1]
        if not utils.is_path_sane(outf):
            return False, gtype, outf, ftype
    except:
        outf = None
    try:
        ftype = args[2]
    except:
        ftype = gtype
    return True, gtype, outf, ftype


class CibConfig(UserInterface):
    '''
    The configuration class
    '''
    lvl_name = "configure"

    def __init__(self):
        UserInterface.__init__(self)
        self.cmd_table["erase"] = (self.erase, (0, 1), 1, 0)
        self.cmd_table["verify"] = (self.verify, (0, 0), 1, 0)
        self.cmd_table["refresh"] = (self.refresh, (0, 0), 1, 0)
        self.cmd_table["ptest"] = (self.ptest, (0, 5), 1, 0)
        self.cmd_table["commit"] = (self.commit, (0, 1), 1, 1)
        self.cmd_table["upgrade"] = (self.upgrade, (0, 1), 1, 0)
        self.cmd_table["show"] = (self.show, (0,), 1, 0)
        self.cmd_table["edit"] = (self.edit, (0,), 1, 0)
        self.cmd_table["modgroup"] = (self.modgroup, (3, 5), 1, 0)
        self.cmd_table["filter"] = (self.filter, (1,), 1, 0)
        self.cmd_table["delete"] = (self.delete, (1,), 1, 0)
        self.cmd_table["default-timeouts"] = (self.default_timeouts, (1,), 1, 0)
        self.cmd_table["rename"] = (self.rename, (2, 2), 1, 0)
        self.cmd_table["save"] = (self.save, (1, 2), 1, 0)
        self.cmd_table["load"] = (self.load, (2, 3), 1, 0)
        self.cmd_table["graph"] = (self.graph, (0, 3), 1, 0)
        self.cmd_table["schema"] = (self.schema, (0, 1), 1, 0)
        self.cmd_table["node"] = (self.conf_node, (1,), 1, 0)
        self.cmd_table["primitive"] = (self.conf_primitive, (2,), 1, 0)
        self.cmd_table["group"] = (self.conf_group, (2,), 1, 0)
        self.cmd_table["clone"] = (self.conf_clone, (2,), 1, 0)
        self.cmd_table["ms"] = (self.conf_ms, (2,), 1, 0)
        self.cmd_table["rsc_template"] = (self.conf_rsc_template, (2,), 1, 0)
        self.cmd_table["location"] = (self.conf_location, (2,), 1, 0)
        self.cmd_table["colocation"] = (self.conf_colocation, (2,), 1, 0)
        self.cmd_table["order"] = (self.conf_order, (2,), 1, 0)
        self.cmd_table["rsc_ticket"] = (self.conf_rsc_ticket, (2,), 1, 0)
        self.cmd_table["property"] = (self.conf_property, (1,), 1, 0)
        self.cmd_table["rsc_defaults"] = (self.conf_rsc_defaults, (1,), 1, 0)
        self.cmd_table["op_defaults"] = (self.conf_op_defaults, (1,), 1, 0)
        self.cmd_table["fencing_topology"] = (self.conf_fencing_order, (1,), 1, 0)
        self.cmd_table["xml"] = (self.conf_xml, (1,), 1, 0)
        self.cmd_table["monitor"] = (self.conf_monitor, (2, 2), 1, 0)
        self.cmd_table["role"] = (self.conf_role, (2,), 2, 0)
        self.cmd_table["user"] = (self.conf_user, (2,), 2, 0)
        self.cmd_table["rsctest"] = (self.rsc_test, (1,), 2, 0)
        self.cmd_table["ra"] = RA
        self.cmd_table["cib"] = CibShadow
        self.cmd_table["cibstatus"] = StatusMgmt
        self.cmd_table["template"] = Template
        self.cmd_table["history"] = History
        self.cmd_table["_test"] = (self.check_structure, (0, 0), 1, 0)
        self.cmd_table["_regtest"] = (self.regression_testing, (1, 1), 1, 0)
        self.cmd_table["_objects"] = (self.showobjects, (0, 0), 1, 0)
        self.cmd_aliases.update({
            "colocation": ("collocation",),
            "ms": ("master",),
            "ptest": ("simulate",),
        })
        utils.setup_aliases(self)
        # for interactive use, we want to populate the CIB
        # immediately so that tab completion works
        if options.interactive:
            cib_factory.initialize()

    def check_structure(self, cmd):
        return cib_factory.check_structure()

    def regression_testing(self, cmd, param):
        return cib_factory.regression_testing(param)

    def showobjects(self, cmd):
        cib_factory.showobjects()

    def show(self, cmd, *args):
        "usage: show [xml] [<id>...]"
        if not cib_factory.is_cib_sane():
            return False
        set_obj = mkset_obj(*args)
        return set_obj.show()

    def filter(self, cmd, filter, *args):
        "usage: filter <prog> [xml] [<id>...]"
        if not cib_factory.is_cib_sane():
            return False
        set_obj = mkset_obj(*args)
        return set_obj.filter(filter)

    def modgroup(self, cmd, group_id, subcmd, prim_id, *args):
        """usage: modgroup <id> add <id> [after <id>|before <id>]
        modgroup <id> remove <id>"""
        if not cib_factory.is_cib_sane():
            return False
        if subcmd not in ("add", "remove"):
            common_err("modgroup subcommand %s unknown" % subcmd)
            return False
        after_before = None
        if args:
            if subcmd != "add" or args[0] not in ("after", "before"):
                syntax_err(((cmd, group_id, subcmd, prim_id) + args), context='modgroup')
                return False
            if len(args) != 2:
                syntax_err(((cmd, group_id, subcmd, prim_id) + args), context='modgroup')
                return False
            after_before = args[0]
            ref_member_id = args[1]
        g = cib_factory.find_object(group_id)
        if not g:
            common_err("group %s does not exist" % group_id)
            return False
        if not xmlutil.is_group(g.node):
            common_err("element %s is not a group" % group_id)
            return False
        children = xmlutil.get_rsc_children_ids(g.node)
        if after_before and ref_member_id not in children:
            common_err("%s is not member of %s" % (ref_member_id, group_id))
            return False
        if subcmd == "remove" and prim_id not in children:
            common_err("%s is not member of %s" % (prim_id, group_id))
            return False
        # done checking arguments
        # have a group and children
        if not after_before:
            after_before = "after"
            ref_member_id = children[-1]
        # just do the filter
        # (i wonder if this is a feature abuse?)
        if subcmd == "add":
            if after_before == "after":
                sed_s = r's/ %s( |$)/& %s /' % (ref_member_id, prim_id)
            else:
                sed_s = r's/ %s( |$)/ %s& /' % (ref_member_id, prim_id)
        else:
            sed_s = r's/ %s( |$)/ /' % prim_id
        l = (group_id,)
        set_obj = mkset_obj(*l)
        return set_obj.filter("sed -r '%s'" % sed_s)

    def edit(self, cmd, *args):
        "usage: edit [xml] [<id>...]"
        if not cib_factory.is_cib_sane():
            return False
        err_buf.buffer()  # keep error messages
        set_obj = mkset_obj(*args)
        err_buf.release()  # show them, but get an ack from the user
        return set_obj.edit()

    def _verify(self, set_obj_semantic, set_obj_all):
        rc1 = set_obj_all.verify()
        if user_prefs.check_frequency != "never":
            rc2 = set_obj_semantic.semantic_check(set_obj_all)
        else:
            rc2 = 0
        return rc1 and rc2 <= 1

    def verify(self, cmd):
        "usage: verify"
        if not cib_factory.is_cib_sane():
            return False
        set_obj_all = mkset_obj("xml")
        return self._verify(set_obj_all, set_obj_all)

    def save(self, cmd, *args):
        "usage: save [xml] <filename>"
        if not cib_factory.is_cib_sane():
            return False
        if args[0] == "xml":
            f = args[1]
            set_obj = mkset_obj("xml")
        else:
            f = args[0]
            set_obj = mkset_obj()
        return set_obj.save_to_file(f)

    def load(self, cmd, *args):
        "usage: load [xml] {replace|update} {<url>|<path>}"
        if not cib_factory.is_cib_sane():
            return False
        if args[0] == "xml":
            if len(args) != 3:
                syntax_err(args, context='load')
                return False
            url = args[2]
            method = args[1]
            xml = True
        else:
            if len(args) != 2:
                syntax_err(args, context='load')
                return False
            url = args[1]
            method = args[0]
            xml = False
        if method not in ("replace", "update"):
            common_err("unknown method %s" % method)
            return False
        if method == "replace":
            if options.interactive and cib_factory.has_cib_changed():
                if not utils.ask("This operation will erase all changes. Do you want to proceed?"):
                    return False
            cib_factory.erase()
        if xml:
            set_obj = mkset_obj("xml")
        else:
            set_obj = mkset_obj()
        return set_obj.import_file(method, url)

    def graph(self, cmd, *args):
        "usage: graph [<gtype> [<file> [<img_format>]]]"
        if args and args[0] == "exportsettings":
            return utils.save_graphviz_file(vars.graphviz_user_file, vars.graph)
        if not cib_factory.is_cib_sane():
            return False
        rc, gtype, outf, ftype = _graph_args(args)
        if not rc:
            return False
        rc, d = utils.load_graphviz_file(vars.graphviz_user_file)
        if rc and d:
            vars.graph = d
        set_obj = mkset_obj()
        if not outf:
            rc = set_obj.show_graph(gtype)
        elif gtype == ftype:
            rc = set_obj.save_graph(gtype, outf)
        else:
            rc = set_obj.graph_img(gtype, outf, ftype)
        return rc

    def delete(self, cmd, *args):
        "usage: delete <id> [<id>...]"
        if not cib_factory.is_cib_sane():
            return False
        return cib_factory.delete(*args)

    def default_timeouts(self, cmd, *args):
        "usage: default-timeouts <id> [<id>...]"
        if not cib_factory.is_cib_sane():
            return False
        return cib_factory.default_timeouts(*args)

    def rename(self, cmd, old_id, new_id):
        "usage: rename <old_id> <new_id>"
        if not cib_factory.is_cib_sane():
            return False
        return cib_factory.rename(old_id, new_id)

    def erase(self, cmd, nodes=None):
        "usage: erase [nodes]"
        if not cib_factory.is_cib_sane():
            return False
        if nodes:
            if nodes == "nodes":
                return cib_factory.erase_nodes()
            else:
                syntax_err((cmd, nodes), context='erase')
        else:
            return cib_factory.erase()

    def refresh(self, cmd):
        "usage: refresh"
        if options.interactive and cib_factory.has_cib_changed():
            if not utils.ask("All changes will be dropped. Do you want to proceed?"):
                return
        cib_factory.refresh()

    def ptest(self, cmd, *args):
        "usage: ptest [nograph] [v...] [scores] [utilization] [actions]"
        if not cib_factory.is_cib_sane():
            return False
        # use ptest/crm_simulate depending on which command was
        # used
        user_prefs.ptest = vars.simulate_programs[cmd]
        if not user_prefs.ptest:
            return False
        set_obj = mkset_obj("xml")
        return ptestlike(set_obj.ptest, 'vv', cmd, args)

    def commit(self, cmd, force=None):
        "usage: commit [force]"
        if force and force != "force":
            syntax_err((cmd, force))
            return False
        if not cib_factory.is_cib_sane():
            return False
        if not cib_factory.has_cib_changed():
            common_info("apparently there is nothing to commit")
            common_info("try changing something first")
            return
        rc1 = True
        if not (force or utils.cibadmin_can_patch()):
            rc1 = cib_factory.is_current_cib_equal()
        rc2 = cib_factory.is_cib_empty() or \
            self._verify(mkset_obj("xml", "changed"), mkset_obj("xml"))
        if rc1 and rc2:
            return cib_factory.commit()
        if force or user_prefs.force:
            common_info("commit forced")
            return cib_factory.commit(force=True)
        if utils.ask("Do you still want to commit?"):
            return cib_factory.commit(force=True)
        return False

    def upgrade(self, cmd, force=None):
        "usage: upgrade [force]"
        if not cib_factory.is_cib_sane():
            return False
        if force and force != "force":
            syntax_err((cmd, force))
            return False
        if user_prefs.force or force:
            return cib_factory.upgrade_cib_06to10(True)
        else:
            return cib_factory.upgrade_cib_06to10()

    def schema(self, cmd, schema_st=None):
        "usage: schema [<schema>]"
        if not cib_factory.is_cib_sane():
            return False
        if not schema_st:
            print cib_factory.get_schema()
            return True
        return cib_factory.change_schema(schema_st)

    def __conf_object(self, cmd, *args):
        "The configure object command."
        if not cib_factory.is_cib_sane():
            return False
        if cmd in vars.cib_cli_map.values() and \
                not cib_factory.is_elem_supported(cmd):
            common_err("%s not supported by the RNG schema" % cmd)
            return False
        f = lambda: cib_factory.create_object(cmd, *args)
        return f()

    def conf_node(self, cmd, *args):
        """usage: node <uname>[:<type>]
           [attributes <param>=<value> [<param>=<value>...]]
           [utilization <param>=<value> [<param>=<value>...]]"""
        return self.__conf_object(cmd, *args)

    def conf_primitive(self, cmd, *args):
        """usage: primitive <rsc> {[<class>:[<provider>:]]<type>|@<template>}
        [params <param>=<value> [<param>=<value>...]]
        [meta <attribute>=<value> [<attribute>=<value>...]]
        [utilization <attribute>=<value> [<attribute>=<value>...]]
        [operations id_spec
            [op op_type [<attribute>=<value>...] ...]]"""
        return self.__conf_object(cmd, *args)

    def conf_group(self, cmd, *args):
        """usage: group <name> <rsc> [<rsc>...]
        [params <param>=<value> [<param>=<value>...]]
        [meta <attribute>=<value> [<attribute>=<value>...]]"""
        return self.__conf_object(cmd, *args)

    def conf_clone(self, cmd, *args):
        """usage: clone <name> <rsc>
        [params <param>=<value> [<param>=<value>...]]
        [meta <attribute>=<value> [<attribute>=<value>...]]"""
        return self.__conf_object(cmd, *args)

    def conf_ms(self, cmd, *args):
        """usage: ms <name> <rsc>
        [params <param>=<value> [<param>=<value>...]]
        [meta <attribute>=<value> [<attribute>=<value>...]]"""
        return self.__conf_object(cmd, *args)

    def conf_rsc_template(self, cmd, *args):
        """usage: rsc_template <name> [<class>:[<provider>:]]<type>
        [params <param>=<value> [<param>=<value>...]]
        [meta <attribute>=<value> [<attribute>=<value>...]]
        [utilization <attribute>=<value> [<attribute>=<value>...]]
        [operations id_spec
            [op op_type [<attribute>=<value>...] ...]]"""
        return self.__conf_object(cmd, *args)

    def conf_location(self, cmd, *args):
        """usage: location <id> <rsc> {node_pref|rules}

        node_pref :: <score>: <node>

        rules ::
          rule [id_spec] [$role=<role>] <score>: <expression>
          [rule [id_spec] [$role=<role>] <score>: <expression> ...]

        id_spec :: $id=<id> | $id-ref=<id>
        score :: <number> | <attribute> | [-]inf
        expression :: <simple_exp> [bool_op <simple_exp> ...]
        bool_op :: or | and
        simple_exp :: <attribute> [type:]<binary_op> <value>
                      | <unary_op> <attribute>
                      | date <date_expr>
        type :: string | version | number
        binary_op :: lt | gt | lte | gte | eq | ne
        unary_op :: defined | not_defined"""
        return self.__conf_object(cmd, *args)

    def conf_colocation(self, cmd, *args):
        """usage: colocation <id> <score>: <rsc>[:<role>] <rsc>[:<role>] ...
        [node-attribute=<node_attr>]"""
        return self.__conf_object(cmd, *args)

    def conf_order(self, cmd, *args):
        """usage: order <id> {kind|<score>}: <rsc>[:<action>] <rsc>[:<action>] ...
        [symmetrical=<bool>]"""
        return self.__conf_object(cmd, *args)

    def conf_rsc_ticket(self, cmd, *args):
        """usage: rsc_ticket <id> <ticket_id>: <rsc>[:<role>] [<rsc>[:<role>] ...]
        [loss-policy=<loss_policy_action>]"""
        return self.__conf_object(cmd, *args)

    def conf_property(self, cmd, *args):
        "usage: property [$id=<set_id>] <option>=<value>"
        return self.__conf_object(cmd, *args)

    def conf_rsc_defaults(self, cmd, *args):
        "usage: rsc_defaults [$id=<set_id>] <option>=<value>"
        return self.__conf_object(cmd, *args)

    def conf_op_defaults(self, cmd, *args):
        "usage: op_defaults [$id=<set_id>] <option>=<value>"
        return self.__conf_object(cmd, *args)

    def conf_fencing_order(self, cmd, *args):
        "usage: fencing_topology [<node>:] stonith_resources [stonith_resources ...]"
        return self.__conf_object(cmd, *args)

    def conf_xml(self, cmd, *args):
        "usage: xml <xml>"
        return self.__conf_object(cmd, *args)

    def conf_monitor(self, cmd, *args):
        "usage: monitor <rsc>[:<role>] <interval>[:<timeout>]"
        return self.__conf_object(cmd, *args)

    def conf_user(self, cmd, *args):
        """user <uid> {roles|rules}

        roles :: role:<role-ref> [role:<role-ref> ...]
        rules :: rule [rule ...]

        (See the role command for details on rules.)"""
        return self.__conf_object(cmd, *args)

    def conf_role(self, cmd, *args):
        """role <role-id> rule [rule ...]

        rule :: acl-right cib-spec [attribute:<attribute>]

        acl-right :: read | write | deny

        cib-spec :: xpath-spec | tag-ref-spec
        xpath-spec :: xpath:<xpath> | shortcut
        tag-ref-spec :: tag:<tag> | ref:<id> | tag:<tag> ref:<id>

        shortcut :: meta:<rsc>[:<attr>]
                    params:<rsc>[:<attr>]
                    utilization:<rsc>
                    location:<rsc>
                    property[:<attr>]
                    node[:<node>]
                    nodeattr[:<attr>]
                    nodeutil[:<node>]
                    status"""
        return self.__conf_object(cmd, *args)

    def rsc_test(self, cmd, *args):
        "usage: rsctest <rsc_id> [<rsc_id> ...] [<node_id> ...]"
        if not cib_factory.is_cib_sane():
            return False
        rc = True
        rsc_l = []
        node_l = []
        current = "r"
        for id in args:
            el = cib_factory.find_object(id)
            if not el:
                common_err("element %s does not exist" % id)
                rc = False
            elif current == "r" and xmlutil.is_resource(el.node):
                if xmlutil.is_container(el.node):
                    rsc_l += el.node.findall("primitive")
                else:
                    rsc_l.append(el.node)
            elif xmlutil.is_normal_node(el.node):
                current = "n"
                node_l.append(el.node.get("uname"))
            else:
                syntax_err((cmd, id), context='rsctest')
                return False
        if not rc:
            return False
        if not rsc_l:
            common_err("specify at least one resource")
            return False
        all_nodes = cib_factory.node_id_list()
        if not node_l:
            node_l = all_nodes
        return test_resources(rsc_l, node_l, all_nodes)

    def should_wait(self):
        return cib_factory.has_cib_changed()

    def end_game(self, no_questions_asked=False):
        ok = True
        if cib_factory.has_cib_changed():
            if no_questions_asked or not options.interactive or \
                utils.ask("There are changes pending. Do you want to commit them?"):
                ok = self.commit("commit")
        cib_factory.reset()
        return ok


class History(UserInterface):
    '''
    The history class
    '''
    lvl_name = "history"

    def __init__(self):
        UserInterface.__init__(self)
        self.cmd_table["source"] = (self.source, (1, 1), 1, 0)
        self.cmd_table["limit"] = (self.limit, (0, 2), 1, 0)
        self.cmd_table["refresh"] = (self.refresh, (0, 1), 1, 0)
        self.cmd_table["detail"] = (self.detail, (1, 1), 1, 0)
        self.cmd_table["setnodes"] = (self.setnodes, (1,), 1, 0)
        self.cmd_table["info"] = (self.info, (0, 0), 1, 0)
        self.cmd_table["latest"] = (self.latest, (0, 0), 1, 0)
        self.cmd_table["resource"] = (self.resource, (1,), 1, 0)
        self.cmd_table["node"] = (self.node, (1,), 1, 1)
        self.cmd_table["log"] = (self.log, (0,), 1, 0)
        self.cmd_table["peinputs"] = (self.peinputs, (0,), 1, 0)
        self.cmd_table["transition"] = (self.transition, (0,), 1, 0)
        self.cmd_table["diff"] = (self.diff, (2, 4), 1, 0)
        self.cmd_table["show"] = (self.show, (1, 2), 1, 0)
        self.cmd_table["graph"] = (self.graph, (1, 4), 1, 0)
        self.cmd_table["_dump"] = (self._dump, (1, 2), 1, 0)
        self.cmd_table["session"] = (self.session, (0, 2), 1, 0)
        self.cmd_table["exclude"] = (self.exclude, (0, 1), 1, 0)
        self.cmd_aliases.update({
            "limit": ("timeframe",),
        })
        utils.setup_aliases(self)
        self._set_source(options.history)
        self.current_session = None

    def _no_source(self):
        common_error("we have no source set yet! please use the source command")

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
        if to_dt and to_dt <= from_dt:
            common_err("%s - %s: bad period" % (from_time, to_time))
            return False
        return crm_report.set_period(from_dt, to_dt)

    def _check_source(self, src):
        'a (very) quick source check'
        if src == "live" or os.path.isfile(src) or os.path.isdir(src):
            return True
        else:
            common_error("source %s doesn't exist" % src)
            return False

    def _set_source(self, src, live_from_time=None):
        '''
        Have the last history source survive the History
        and Report instances
        '''
        common_debug("setting source to %s" % src)
        if not self._check_source(src):
            return False
        crm_report.set_source(src)
        options.history = src
        self.current_session = None
        to_time = ''
        if src == "live":
            from_time = time.ctime(live_from_time and live_from_time or (time.time() - 60*60))
        else:
            from_time = ''
        return self._set_period(from_time, to_time)

    def source(self, cmd, src=None):
        "usage: source {<dir>|<file>|live}"
        if src != options.history:
            return self._set_source(src)

    def limit(self, cmd, from_time='', to_time=''):
        "usage: limit [<from_time> [<to_time>]]"
        if options.history == "live" and not from_time:
            from_time = time.ctime(time.time() - 60*60)
        return self._set_period(from_time, to_time)

    def refresh(self, cmd, force=''):
        "usage: refresh"
        if options.history != "live":
            common_info("nothing to refresh if source isn't live")
            return False
        if force:
            if force != "force" and force != "--force":
                syntax_err((cmd, force), context='refresh')
                return False
            force = True
        return crm_report.refresh_source(force)

    def detail(self, cmd, detail_lvl):
        "usage: detail <detail_level>"
        detail_num = utils.convert2ints(detail_lvl)
        if not (isinstance(detail_num, int) and int(detail_num) >= 0):
            bad_usage(cmd, detail_lvl)
            return False
        return crm_report.set_detail(detail_lvl)

    def setnodes(self, cmd, *args):
        "usage: setnodes <node> [<node> ...]"
        if options.history != "live":
            common_info("setting nodes not necessary for existing reports, proceeding anyway")
        return crm_report.set_nodes(*args)

    def info(self, cmd):
        "usage: info"
        return crm_report.info()

    def latest(self, cmd):
        "usage: latest"
        if not utils.wait4dc("transition", not options.batch):
            return False
        self._set_source("live")
        crm_report.refresh_source()
        f = self._get_pe_byidx(-1)
        if not f:
            return False
        crm_report.show_transition_log(f)

    def resource(self, cmd, *args):
        "usage: resource <rsc> [<rsc> ...]"
        return crm_report.resource(*args)

    def node(self, cmd, *args):
        "usage: node <node> [<node> ...]"
        return crm_report.node(*args)

    def log(self, cmd, *args):
        "usage: log [<node> ...]"
        return crm_report.log(*args)

    def ptest(self, nograph, scores, utilization, actions, verbosity):
        'Send a decompressed self.pe_file to ptest'
        try:
            f = open(self.pe_file)
        except IOError, msg:
            common_err("open: %s" % msg)
            return False
        s = bz2.decompress(''.join(f))
        f.close()
        return utils.run_ptest(s, nograph, scores, utilization, actions, verbosity)

    def peinputs(self, cmd, *args):
        """usage: peinputs [{<range>|<number>} ...] [v]"""
        argl = list(args)
        opt_l = fetch_opts(argl, ["v"])
        if argl:
            l = []
            for s in argl:
                a = utils.convert2ints(s.split(':'))
                if a and len(a) == 2 and not utils.check_range(a):
                    common_err("%s: invalid peinputs range" % a)
                    return False
                l += crm_report.pelist(a, long=("v" in opt_l))
        else:
            l = crm_report.pelist(long=("v" in opt_l))
        if not l:
            return False
        s = '\n'.join(l)
        utils.page_string(s)

    def _get_pe_byname(self, s):
        l = crm_report.find_pe_files(s)
        if len(l) == 0:
            common_err("%s: path not found" % s)
            return None
        elif len(l) > 1:
            common_err("%s: path ambiguous" % s)
            return None
        return l[0]

    def _get_pe_byidx(self, idx):
        l = crm_report.pelist()
        if len(l) < abs(idx):
            if idx == -1:
                common_err("no transitions found in the source")
            else:
                common_err("PE input file for index %d not found" % (idx+1))
            return None
        return l[idx]

    def _get_pe_bynum(self, n):
        l = crm_report.pelist([n])
        if len(l) == 0:
            common_err("PE file %d not found" % n)
            return None
        elif len(l) > 1:
            common_err("PE file %d ambiguous" % n)
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
        ptestlike(self.ptest, 'vv', "transition", opt_l)
        return crm_report.show_transition_log(f)

    def _display_dot(self, f):
        if not user_prefs.dotty:
            common_err("install graphviz to draw transition graphs")
            return False
        f = crm_report.pe2dot(f)
        if not f:
            common_err("dot file not found in the report")
            return False
        utils.show_dot_graph(f, keep_file=True, desc="configuration graph")
        return True

    def _pe2shadow(self, f, argl):
        try:
            name = argl[0]
        except:
            name = os.path.basename(f).replace(".bz2", "")
        common_info("transition %s saved to shadow %s" % (f, name))
        return xmlutil.pe2shadow(f, name)

    def transition(self, cmd, *args):
        """usage: transition [<number>|<index>|<file>] [nograph] [v...] [scores] [actions] [utilization]
        transition showdot [<number>|<index>|<file>]
        transition log [<number>|<index>|<file>]
        transition save [<number>|<index>|<file> [name]]"""
        argl = list(args)
        subcmd = "show"
        if argl and argl[0] in ("showdot", "log", "save"):
            subcmd = argl[0]
            del argl[0]
        if subcmd == "show":
            opt_l = fetch_opts(argl, ptest_options)
        if argl:
            f = self._get_pe_input(argl[0])
            del argl[0]
        else:
            f = self._get_pe_byidx(-1)
        if (subcmd == "save" and len(argl) > 1) or \
                (subcmd in ("show", "showdot", "log") and argl):
            syntax_err(args, context="transition")
            return False
        if not f:
            return False
        if subcmd == "show":
            common_info("running ptest with %s" % f)
            rc = self._show_pe(f, opt_l)
        elif subcmd == "showdot":
            rc = self._display_dot(f)
        elif subcmd == "save":
            rc = self._pe2shadow(f, argl)
        else:
            rc = crm_report.show_transition_log(f, True)
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
        cib_factory.refresh()
        if not cib_factory.is_cib_sane():
            return False
        set_obj = mkset_obj()
        return set_obj

    def _pe_config_noclr(self, pe_f):
        '''Configuration with no formatting (no colors).'''
        return self._pe_config_obj(pe_f).repr_nopretty()

    def _pe_config_plain(self, pe_f):
        '''Configuration with no formatting (but with colors).'''
        return self._pe_config_obj(pe_f).repr(format=0)

    def _pe_config(self, pe_f):
        '''Formatted configuration.'''
        return self._pe_config_obj(pe_f).repr()

    def _pe_status(self, pe_f):
        '''Return status as a string.'''
        self._setup_cib_env(pe_f)
        rc, s = crm_mon()
        if rc != 0:
            if s:
                common_err("crm_mon exited with code %d and said: %s" %
                           (rc, s))
            else:
                common_err("crm_mon exited with code %d" % rc)
            return None
        return s

    def _pe_status_nohdr(self, pe_f):
        '''Return status (without header) as a string.'''
        self._setup_cib_env(pe_f)
        rc, s = crm_mon()
        if rc != 0:
            common_err("crm_mon exited with code %d and said: %s" %
                       (rc, s))
            return None
        l = s.split('\n')
        for i, ln in enumerate(l):
            if ln == "":
                break
        try:
            while l[i] == "":
                i += 1
        except:
            pass
        return '\n'.join(l[i:])

    def _get_diff_pe_input(self, t):
        if t != "live":
            return self._get_pe_input(t)
        if not utils.get_dc():
            common_err("cluster not running")
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

    def _unidiff(self, s1, s2, t1, t2):
        s = None
        f1 = utils.str2tmp(s1)
        f2 = utils.str2tmp(s2)
        if f1 and f2:
            rc, s = utils.get_stdout("diff -U 0 -d -b --label %s --label %s %s %s" % (t1, t2, f1, f2))
        try:
            os.unlink(f1)
        except:
            pass
        try:
            os.unlink(f2)
        except:
            pass
        return s

    def _diffhtml(self, s1, s2, t1, t2):
        import difflib
        fromlines = s1.split('\n')
        tolines = s2.split('\n')
        diff_l = difflib.HtmlDiff(wrapcolumn=60).make_table(
            fromlines, tolines, t1, t2)
        return ''.join(diff_l)

    def _diff(self, pe_fun, t1, t2, html=False):
        s1 = self._render_pe(pe_fun, t1)
        s2 = self._render_pe(pe_fun, t2)
        if not s1 or not s2:
            return None
        if html:
            s = self._diffhtml(s1, s2, t1, t2)
        else:
            s = self._unidiff(s1, s2, t1, t2)
        return s

    def _common_pe_render_check(self, cmd, opt_l, *args):
        if levels.previous().myname() == "cibconfig" \
                and cib_factory.has_cib_changed():
            common_err("please try again after committing CIB changes")
            return False
        argl = list(args)
        supported_l = ["status"]
        if cmd == "diff":
            supported_l.append("html")
        opt_l += fetch_opts(argl, supported_l)
        if argl:
            syntax_err(' '.join(argl), context=cmd)
            return False
        return True

    def _dump(self, cmd, t, *args):
        '''dump configuration or status to a file and print file
        name.
        NB: The configuration is color rendered, but note that
        that depends on the current value of the TERM variable.
        '''
        opt_l = []
        if not self._common_pe_render_check(cmd, opt_l, *args):
            return False
        if "status" in opt_l:
            s = self._render_pe(self._pe_status_nohdr, t)
        else:
            s = utils.term_render(self._render_pe(self._pe_config_plain, t))
        if levels.previous().myname() == "cibconfig":
            cib_factory.refresh()
        if not s:
            return False
        print utils.str2tmp(s)

    def show(self, cmd, t, *args):
        "usage: show <pe> [status]"
        opt_l = []
        if not self._common_pe_render_check(cmd, opt_l, *args):
            return False
        showfun = self._pe_config
        if "status" in opt_l:
            showfun = self._pe_status
        s = self._render_pe(showfun, t)
        if levels.previous().myname() == "cibconfig":
            cib_factory.refresh()
        if not s:
            return False
        utils.page_string(s)

    def graph(self, cmd, t, *args):
        "usage: graph <pe> [<gtype> [<file> [<img_format>]]]"
        pe_f = self._get_diff_pe_input(t)
        if not pe_f:
            return False
        rc, gtype, outf, ftype = _graph_args(args)
        if not rc:
            return False
        rc, d = utils.load_graphviz_file(vars.graphviz_user_file)
        if rc and d:
            vars.graph = d
        set_obj = self._pe_config_obj(pe_f)
        if not outf:
            rc = set_obj.show_graph(gtype)
        elif gtype == ftype:
            rc = set_obj.save_graph(gtype, outf)
        else:
            rc = set_obj.graph_img(gtype, outf, ftype)
        if levels.previous().myname() == "cibconfig":
            cib_factory.refresh()
        return rc

    def diff(self, cmd, t1, t2, *args):
        "usage: diff <pe> <pe> [status] [html]"
        opt_l = []
        if not self._common_pe_render_check(cmd, opt_l, *args):
            return False
        showfun = self._pe_config_plain
        mkhtml = "html" in opt_l
        if "status" in opt_l:
            showfun = self._pe_status_nohdr
        elif mkhtml:
            showfun = self._pe_config_noclr
        s = self._diff(showfun, t1, t2, html=mkhtml)
        if levels.previous().myname() == "cibconfig":
            cib_factory.refresh()
        if s == None:
            return False
        if not mkhtml:
            utils.page_string(s)
        else:
            sys.stdout.writelines(s)

    def session(self, cmd, subcmd=None, name=None):
        "usage: session [{save|load|delete} <name> | pack [<name>] | update | list]"
        if not subcmd:
            print "current session: %s" % self.current_session
            return True
        # verify arguments
        if subcmd not in ("save", "load", "pack", "delete", "list", "update"):
            common_err("unknown history session subcmd: %s" % subcmd)
            return False
        if name:
            if subcmd not in ("save", "load", "pack", "delete"):
                syntax_err(subcmd, context='session')
                return False
            if not utils.is_filename_sane(name):
                return False
        elif subcmd not in ("list", "update", "pack"):
            syntax_err(subcmd, context='session')
            return False
        elif subcmd in ("update", "pack") and not self.current_session:
            common_err("need to load a history session before update/pack")
            return False
        # do work
        if not name:
            # some commands work on the existing session
            name = self.current_session
        rc = crm_report.manage_session(subcmd, name)
        # set source appropriately
        if rc and subcmd in ("save", "load"):
            options.history = crm_report.get_source()
            crm_report.prepare_source()
            self.current_session = name
        elif rc and subcmd == "delete":
            if name == self.current_session:
                common_info("current history session deleted, setting source to live")
                self._set_source("live")
        return rc

    def exclude(self, cmd, arg=None):
        "usage: exclude [<regex>|clear]"
        if not arg:
            rc = crm_report.manage_excludes("show")
        elif arg == "clear":
            rc = crm_report.manage_excludes("clear")
        else:
            rc = crm_report.manage_excludes("add", arg)
        return rc


class Site(UserInterface):
    '''
    The site class
    '''
    lvl_name = "site"
    crm_ticket = {
        'grant': "crm_ticket -t '%s' -g",
        'revoke': "crm_ticket -t '%s' -r",
        'delete': "crm_ticket -t '%s' -D granted",
        'standby': "crm_ticket -t '%s' -s",
        'activate': "crm_ticket -t '%s' -a",
        'show': "crm_ticket -t '%s' -G granted",
        'time': "crm_ticket -t '%s' -G last-granted",
    }

    def __init__(self):
        UserInterface.__init__(self)
        self.cmd_table["ticket"] = (self.ticket, (2, 2), 1, 0)
        utils.setup_aliases(self)

    def ticket(self, cmd, subcmd, ticket):
        "usage: ticket {grant|revoke|standby|activate|show|time|delete} <ticket>"
        try:
            attr_cmd = self.crm_ticket[subcmd]
        except KeyError:
            bad_usage(cmd, '%s %s' % (subcmd, ticket))
            return False
        if not utils.is_name_sane(ticket):
            return False
        if subcmd not in ("show", "time"):
            return utils.ext_cmd(attr_cmd % ticket) == 0
        rc, l = utils.stdout2list(attr_cmd % ticket)
        try:
            val = l[0]
        except IndexError:
            common_warn("apparently nothing to show for ticket %s" % ticket)
            return False
        if subcmd == "show":
            if val == "false":
                print "ticket %s is revoked" % ticket
            elif val == "true":
                print "ticket %s is granted" % ticket
            else:
                common_warn("unexpected value for ticket %s: %s" % (ticket, val))
                return False
        else:  # time
            if not utils.is_int(val):
                common_warn("unexpected value for ticket %s: %s" % (ticket, val))
                return False
            if val == "-1":
                print "%s: no such ticket" % ticket
                return False
            print "ticket %s last time granted on %s" % (ticket, time.ctime(int(val)))


crm_mon_prog = "crm_mon"


def crm_mon(opts=''):
    """Run crm_mon -1
    """
    status_cmd = "%s -1 %s" % (crm_mon_prog, opts)
    return utils.get_stdout(utils.add_sudo(status_cmd))


class TopLevel(UserInterface):
    '''
    The top level.
    '''
    lvl_name = "."
    crm_mon_opts = {
        "bynode": "-n",
        "inactive": "-r",
        "ops": "-o",
        "timing": "-t",
        "failcounts": "-f",
    }

    def __init__(self):
        UserInterface.__init__(self)
        self.cmd_table['cib'] = CibShadow
        self.cmd_table['resource'] = RscMgmt
        self.cmd_table['configure'] = CibConfig
        self.cmd_table['node'] = NodeMgmt
        self.cmd_table['options'] = CliOptions
        self.cmd_table['history'] = History
        self.cmd_table['site'] = Site
        self.cmd_table['status'] = (self.status, (0, 5), 0, 0)
        self.cmd_table['ra'] = RA
        utils.setup_aliases(self)
        load_init_help_tab(self.help_table, self.cmd_table.keys())
        add_static_help(self.help_table)
        utils.setup_help_aliases(self)

    def status(self, cmd, *args):
        """usage: status [<option> ...]
            option :: bynode | inactive | ops | timing | failcounts
        """
        l = []
        for par in args:
            if par in self.crm_mon_opts:
                l.append(self.crm_mon_opts[par])
            else:
                syntax_err((cmd, par), context='status')
                return False
        rc, s = crm_mon(' '.join(l))
        if rc != 0:
            common_err("crm_mon exited with code %d and said: %s" %
                       (rc, s))
            return False
        else:
            utils.page_string(s)

help_sys = HelpSystem()
user_prefs = UserPrefs.getInstance()
options = Options.getInstance()
err_buf = ErrorBuffer.getInstance()
vars = Vars.getInstance()
levels = Levels.getInstance(TopLevel)
cib_status = CibStatus.getInstance()
cib_factory = CibFactory.getInstance()
crm_report = Report.getInstance()
# vim:ts=4:sw=4:et:
