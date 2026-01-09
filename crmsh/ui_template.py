# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import os
import re
import shlex
from . import command
from . import completers as compl
from . import utils
from . import config
from . import userdir
from . import options
from .template import LoadTemplate
from .cliformat import cli_format
from .cibconfig import mkset_obj, cib_factory
from . import log


logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)


def check_transition(inp, state, possible_l):
    if state not in possible_l:
        logger.error("input (%s) in wrong state %s", inp, state)
        return False
    return True


def _unique_config_name(tmpl):
    n = 0
    while n < 99:
        c = "%s-%d" % (tmpl, n)
        if not os.path.isfile("%s/%s" % (userdir.CRMCONF_DIR, c)):
            return c
        n += 1
    raise ValueError("Failed to generate unique configuration name")


class Template(command.UI):
    '''
    Configuration templates.
    '''
    name = "template"

    def __init__(self):
        command.UI.__init__(self)
        self.curr_conf = ''
        self.init_dir()

    @command.skill_level('administrator')
    @command.completers_repeating(compl.null, compl.call(utils.listtemplates))
    def do_new(self, context, name, *args):
        "usage: new [<config>] <template> [<template> ...] [params name=value ...]"
        if not utils.is_filename_sane(name):
            return False
        if os.path.isfile("%s/%s" % (userdir.CRMCONF_DIR, name)):
            logger.error("config %s exists; delete it first", name)
            return False
        lt = LoadTemplate(name)
        rc = True
        mode = 0
        params = {"id": name}
        loaded_template = False
        for s in args:
            if mode == 0 and s == "params":
                mode = 1
            elif mode == 1:
                a = s.split('=')
                if len(a) != 2:
                    logger_utils.syntax_err(args, context='new')
                    rc = False
                else:
                    params[a[0]] = a[1]
            elif lt.load_template(s):
                loaded_template = True
            else:
                rc = False
        if not loaded_template:
            if name not in utils.listtemplates():
                logger.error("Expected template argument")
                return False
            tmpl = name
            name = _unique_config_name(tmpl)
            lt = LoadTemplate(name)
            lt.load_template(tmpl)
        if rc:
            lt.post_process(params)
        if not rc or not lt.write_config(name):
            return False
        self.curr_conf = name

    @command.skill_level('administrator')
    @command.completers(compl.call(utils.listconfigs))
    def do_delete(self, context, name, force=''):
        "usage: delete <config> [force]"
        if force:
            if force != "force" and force != "--force":
                logger_utils.syntax_err((context.get_command_name(), force), context='delete')
                return False
        if not self.config_exists(name):
            return False
        if name == self.curr_conf:
            if not force and not options.force and \
                not utils.ask("Config %s is currently in use. Do you really want to delete it?" % name):
                return False
            else:
                self.curr_conf = ''
        os.remove("%s/%s" % (userdir.CRMCONF_DIR, name))

    @command.skill_level('administrator')
    @command.completers(compl.call(utils.listconfigs))
    def do_load(self, context, name=''):
        "usage: load [<config>]"
        if not name:
            self.curr_conf = ''
            return True
        if not self.config_exists(name):
            return False
        self.curr_conf = name

    @command.skill_level('administrator')
    @command.completers(compl.call(utils.listconfigs))
    def do_edit(self, context, name=''):
        "usage: edit [<config>]"
        if not name and not self.curr_conf:
            logger.error("please load a config first")
            return False
        if name:
            if not self.config_exists(name):
                return False
            utils.edit_file("%s/%s" % (userdir.CRMCONF_DIR, name))
        else:
            utils.edit_file("%s/%s" % (userdir.CRMCONF_DIR, self.curr_conf))

    @command.completers(compl.call(utils.listconfigs))
    def do_show(self, context, name=''):
        "usage: show [<config>]"
        if not name and not self.curr_conf:
            logger.error("please load a config first")
            return False
        if name:
            if not self.config_exists(name):
                return False
            print(self.process(name))
        else:
            print(self.process())

    @command.skill_level('administrator')
    @command.completers(compl.join(compl.call(utils.listconfigs),
                                   compl.choice(['replace', 'update'])),
                        compl.call(utils.listconfigs))
    def do_apply(self, context, *args):
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
            logger.error("please load a config first")
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

    @command.completers(compl.choice(['configs', 'templates']))
    def do_list(self, context, templates=''):
        "usage: list [configs|templates]"
        if templates == "templates":
            utils.multicolumn(utils.listtemplates())
        elif templates == "configs":
            utils.multicolumn(utils.listconfigs())
        else:
            print("Templates:")
            utils.multicolumn(utils.listtemplates())
            print("\nConfigurations:")
            utils.multicolumn(utils.listconfigs())

    def init_dir(self):
        '''Create the conf directory, link to templates'''
        if not os.path.isdir(userdir.CRMCONF_DIR):
            try:
                os.makedirs(userdir.CRMCONF_DIR)
            except os.error as msg:
                logger.error("makedirs: %s", msg)

    def get_depends(self, tmpl):
        '''return a list of required templates'''
        # Not used. May need it later.
        try:
            templatepath = os.path.join(config.path.sharedir, 'templates', tmpl)
            tf = open(templatepath, "r")
        except IOError as msg:
            logger.error("open: %s", msg)
            return
        l = []
        for s in tf:
            a = s.split()
            if len(a) >= 2 and a[0] == '%depends_on':
                l += a[1:]
        tf.close()
        return l

    def config_exists(self, name):
        if not utils.is_filename_sane(name):
            return False
        if not os.path.isfile("%s/%s" % (userdir.CRMCONF_DIR, name)):
            logger.error("%s: no such config", name)
            return False
        return True

    def replace_params(self, s, user_data):
        change = False
        for i, word in enumerate(s):
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
                l2.append(cli_format(piece2, break_lines=True))
        return '\n'.join(l2)

    def process(self, config=''):
        '''Create a cli configuration from the current config'''
        try:
            f = open("%s/%s" % (userdir.CRMCONF_DIR, config or self.curr_conf), 'r')
        except IOError as msg:
            logger.error("open: %s", msg)
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
        with logger_utils.line_number():
            rc = True
            for inp in f:
                inp = utils.to_ascii(inp)
                logger_utils.incr_lineno()
                if inp.startswith('#'):
                    continue
                inp = inp.strip()
                try:
                    s = shlex.split(inp)
                except ValueError as msg:
                    logger.error(msg)
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
                        logger.warning("user data in wrong state %s", state)
                    if len(s) < 2:
                        logger.warning("parameter name missing")
                    elif len(s) == 2:
                        if data_reqd:
                            logger.error("required parameter %s not set", s[1])
                            rc = False
                    elif len(s) == 3:
                        user_data["%s:%s" % (pfx, s[1])] = s[2]
                    else:
                        logger.error("%s: syntax error", inp)
                elif s[0] == "%generate" and check_transition(inp, state, (DATA,)):
                    state = GENERATE
                    piece = []
                elif state == GENERATE and s:
                    piece.append(s)
                else:
                    logger.error("<%s> unexpected", inp)
            if piece:
                l.append(piece)
        f.close()
        if not rc:
            return ''
        return self.generate(l, user_data)


# vim:ts=4:sw=4:et:
