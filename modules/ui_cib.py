# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
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

import os
import glob
import command
import xmlutil
import utils
import ui_cibstatus
import vars

from tempfile import mkstemp
from msg import UserPrefs, Options
from msg import no_prog_err
from cibstatus import CibStatus
from cibconfig import CibFactory

import completers as compl

_NEWARGS = ('force', '--force', 'withstatus', 'empty')


class CibShadow(command.UI):
    '''
    CIB shadow management class
    '''
    name = "cib"
    extcmd = ">/dev/null </dev/null crm_shadow"
    extcmd_stdout = "</dev/null crm_shadow"

    def requires(self):
        if not utils.is_program('crm_shadow'):
            no_prog_err('crm_shadow')
            return False
        return True

    @command.level(ui_cibstatus.CibStatusUI)
    def do_cibconfig(self):
        pass

    @command.skill_level('administrator')
    @command.completers_repeating(compl.null, compl.choice(_NEWARGS))
    def do_new(self, context, *args):
        "usage: new [<shadow_cib>] [withstatus] [force] [empty]"
        argl = list(args)
        opt_l = utils.fetch_opts(argl, ["force", "--force", "withstatus", "empty"])
        if len(argl) > 1:
            context.fatal_error("Unexpected argument(s): " + ','.join(argl))

        name = None
        if argl:
            name = argl[0]
            if not utils.is_filename_sane(name):
                context.fatal_error("Bad filename: " + name)
            if name in (vars.tmp_cib_prompt, vars.live_cib_prompt):
                context.fatal_error("Shadow name '%s' is not allowed" % (name))
            del argl[0]
            vars.tmp_cib = False
        else:
            fd, fname = mkstemp(dir=xmlutil.cib_shadow_dir(), prefix="shadow.crmsh_")
            vars.tmpfiles.append(fname)
            name = os.path.basename(fname).replace("shadow.", "")
            vars.tmp_cib = True

        if "empty" in opt_l:
            new_cmd = "%s -e '%s'" % (self.extcmd, name)
        else:
            new_cmd = "%s -c '%s'" % (self.extcmd, name)
        if vars.tmp_cib or user_prefs.force or "force" in opt_l or "--force" in opt_l:
            new_cmd = "%s --force" % new_cmd
        if utils.ext_cmd(new_cmd) == 0:
            context.info("%s shadow CIB created" % name)
            self.use("use", name)
            if "withstatus" in opt_l:
                cib_status.load("shadow:%s" % name)

    def _find_pe(self, context, infile):
        'Find a pe input'
        for p in ("%s/%s", "%s/%s.bz2", "%s/pe-*-%s.bz2"):
            fl = glob.glob(p % (vars.pe_dir, infile))
            if fl:
                break
        if not fl:
            context.fatal_error("no %s pe input file" % infile)
        if len(fl) > 1:
            context.fatal_error("more than one %s pe input file: %s" %
                          (infile, ' '.join(fl)))
        if not fl[0]:
            context.fatal_error("bad %s pe input file" % infile)
        return fl[0]

    @command.skill_level('administrator')
    @command.completers(compl.null, compl.shadows)
    def do_pe_import(self, context, infile, name=None):
        "usage: import {<file>|<number>} [<shadow>]"
        if name and not utils.is_filename_sane(name):
            context.fatal_error("Bad filename: " + name)
        # where's the input?
        if not os.access(infile, os.F_OK):
            if "/" in infile:
                context.fatal_error(str(infile) + ": no such file")
            infile = self._find_pe(context, infile)
        if not name:
            name = os.path.basename(infile).replace(".bz2", "")
        if not xmlutil.pe2shadow(infile, name):
            context.fatal_error("Error copying PE file to shadow: %s -> %s" % (infile, name))
        # use the shadow and load the status from there
        return self.use("use", name, "withstatus")

    @command.skill_level('administrator')
    @command.completers(compl.shadows)
    def do_delete(self, context, name):
        "usage: delete <shadow_cib>"
        if not utils.is_filename_sane(name):
            context.fatal_error("Bad filename: " + name)
        if vars.cib_in_use == name:
            context.fatal_error("%s shadow CIB is in use" % name)
        if utils.ext_cmd("%s -D '%s' --force" % (self.extcmd, name)) == 0:
            context.info("%s shadow CIB deleted" % name)
        else:
            context.fatal_error("failed to delete %s shadow CIB" % name)

    @command.skill_level('administrator')
    @command.completers(compl.shadows)
    def do_reset(self, context, name):
        "usage: reset <shadow_cib>"
        if not utils.is_filename_sane(name):
            context.fatal_error("Bad filename: " + name)
        if utils.ext_cmd("%s -r '%s'" % (self.extcmd, name)) == 0:
            context.info("copied live CIB to %s" % name)
        else:
            context.fatal_error("failed to copy live CIB to %s" % name)

    @command.skill_level('administrator')
    @command.wait
    @command.completers(compl.shadows)
    def do_commit(self, context, name=None):
        "usage: commit [<shadow_cib>]"
        if name and not utils.is_filename_sane(name):
            context.fatal_error("Bad filename: " + name)
        if not name:
            name = vars.cib_in_use
        if not name:
            context.fatal_error("There is nothing to commit")
        if utils.ext_cmd("%s -C '%s' --force" % (self.extcmd, name)) == 0:
            context.info("committed '%s' shadow CIB to the cluster" % name)
        else:
            context.fatal_error("failed to commit the %s shadow CIB" % name)

    @command.skill_level('administrator')
    def do_diff(self, context):
        "usage: diff"
        rc, s = utils.get_stdout(utils.add_sudo("%s -d" % self.extcmd_stdout))
        utils.page_string(s)

    @command.skill_level('administrator')
    def do_list(self, context):
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
            if withstatus:
                cib_status.load("live")
            if vars.tmp_cib:
                utils.ext_cmd("%s -D '%s' --force" % (self.extcmd, vars.cib_in_use))
                vars.tmp_cib = False
            vars.cib_in_use = ''
            os.unsetenv(vars.shadow_envvar)
        else:
            os.putenv(vars.shadow_envvar, name)
            vars.cib_in_use = name
            if withstatus:
                cib_status.load("shadow:%s" % name)
        return True

    @command.skill_level('administrator')
    @command.completers(compl.join(compl.shadows, compl.choice(['live'])),
                        compl.choice(['withstatus']))
    def do_use(self, context, name='', withstatus=''):
        "usage: use [<shadow_cib>] [withstatus]"
        # check the name argument
        if name and not utils.is_filename_sane(name):
            context.fatal_error("Bad filename: " + name)
        if name and name != "live":
            if not os.access(xmlutil.shadowfile(name), os.F_OK):
                context.fatal_error("%s: no such shadow CIB" % name)
        if withstatus and withstatus != "withstatus":
            context.fatal_error("Expected 'withstatus', got '%s'" % (withstatus))
        # If invoked from configure
        # take special precautions
        if not context.previous_level_is("cibconfig"):
            return self._use(name, withstatus)
        if not cib_factory.has_cib_changed():
            ret = self._use(name, withstatus)
            # new CIB: refresh the CIB factory
            cib_factory.refresh()
            return ret
        saved_cib = vars.cib_in_use
        self._use(name, '')  # don't load the status yet
        if not cib_factory.is_current_cib_equal(silent=True):
            # user made changes and now wants to switch to a
            # different and unequal CIB; we refuse to cooperate
            context.error_message("the requested CIB is different from the current one")
            if user_prefs.force:
                context.info("CIB overwrite forced")
            elif not utils.ask("All changes will be dropped. Do you want to proceed?"):
                self._use(saved_cib, '')  # revert to the previous CIB
                return False
        return self._use(name, withstatus)  # now load the status too


user_prefs = UserPrefs.getInstance()
options = Options.getInstance()
cib_status = CibStatus.getInstance()
cib_factory = CibFactory.getInstance()

# vim:ts=4:sw=4:et:
