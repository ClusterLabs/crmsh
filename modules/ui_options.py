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

import sys
import command
import completers
from msg import UserPrefs, Options


def _getprefs(opt):
    return completers.call(user_prefs.choice_list, opt)

_yesno = completers.choice(['yes', 'no'])


class CliOptions(command.UI):
    '''
    Manage user preferences
    '''
    name = "options"

    @command.name('skill-level')
    @command.completer_list(_getprefs('skill_level'))
    def do_skill_level(self, context, skill_level):
        """usage: skill-level <level>
        level: operator | administrator | expert"""
        return user_prefs.set_pref("skill-level", skill_level)

    def do_editor(self, context, prog):
        "usage: editor <program>"
        return user_prefs.set_pref("editor", prog)

    def do_pager(self, context, prog):
        "usage: pager <program>"
        return user_prefs.set_pref("pager", prog)

    def do_user(self, context, user=''):
        "usage: user [<crm_user>]"
        return user_prefs.set_pref("user", user)

    @command.completer_list(_getprefs('output'))
    def do_output(self, context, otypes):
        "usage: output <type>"
        return user_prefs.set_pref("output", otypes)

    def do_colorscheme(self, context, scheme):
        "usage: colorscheme <colors>"
        return user_prefs.set_pref("colorscheme", scheme)

    @command.name('check-frequency')
    @command.completer_list(_getprefs('check_frequency'))
    def do_check_frequency(self, context, freq):
        "usage: check-frequency <freq>"
        return user_prefs.set_pref("check-frequency", freq)

    @command.name('check-mode')
    @command.completer_list(_getprefs('check_mode'))
    def do_check_mode(self, context, mode):
        "usage: check-mode <mode>"
        return user_prefs.set_pref("check-mode", mode)

    @command.name('sort-elements')
    @command.completer_list(_yesno)
    def do_sort_elements(self, context, opt):
        "usage: sort-elements {yes|no}"
        return user_prefs.set_pref("sort-elements", opt)

    @command.completer_list(_yesno)
    def do_wait(self, context, opt):
        "usage: wait {yes|no}"
        return user_prefs.set_pref("wait", opt)

    @command.name('add-quotes')
    @command.completer_list(_yesno)
    def do_add_quotes(self, context, opt):
        "usage: add-quotes {yes|no}"
        return user_prefs.set_pref("add-quotes", opt)

    @command.name('manage-children')
    @command.completer_list(_getprefs('manage_children'))
    def do_manage_children(self, context, opt):
        "usage: manage-children <option>"
        return user_prefs.set_pref("manage-children", opt)

    def do_show(self, context):
        "usage: show"
        return user_prefs.write_rc(sys.stdout)

    def do_save(self, context):
        "usage: save"
        return user_prefs.save_options(vars.rc_file)

    def do_reset(self, context):
        "usage: reset"
        return user_prefs.reset_options()

    def end_game(self, no_questions_asked=False):
        if no_questions_asked and not options.interactive:
            self.save_options("save")

user_prefs = UserPrefs.getInstance()
options = Options.getInstance()
# vim:ts=4:sw=4:et:
