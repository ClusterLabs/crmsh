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
import userdir

user_prefs = UserPrefs.getInstance()
options = Options.getInstance()
_yesno = completers.choice(['yes', 'no'])


def _getprefs(opt):
    return completers.call(user_prefs.choice_list, opt)


class CliOptions(command.UI):
    '''
    Manage user preferences
    '''
    name = "options"

    @command.name('skill-level')
    @command.completers(_getprefs('skill_level'))
    def do_skill_level(self, context, level):
        """usage: skill-level <level>
        level: operator | administrator | expert"""
        return user_prefs.set_pref('skill-level', level)

    def do_editor(self, context, program):
        "usage: editor <program>"
        return user_prefs.set_pref('editor', program)

    def do_pager(self, context, program):
        "usage: pager <program>"
        return user_prefs.set_pref('pager', program)

    def do_user(self, context, crm_user=''):
        "usage: user [<crm_user>]"
        return user_prefs.set_pref('user', crm_user)

    @command.completers(_getprefs('output'))
    def do_output(self, context, output_type):
        "usage: output <type>"
        return user_prefs.set_pref("output", output_type)

    def do_colorscheme(self, context, colors):
        "usage: colorscheme <colors>"
        return user_prefs.set_pref("colorscheme", colors)

    @command.name('check-frequency')
    @command.completers(_getprefs('check_frequency'))
    def do_check_frequency(self, context, freq):
        "usage: check-frequency <freq>"
        return user_prefs.set_pref("check-frequency", freq)

    @command.name('check-mode')
    @command.completers(_getprefs('check_mode'))
    def do_check_mode(self, context, mode):
        "usage: check-mode <mode>"
        return user_prefs.set_pref("check-mode", mode)

    @command.name('sort-elements')
    @command.completers(_yesno)
    def do_sort_elements(self, context, opt):
        "usage: sort-elements {yes|no}"
        return user_prefs.set_pref("sort-elements", opt)

    @command.completers(_yesno)
    def do_wait(self, context, opt):
        "usage: wait {yes|no}"
        return user_prefs.set_pref("wait", opt)

    @command.name('add-quotes')
    @command.completers(_yesno)
    def do_add_quotes(self, context, opt):
        "usage: add-quotes {yes|no}"
        return user_prefs.set_pref("add-quotes", opt)

    @command.name('manage-children')
    @command.completers(_getprefs('manage_children'))
    def do_manage_children(self, context, opt):
        "usage: manage-children <option>"
        return user_prefs.set_pref("manage-children", opt)

    @command.completers(completers.call(user_prefs.all_options))
    def do_show(self, context, option=None):
        "usage: show [option]"
        if option is None:
            return user_prefs.write_rc(sys.stdout)
        return user_prefs.print_option(option)

    def do_save(self, context):
        "usage: save"
        return user_prefs.save_options(userdir.RC_FILE)

    def do_reset(self, context):
        "usage: reset"
        return user_prefs.reset_options()

    def end_game(self, no_questions_asked=False):
        if no_questions_asked and not options.interactive:
            self.do_save(None)

# vim:ts=4:sw=4:et:
