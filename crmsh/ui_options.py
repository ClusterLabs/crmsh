# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

from . import command
from . import completers
from . import config
from . import options

_yesno = completers.choice(['yes', 'no'])

_legacy_map = {
    'editor': ('core', 'editor'),
    'pager': ('core', 'pager'),
    'user': ('core', 'user'),
    'skill_level': ('core', 'skill_level'),
    'sort_elements': ('core', 'sort_elements'),
    'check_frequency': ('core', 'check_frequency'),
    'check_mode': ('core', 'check_mode'),
    'wait': ('core', 'wait'),
    'add_quotes': ('core', 'add_quotes'),
    'manage_children': ('core', 'manage_children'),
    'debug': ('core', 'debug'),
    'ptest': ('core', 'ptest'),
    'dotty': ('core', 'dotty'),
    'dot': ('core', 'dot'),
    'output': ('color', 'style'),
    'colorscheme': ('color', 'colorscheme'),
}


def _legacy_set_pref(name, value):
    'compatibility with old versions'
    name = name.replace('-', '_')
    if name == 'colorscheme':
        return  # TODO
    opt = _legacy_map.get(name)
    if opt:
        config.set_option(opt[0], opt[1], value)


def _getprefs(opt):
    'completer for legacy options'
    opt = opt.replace('-', '_')
    if opt == 'colorscheme':
        return ('black', 'blue', 'green', 'cyan',
                'red', 'magenta', 'yellow', 'white', 'normal')
    opt = _legacy_map.get(opt)
    if opt:
        return config.complete(*opt)
    return []


def _set_completer(args):
    opt = args[-1]
    opts = opt.split('.')
    if len(opts) != 2:
        return []
    return config.complete(*opts)


class CliOptions(command.UI):
    '''
    Manage user preferences
    '''
    name = "options"

    @command.completers(completers.choice(config.get_all_options()), _set_completer)
    def do_set(self, context, option, value):
        '''usage: set <option> <value>'''
        parts = option.split('.')
        if len(parts) != 2:
            context.fatal_error("Unknown option: " + option)
        config.set_option(parts[0], parts[1], value)

    @command.name('skill-level')
    @command.alias('skill_level')
    @command.completers(_getprefs('skill_level'))
    def do_skill_level(self, context, level):
        """usage: skill-level <level>
        level: operator | administrator | expert"""
        return _legacy_set_pref('skill-level', level)

    def do_editor(self, context, program):
        "usage: editor <program>"
        return _legacy_set_pref('editor', program)

    def do_pager(self, context, program):
        "usage: pager <program>"
        return _legacy_set_pref('pager', program)

    def do_user(self, context, crm_user=''):
        "usage: user [<crm_user>]"
        return _legacy_set_pref('user', crm_user)

    @command.completers(_getprefs('output'))
    def do_output(self, context, output_type):
        "usage: output <type>"
        _legacy_set_pref("output", output_type)
        from . import term
        term.init()

    def do_colorscheme(self, context, colors):
        "usage: colorscheme <colors>"
        return _legacy_set_pref("colorscheme", colors)

    @command.name('check-frequency')
    @command.alias('check_frequency')
    @command.completers(_getprefs('check_frequency'))
    def do_check_frequency(self, context, freq):
        "usage: check-frequency <freq>"
        return _legacy_set_pref("check-frequency", freq)

    @command.name('check-mode')
    @command.alias('check_mode')
    @command.completers(_getprefs('check_mode'))
    def do_check_mode(self, context, mode):
        "usage: check-mode <mode>"
        return _legacy_set_pref("check-mode", mode)

    @command.name('sort-elements')
    @command.alias('sort_elements')
    @command.completers(_yesno)
    def do_sort_elements(self, context, opt):
        "usage: sort-elements {yes|no}"
        return _legacy_set_pref("sort-elements", opt)

    @command.completers(_yesno)
    def do_wait(self, context, opt):
        "usage: wait {yes|no}"
        return _legacy_set_pref("wait", opt)

    @command.name('add-quotes')
    @command.alias('add_quotes')
    @command.completers(_yesno)
    def do_add_quotes(self, context, opt):
        "usage: add-quotes {yes|no}"
        return _legacy_set_pref("add-quotes", opt)

    @command.name('manage-children')
    @command.alias('manage_children')
    @command.completers(_getprefs('manage_children'))
    def do_manage_children(self, context, opt):
        "usage: manage-children <option>"
        return _legacy_set_pref("manage-children", opt)

    @command.alias('list')
    @command.completers(completers.choice(config.get_all_options()))
    def do_show(self, context, option=None):
        "usage: show [all | <option>]"
        from . import utils
        opts = config.get_configured_options() if option is None else config.get_all_options()

        def show_options(fn):
            s = ''
            for opt in opts:
                if fn(opt):
                    parts = opt.split('.')
                    val = (opt, config.get_option(parts[0], parts[1], raw=True))
                    s += "%s = %s\n" % val
            utils.page_string(s)

        if option == 'all' or option is None:
            show_options(lambda o: True)
        else:
            show_options(lambda o: o.startswith(option) or o.endswith(option))

    def do_save(self, context):
        "usage: save"
        config.save()

    def do_reset(self, context):
        "usage: reset"
        config.reset()

    def end_game(self, no_questions_asked=False):
        if no_questions_asked and not options.interactive:
            self.do_save(None)

# vim:ts=4:sw=4:et:
