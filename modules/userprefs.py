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

import os
import sys

from singletonmixin import Singleton
from term import TerminalController


class Options(Singleton):
    interactive = False
    batch = False
    regression_tests = False
    profile = ""
    history = "live"
    file = ""
    shadow = ""

options = Options.getInstance()
termctrl = TerminalController.getInstance()


def is_program(prog):
    """Is this program available?"""
    for p in os.getenv("PATH").split(os.pathsep):
        filename = os.path.join(p, prog)
        if os.path.isfile(filename) and os.access(filename, os.X_OK):
            return True


def find_program(envvar, proglist):
    if envvar and os.getenv(envvar):
        return os.getenv(envvar)
    for prog in proglist:
        if is_program(prog):
            return prog


def is_boolean_true(opt):
    return opt.lower() in ("yes", "true", "on", "1")


def is_boolean_false(opt):
    return opt.lower() in ("no", "false", "off", "0")


def is_boolean(opt):
    return is_boolean_true(opt) or is_boolean_false(opt)


def common_err(s):
    print >> sys.stderr, "ERROR: %s" % s


class Preference(object):
    '''
    Single user preference. Includes default and validation. set
    and get.
    '''

    def __init__(self, name, dflt, vtype):
        self.name = name
        self.dflt = dflt
        self.vtype = vtype
        self.reset()

    def validate(self, value):
        '''
        Is the value valid.
        '''
        return True

    def _preproc(self, value):
        '''Preprocess user's input'''
        return value

    def set(self, value):
        '''
        Set the preference.
        '''
        if not self.validate(value):
            return False
        self.value = self._preproc(value)
        return True

    def get(self):
        'Return setting.'
        return self.value

    def reset(self):
        'Reset value.'
        self.set(self.dflt)

    def __str__(self):
        'Return string representation.'
        if isinstance(self.value, basestring):
            return self.value
        else:
            return str(self.value)


class StringOpt(Preference):
    '''A string preference.'''  

    def __init__(self, name, dflt, ignored):
        Preference.__init__(self, name, dflt, "string")


class ProgramOpt(Preference):
    '''A program preference'''  

    def __init__(self, name, envvar, proglist):
        self.envvar = envvar
        self.proglist = proglist
        self.name = name
        self.vtype = "program"
        self.reset()

    def validate(self, value):
        '''Is the value valid.'''
        if not is_program(value):
            common_err("%s does not exist or is not a program" % value)
            return False
        return True

    def reset(self):
        '''Pick a program from a envvar, list.'''
        self.value = find_program(self.envvar, self.proglist)


class BooleanOpt(Preference):
    '''A true/false preference.'''  

    def __init__(self, name, dflt, ignored):
        Preference.__init__(self, name, dflt, "boolean")

    def validate(self, value):
        '''Is the value valid.'''
        if not is_boolean(value):
            common_err("%s not valid (yes or no are valid)" % value)
            return False
        return True

    def get(self):
        'Return setting.'
        return is_boolean_true(self.value)


class ChoiceOpt(Preference):
    '''A string preference with limited choice.'''  

    def __init__(self, name, dflt, choices):
        self.choices = choices
        Preference.__init__(self, name, dflt, "choice")

    def validate(self, value):
        '''Is the value valid.'''
        if value not in self.choices:
            common_err("%s not valid (choose one from %s)" %
                (value, ','.join(self.choices)))
        return (value in self.choices)


class DictOpt(ChoiceOpt):
    '''A skill level preference.'''  

    def __init__(self, name, dflt, choices):
        self.choices = choices
        Preference.__init__(self, name, dflt, "dict")

    def get(self):
        'Return setting.'
        try:
            return self.choices[self.value]
        except KeyError:
            return None


class MultiChoiceOpt(Preference):
    '''Multiple string preference with limited choice.'''  

    def __init__(self, name, dflt, choices):
        self.choices = choices
        Preference.__init__(self, name, dflt, "multi")

    def _preproc(self, value):
        '''Preprocess user's input'''
        return [x.strip() for x in value.split(',')]

    def validate(self, value):
        '''Is the value valid.'''
        l = self._preproc(value)
        for otype in l:
            if not otype in self.choices:
                common_err("%s not valid (choose one from %s)" %
                    (value, ','.join(self.choices)))
                return False
        return True

    def __str__(self):
        'Return string representation.'
        return ','.join(self.value)


class ColorOpt(MultiChoiceOpt):
    '''A list of terminal colors preference.'''  

    def __init__(self, name, dflt, ignored):
        Preference.__init__(self, name, dflt, "color")

    def validate(self, scheme):
        '''Is the color scheme valid.'''
        colors = self._preproc(scheme)
        if len(colors) != 6:
            common_err("bad color scheme: %s" % scheme)
            return False
        rc = True
        for c in colors:
            if not termctrl.is_color(c):
                common_err("%s is not a recognized color" % c)
                rc = False
        return rc


class UserPrefs(Singleton):
    '''
    Keep user preferences here.
    '''

    opt_dict = {
        "editor": (ProgramOpt, "EDITOR", ("vim", "vi", "emacs", "nano")),
        "pager": (ProgramOpt, "PAGER", ("less", "more", "pg")),
        "user": (StringOpt, "", ()),
        "skill_level": (DictOpt, "expert", 
            {"operator": 0, "administrator": 1, "expert": 2}),
        "output": (MultiChoiceOpt, "color", ("plain", "color", "uppercase")),
        "colorscheme": (ColorOpt, "yellow,normal,cyan,red,green,magenta", ()),
        "sort_elements": (BooleanOpt, "yes", ()),
        "check_frequency": (ChoiceOpt, "always", ("always", "on-verify", "never")),
        "check_mode": (ChoiceOpt, "strict", ("strict", "relaxed")),
        "wait": (BooleanOpt, "no", ()),
        "add_quotes": (BooleanOpt, "yes", ()),
        "manage_children": (ChoiceOpt, "ask", ("ask", "never", "always")),

        "force": (BooleanOpt, "no", ()),
        "debug": (BooleanOpt, "no", ()),
        "ptest": (ProgramOpt, "", ("ptest", "crm_simulate")),
        "dotty": (ProgramOpt, "", ("dotty",)),
        "dot": (ProgramOpt, "", ("dot",)),
    }
    # this defines the write order and what needs to be saved to
    # a rc file
    _prefs = ("editor", "pager", "user", "skill_level", "output",
        "colorscheme", "sort_elements", "check_frequency", "check_mode",
        "wait", "add_quotes", "manage_children")

    _options = {}

    def __init__(self):
        if self._options:
            return
        self.reset_options()

    def reset_options(self):
        for attr in self.opt_dict.keys():
            opt = self.opt_dict[attr]
            self._options[attr] = opt[0](attr, opt[1], opt[2])

    def _get_opt(self, name):
        int_name = name.replace("-", "_")
        try:
            return self.opt_dict[int_name], int_name
        except KeyError:
            common_err("unknown option: %s" % name)
            return None, None

    def __setattr__(self, name, value):
        opt, int_name = self._get_opt(name)
        if not opt or not int_name:
            return
        # if not defined, create an instance
        if int_name not in self._options:
            self._options[int_name] = opt[0](name, opt[1], opt[2])
        return self._options[int_name].set(value)

    def set_pref(self, name, value):
        return self.__setattr__(name, value)

    def __getattr__(self, name):
        opt, int_name = self._get_opt(name)
        if not int_name:
            return None
        return self._options[int_name].get()

    def is_check_always(self):
        '''
        Even though the frequency may be set to always, it doesn't
        make sense to do that with non-interactive sessions.
        '''
        return options.interactive and self.check_frequency == "always"

    def choice_list(self, attr):
        '''
        Return list of possible choices for multichoice, etc.
        '''
        try:
            return self.opt_dict[attr][2]
        except KeyError:
            return []

    def get_check_rc(self):
        '''
        If the check mode is set to strict, then on errors we
        return 2 which is the code for error. Otherwise, we
        pretend that errors are warnings.
        '''
        return self.check_mode == "strict" and 2 or 1

    def write_rc(self, f):
        for attr in self._prefs:
            n = attr.replace("_", "-")
            print >> f, '%s "%s"' % (n, self._options[attr])

    def print_option(self, name):
        try:
            key = name.replace('-', '_')
            print '%s "%s"' % (name, self._options[key])
        except KeyError:
            print >>sys.stderr, "ERROR: %s not set" % (name)

    def save_options(self, rc_file):
        #print "saving options to %s" % rc_file
        try:
            f = open(rc_file, "w")
        except IOError, msg:
            common_err("open: %s" % msg)
            return
        print >> f, 'options'
        self.write_rc(f)
        print >> f, 'end'
        f.close()

# vim:ts=4:sw=4:et:
