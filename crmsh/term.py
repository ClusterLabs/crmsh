# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.
import re
import sys

from . import constants

# Colors and output modes are plain ANSI escape sequences (see constants).
# They stay '' until init() finds that colored output is wanted, so that
# output built from them is simply uncolored otherwise.
# The attributes can be used directly:
#     >>> print('This is ' + term.colors.GREEN + 'green' + term.colors.NORMAL)
# Alternatively, `render()` replaces '${action}' with the string for 'action':
#     >>> print(term.render('This is ${GREEN}green${NORMAL}'))
# `colorize()` wraps a text in a named color:
#     >>> print(term.colorize('green', 'green'))

_ATTRS = "RED GREEN YELLOW BLUE MAGENTA CYAN BOLD UNDERLINE NORMAL".split()


class colors(object):
    # Foreground colors:
    BLUE = GREEN = CYAN = RED = MAGENTA = YELLOW = ''
    # Output modes:
    BOLD = ''            #: Turn on bold mode
    UNDERLINE = ''       #: Turn on underline mode
    NORMAL = ''          #: Turn off all modes
    RLIGNOREBEGIN = '\001'
    RLIGNOREEND = '\002'


def init():
    """
    Enable colors if stdout is a tty or the color style is 'color-always'.
    """
    # config imports userdir, which imports log, which imports term
    from . import config
    if not sys.stdout.isatty() and 'color-always' not in config.color.style:
        return
    for name in _ATTRS:
        setattr(colors, name, getattr(constants, name))


def render(template):
    """
    Replace each $-substitutions in the given template string with
    the corresponding terminal control string (if it's defined) or
    '' (if it's not).
    """
    def render_sub(match):
        s = match.group()
        return getattr(colors, s[2:-1].upper(), '')
    return re.sub(r'\${\w+}', render_sub, template)


def colorize(color, text):
    """
    Wrap text in the named color (e.g. "green"), or return it unchanged
    if colors are not enabled.
    """
    code = getattr(colors, color.upper(), "")
    if not code:
        return text
    return f"{code}{text}{colors.NORMAL}"


def is_color(s):
    return hasattr(colors, s.upper())

# vim:ts=4:sw=4:et:
