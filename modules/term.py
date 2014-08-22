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
import re

# from: http://code.activestate.com/recipes/475116/

"""
A module that can be used to portably generate formatted output to
a terminal.
Defines a set of instance variables whose
values are initialized to the control sequence necessary to
perform a given action.  These can be simply included in normal
output to the terminal:
    >>> print 'This is '+term.colors.GREEN+'green'+term.colors.NORMAL
Alternatively, the `render()` method can used, which replaces
'${action}' with the string required to perform 'action':
    >>> print term.render('This is ${GREEN}green${NORMAL}')
If the terminal doesn't support a given action, then the value of
the corresponding instance variable will be set to ''.  As a
result, the above code will still work on terminals that do not
support color, except that their output will not be colored.
Also, this means that you can test whether the terminal supports a
given action by simply testing the truth value of the
corresponding instance variable:
    >>> if term.colors.CLEAR_SCREEN:
    ...     print 'This terminal supports clearning the screen.'
Finally, if the width and height of the terminal are known, then
they will be stored in the `COLS` and `LINES` attributes.
"""


class colors(object):
    # Cursor movement:
    BOL = ''             #: Move the cursor to the beginning of the line
    UP = ''              #: Move the cursor up one line
    DOWN = ''            #: Move the cursor down one line
    LEFT = ''            #: Move the cursor left one char
    RIGHT = ''           #: Move the cursor right one char
    # Deletion:
    CLEAR_SCREEN = ''    #: Clear the screen and move to home position
    CLEAR_EOL = ''       #: Clear to the end of the line.
    CLEAR_BOL = ''       #: Clear to the beginning of the line.
    CLEAR_EOS = ''       #: Clear to the end of the screen
    # Output modes:
    BOLD = ''            #: Turn on bold mode
    BLINK = ''           #: Turn on blink mode
    DIM = ''             #: Turn on half-bright mode
    REVERSE = ''         #: Turn on reverse-video mode
    UNDERLINE = ''       #: Turn on underline mode
    NORMAL = ''          #: Turn off all modes
    # Cursor display:
    HIDE_CURSOR = ''     #: Make the cursor invisible
    SHOW_CURSOR = ''     #: Make the cursor visible
    # Terminal size:
    COLS = None          #: Width of the terminal (None for unknown)
    LINES = None         #: Height of the terminal (None for unknown)
    # Foreground colors:
    BLACK = BLUE = GREEN = CYAN = RED = MAGENTA = YELLOW = WHITE = ''
    # Background colors:
    BG_BLACK = BG_BLUE = BG_GREEN = BG_CYAN = ''
    BG_RED = BG_MAGENTA = BG_YELLOW = BG_WHITE = ''
    RLIGNOREBEGIN = '\001'
    RLIGNOREEND = '\002'

_STRING_CAPABILITIES = """
BOL=cr UP=cuu1 DOWN=cud1 LEFT=cub1 RIGHT=cuf1
CLEAR_SCREEN=clear CLEAR_EOL=el CLEAR_BOL=el1 CLEAR_EOS=ed BOLD=bold
BLINK=blink DIM=dim REVERSE=rev UNDERLINE=smul NORMAL=sgr0
HIDE_CURSOR=cinvis SHOW_CURSOR=cnorm""".split()

_COLORS = """BLACK BLUE GREEN CYAN RED MAGENTA YELLOW WHITE""".split()
_ANSICOLORS = "BLACK RED GREEN YELLOW BLUE MAGENTA CYAN WHITE".split()


def _init():
    """
    Initialize attributes with appropriate values for the current terminal.

    `_term_stream` is the stream that will be used for terminal
    output; if this stream is not a tty, then the terminal is
    assumed to be a dumb terminal (i.e., have no capabilities).
    """
    def _tigetstr(cap_name):
        # String capabilities can include "delays" of the form "$<2>".
        # For any modern terminal, we should be able to just ignore
        # these, so strip them out.
        import curses
        cap = curses.tigetstr(cap_name) or ''
        return re.sub(r'\$<\d+>[/*]?', '', cap)

    _term_stream = sys.stdout
    # Curses isn't available on all platforms
    try:
        import curses
    except:
        sys.stderr.write("INFO: no curses support: you won't see colors\n")
        return
    # If the stream isn't a tty, then assume it has no capabilities.
    if not _term_stream.isatty():
        return
    # Check the terminal type.  If we fail, then assume that the
    # terminal has no capabilities.
    try:
        curses.setupterm()
    except:
        return

    # Look up numeric capabilities.
    colors.COLS = curses.tigetnum('cols')
    colors.LINES = curses.tigetnum('lines')
    # Look up string capabilities.
    for capability in _STRING_CAPABILITIES:
        (attrib, cap_name) = capability.split('=')
        setattr(colors, attrib, _tigetstr(cap_name) or '')
    # Colors
    set_fg = _tigetstr('setf')
    if set_fg:
        for i, color in zip(range(len(_COLORS)), _COLORS):
            setattr(colors, color, curses.tparm(set_fg, i) or '')
    set_fg_ansi = _tigetstr('setaf')
    if set_fg_ansi:
        for i, color in zip(range(len(_ANSICOLORS)), _ANSICOLORS):
            setattr(colors, color, curses.tparm(set_fg_ansi, i) or '')
    set_bg = _tigetstr('setb')
    if set_bg:
        for i, color in zip(range(len(_COLORS)), _COLORS):
            setattr(colors, 'BG_'+color, curses.tparm(set_bg, i) or '')
    set_bg_ansi = _tigetstr('setab')
    if set_bg_ansi:
        for i, color in zip(range(len(_ANSICOLORS)), _ANSICOLORS):
            setattr(colors, 'BG_'+color, curses.tparm(set_bg_ansi, i) or '')

_init()


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


def is_color(s):
    return hasattr(colors, s.upper())


# vim:ts=4:sw=4:et:
