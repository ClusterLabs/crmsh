# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.
import os
import sys
import re
# from: http://code.activestate.com/recipes/475116/

# A module that can be used to portably generate formatted output to
# a terminal.
# Defines a set of instance variables whose
# values are initialized to the control sequence necessary to
# perform a given action.  These can be simply included in normal
# output to the terminal:
#     >>> print 'This is '+term.colors.GREEN+'green'+term.colors.NORMAL
# Alternatively, the `render()` method can used, which replaces
# '${action}' with the string required to perform 'action':
#     >>> print term.render('This is ${GREEN}green${NORMAL}')
# If the terminal doesn't support a given action, then the value of
# the corresponding instance variable will be set to ''.  As a
# result, the above code will still work on terminals that do not
# support color, except that their output will not be colored.
# Also, this means that you can test whether the terminal supports a
# given action by simply testing the truth value of the
# corresponding instance variable:
#     >>> if term.colors.CLEAR_SCREEN:
#     ...     print 'This terminal supports clearning the screen.'
# Finally, if the width and height of the terminal are known, then
# they will be stored in the `COLS` and `LINES` attributes.


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


def _tigetstr(cap_name):
    import curses
    if not curses.tigetstr(cap_name):
        return None
    from .utils import to_ascii
    cap = to_ascii(curses.tigetstr(cap_name)) or ''

    # String capabilities can include "delays" of the form "$<2>".
    # For any modern terminal, we should be able to just ignore
    # these, so strip them out.
    # terminof(5) states that:
    #   A "/" suffix indicates that the padding is mandatory and forces a
    #   delay of the given number of milliseconds even on devices for which
    #   xon is present to indicate flow control.
    # So let's respect that. But not the optional ones.
    cap = re.sub(r'\$<\d+>[*]?', '', cap)

    # To switch back to "NORMAL", we use sgr0, which resets "everything" to defaults.
    # That on some terminals includes ending "alternate character set mode".
    # Which is usually done by appending '\017'.  Unfortunately, less -R
    # does not eat that, but shows it as an annoying inverse '^O'
    # Instead of falling back to less -r, which would have other implications as well,
    # strip off that '\017': we don't use the alternative character set,
    # so we won't need to reset it either.
    if cap_name == 'sgr0':
        cap = re.sub(r'\017$', '', cap)

    return cap


def _lookup_caps():
    import curses
    from .utils import to_ascii

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
        for i, color in zip(list(range(len(_COLORS))), _COLORS):
            setattr(colors, color, to_ascii(curses.tparm(set_fg.encode('utf-8'), i)) or '')
    set_fg_ansi = _tigetstr('setaf')
    if set_fg_ansi:
        for i, color in zip(list(range(len(_ANSICOLORS))), _ANSICOLORS):
            setattr(colors, color, to_ascii(curses.tparm(set_fg_ansi.encode('utf-8'), i)) or '')
    set_bg = _tigetstr('setb')
    if set_bg:
        for i, color in zip(list(range(len(_COLORS))), _COLORS):
            setattr(colors, 'BG_'+color, to_ascii(curses.tparm(set_bg.encode('utf-8'), i)) or '')
    set_bg_ansi = _tigetstr('setab')
    if set_bg_ansi:
        for i, color in zip(list(range(len(_ANSICOLORS))), _ANSICOLORS):
            setattr(colors, 'BG_'+color, to_ascii(curses.tparm(set_bg_ansi.encode('utf-8'), i)) or '')


def init():
    """
    Initialize attributes with appropriate values for the current terminal.

    `_term_stream` is the stream that will be used for terminal
    output; if this stream is not a tty, then the terminal is
    assumed to be a dumb terminal (i.e., have no capabilities).
    """
    _term_stream = sys.stdout
    # Curses isn't available on all platforms
    try:
        import curses
    except ImportError:
        sys.stderr.write("INFO: no curses support: you won't see colors\n")
        return
    # If the stream isn't a tty, then assume it has no capabilities.
    from . import config
    if not _term_stream.isatty() and 'color-always' not in config.color.style:
        return
    _ignore_environ()
    # Check the terminal type.  If we fail, then assume that the
    # terminal has no capabilities.
    try:
        curses.setupterm()
    except curses.error:
        return

    _lookup_caps()


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


def _ignore_environ():
    """Ignore environment variable COLUMNS and ROWS"""
    # See https://bugzilla.suse.com/show_bug.cgi?id=1205925
    # and https://gitlab.com/procps-ng/procps/-/blob/c415fc86452c933716053a50ab1777a343190dcc/src/ps/global.c#L279
    for name in ["COLUMNS", "ROWS"]:
        if name in os.environ:
            del os.environ[name]

# vim:ts=4:sw=4:et:
