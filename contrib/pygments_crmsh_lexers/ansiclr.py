# -*- coding: utf-8 -*-
"""
    pygments.lexers.console
    ~~~~~~~~~~~~~~~~~~~~~~~

    Lexers for misc console output.

    :copyright: Copyright 2006-2015 by the Pygments team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

from pygments.lexer import RegexLexer, include, bygroups
from pygments.token import Generic, Comment, String, Text, Keyword, Name, \
    Punctuation, Number

__all__ = ['ANSIColorsLexer']

_ESC = "\x1b\["
# this is normally to reset (reset attributes, set primary font)
# there could be however other reset sequences and in that case
# sgr0 needs to be updated
_SGR0 = "%s(?:0;10|10;0)m" % _ESC
# BLACK RED GREEN YELLOW
# BLUE MAGENTA CYAN WHITE
_ANSI_COLORS = (Generic.Emph, Generic.Error, Generic.Inserted, Generic.Keyword,
                Generic.Keyword, Generic.Prompt, Generic.Traceback, Generic.Output)


def _ansi2rgb(lexer, match):
    code = match.group(1)
    text = match.group(2)
    yield match.start(), _ANSI_COLORS[int(code)-30], text


class ANSIColorsLexer(RegexLexer):
    """
    Interpret ANSI colors.
    """
    name = 'ANSI Colors'
    aliases = ['ansiclr']
    filenames = ["*.typescript"]

    tokens = {
        'root': [
            (r'%s(3[0-7]+)m(.*?)%s' % (_ESC, _SGR0), _ansi2rgb),
            (r'[^\x1b]+', Text),
            # drop the rest of the graphic codes
            (r'(%s[0-9;]+m)()' % _ESC, bygroups(None, Text)),
        ]
    }
