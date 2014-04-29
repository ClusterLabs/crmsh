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

"""
Display output for various syntax elements.
"""

import config


# Enable colors/upcasing
_pretty = True


def enable_pretty():
    global _pretty
    _pretty = True


def disable_pretty():
    global _pretty
    _pretty = False


def colors_enabled():
    return 'color' in config.color.style and _pretty


def _colorize(s, colors):
    if colors_enabled():
        return ''.join(('${%s}' % clr.upper()) for clr in colors) + s + '${NORMAL}'
    return s


def error(s):
    return _colorize(s, config.color.error)


def ok(s):
    return _colorize(s, config.color.ok)


def info(s):
    return _colorize(s, config.color.info)


def warn(s):
    return _colorize(s, config.color.warn)


def keyword(s):
    if "uppercase" in config.color.style:
        s = s.upper()
    if "color" in config.color.style:
        s = _colorize(s, config.color.keyword)
    return s


def prompt(s):
    if colors_enabled():
        s = "${RLIGNOREBEGIN}${GREEN}${BOLD}${RLIGNOREEND}" + s
        return s + "${RLIGNOREBEGIN}${NORMAL}${RLIGNOREEND}"
    return s


def prompt_noreadline(s):
    if colors_enabled():
        return "${GREEN}${BOLD}" + s + "${NORMAL}"
    return s


def help_header(s):
    return _colorize(s, config.color.help_header)


def help_keyword(s):
    return _colorize(s, config.color.help_keyword)


def help_topic(s):
    return _colorize(s, config.color.help_topic)


def help_block(s):
    return _colorize(s, config.color.help_block)


def id(s):
    return _colorize(s, config.color.identifier)


def attr_name(s):
    return _colorize(s, config.color.attr_name)


def attr_value(s):
    return _colorize(s, config.color.attr_value)


def rscref(s):
    return _colorize(s, config.color.resource_reference)


def idref(s):
    return _colorize(s, config.color.id_reference)


def score(s):
    return _colorize(s, config.color.score)


def ticket(s):
    return _colorize(s, config.color.ticket)


# vim:ts=4:sw=4:et:
