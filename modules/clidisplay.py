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

from singletonmixin import Singleton
import config


class CliDisplay(Singleton):
    """
    Display output for various syntax elements.
    """
    def __init__(self):
        self.no_pretty = False

    def set_no_pretty(self):
        self.no_pretty = True

    def reset_no_pretty(self):
        self.no_pretty = False

    def colors_enabled(self):
        return 'color' in config.color.style and not self.no_pretty

    def error(self, s):
        return self._colorize(s, config.color.error)

    def ok(self, s):
        return self._colorize(s, config.color.ok)

    def info(self, s):
        return self._colorize(s, config.color.info)

    def warn(self, s):
        return self._colorize(s, config.color.warn)

    def keyword(self, s):
        if "uppercase" in config.color.style:
            s = s.upper()
        if "color" in config.color.style:
            s = self._colorize(s, config.color.keyword)
        return s

    def _colorize(self, s, colors):
        if self.colors_enabled():
            return ''.join(('${%s}' % clr.upper()) for clr in colors) + s + '${NORMAL}'
        return s

    def prompt(self, s):
        if self.colors_enabled():
            s = "${RLIGNOREBEGIN}${GREEN}${BOLD}${RLIGNOREEND}" + s
            return s + "${RLIGNOREBEGIN}${NORMAL}${RLIGNOREEND}"
        return s

    def help_header(self, s):
        return self._colorize(s, config.color.help_header)

    def help_keyword(self, s):
        return self._colorize(s, config.color.help_keyword)

    def help_topic(self, s):
        return self._colorize(s, config.color.help_topic)

    def help_block(self, s):
        return self._colorize(s, config.color.help_block)

    def id(self, s):
        return self._colorize(s, config.color.identifier)

    def attr_name(self, s):
        return self._colorize(s, config.color.attr_name)

    def attr_value(self, s):
        return self._colorize(s, config.color.attr_value)

    def rscref(self, s):
        return self._colorize(s, config.color.resource_reference)

    def idref(self, s):
        return self._colorize(s, config.color.id_reference)

    def score(self, s):
        return self._colorize(s, config.color.score)

    def ticket(self, s):
        return self._colorize(s, config.color.ticket)


# vim:ts=4:sw=4:et:
