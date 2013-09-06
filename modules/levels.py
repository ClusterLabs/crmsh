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
from ui import TopLevel


class Levels(Singleton):
    '''
    Keep track of levels and prompts.
    '''

    def __init__(self):
        self._marker = 0
        self._in_transit = False
        self.level_stack = [TopLevel()]
        self.prompts = []
        self.current_level().setup_completion({})

    def current_level(self):
        return self.level_stack[-1]

    def _parse_root(self):
        return self.current_level().cmd_table

    def completion_tab(self):
        return self.current_level().completion_tab

    def getprompt(self):
        return ' '.join(self.prompts)

    def is_in_transit(self):
        return self._in_transit

    def mark(self):
        self._marker = len(self.level_stack)
        self._in_transit = False
        return self._parse_root()

    def release(self):
        while len(self.level_stack) > self._marker:
            self.droplevel()

    def new_level(self, level_obj, token):
        sublevel = level_obj()
        sublevel.setup_completion(self.completion_tab()[token])
        self.level_stack.append(sublevel)
        self.prompts.append(token)
        self._in_transit = True
        return self._parse_root()

    def previous(self):
        if len(self.level_stack) > 1:
            return self.level_stack[-2]
        return ''

    def droplevel(self):
        if len(self.level_stack) > 1:
            self.current_level().end_game(no_questions_asked=self._in_transit)
            self.level_stack.pop()
            self.prompts.pop()

    def should_wait(self):
        """Wait for command completion in certain circumstances.
        """
        from userprefs import Options
        options = Options.getInstance()
        by_level = self.current_level().should_wait()
        transit_or_noninteractive = self.is_in_transit() or not options.interactive
        return by_level and transit_or_noninteractive

# vim:ts=4:sw=4:et:
