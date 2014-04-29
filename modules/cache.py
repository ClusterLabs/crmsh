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

import time

"Cache stuff. A naive implementation."


_max_cache_age = 600  # seconds
_stamp = time.time()
_lists = {}


def _clear():
    global _stamp
    global _lists
    _stamp = time.time()
    _lists = {}


def is_cached(name):
    if time.time() - _stamp > _max_cache_age:
        _clear()
    return name in _lists


def store(name, lst):
    _lists[name] = lst
    return lst


def retrieve(name):
    if is_cached(name):
        return _lists[name]
    return None


# vim:ts=4:sw=4:et:
