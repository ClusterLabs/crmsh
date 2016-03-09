# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.

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
