# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2018 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
#
# Cache stuff. A naive implementation.
# Used by ra.py to cache named lists of things.

import time


_max_cache_age = 600.0  # seconds
_stamp = time.time()
_lists = {}


def _clear():
    "Clear the cache."
    global _stamp
    global _lists
    _stamp = time.time()
    _lists = {}


def is_cached(name):
    "True if the argument exists in the cache."
    return retrieve(name) is not None


def store(name, lst):
    """
    Stores the given list for the given name.
    Returns the given list.
    """
    _lists[name] = lst
    return lst


def retrieve(name):
    """
    Returns the cached list for name, or None.
    """
    if time.time() - _stamp > _max_cache_age:
        _clear()
    return _lists.get(name)


# vim:ts=4:sw=4:et:
