# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.
'''
Files added to tmpfiles are removed at program exit.
'''

import os
import shutil
import atexit
from tempfile import mkstemp, mkdtemp

from . import utils

_FILES = []
_DIRS = []


def _exit_handler():
    "Called at program exit"
    for f in _FILES:
        try:
            os.unlink(f)
        except OSError:
            pass
    for d in _DIRS:
        try:
            shutil.rmtree(d)
        except OSError:
            pass


def add(filename):
    '''
    Remove the named file at program exit.
    '''
    if len(_FILES) + len(_DIRS) == 0:
        atexit.register(_exit_handler)
    _FILES.append(filename)


def create(dir=utils.get_tempdir(), prefix='crmsh_'):
    '''
    Create a temporary file and remove it at program exit.
    Returns (fd, filename)
    '''
    fd, fname = mkstemp(dir=dir, prefix=prefix)
    add(fname)
    return fd, fname


def create_dir(dir=utils.get_tempdir(), prefix='crmsh_'):
    ret = mkdtemp(dir=dir, prefix=prefix)
    if len(_FILES) + len(_DIRS) == 0:
        atexit.register(_exit_handler)
    _DIRS.append(ret)
    return ret
