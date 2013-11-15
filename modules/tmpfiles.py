# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
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
'''
Files added to tmpfiles are removed at program exit.
'''

import os
import atexit
from tempfile import mkstemp

_FILES = []


def _exit_handler():
    "Called at program exit"
    for f in _FILES:
        try:
            os.unlink(f)
        except OSError:
            pass


def add(filename):
    '''
    Remove the named file at program exit.
    '''
    if len(_FILES) == 0:
        atexit.register(_exit_handler)
    _FILES.append(filename)


def create(dir='/tmp', prefix='crmsh_'):
    '''
    Create a temporary file and remove it at program exit.
    Returns (fd, filename)
    '''
    fd, fname = mkstemp(dir=dir, prefix=prefix)
    add(fname)
    return fd, fname
