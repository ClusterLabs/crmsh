#!/usr/bin/env python
#
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
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
# simple unit test testrunner

import os
import sys
import re
import subprocess

os.chdir(os.path.dirname(os.path.abspath(sys.modules[__name__].__file__)))


def test_info(f):
    m = re.match(r'^test_(.+)\.py$', os.path.basename(f))
    if m:
        return (m.group(1), f)
    return None
tests = [test_info(f) for f in os.listdir('.') if test_info(f)]


def run_test(name, testfile):
    print "%s" % (name.capitalize())
    cmd = 'PYTHONPATH=%s CRM_CONFIG_FILE=%s python -B %s' % (
        '../../modules',
        'test.conf',
        testfile
    )
    ret = subprocess.call(cmd, shell=True)
    return ret == 0

results = [run_test(name, test) for name, test in tests]

sys.exit(False in results)
