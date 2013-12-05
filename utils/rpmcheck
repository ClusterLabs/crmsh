#!/usr/bin/python
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

import sys
import json
import subprocess


def run(cmd):
    proc = subprocess.Popen(cmd,
                            shell=False,
                            stdin=None,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    out, err = proc.communicate(None)
    proc.wait()
    return proc.returncode, out, err


def package_data(pkg):
    """
    Gathers version and release information about a package.
    """
    _qfmt = 'version: %{VERSION}\nrelease: %{RELEASE}\n'
    rc, out, err = run(['/bin/rpm', '-q', '--queryformat=' + _qfmt, pkg])
    if rc == 0:
        data = {'name': pkg}
        for line in out.split('\n'):
            info = line.split(':', 1)
            if len(info) == 2:
                data[info[0].strip()] = info[1].strip()
        return data
    else:
        return {'name': pkg, 'error': "package not installed"}


def main():
    data = [package_data(pkg) for pkg in sys.argv[1:]]
    print json.dumps(data)

main()
