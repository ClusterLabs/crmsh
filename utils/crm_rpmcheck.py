#!/usr/bin/python3
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import os
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
    return proc.returncode, out.decode('utf-8'), err.decode('utf-8')


def package_data(pkg):
    """
    Gathers version and release information about a package.
    """
    if os.path.isfile('/bin/rpm'):
        return rpm_package_data(pkg)

    if os.path.isfile('/usr/bin/dpkg'):
        return dpkg_package_data(pkg)

    return {'name': pkg, 'error': "unknown package manager"}


def rpm_package_data(pkg):
    """
    Gathers version and release information about an RPM package.
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


def dpkg_package_data(pkg):
    """
    Gathers version and release information about a DPKG package.
    """
    rc, out, err = run(['/usr/bin/dpkg', '--status', pkg])
    if rc == 0:
        data = {'name': pkg}
        for line in out.split('\n'):
            info = line.split(':', 1)
            if len(info) == 2:
                data[info[0].strip().lower()] = info[1].strip()
        return data
    else:
        return {'name': pkg, 'error': "package not installed"}


def main():
    data = [package_data(pkg) for pkg in sys.argv[1:]]
    print(json.dumps(data))

main()
