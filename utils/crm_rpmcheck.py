#!/usr/bin/python3
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import os
import sys
import json
import subprocess
import shutil

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
    if shutil.which('ansible'):
        rc, data = ansible_package_data(pkg)
        if rc == 0:
            return data

    if shutil.which('rpm'):
        return rpm_package_data(pkg)

    if shutil.which('dpkg'):
        return dpkg_package_data(pkg)

    return {'name': pkg, 'error': "unknown package manager"}

_packages = None
def ansible_package_data(pkg) -> tuple[int, dict]:
    """
    Gathers version and release information about a package.
    Using ansible.
    """
    global _packages
    if not _packages:
        # if _packages is None, then get it
        rc, out, err = run(['ansible', '-m', 'package_facts', 'localhost'])
        if rc == -1:
            return -1, {}
        # output format 'localhost | SUCCESS => { json...'
        bracket_pos = out.find('{')
        if bracket_pos == -1:
            return -1, {}
        is_ok = out[:bracket_pos].find('SUCCESS =>')
        if is_ok == -1:
            return -1, {}

        # get the json part
        out = out[bracket_pos:]
        json_tree = json.loads(out)
        # get _packages
        _packages = json_tree['ansible_facts']['packages']

    if pkg not in _packages:
        return 0, {'name': pkg, 'error': "package not installed"}
    else:
        return 0, _packages[pkg][0]


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
