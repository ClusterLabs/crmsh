#!/usr/bin/python
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import os
import sys
import subprocess
import json


DRY_RUN = False


def get_platform():
    return os.uname()[0]


def fail(msg):
    print >>sys.stderr, msg
    sys.exit(1)


def run(cmd):
    proc = subprocess.Popen(cmd,
                            shell=False,
                            stdin=None,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    out, err = proc.communicate(None)
    return proc.returncode, out, err


def is_program(prog):
    """Is this program available?"""
    for p in os.getenv("PATH").split(os.pathsep):
        filename = os.path.join(p, prog)
        if os.path.isfile(filename) and os.access(filename, os.X_OK):
            return filename
    return None


class PackageManager(object):
    def dispatch(self, name, state):
        if state in ('installed', 'present'):
            return self.present(name)
        elif state in ('absent', 'removed'):
            return self.absent(name)
        elif state == 'latest':
            return self.latest(name)
        fail(msg="Unknown state: " + state)

    def present(self, name):
        raise NotImplementedError

    def latest(self, name):
        raise NotImplementedError

    def absent(self, name):
        raise NotImplementedError


class Zypper(PackageManager):
    def __init__(self):
        self._rpm = is_program('rpm')
        self._zyp = is_program('zypper')
        if self._rpm is None or self._zyp is None:
            raise OSError("Missing tools: %s, %s" % (self._rpm, self._zyp))

    def get_version(self, name):
        cmd = [self._rpm, '-q', name]
        rc, stdout, stderr = run(cmd)
        if rc == 0:
            for line in stdout.splitlines():
                if name in line:
                    return line.strip()
        return None

    def is_installed(self, name):
        if not isinstance(self._rpm, basestring):
            raise IOError(str(self._rpm))
        if not isinstance(name, basestring):
            raise IOError(str(name))
        cmd = [self._rpm, '--query', '--info', name]
        rc, stdout, stderr = run(cmd)
        return rc == 0

    def present(self, name):
        if self.is_installed(name):
            return (0, '', '', False)

        if DRY_RUN:
            return (0, '', '', True)

        cmd = [self._zyp,
               '--non-interactive',
               '--no-refresh',
               'install',
               '--auto-agree-with-licenses',
               name]
        rc, stdout, stderr = run(cmd)
        changed = rc == 0
        return (rc, stdout, stderr, changed)

    def latest(self, name):
        if not self.is_installed(name):
            return self.present(name)

        if DRY_RUN:
            return (0, '', '', True)

        pre_version = self.get_version(name)
        cmd = [self._zyp,
               '--non-interactive',
               '--no-refresh',
               'update',
               '--auto-agree-with-licenses',
               name]
        rc, stdout, stderr = run(cmd)
        post_version = self.get_version(name)
        changed = pre_version != post_version
        return (rc, stdout, stderr, changed)

    def absent(self, name):
        if not self.is_installed(name):
            return (0, '', '', False)

        if DRY_RUN:
            return (0, '', '', True)

        cmd = [self._zyp,
               '--non-interactive',
               'remove',
               name]
        rc, stdout, stderr = run(cmd)
        changed = rc == 0
        return (rc, stdout, stderr, changed)


class Yum(PackageManager):
    def __init__(self):
        self._rpm = is_program('rpm')
        self._yum = is_program('yum')

    def get_version(self, name):
        cmd = [self._rpm, '-q', name]
        rc, stdout, stderr = run(cmd)
        if rc == 0:
            for line in stdout.splitlines():
                if name in line:
                    return line.strip()
        return None

    def is_installed(self, name):
        cmd = [self._rpm, '--query', '--info', name]
        rc, stdout, stderr = run(cmd)
        return rc == 0

    def present(self, name):
        if self.is_installed(name):
            return (0, '', '', False)

        if DRY_RUN:
            return (0, '', '', True)

        cmd = [self._yum,
               '--assumeyes',
               '-d', '2',
               'install',
               name]
        rc, stdout, stderr = run(cmd)
        changed = rc == 0
        return (rc, stdout, stderr, changed)

    def latest(self, name):
        if not self.is_installed(name):
            return self.present(name)

        if DRY_RUN:
            return (0, '', '', True)

        pre_version = self.get_version(name)
        cmd = [self._yum,
               '--assumeyes',
               '-d', '2',
               'update',
               name]
        rc, stdout, stderr = run(cmd)
        post_version = self.get_version(name)
        changed = pre_version != post_version
        return (rc, stdout, stderr, changed)

    def absent(self, name):
        if not self.is_installed(name):
            return (0, '', '', False)

        if DRY_RUN:
            return (0, '', '', True)

        cmd = [self._yum,
               '--assumeyes',
               '-d', '2',
               'erase',
               name]
        rc, stdout, stderr = run(cmd)
        changed = rc == 0
        return (rc, stdout, stderr, changed)


class Apt(PackageManager):
    pass


class Pacman(PackageManager):
    pass


def manage_package(pkg, state):
    """
    Gathers version and release information about a package.
    """
    if pkg is None:
        raise IOError("PKG IS NONE")
    pf = get_platform()
    if pf != 'Linux':
        fail(msg="Unsupported platform: " + pf)
    managers = {
        'zypper': Zypper,
        'yum': Yum,
        #'apt-get': Apt,
        #'pacman': Pacman
    }
    for name, mgr in managers.iteritems():
        exe = is_program(name)
        if exe:
            rc, stdout, stderr, changed = mgr().dispatch(pkg, state)
            return {'rc': rc,
                    'stdout': stdout,
                    'stderr': stderr,
                    'changed': changed
                    }
    fail(msg="No supported package manager found")


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="(Semi)-Universal package installer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-d', '--dry-run', dest='dry_run', action='store_true',
                        help="Only check if changes would be made")

    parser.add_argument('-n', '--name', metavar='name', type=str,
                        help="Name of package")

    parser.add_argument('-s', '--state', metavar='state', type=str,
                        help="Desired state (present|latest|removed)", default="present")

    args = parser.parse_args()
    global DRY_RUN
    DRY_RUN = args.dry_run
    if not args.name or not args.state:
        raise IOError("Bad arguments: %s" % (sys.argv))
    data = manage_package(args.name, args.state)
    print json.dumps(data)

main()
