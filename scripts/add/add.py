#!/usr/bin/env python
import sys
import os
import crm_script

COROSYNC_AUTH = '/etc/corosync/authkey'
COROSYNC_CONF = '/etc/corosync/corosync.conf'

host = crm_script.host()
add_nodes = crm_script.param('node').split(',')

PACKAGES = ['pacemaker', 'corosync', 'crmsh']


def run_collect():
    if host not in add_nodes:
        crm_script.exit_ok(host)

    rc, out, err = crm_script.service('pacemaker', 'is-active')
    if rc == 0 and out.strip() == 'active':
        crm_script.exit_fail("Pacemaker already running on %s" % (host))
    crm_script.exit_ok(host)


def make_opts():
    from psshlib import api as pssh
    opts = pssh.Options()
    opts.timeout = 60
    opts.recursive = True
    opts.user = 'root'
    opts.ssh_options += ['PasswordAuthentication=no',
                         'StrictHostKeyChecking=no',
                         'ControlPersist=no']
    return opts


def run_validate():
    try:
        from psshlib import api
    except ImportError:
        crm_script.exit_fail("Command node needs pssh installed")

    if host in add_nodes:
        crm_script.exit_fail("Run script from node in cluster")

    crm_script.exit_ok(host)


def run_install():
    if host not in add_nodes:
        crm_script.exit_ok(host)
    for pkg in PACKAGES:
        try:
            crm_script.package(pkg, 'latest')
        except Exception, e:
            crm_script.exit_fail("Error installing package '%s': %s" % (pkg, e))
    crm_script.exit_ok(host)


def check_results(pssh, results):
    failures = []
    for host, result in results.items():
        if isinstance(result, pssh.Error):
            failures.add("%s: %s" % (host, str(result)))
    if failures:
        crm_script.exit_fail(', '.join(failures))


def run_copy():
    try:
        from psshlib import api as pssh
    except ImportError:
        crm_script.exit_fail("Command node needs pssh installed")
    opts = make_opts()
    has_auth = os.path.isfile(COROSYNC_AUTH)
    if has_auth:
        results = pssh.copy(add_nodes, COROSYNC_AUTH, COROSYNC_AUTH, opts)
        check_results(pssh, results)
        results = pssh.call(add_nodes,
                            "chown root:root %s;chmod 400 %s" % (COROSYNC_AUTH, COROSYNC_AUTH),
                            opts)
        check_results(pssh, results)
    results = pssh.copy(add_nodes, COROSYNC_CONF, COROSYNC_CONF, opts)
    check_results(pssh, results)
    crm_script.exit_ok(host)


def start_new_node():
    if host not in add_nodes:
        crm_script.exit_ok(host)
    rc, _, err = crm_script.call(['crm', 'cluster', 'start'])
    if rc == 0:
        crm_script.exit_ok(host)
    crm_script.exit_fail(err)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        crm_script.exit_fail("Missing argument")
    elif sys.argv[1] == 'collect':
        run_collect()
    elif sys.argv[1] == 'validate':
        run_validate()
    elif sys.argv[1] == 'install':
        run_install()
    elif sys.argv[1] == 'copy':
        run_copy()
    elif sys.argv[1] == 'start':
        start_new_node()
    else:
        crm_script.exit_fail("Unknown argument: %s" % sys.argv[1])
