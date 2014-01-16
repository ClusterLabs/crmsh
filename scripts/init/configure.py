#!/usr/bin/env python
import sys
import crm_script

host = crm_script.host()


def run_install():
    # install packages
    PACKAGES = ['cluster-glue', 'corosync', 'crmsh', 'pacemaker', 'resource-agents']
    for pkg in PACKAGES:
        try:
            crm_script.package(pkg, 'latest')
        except Exception, e:
            crm_script.exit_fail("Failed to install %s: %s" % (pkg, e))

    crm_script.exit_ok(True)


# configure corosync
def run_corosync():
    # create corosync.conf
    tmpl = open('./corosync.template').read()
    tmpl % {
        'bindnetaddr': None,
        'mcastaddr': None,
        'mcastport': None,
        'transport': None,
        'nodelist': None,
        'quorum': None
    }

    # start cluster
    rc, out, err = crm_script.call(['crm', 'cluster', 'start'])
    if rc != 0:
        crm_script.exit_fail("Failed to start cluster: %s" % (err))

    crm_script.exit_ok(True)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        crm_script.exit_fail("Missing argument to configure.py")
    elif sys.argv[1] == 'install':
        run_install()
    elif sys.argv[1] == 'corosync':
        run_corosync()
    else:
        crm_script.exit_fail("Bad argument to configure.py: %s" % (sys.argv[1]))
