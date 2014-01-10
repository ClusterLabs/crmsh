#!/usr/bin/env python
import crm_script
data = crm_script.get_input()

PACKAGES = ['booth',
            'cluster-glue',
            'corosync',
            'crmsh',
            'csync2',
            'drbd',
            'fence-agents',
            'gfs2',
            'gfs2-utils',
            'ha-cluster-bootstrap',
            'haproxy',
            'hawk',
            'libdlm',
            'libqb',
            'ocfs2',
            'ocfs2-tools',
            'pacemaker',
            'pacemaker-mgmt',
            'pcs',
            'pssh',
            'resource-agents',
            'rubygem-sinatra',
            'sbd']

try:
    rpm_states = crm_script.rpmcheck(PACKAGES)
    package_states = []
    for pkg in PACKAGES:
        package_states.append(crm_script.check_package(pkg, state='present'))

    data = {'rpm': rpm_states,
            'packages': package_states}
    crm_script.exit_ok(data)
except Exception, e:
    crm_script.exit_fail(str(e))
