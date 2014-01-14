#!/usr/bin/env python
import os
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

def rpm_info():
    return crm_script.rpmcheck(PACKAGES)

def package_info():
    package_states = []
    for pkg in PACKAGES:
        package_states.append(crm_script.check_package(pkg, state='present'))
    return package_states

def logrotate_info():
    rc, _, _ = crm_script.call(
        'grep -r corosync.conf /etc/logrotate.d',
        shell=True)
    return {'corosync.conf': rc == 0}

def sys_info():
    sysname, nodename, release, version, machine = os.uname()
    return {'sysname': sysname,
            'nodename': nodename,
            'release': release,
            'version': version,
            'machine': machine}

def disk_info():
    rc, out, err = crm_script.call(['df'], shell=False)
    if rc == 0:
        disk_use = []
        for line in out.split('\n')[1:]:
            line = line.strip()
            if line:
                data = line.split()
                if len(data) >= 6:
                    disk_use.append((data[5], data[4]))
        return disk_use
    return []
"""
Filesystem      Size  Used Avail Use% Mounted on
/dev/sdb3       197G  100G   88G  54% /
devtmpfs        7.9G   56K  7.9G   1% /dev
tmpfs           7.9G  1.1M  7.9G   1% /dev/shm
tmpfs           7.9G   11M  7.9G   1% /run
tmpfs           7.9G     0  7.9G   0% /sys/fs/cgroup
tmpfs           7.9G   11M  7.9G   1% /var/run
tmpfs           7.9G   11M  7.9G   1% /var/lock
/dev/sdb1       195M  128K  195M   1% /boot/efi
/dev/sdb4       697G  310G  352G  47% /home
"""

try:
    data = {
        'rpm': rpm_info(),
        'packages': package_info(),
        'logrotate': logrotate_info(),
        'system': sys_info(),
        'disk': disk_info()
    }
    crm_script.exit_ok(data)
except Exception, e:
    crm_script.exit_fail(str(e))
