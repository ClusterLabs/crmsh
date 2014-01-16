import os
import platform
import socket
import crm_script

PACKAGES = ['booth', 'cluster-glue', 'corosync', 'crmsh', 'csync2', 'drbd',
            'fence-agents', 'gfs2', 'gfs2-utils', 'hawk', 'ocfs2',
            'ocfs2-tools', 'pacemaker', 'pacemaker-mgmt',
            'resource-agents', 'sbd']
SERVICES = ['sshd', 'ntp', 'corosync', 'pacemaker', 'hawk', 'SuSEfirewall2_init']
SSH_KEY = os.path.expanduser('~/.ssh/id_rsa')
CSYNC2_KEY = '/etc/csync2/key_hagroup'
CSYNC2_CFG = '/etc/csync2/csync2.cfg'
COROSYNC_CONF = '/etc/corosync/corosync.conf'
SYSCONFIG_SBD = '/etc/sysconfig/sbd'
SYSCONFIG_FW = '/etc/sysconfig/SuSEfirewall2'
SYSCONFIG_FW_CLUSTER = '/etc/sysconfig/SuSEfirewall2.d/services/cluster'


def rpm_info():
    'check installed packages'
    return crm_script.rpmcheck(PACKAGES)


def svc_info():
    'check enabled/active services'
    state = []
    for service in SERVICES:
        active, enabled = 'unknown', 'unknown'
        rc, out, err = crm_script.call(["systemctl", "is-enabled", "%s.service" % (service)])
        if rc in (0, 1, 3) and out:
            enabled = out.strip()
        else:
            state.append({'name': service, 'error': err.strip()})
            continue
        rc, out, err = crm_script.call(["systemctl", "is-active", "%s.service" % (service)])
        if rc in (0, 1, 3) and out:
            active = out.strip()
        else:
            state.append({'name': service, 'error': err.strip()})
            continue
        state.append({'name': service, 'active': active, 'enabled': enabled})
    return state


def sys_info():
    'system information'
    system, node, release, version, machine, processor = platform.uname()
    distname, distver, distid = platform.linux_distribution()
    hostname = platform.node().split('.')[0]
    return {'system': system,
            'node': node,
            'release': release,
            'version': version,
            'machine': machine,
            'processor': processor,
            'distname': distname,
            'distver': distver,
            'distid': distid,
            'user': os.getlogin(),
            'hostname': hostname,
            'fqdn': socket.getfqdn()}


def net_info():
    ret = {}
    interfaces = []
    rc, out, err = crm_script.call(['netstat', '-r'])
    if rc == 0:
        data = [l.split() for l in out.split('\n')]
        if len(data) < 3:
            return {'error': "Failed to parse netstat output"}
        keys = data[1]
        for line in data[2:]:
            if len(line) == len(keys):
                interfaces.append(dict(zip(keys, line)))
    else:
        interfaces.append({'error': err.strip()})
    ret['interfaces'] = interfaces
    hostname = platform.node().split('.')[0]
    try:
        ip = socket.gethostbyname(hostname)
        ret['hostname'] = {'name': hostname, 'ip': ip}
    except Exception, e:
        ret['hostname'] = {'error': str(e)}
    return ret


def files_info():
    def check(fn):
        if os.path.isfile(os.path.expanduser(fn)):
            return os.path.expanduser(fn)
        return ''
    return {'ssh_key': check(SSH_KEY),
            'csync2_key': check(CSYNC2_KEY),
            'csync2_cfg': check(CSYNC2_CFG),
            'corosync_conf': check(COROSYNC_CONF),
            'sysconfig_sbd': check(SYSCONFIG_SBD),
            'sysconfig_fw': check(SYSCONFIG_FW),
            'sysconfig_fw_cluster': check(SYSCONFIG_FW_CLUSTER),
            }


def logrotate_info():
    rc, _, _ = crm_script.call(
        'grep -r corosync.conf /etc/logrotate.d',
        shell=True)
    return {'corosync.conf': rc == 0}


def disk_info():
    rc, out, err = crm_script.call(['df'], shell=False)
    if rc == 0:
        disk_use = []
        for line in out.split('\n')[1:]:
            line = line.strip()
            if line:
                data = line.split()
                if len(data) >= 6:
                    disk_use.append((data[5], int(data[4][:-1])))
        return disk_use
    return []


def info():
    return {'rpm': rpm_info(),
            'services': svc_info(),
            'system': sys_info(),
            'net': net_info(),
            'files': files_info(),
            'logrotate': logrotate_info(),
            'disk': disk_info()}
