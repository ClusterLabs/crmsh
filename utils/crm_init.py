import os
import pwd
import re
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


def service_info(service):
    "Returns information about a given service"
    active, enabled = 'unknown', 'unknown'
    rc, out, err = crm_script.call(["/usr/bin/systemctl", "is-enabled", "%s.service" % (service)])
    if rc in (0, 1, 3) and out:
        enabled = out.strip()
    else:
        return {'name': service, 'error': err.strip()}
    rc, out, err = crm_script.call(["/usr/bin/systemctl", "is-active", "%s.service" % (service)])
    if rc in (0, 1, 3) and out:
        active = out.strip()
    else:
        return {'name': service, 'error': err.strip()}
    return {'name': service, 'active': active, 'enabled': enabled}


def services_info():
    'check enabled/active services'
    return [service_info(service) for service in SERVICES]

def get_user():
    return pwd.getpwuid(os.getuid()).pw_name

def sys_info():
    'system information'
    system, node, release, version, machine, processor = platform.uname()
    hostname = platform.node().split('.')[0]
    return {'system': system,
            'node': node,
            'release': release,
            'version': version,
            'machine': machine,
            'processor': processor,
            'user': get_user(),
            'hostname': hostname,
            'fqdn': socket.getfqdn()}


def net_info():
    ret = {}
    interfaces = []
    ret['interfaces'] = interfaces
    hostname = platform.node().split('.')[0]
    try:
        ip = socket.gethostbyname(hostname)
        ret['hostname'] = {'name': hostname, 'ip': ip}
    except Exception as e:
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
            'services': services_info(),
            'system': sys_info(),
            'net': net_info(),
            'files': files_info(),
            'logrotate': logrotate_info(),
            'disk': disk_info()}


def verify(data):
    """
    Given output from info(), verifies
    as much as possible before init/add.
    """
    def check_diskspace():
        for host, info in data.items():
            for mount, percent in info['disk']:
                interesting = (mount == '/' or
                               mount.startswith('/var/log') or
                               mount.startswith('/tmp'))
                if interesting and percent > 90:
                    crm_script.exit_fail("Not enough space on %s:%s" % (host, mount))

    def check_services():
        for host, info in data.items():
            for svc in info['services']:
                if svc['name'] == 'pacemaker' and svc['active'] == 'active':
                    crm_script.exit_fail("%s already running pacemaker" % (host))
                if svc['name'] == 'corosync' and svc['active'] == 'active':
                    crm_script.exit_fail("%s already running corosync" % (host))

    def verify_host(host, info):
        if host != info['system']['hostname']:
            crm_script.exit_fail("Hostname mismatch: %s is not %s" %
                                 (host, info['system']['hostname']))

    def compare_system(systems):
        def check(value, msg):
            vals = set([system[value] for host, system in systems])
            if len(vals) > 1:
                info = ', '.join('%s: %s' % (h, system[value]) for h, system in systems)
                crm_script.exit_fail("%s: %s" % (msg, info))

        check('machine', 'Architecture differs')
        #check('release', 'Kernel release differs')
        #check('distname', 'Distribution differs')
        #check('distver', 'Distribution version differs')
        #check('version', 'Kernel version differs')

    for host, info in data.items():
        verify_host(host, info)

    compare_system((h, info['system']) for h, info in data.items())

    check_diskspace()
    check_services()


# common functions to initialize a cluster node


def is_service_enabled(name):
    info = service_info(name)
    if info.get('name') == name and info.get('enabled') == 'enabled':
        return True
    return False


def is_service_active(name):
    info = service_info(name)
    if info.get('name') == name and info.get('active') == 'active':
        return True
    return False


def install_packages(packages):
    for pkg in packages:
        try:
            crm_script.package(pkg, 'latest')
        except Exception as e:
            crm_script.exit_fail("Failed to install %s: %s" % (pkg, e))


def configure_firewall():
    _SUSE_FW_TEMPLATE = """## Name: HAE cluster ports
## Description: opens ports for HAE cluster services
TCP="%(tcp)s"
UDP="%(udp)s"
"""
    corosync_mcastport = crm_script.param('mcastport')
    if not corosync_mcastport:
        rc, out, err = crm_script.call(['crm', 'corosync', 'get', 'totem.interface.mcastport'])
        if rc == 0:
            corosync_mcastport = out.strip()
    FW = '/etc/sysconfig/SuSEfirewall2'
    FW_CLUSTER = '/etc/sysconfig/SuSEfirewall2.d/services/cluster'

    tcp_ports = '30865 5560 7630 21064'
    udp_ports = '%s %s' % (corosync_mcastport, int(corosync_mcastport) - 1)

    if is_service_enabled('SuSEfirewall2'):
        if os.path.isfile(FW_CLUSTER):
            tmpl = open(FW_CLUSTER).read()
            tmpl = re.sub(r'^TCP="(.*)"', 'TCP="%s"' % (tcp_ports), tmpl, flags=re.M)
            tmpl = re.sub(r'^UDP="(.*)"', 'UDP="%s"' % (udp_ports), tmpl, flags=re.M)
            with open(FW_CLUSTER, 'w') as f:
                f.write(tmpl)
        elif os.path.isdir(os.path.dirname(FW_CLUSTER)):
            with open(FW_CLUSTER, 'w') as fwc:
                fwc.write(_SUSE_FW_TEMPLATE % {'tcp': tcp_ports,
                                               'udp': udp_ports})
        else:
            # neither the cluster file nor the services
            # directory exists
            crm_script.exit_fail("SUSE firewall is configured but %s does not exist" %
                                 os.path.dirname(FW_CLUSTER))

        # add cluster to FW_CONFIGURATIONS_EXT
        if os.path.isfile(FW):
            txt = open(FW).read()
            m = re.search(r'^FW_CONFIGURATIONS_EXT="(.*)"', txt, re.M)
            if m:
                services = m.group(1).split()
                if 'cluster' not in services:
                    services.append('cluster')
                txt = re.sub(r'^FW_CONFIGURATIONS_EXT="(.*)"',
                             r'FW_CONFIGURATIONS_EXT="%s"' % (' '.join(services)),
                             txt,
                             flags=re.M)
            else:
                txt += '\nFW_CONFIGURATIONS_EXT="cluster"'
            with open(FW, 'w') as fw:
                fw.write(txt)
        if is_service_active('SuSEfirewall2'):
            crm_script.service('SuSEfirewall2', 'restart')

    # TODO: other platforms
