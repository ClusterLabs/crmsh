#!/usr/bin/env python
import crm_script

'''
  'ha-two': {u'disk': [[u'/', 25],
                       [u'/dev', 1],
                       [u'/dev/shm', 8],
                       [u'/run', 1],
                       [u'/sys/fs/cgroup', 0],
                       [u'/var/run', 1],
                       [u'/var/lock', 1]],
             u'files': {u'corosync_conf': u'/etc/corosync/corosync.conf',
                        u'csync2_cfg': u'/etc/csync2/csync2.cfg',
                        u'csync2_key': u'/etc/csync2/key_hagroup',
                        u'ssh_key': u'/root/.ssh/id_rsa',
                        u'sysconfig_fw': u'/etc/sysconfig/SuSEfirewall2',
                        u'sysconfig_fw_cluster': u'/etc/sysconfig/SuSEfirewall2.d/services/cluster',
                        u'sysconfig_sbd': u'/etc/sysconfig/sbd'},
             u'logrotate': {u'corosync.conf': False},
             u'net': {u'hostname': {u'ip': u'192.168.122.120',
                                    u'name': u'ha-two'},
                      u'interfaces': [{u'Destination': u'default',
                                       u'Flags': u'UG',
                                       u'Gateway': u'192.168.122.1',
                                       u'Genmask': u'0.0.0.0',
                                       u'Iface': u'eth0',
                                       u'MSS': u'0',
                                       u'Window': u'0',
                                       u'irtt': u'0'},
                                      {u'Destination': u'loopback',
                                       u'Flags': u'U',
                                       u'Gateway': u'*',
                                       u'Genmask': u'255.0.0.0',
                                       u'Iface': u'lo',
                                       u'MSS': u'0',
                                       u'Window': u'0',
                                       u'irtt': u'0'},
                                      {u'Destination': u'192.168.122.0',
                                       u'Flags': u'U',
                                       u'Gateway': u'*',
                                       u'Genmask': u'255.255.255.0',
                                       u'Iface': u'eth0',
                                       u'MSS': u'0',
                                       u'Window': u'0',
                                       u'irtt': u'0'}]},
             u'rpm': [{u'error': u'package not installed',
                       u'name': u'booth'},
                      {u'name': u'cluster-glue',
                       u'release': u'0.rc1.71.22',
                       u'version': u'1.0.12'},
                      {u'name': u'corosync',
                       u'release': u'47.5',
                       u'version': u'2.3.2'},
                      {u'name': u'crmsh',
                       u'release': u'79.5',
                       u'version': u'2.0'},
                      {u'name': u'csync2',
                       u'release': u'54.38',
                       u'version': u'2.0+git.1368794815.cf835a7'},
                      {u'error': u'package not installed',
                       u'name': u'drbd'},
                      {u'error': u'package not installed',
                       u'name': u'fence-agents'},
                      {u'error': u'package not installed',
                       u'name': u'gfs2'},
                      {u'error': u'package not installed',
                       u'name': u'gfs2-utils'},
                      {u'name': u'hawk',
                       u'release': u'72.15',
                       u'version': u'0.6.2+git.1387458085.5cd8197'},
                      {u'error': u'package not installed',
                       u'name': u'ocfs2'},
                      {u'error': u'package not installed',
                       u'name': u'ocfs2-tools'},
                      {u'name': u'pacemaker',
                       u'release': u'98.3',
                       u'version': u'1.1.10+git20140110.3e89301'},
                      {u'error': u'package not installed',
                       u'name': u'pacemaker-mgmt'},
                      {u'name': u'resource-agents',
                       u'release': u'57.1',
                       u'version': u'3.9.5'},
                      {u'name': u'sbd',
                       u'release': u'7.15',
                       u'version': u'1.2.1'}],
             u'services': [{u'active': u'active',
                            u'enabled': u'enabled',
                            u'name': u'sshd'},
                           {u'active': u'active',
                            u'enabled': u'enabled',
                            u'name': u'ntp'},
                           {u'active': u'active',
                            u'enabled': u'enabled',
                            u'name': u'corosync'},
                           {u'active': u'active',
                            u'enabled': u'enabled',
                            u'name': u'pacemaker'},
                           {u'active': u'active',
                            u'enabled': u'enabled',
                            u'name': u'hawk'},
                           {u'active': u'inactive',
                            u'enabled': u'disabled',
                            u'name': u'SuSEfirewall2_init'}],
             u'system': {u'distid': u'x86_64',
                         u'distname': u'openSUSE ',
                         u'distver': u'13.1',
                         u'fqdn': u'ha-two',
                         u'hostname': u'ha-two',
                         u'machine': u'x86_64',
                         u'node': u'ha-two',
                         u'processor': u'x86_64',
                         u'release': u'3.13.0-rc7-1-default',
                         u'system': u'Linux',
                         u'user': u'root',
                         u'version': u'#1 SMP Wed Jan 8 17:30:05 UTC 2014 (57a2f1c)'}}}]
'''

data = crm_script.output(1)


def verify_host(host, info):
    if host != info['system']['hostname']:
        crm_script.exit_fail("Hostname mismatch: %s is not %s" %
                             (host, info['system']['hostname']))


def select_interfaces(user_iface, data):
    selections = dict([(host, user_iface) for host in data.keys()])
    if not user_iface:
        for host, info in data.iteritems():
            for i in info['net']['interfaces']:
                if i.get('Destination') == 'default':
                    selections[host] = i['Iface']

    def invalid(iface):
        for i in data[host]['net']['interfaces']:
            if i['Iface'] == iface:
                return False
        return True

    for host, iface in selections.iteritems():
        if not iface or invalid(host, iface):
            crm_script.exit_fail("No usable network interface on %s: %s" % (host, iface))

    return user_iface


def compare_system(systems):
    def check(value, msg):
        vals = set([system[value] for host, system in systems])
        if len(vals) > 1:
            info = ', '.join('%s: %s' % (h, system[value]) for h, system in systems)
            crm_script.exit_fail("%s: %s" % (msg, info))

    check('machine', 'Architecture differs')
    #check('release', 'Kernel release differs')
    check('distname', 'Distribution differs')
    check('distver', 'Distribution version differs')
    #check('version', 'Kernel version differs')


def check_diskspace():
    for host, info in data.iteritems():
        for mount, percent in info['disk']:
            interesting = (mount == '/' or
                           mount.startswith('/var/log') or
                           mount.startswith('/tmp'))
            if interesting and percent > 90:
                crm_script.exit_fail("Not enough space on %s:%s" % (host, mount))


def check_services():
    for host, info in data.iteritems():
        for svc in info['services']:
            if svc['name'] == 'pacemaker' and svc['active'] == 'active':
                crm_script.exit_fail("%s already running pacemaker" % (host))
            if svc['name'] == 'corosync' and svc['active'] == 'active':
                crm_script.exit_fail("%s already running corosync" % (host))


try:
    for host, info in data.iteritems():
        verify_host(host, info)
    compare_system((h, info['system']) for h, info in data.iteritems())

    check_diskspace()
    check_services()

    ret = {}
    ret['iface'] = select_interfaces(crm_script.param('iface'), data)

    crm_script.exit_ok(ret)

except Exception, e:
    crm_script.exit_fail("Verification failed: %s" % (e))
