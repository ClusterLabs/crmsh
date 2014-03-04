#!/usr/bin/env python
import crm_script

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
                if i.get('Destination') == '0.0.0.0':
                    selections[host] = i['Iface']
                    break

    def invalid(host, iface):
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


def make_mcastaddr():
    import random
    random.seed()
    b, c, d = random.randint(1, 254), random.randint(1, 254), random.randint(1, 254)
    return "%d.%d.%d.%d" % (239, b, c, d)

try:
    for host, info in data.iteritems():
        verify_host(host, info)
    compare_system((h, info['system']) for h, info in data.iteritems())

    check_diskspace()
    check_services()

    ret = {}
    ret['iface'] = select_interfaces(crm_script.param('iface'), data)

    if not crm_script.param('mcastaddr'):
        ret['mcastaddr'] = make_mcastaddr()

    crm_script.exit_ok(ret)

except Exception, e:
    crm_script.exit_fail("Verification failed: %s" % (e))
