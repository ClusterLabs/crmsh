#!/usr/bin/env python
import crm_script
import crm_init


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


def make_mcastaddr():
    import random
    random.seed()
    b, c, d = random.randint(1, 254), random.randint(1, 254), random.randint(1, 254)
    return "%d.%d.%d.%d" % (239, b, c, d)

try:
    data = crm_script.output(2)

    crm_init.verify(data)

    ret = {}
    ret['iface'] = select_interfaces(crm_script.param('iface'), data)

    if not crm_script.param('mcastaddr'):
        ret['mcastaddr'] = make_mcastaddr()

    crm_script.exit_ok(ret)

except Exception, e:
    crm_script.exit_fail("Verification failed: %s" % (e))
