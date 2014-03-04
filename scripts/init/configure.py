#!/usr/bin/env python
import sys
import os
import crm_script

host = crm_script.host()
hostinfo = crm_script.output(1)[host]


def service_enabled(name):
    for svc in hostinfo['services']:
        if svc['name'] == name and svc['enabled'] == 'enabled':
            return True
    return False


def service_active(name):
    for svc in hostinfo['services']:
        if svc['name'] == name and svc['active'] == 'active':
            return True
    return False

SUSE_FW_TEMPLATE = """## Name: HAE cluster ports
## Description: opens ports for HAE cluster services
TCP="%(tcp)s"
UDP="%(udp)s"
"""


def configure_firewall():
    corosync_mcastport = crm_script.param('mcastport')
    FW_CLUSTER = '/etc/sysconfig/SuSEfirewall2.d/services/cluster'

    tcp_ports = '30865 5560 7630 21064'
    udp_ports = corosync_mcastport

    if service_enabled('SuSEfirewall2_init'):
        if os.path.isfile(FW_CLUSTER):
            import re
            tmpl = open(FW_CLUSTER).read()
            tmpl = re.sub(r'^TCP="(.*)"', 'TCP="%s"' % (tcp_ports), tmpl, flags=re.M)
            tmpl = re.sub(r'^UDP="(.*)"', 'UDP="%s"' % (udp_ports), tmpl, flags=re.M)
            with open(FW_CLUSTER, 'w') as f:
                f.write(tmpl)
        elif os.path.isdir(os.path.dirname(FW_CLUSTER)):
            with open(FW_CLUSTER, 'w') as fwc:
                fwc.write(SUSE_FW_TEMPLATE % {'tcp': tcp_ports,
                                              'udp': udp_ports})
        else:
            # neither the cluster file nor the services
            # directory exists
            crm_script.exit_fail("SUSE firewall is configured but %s does not exist" %
                                 os.path.dirname(FW_CLUSTER))
        if service_active('SuSEfirewall2_init'):
            crm_script.service('SuSEfirewall2_init', 'restart')

    # TODO: other platforms


def run_install():
    # install packages
    PACKAGES = ['cluster-glue', 'corosync', 'crmsh', 'pacemaker', 'resource-agents']
    for pkg in PACKAGES:
        try:
            crm_script.package(pkg, 'latest')
        except Exception, e:
            crm_script.exit_fail("Failed to install %s: %s" % (pkg, e))

    configure_firewall()

    crm_script.exit_ok(True)


def make_bindnetaddr():
    ba = crm_script.param('bindnetaddr')
    if ba:
        return ba

    # if not, try to figure it out based
    # on preferred interface
    iface = crm_script.param('iface')
    if isinstance(iface, dict):
        iface = iface[host]
    interfaces = hostinfo['net']['interfaces']
    if not iface:
        for info in interfaces:
            if info.get('Destination') == '0.0.0.0':
                iface = info.get('Iface')
                break
    try:
        for info in interfaces:
            if info.get('Iface') != iface:
                continue
            dst = info.get('Destination')
            if dst != '0.0.0.0':
                return info.get('Destination')
    except:
        pass
    crm_script.fail_exit("Could not discover appropriate bindnetaddr")


# configure corosync
def run_corosync():
    # create corosync.conf

    nodelist = crm_script.output(1).keys()
    nodelist_txt = ""
    for i, node in enumerate(nodelist):
        nodelist_txt += """
    node {
        ring0_addr: %s
        nodeid: %s
    }
""" % (node, i + 1)

    quorum_txt = ""
    if len(nodelist) == 1:
        quorum_txt = ''
    if len(nodelist) == 2:
        quorum_txt = """    two_node: 1
"""
    else:
        quorum_txt = """    provider: corosync_votequorum
    expected_votes: %s
""" % ((len(nodelist) / 2) + 1)

    try:
        crm_script.save_template('./corosync.conf.template',
                                 '/etc/corosync/corosync.conf',
                                 bindnetaddr=make_bindnetaddr(),
                                 mcastaddr=crm_script.param('mcastaddr'),
                                 mcastport=crm_script.param('mcastport'),
                                 transport=crm_script.param('transport'),
                                 nodelist=nodelist_txt,
                                 quorum=quorum_txt)
    except Exception, e:
        crm_script.exit_fail(str(e))

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
