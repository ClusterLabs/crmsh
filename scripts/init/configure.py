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


def make_bindnetaddr():
    ba = crm_script.param('bindnetaddr')
    if ba:
        return ba

    # if not, try to figure it out based
    # on preferred interface
    iface = crm_script.param('iface')
    if isinstance(iface, dict):
        iface = iface[host]
    interfaces = crm_script.output(1)[host]['net']['interfaces']
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
