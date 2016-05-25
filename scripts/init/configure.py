#!/usr/bin/env python
import sys
import os
import crm_script
import crm_init


def _authorize_key(keypath):
    "add key to authorized_keys"
    pubkeypath = ''.join([keypath, '.pub'])
    if os.path.exists('/root/.ssh/authorized_keys'):
        pubkey = open(pubkeypath).read()
        if pubkey not in open('/root/.ssh/authorized_keys').read():
            crm_script.sudo_call("cat %s >> /root/.ssh/authorized_keys" % (pubkeypath), shell=True)
    else:
        crm_script.sudo_call(["cp", pubkeypath, '/root/.ssh/authorized_keys'])


def run_ssh():
    try:
        crm_script.service('sshd', 'start')
        rc, _, _ = crm_script.sudo_call(["mkdir", "-m", "700", "-p", "/root/.ssh"])
        if rc != 0:
            crm_script.exit_fail("Failed to create /root/.ssh directory")
        keypath = None
        for key in ('id_rsa', 'id_dsa', 'id_ecdsa'):
            if os.path.exists(os.path.join('/root/.ssh', key)):
                keypath = os.path.join('/root/.ssh', key)
                break
        if not keypath:
            keypath = os.path.join('/root/.ssh', 'id_rsa')
            keygen = ['ssh-keygen', '-q', '-f', keypath,
                      '-C', 'Cluster Internal', '-N', '']
            rc, out, err = crm_script.sudo_call(keygen)
            if rc != 0:
                crm_script.exit_fail("Failed to generate SSH key")
        _authorize_key(keypath)
        crm_script.exit_ok(True)
    except IOError, e:
        crm_script.exit_fail(str(e))


def run_install():
    packages = ['cluster-glue', 'corosync', 'crmsh', 'pacemaker', 'resource-agents']
    crm_init.install_packages(packages)
    crm_init.configure_firewall()
    crm_script.exit_ok(True)


def make_bindnetaddr():
    host = crm_script.host()
    hostinfo = crm_script.output(2)[host]
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

    nodelist = crm_script.output(2).keys()
    nodelist_txt = ""
    for i, node in enumerate(nodelist):
        nodelist_txt += """
    node {
        ring0_addr: %s
        nodeid: %s
    }
""" % (node, i + 1)

    twonode = 1 if len(nodelist) == 2 else 0
    expected_votes = len(nodelist)

    quorum_txt = """
    provider: corosync_votequorum
    two_node: %s
    expected_votes: %s
    """ % (twonode, expected_votes)

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
    elif sys.argv[1] == 'ssh':
        run_ssh()
    elif sys.argv[1] == 'install':
        run_install()
    elif sys.argv[1] == 'corosync':
        run_corosync()
    else:
        crm_script.exit_fail("Bad argument to configure.py: %s" % (sys.argv[1]))
