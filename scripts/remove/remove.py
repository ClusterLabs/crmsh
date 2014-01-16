#!/usr/bin/env python
import sys
import crm_script

host = crm_script.host()
remove_nodes = crm_script.param('node').split(',')


def run_collect():
    crm_script.exit_ok(host)


def run_validate():
    data = crm_script.output(1)
    for node in remove_nodes:
        if data.get(node) != node:
            crm_script.exit_fail("%s not found or not responding: %s" % (node, data.get(node)))
        if host == node:
            crm_script.exit_fail("Call from another node: %s = %s" % (node, host))
    crm_script.exit_ok(host)


def run_apply():
    for node in remove_nodes:
        rc, out, err = crm_script.call(['ssh',
                                        '-o', 'PasswordAuthentication=no',
                                        'root@%s' % (node),
                                        'systemctl stop corosync.service'])
        if rc != 0:
            crm_script.exit_fail("Failed to stop corosync on %s: %s" % (node, err))

        rc, out, err = crm_script.call(['crm', 'node', 'delete', node])
        if rc != 0:
            crm_script.exit_fail("Failed to remove %s from CIB: %s" % (node, err))

    crm_script.exit_ok({"removed": remove_nodes})

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == 'collect':
        run_collect()
    elif sys.argv[1] == 'validate':
        run_validate()
    elif sys.argv[1] == 'apply':
        run_apply()
    else:
        crm_script.exit_fail("Unknown argument: %s" % sys.argv[1])
