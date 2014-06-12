#!/usr/bin/env python
import crm_script

rc, _, err = crm_script.call(['crm', 'cluster', 'wait_for_startup', '30'])
if rc != 0:
    crm_script.exit_fail("Cluster not responding")

def check_for_primitives():
    rc, out, err = crm_script.call("crm configure show type:primitive | grep primitive", shell=True)
    if rc == 0 and out:
        return True
    return False

if check_for_primitives():
    crm_script.debug("Joined existing cluster - will not reconfigure")
    crm_script.exit_ok(True)

try:
    nodelist = crm_script.param('nodes')
    if len(nodelist) < 3:
        policy = 'ignore'
    else:
        policy = 'stop'
    crm_script.save_template('./basic.cib.template',
                             './basic.cib',
                             no_quorum_policy=policy)
except IOError, e:
    crm_script.exit_fail("IO error: %s" % (str(e)))
except ValueError, e:
    crm_script.exit_fail("Value error: %s" % (str(e)))

rc, _, err = crm_script.call(['crm', 'configure', 'load', 'replace', './basic.cib'])
if rc != 0:
    crm_script.exit_fail("Failed to load CIB configuration: %s" % (err))

crm_script.exit_ok(True)
