#!/usr/bin/env python
import crm_script

rc, _, err = crm_script.call(['crm', 'cluster', 'wait_for_startup', '30'])
if rc != 0:
    crm_script.exit_fail("Cluster not responding")

try:
    nodelist = crm_script.output(1).keys()
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
