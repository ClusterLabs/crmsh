#!/usr/bin/env python
import crm_script

rc, _, err = crm_script.call(['crm', 'cluster', 'wait_for_startup', '30'])
if rc != 0:
    crm_script.exit_fail("Cluster not responding")

rc, _, err = crm_script.call(['crm', 'configure', 'load', 'replace', './basic.cib'])
if rc != 0:
    crm_script.exit_fail("Failed to load CIB configuration: %s" % (err))

crm_script.exit_ok(True)
