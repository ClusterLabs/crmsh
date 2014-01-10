#!/usr/bin/env python
import crm_script
try:
    uptime = open('/proc/uptime').read().split()[0]
except:
    crm_script.exit_fail("Couldn't open /proc/uptime")
crm_script.exit_ok({'uptime': uptime})
