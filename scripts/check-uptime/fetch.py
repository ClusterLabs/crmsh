#!/usr/bin/python3
import crm_script
try:
    uptime = open('/proc/uptime').read().split()[0]
    crm_script.exit_ok(uptime)
except Exception as e:
    crm_script.exit_fail("Couldn't open /proc/uptime: %s" % (e))
