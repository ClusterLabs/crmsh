#!/usr/bin/env python
from __future__ import unicode_literals
import crm_script
try:
    uptime = open('/proc/uptime').read().split()[0]
    crm_script.exit_ok(uptime)
except Exception as e:
    crm_script.exit_fail("Couldn't open /proc/uptime: %s" % (e))
