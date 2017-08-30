#!/usr/bin/env python
from __future__ import print_function
from __future__ import unicode_literals
import crm_script
show_all = crm_script.is_true(crm_script.param('show_all'))
uptimes = list(crm_script.output(1).items())
max_uptime = '', 0
for host, uptime in uptimes:
    if uptime > max_uptime[1]:
        max_uptime = host, uptime
if show_all:
    print("Uptimes: %s" % (', '.join("%s: %s" % v for v in uptimes)))
print("Longest uptime is %s seconds on host %s" % (max_uptime[1], max_uptime[0]))
