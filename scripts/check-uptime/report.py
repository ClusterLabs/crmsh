#!/usr/bin/python3
import crm_script
show_all = crm_script.is_true(crm_script.param('show_all'))
uptimes = list(crm_script.output(1).items())
max_uptime = '', 0.0
for host, uptime in uptimes:
    if float(uptime) > max_uptime[1]:
        max_uptime = host, float(uptime)
if show_all:
    print("Uptimes: %s" % (', '.join("%s: %s" % v for v in uptimes)))
print("Longest uptime is %s seconds on host %s" % (max_uptime[1], max_uptime[0]))
