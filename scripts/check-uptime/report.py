#!/usr/bin/env python
import crm_script
data = crm_script.get_input()
show_all = crm_script.is_true(data[0]['show_all'])
uptimes = [(h, v['uptime']) for h, v in data[1].iteritems()]
max_uptime = '', 0
for h, t in uptimes:
    if t > max_uptime[1]:
        max_uptime = h, t
if show_all:
    print "Uptimes: %s" % (', '.join("%s: %s" % v for v in uptimes))
print "Longest uptime is %s seconds on host %s" % (max_uptime[1], max_uptime[0])
