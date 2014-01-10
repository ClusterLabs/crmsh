#!/usr/bin/env python
import crm_script
data = crm_script.get_input()
health_report = data[1]

rpm_versions = {}

for node, info in health_report.iteritems():
    for rpm in info['rpm']:
        if rpm['name'] not in rpm_versions:
            rpm_versions[rpm['name']] = {}
        if 'error' in rpm:
            rpm_versions[rpm['name']][node] = None
        else:
            rpm_versions[rpm['name']][node] = rpm['version']

print "RPM versions:"
for name, rpm in rpm_versions.iteritems():
    for k, v in rpm.iteritems():
        if v is not None:
            break
    else:
        print "%s: Not installed" % (name)
        continue
    print "%s: %s" % (name, ', '.join('%s:%s' % (k, v) for k, v in rpm.iteritems()))
print "Health check complete."
