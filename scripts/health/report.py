#!/usr/bin/env python
import crm_script
data = crm_script.get_input()
health_report = data[1]

print "Processing collected information..."

CORE_PACKAGES = ['corosync', 'pacemaker', 'resource-agents']

warnings = []
errors = []

def warn(fmt, *args):
    warnings.append(fmt % args)

def error(fmt, *args):
    errors.append(fmt % args)

# sort {package: {version: [host]}}
rpm_versions = {}

for node, info in health_report.iteritems():
    for rpm in info['rpm']:
        if 'error' in rpm:
            if rpm['name'] not in rpm_versions:
                rpm_versions[rpm['name']] = {rpm['error']: [node]}
            else:
                versions = rpm_versions[rpm['name']]
                if rpm['error'] in versions:
                    versions[rpm['error']].append(node)
                else:
                    versions[rpm['error']] = [node]
        else:
            if rpm['name'] not in rpm_versions:
                rpm_versions[rpm['name']] = {rpm['version']: [node]}
            else:
                versions = rpm_versions[rpm['name']]
                if rpm['version'] in versions:
                    versions[rpm['version']].append(node)
                else:
                    versions[rpm['version']] = [node]
    for disk, use in info['disk']:
        use = int(use[:-1])
        if use > 90:
            warn("On %s, disk %s usage is %s%%", node, disk, use)

for cp in CORE_PACKAGES:
    if cp not in rpm_versions:
        error("Core package '%s' not installed on any node", cp)

for name, versions in rpm_versions.iteritems():
    if len(versions) > 1:
        desc = ', '.join('%s (%s)' % (v, ', '.join(nodes)) for v, nodes in versions.items())
        warn("Package %s: Versions differ! %s", name, desc)

    all_hosts = set(sum([hosts for hosts in versions.values()], []))
    for node in health_report.keys():
        if len(all_hosts) > 0 and node not in all_hosts:
            warn("Package '%s' not installed on host '%s'" % (name, node))

if errors:
    for e in errors:
        print "ERROR:", e
if warnings:
    for w in warnings:
        print "WARNING:", w
if not errors and not warnings:
    print "No issues found."
