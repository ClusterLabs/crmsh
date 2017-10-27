#!/usr/bin/env python
from __future__ import print_function
from __future__ import unicode_literals
import crm_script
data = crm_script.get_input()
health_report = data[1]

print("Processing collected information...")

CORE_PACKAGES = ['corosync', 'pacemaker', 'resource-agents']

warnings = []
errors = []

def warn(fmt, *args):
    warnings.append(fmt % args)

def error(fmt, *args):
    errors.append(fmt % args)

# sort {package: {version: [host]}}
rpm_versions = {}

LOW_UPTIME = 60.0
HIGH_LOAD = 1.0

for node, info in health_report.items():
    if node != info['system']['hostname']:
        error("Hostname mismatch: %s is not %s" %
              (node, info['system']['hostname']))

    if float(info['system']['uptime']) < LOW_UPTIME:
        warn("%s: Uptime is low: %ss" % (node, info['system']['uptime']))

    if float(info['system']['loadavg']) > HIGH_LOAD:
        warn("%s: 15 minute load average is %s" % (node, info['system']['loadavg']))

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

    for logfile, state in info['logrotate'].items():
        if not state:
            warn("%s: No log rotation configured for %s" % (node, logfile))

for cp in CORE_PACKAGES:
    if cp not in rpm_versions:
        error("Core package '%s' not installed on any node", cp)

for name, versions in rpm_versions.items():
    if len(versions) > 1:
        desc = ', '.join('%s (%s)' % (v, ', '.join(nodes)) for v, nodes in list(versions.items()))
        warn("Package %s: Versions differ! %s", name, desc)

    all_hosts = set(sum([hosts for hosts in list(versions.values())], []))
    for node in list(health_report.keys()):
        if len(all_hosts) > 0 and node not in all_hosts:
            warn("Package '%s' not installed on host '%s'" % (name, node))


def compare_system(systems):
    def check(value, msg):
        vals = set([system[value] for host, system in systems])
        if len(vals) > 1:
            info = ', '.join('%s: %s' % (h, system[value]) for h, system in systems)
            warn("%s: %s" % (msg, info))

    check('machine', 'Architecture differs')
    check('release', 'Kernel release differs')
    check('distname', 'Distribution differs')
    check('distver', 'Distribution version differs')
    #check('version', 'Kernel version differs')

def compare_files(systems):
    keys = set()
    for host, files in systems:
        keys.update(list(files.keys()))
    for filename in keys:
        vals = set([files.get(filename) for host, files in systems])
        if len(vals) > 1:
            info = ', '.join('%s: %s' % (h, files.get(filename)) for h, files in systems)
            warn("%s: %s" % ("Files differ", info))

compare_system((h, info['system']) for h, info in health_report.items())
compare_files((h, info['files']) for h, info in health_report.items())

if crm_script.output(2):
    report = crm_script.output(2)
    status = report.get('status')
    analysis = report.get('analysis')
    if status and not analysis:
        warn("Cluster report: %s" % (status))
    elif analysis:
        print("INFO: Cluster report:")
        print(analysis)
    else:
        warn("No cluster report generated")

if errors:
    for e in errors:
        print("ERROR:", e)
if warnings:
    for w in warnings:
        print("WARNING:", w)

if not errors and not warnings:
    print("No issues found.")

import os
workdir = os.path.dirname(crm_script.__file__)
print("\nINFO: health-report in directory \"%s\"" % workdir)
