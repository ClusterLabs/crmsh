#!/usr/bin/python3
import os
import crm_script as crm


if not os.path.isfile('/usr/sbin/crm') and not os.path.isfile('/usr/bin/crm'):
    # crm not installed
    crm.exit_ok({'status': 'crm not installed'})


def get_from_date():
    rc, out, err = crm.call("date '+%F %H:%M' --date='1 day ago'", shell=True)
    return out.strip()


def create_report():
    cmd = ['crm', 'report',
           '-f', get_from_date(),
           '-Z', 'health-report']
    rc, out, err = crm.call(cmd, shell=False)
    return rc == 0


if not create_report():
    crm.exit_ok({'status': 'Failed to create report'})


def extract_report():
    rc, out, err = crm.call(['tar', 'xzf', 'health-report.tar.gz'], shell=False)
    return rc == 0


if not extract_report():
    crm.exit_ok({'status': 'Failed to extract report'})

analysis = ''
if os.path.isfile('health-report/analysis.txt'):
    analysis = open('health-report/analysis.txt').read()

crm.exit_ok({'status': 'OK', 'analysis': analysis})
