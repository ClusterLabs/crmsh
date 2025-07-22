#!/usr/bin/env python3
# Note that this script only installs the python modules,
# the other parts of crmsh are installed by autotools
from setuptools import setup
import contextlib
import re

VERSION = '0.0.1'

with contextlib.suppress(Exception):
    with open('version', 'r', encoding='ascii') as f:
        match = re.match('^\\d+\\.\\d+\\.\\d+', f.read().strip())
        if match:
            VERSION = match.group(0)

setup(name='crmsh',
      version=VERSION,
      description='Command-line interface for High-Availability cluster management',
      author='Kristoffer Gronlund, Xin Liang',
      author_email='XLiang@suse.com',
      url='http://crmsh.github.io/',
      packages=['crmsh', 'crmsh.crash_test', 'crmsh.report', 'crmsh.prun'],
      install_requires=['lxml', 'PyYAML', 'python-dateutil', 'packaging'],
      scripts=['bin/crm'],
      include_package_data=True)
