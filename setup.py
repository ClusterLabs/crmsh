#!/usr/bin/env python3
# Note that this script only installs the python modules,
# the other parts of crmsh are installed by autotools
from setuptools import setup

setup(name='crmsh',
      version='4.4.0',
      description='Command-line interface for High-Availability cluster management',
      author='Kristoffer Gronlund, Xin Liang',
      author_email='XLiang@suse.com',
      url='http://crmsh.github.io/',
      packages=['crmsh', 'crmsh.crash_test', 'crmsh.report'],
      install_requires=['parallax', 'lxml', 'PyYAML', 'py-dateutil'],
      scripts=['bin/crm'],
      data_files=[('/usr/share/crmsh', ['doc/crm.8.adoc'])],
      include_package_data=True)
