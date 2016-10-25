#!/usr/bin/env python
# Note that this script only installs the python modules,
# the other parts of crmsh are installed by autotools
from setuptools import setup

setup(name='crmsh',
      version='2.3.2',
      description='Command-line interface for High-Availability cluster management',
      author='Kristoffer Gronlund',
      author_email='kgronlund@suse.com',
      url='http://crmsh.github.io/',
      packages=['crmsh'],
      install_requires=['parallax', 'lxml', 'PyYAML', 'python-dateutil'],
      scripts=['crm'],
      data_files=[('/usr/share/crmsh', ['doc/crm.8.adoc'])],
      include_package_data = True)
