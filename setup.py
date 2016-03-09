#!/usr/bin/env python
# Note that this script only installs the python modules,
# the other parts of crmsh are installed by autotools
from distutils.core import setup

setup(name='crmsh',
      version='2.2.0',
      description='Command-line interface for High-Availability cluster management',
      author='Kristoffer Gronlund',
      author_email='kgronlund@suse.com',
      url='http://crmsh.github.io/',
      packages=['crmsh'])
