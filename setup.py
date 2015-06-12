#!/usr/bin/env python
# Note that this script only installs the python modules,
# the other parts of crmsh are installed by autotools
from distutils.core import setup
import os

SRC_PATH = os.path.relpath(os.path.join(os.path.dirname(__file__), "modules"))

setup(name='crmsh',
      version='2.2.0-rc3',
      description='Command-line interface for High-Availability cluster management',
      author='Dejan Muhamedagic',
      author_email='dejan@suse.de',
      url='http://crmsh.github.io/',
      packages=['crmsh'],
      package_dir={'crmsh': SRC_PATH})
