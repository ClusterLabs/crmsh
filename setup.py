#!/usr/bin/env python
# Note that this script only installs the python modules,
# the other parts of crmsh are installed by autotools
from distutils.core import setup
import os
from setuptools.command.egg_info import egg_info

SRC_PATH = os.path.relpath(os.path.join(os.path.dirname(__file__), "modules"))


class EggInfoCommand(egg_info):
    def run(self):
        if "build" in self.distribution.command_obj:
            build_command = self.distribution.command_obj["build"]
            self.egg_base = build_command.build_base
            self.egg_info = os.path.join(self.egg_base, os.path.basename(self.egg_info))

        egg_info.run(self)

setup(name='crmsh',
      version='2.2.0-rc1',
      description='Command-line interface for High-Availability cluster management',
      author='Dejan Muhamedagic',
      author_email='dejan@suse.de',
      url='http://crmsh.github.io/',
      packages=['crmsh'],
      package_dir={'crmsh': SRC_PATH},
      scripts=['crm'],
      cmdclass={
          "egg_info": EggInfoCommand,
      }
     )
