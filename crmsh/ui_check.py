# Copyright (C) 2024 Aleksei Burlakov <aburlakov@suse.com>
# See COPYING for license information.
from . import command
from . import log
from typing import Tuple
from crmsh.report import utils as report_utils
from crmsh import utils as just_utils, constants

logger = log.setup_logger(__name__)

class Check(command.UI):
    '''
    Check that migration to sle16 is safe

    - Packages installed correctly
    - T.B.A.
    '''
    name = "check"

    def requires(self):
        return True

    def __init__(self):
        command.UI.__init__(self)


    def check_version(self, package_name, minimum_version) -> Tuple[int, str]:
        pkg = report_utils.Package(package_name)
        current_version = pkg.pkg_ver_rpm('%{VERSION}')
        if current_version == '':
            return -1, ''
        if not just_utils.is_larger_than_min_version(current_version, minimum_version):
            return -2, current_version
        return 0, current_version

    def check_versions(self):
        print('Package versions')
        for package_name, minimum_version in [
            ['SAPHanaSR', '0.162.2'], # all sle15 have the same SAPHanaSR
            ['libknet1', '1.21'],     # sle154 and older have no libknet
            ['libqb100','2.0.4'],     # minimum (sle154). 2.0.2 (15.3) is too old
            ['systemd','249.11']      # not sure, possibly older
            ]:
            rc, current_version = self.check_version(package_name, minimum_version)
            if rc == 0:
                print(f'  {constants.GREEN}OK{constants.END}: {package_name}-{current_version}')
            elif rc == -1:
                print(f'  {constants.RED}FAIL{constants.END}: {package_name} is not installed')
            elif rc == -2:
                print(f'  {constants.RED}FAIL{constants.END}: {package_name}-{current_version} is too old. \
Minimum required version {minimum_version}')

    @command.skill_level('administrator')
    def do_migration(self, context, *args):
        'usage: migration'
        self.check_versions()
