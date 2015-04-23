# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA


from crmsh import ui_resource
from crmsh import utils


def test_maintenance():
    errors = []
    commands = []

    def mockcmd(*args):
        commands.append(args)
        return 0

    class MockContext(object):
        def fatal_error(*args):
            errors.append(args)
    mc = MockContext()

    _pre_ext_cmd = utils.ext_cmd
    try:
        utils.ext_cmd = mockcmd
        rscui = ui_resource.RscMgmt()
        assert rscui.do_maintenance(mc, 'rsc1') is True
        assert commands[-1] == ("crm_resource -r 'rsc1' --meta -p maintenance -v 'true'",)
        assert rscui.do_maintenance(mc, 'rsc1', 'on') is True
        assert commands[-1] == ("crm_resource -r 'rsc1' --meta -p maintenance -v 'true'",)
        assert rscui.do_maintenance(mc, 'rsc1', 'off') is True
        assert commands[-1] == ("crm_resource -r 'rsc1' --meta -p maintenance -v 'false'",)
    finally:
        utils.ext_cmd = _pre_ext_cmd
