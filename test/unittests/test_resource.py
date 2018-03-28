# Copyright (C) 2014-2018 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.


#standard_library.install_aliases()
from builtins import object
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
        assert commands[-1] == ("crm_resource --resource 'rsc1' --meta --set-parameter maintenance --parameter-value 'true'",)
        assert rscui.do_maintenance(mc, 'rsc1', 'on') is True
        assert commands[-1] == ("crm_resource --resource 'rsc1' --meta --set-parameter maintenance --parameter-value 'true'",)
        assert rscui.do_maintenance(mc, 'rsc1', 'off') is True
        assert commands[-1] == ("crm_resource --resource 'rsc1' --meta --set-parameter maintenance --parameter-value 'false'",)
    finally:
        utils.ext_cmd = _pre_ext_cmd
