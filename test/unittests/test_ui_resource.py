import unittest
from unittest import mock

from crmsh import options
from crmsh import ui_resource


class TestUIResource(unittest.TestCase):
    def setUp(self):
        self.rsc_mgmt = ui_resource.RscMgmt()
        self.context = mock.Mock()
        self.context.fatal_error.side_effect = ValueError
        options.force = False

    @mock.patch('crmsh.utils.is_name_sane')
    def test_do_move_invalid_rsc(self, mock_is_sane):
        mock_is_sane.return_value = False
        res = self.rsc_mgmt.do_move(self.context, 'bad:rsc', 'node1')
        self.assertFalse(res)

    @mock.patch('crmsh.utils.is_name_sane')
    def test_do_move_too_many_args(self, mock_is_sane):
        mock_is_sane.return_value = True
        with self.assertRaises(ValueError):
            self.rsc_mgmt.do_move(self.context, 'rsc1', 'node1', 'reboot', 'extra')
        self.context.fatal_error.assert_called_once_with('usage: move <rsc> [<node>] [<lifetime>] [force]')

    @mock.patch('crmsh.xmlutil.is_our_node')
    @mock.patch('crmsh.utils.is_name_sane')
    def test_do_move_invalid_node(self, mock_is_sane, mock_is_our_node):
        mock_is_sane.return_value = True
        mock_is_our_node.return_value = False
        with self.assertRaises(ValueError):
            self.rsc_mgmt.do_move(self.context, 'rsc1', 'invalid_node', 'reboot')
        self.context.fatal_error.assert_called_once_with('Not our node: invalid_node')

    @mock.patch('crmsh.xmlutil.is_our_node')
    @mock.patch('crmsh.utils.is_name_sane')
    def test_do_move_no_node_no_force(self, mock_is_sane, mock_is_our_node):
        mock_is_sane.return_value = True
        mock_is_our_node.return_value = False
        with self.assertRaises(ValueError):
            self.rsc_mgmt.do_move(self.context, 'rsc1')
        self.context.fatal_error.assert_called_once_with(
            "No destination node: specify a destination node or use 'force' to move away from the current node"
        )

    @mock.patch('crmsh.utils.ext_cmd')
    @mock.patch('crmsh.xmlutil.is_our_node')
    @mock.patch('crmsh.utils.is_name_sane')
    def test_do_move_node_success(self, mock_is_sane, mock_is_our_node, mock_ext_cmd):
        mock_is_sane.return_value = True
        mock_is_our_node.return_value = True
        mock_ext_cmd.return_value = 0
        res = self.rsc_mgmt.do_move(self.context, 'rsc1', 'node1')
        self.assertTrue(res)
        mock_ext_cmd.assert_called_once_with("crm_resource --quiet --move --resource 'rsc1' --node 'node1'")

    @mock.patch('crmsh.utils.ext_cmd')
    @mock.patch('crmsh.xmlutil.is_our_node')
    @mock.patch('crmsh.utils.is_name_sane')
    def test_do_move_node_lifetime_force(self, mock_is_sane, mock_is_our_node, mock_ext_cmd):
        mock_is_sane.return_value = True
        mock_is_our_node.return_value = True
        mock_ext_cmd.return_value = 0
        res = self.rsc_mgmt.do_move(self.context, 'rsc1', 'node1', 'reboot', 'force')
        self.assertTrue(res)
        mock_ext_cmd.assert_called_once_with(
            "crm_resource --quiet --move --resource 'rsc1' --node 'node1' --lifetime 'reboot' --force"
        )

    @mock.patch('crmsh.utils.ext_cmd')
    @mock.patch('crmsh.xmlutil.is_our_node')
    @mock.patch('crmsh.utils.is_name_sane')
    def test_do_move_force_without_node(self, mock_is_sane, mock_is_our_node, mock_ext_cmd):
        mock_is_sane.return_value = True
        mock_is_our_node.return_value = False
        mock_ext_cmd.return_value = 0
        res = self.rsc_mgmt.do_move(self.context, 'rsc1', 'force')
        self.assertTrue(res)
        mock_ext_cmd.assert_called_once_with("crm_resource --quiet --move --resource 'rsc1'  --force")

    @mock.patch('crmsh.utils.is_name_sane')
    def test_do_ban_invalid_rsc(self, mock_is_sane):
        mock_is_sane.return_value = False
        res = self.rsc_mgmt.do_ban(self.context, 'bad:rsc', 'node1')
        self.assertFalse(res)

    @mock.patch('crmsh.utils.is_name_sane')
    def test_do_ban_too_many_args(self, mock_is_sane):
        mock_is_sane.return_value = True
        with self.assertRaises(ValueError):
            self.rsc_mgmt.do_ban(self.context, 'rsc1', 'node1', 'reboot', 'extra')
        self.context.fatal_error.assert_called_once_with('usage: ban <rsc> [<node>] [<lifetime>]')

    @mock.patch('crmsh.xmlutil.is_our_node')
    @mock.patch('crmsh.utils.is_name_sane')
    def test_do_ban_invalid_node(self, mock_is_sane, mock_is_our_node):
        mock_is_sane.return_value = True
        mock_is_our_node.return_value = False
        with self.assertRaises(ValueError):
            self.rsc_mgmt.do_ban(self.context, 'rsc1', 'invalid_node', 'reboot')
        self.context.fatal_error.assert_called_once_with('Not our node: invalid_node')

    @mock.patch('crmsh.utils.ext_cmd')
    @mock.patch('crmsh.utils.is_name_sane')
    def test_do_ban_no_node_success(self, mock_is_sane, mock_ext_cmd):
        mock_is_sane.return_value = True
        mock_ext_cmd.return_value = 0
        res = self.rsc_mgmt.do_ban(self.context, 'rsc1')
        self.assertTrue(res)
        mock_ext_cmd.assert_called_once_with("crm_resource --ban --resource 'rsc1' ")

    @mock.patch('crmsh.utils.ext_cmd')
    @mock.patch('crmsh.xmlutil.is_our_node')
    @mock.patch('crmsh.utils.is_name_sane')
    def test_do_ban_node_and_lifetime_success(self, mock_is_sane, mock_is_our_node, mock_ext_cmd):
        mock_is_sane.return_value = True
        mock_is_our_node.return_value = True
        mock_ext_cmd.return_value = 0
        res = self.rsc_mgmt.do_ban(self.context, 'rsc1', 'node1', 'reboot')
        self.assertTrue(res)
        mock_ext_cmd.assert_called_once_with(
            "crm_resource --ban --resource 'rsc1' --node 'node1' --lifetime 'reboot'"
        )

    @mock.patch('crmsh.utils.ext_cmd')
    @mock.patch('crmsh.xmlutil.is_our_node')
    @mock.patch('crmsh.utils.is_name_sane')
    def test_do_ban_lifetime_only(self, mock_is_sane, mock_is_our_node, mock_ext_cmd):
        mock_is_sane.return_value = True
        mock_is_our_node.return_value = False
        mock_ext_cmd.return_value = 0
        res = self.rsc_mgmt.do_ban(self.context, 'rsc1', 'reboot')
        self.assertTrue(res)
        mock_ext_cmd.assert_called_once_with("crm_resource --ban --resource 'rsc1'  --lifetime 'reboot'")

    @mock.patch('crmsh.utils.ext_cmd')
    @mock.patch('crmsh.xmlutil.is_our_node')
    @mock.patch('crmsh.utils.is_name_sane')
    def test_do_ban_node_lifetime_force(self, mock_is_sane, mock_is_our_node, mock_ext_cmd):
        mock_is_sane.return_value = True
        mock_is_our_node.return_value = True
        mock_ext_cmd.return_value = 0
        res = self.rsc_mgmt.do_ban(self.context, 'rsc1', 'node1', 'reboot', 'force')
        self.assertTrue(res)
        mock_ext_cmd.assert_called_once_with(
            "crm_resource --ban --resource 'rsc1' --node 'node1' --lifetime 'reboot' --force"
        )

    @mock.patch('crmsh.utils.ext_cmd')
    @mock.patch('crmsh.utils.is_name_sane')
    def test_do_ban_force_only(self, mock_is_sane, mock_ext_cmd):
        mock_is_sane.return_value = True
        mock_ext_cmd.return_value = 0
        res = self.rsc_mgmt.do_ban(self.context, 'rsc1', 'force')
        self.assertTrue(res)
        mock_ext_cmd.assert_called_once_with("crm_resource --ban --resource 'rsc1'  --force")

