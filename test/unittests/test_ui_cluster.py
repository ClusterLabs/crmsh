import logging
import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from crmsh import ui_cluster

logging.basicConfig(level=logging.INFO)

class TestCluster(unittest.TestCase):
    """
    Unitary tests for class utils.IP
    """
    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """
        self.ui_cluster_inst = ui_cluster.Cluster()

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.utils.service_is_active')
    @mock.patch('crmsh.ui_cluster.parse_option_for_nodes')
    @mock.patch('crmsh.utils.is_qdevice_configured')
    def test_do_start_already_started(self, mock_qdevice_configured, mock_parse_nodes, mock_active, mock_info):
        mock_qdevice_configured.return_value = False
        context_inst = mock.Mock()
        mock_parse_nodes.return_value = ["node1", "node2"]
        mock_active.side_effect = [True, True]
        self.ui_cluster_inst.do_start(context_inst, "node1", "node2")
        mock_parse_nodes.assert_called_once_with(context_inst, "node1", "node2")
        mock_active.assert_has_calls([
            mock.call("pacemaker.service", remote_addr="node1"),
            mock.call("pacemaker.service", remote_addr="node2")
            ])
        mock_info.assert_has_calls([
            mock.call("The cluster stack already started on node1"),
            mock.call("The cluster stack already started on node2")
            ])

    @mock.patch('crmsh.qdevice.QDevice.check_qdevice_vote')
    @mock.patch('crmsh.bootstrap.start_pacemaker')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.utils.is_qdevice_configured')
    @mock.patch('crmsh.utils.start_service')
    @mock.patch('crmsh.utils.service_is_active')
    @mock.patch('crmsh.ui_cluster.parse_option_for_nodes')
    def test_do_start(self, mock_parse_nodes, mock_active, mock_start, mock_qdevice_configured, mock_info, mock_start_pacemaker, mock_check_qdevice):
        context_inst = mock.Mock()
        mock_start_pacemaker.return_value = ["node1"]
        mock_parse_nodes.return_value = ["node1"]
        mock_active.side_effect = [False, False]
        mock_qdevice_configured.return_value = True

        self.ui_cluster_inst.do_start(context_inst, "node1")

        mock_active.assert_has_calls([
            mock.call("pacemaker.service", remote_addr="node1"),
            mock.call("corosync-qdevice.service", remote_addr="node1")
            ])
        mock_start.assert_called_once_with("corosync-qdevice", node_list=["node1"])
        mock_qdevice_configured.assert_called_once_with()
        mock_info.assert_called_once_with("The cluster stack started on node1")

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.utils.service_is_active')
    @mock.patch('crmsh.ui_cluster.parse_option_for_nodes')
    def test_do_stop_already_stopped(self, mock_parse_nodes, mock_active, mock_info):
        context_inst = mock.Mock()
        mock_parse_nodes.return_value = ["node1"]
        mock_active.side_effect = [False, False]
        self.ui_cluster_inst.do_stop(context_inst, "node1")
        mock_active.assert_has_calls([
            mock.call("corosync.service", remote_addr="node1"),
            mock.call("sbd.service", remote_addr="node1")
            ])
        mock_info.assert_called_once_with("The cluster stack already stopped on node1")

    @mock.patch('logging.Logger.debug')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.utils.stop_service')
    @mock.patch('crmsh.utils.set_dlm_option')
    @mock.patch('crmsh.utils.is_quorate')
    @mock.patch('crmsh.utils.is_dlm_running')
    @mock.patch('crmsh.utils.get_dc')
    @mock.patch('crmsh.utils.check_function_with_timeout')
    @mock.patch('crmsh.utils.get_property')
    @mock.patch('crmsh.utils.service_is_active')
    @mock.patch('crmsh.ui_cluster.parse_option_for_nodes')
    def test_do_stop(self, mock_parse_nodes, mock_active, mock_get_property, mock_check, mock_get_dc, mock_dlm_running, mock_is_quorate, mock_set_dlm, mock_stop, mock_info, mock_debug):
        context_inst = mock.Mock()
        mock_stop.side_effect = [["node1"], ["ndoe1"], ["node1"]]
        mock_parse_nodes.return_value = ["node1"]
        mock_active.side_effect = [True, True, True]
        mock_dlm_running.return_value = True
        mock_is_quorate.return_value = False
        mock_get_property.return_value = "20s"

        self.ui_cluster_inst.do_stop(context_inst, "node1")

        mock_active.assert_has_calls([
            mock.call("corosync.service", remote_addr="node1"),
            mock.call("pacemaker.service", remote_addr="node1"),
            mock.call("corosync-qdevice.service")
            ])
        mock_stop.assert_has_calls([
            mock.call("pacemaker", node_list=["node1"]),
            mock.call("corosync-qdevice.service", node_list=["node1"]),
            mock.call("corosync", node_list=["node1"])
            ])
        mock_info.assert_called_once_with("The cluster stack stopped on node1")
        mock_debug.assert_called_once_with("Quorum is lost; Set enable_quorum_fencing=0 and enable_quorum_lockspace=0 for dlm")
        mock_check.assert_called_once_with(mock_get_dc, wait_timeout=25)
