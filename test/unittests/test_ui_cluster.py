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
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    @mock.patch('crmsh.ui_cluster.parse_option_for_nodes')
    @mock.patch('crmsh.corosync.is_qdevice_configured')
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
    @mock.patch('crmsh.corosync.is_qdevice_configured')
    @mock.patch('crmsh.service_manager.ServiceManager.start_service')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
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

    @mock.patch('crmsh.ui_cluster.Cluster._wait_for_dc')
    @mock.patch('crmsh.ui_cluster.Cluster._node_ready_to_stop_cluster_service')
    @mock.patch('crmsh.ui_cluster.parse_option_for_nodes')
    def test_do_stop_return(self, mock_parse_nodes, mock_node_ready_to_stop_cluster_service, mock_dc):
        mock_parse_nodes.return_value = ["node1", "node2"]
        mock_node_ready_to_stop_cluster_service.side_effect = [False, False]

        context_inst = mock.Mock()
        self.ui_cluster_inst.do_stop(context_inst, "node1", "node2")

        mock_parse_nodes.assert_called_once_with(context_inst, "node1", "node2")
        mock_node_ready_to_stop_cluster_service.assert_has_calls([mock.call("node1"), mock.call("node2")])
        mock_dc.assert_not_called()

    @mock.patch('logging.Logger.debug')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.ui_cluster.ServiceManager')
    @mock.patch('crmsh.ui_cluster.Cluster._set_dlm')
    @mock.patch('crmsh.ui_cluster.Cluster._wait_for_dc')
    @mock.patch('crmsh.ui_cluster.Cluster._node_ready_to_stop_cluster_service')
    @mock.patch('crmsh.ui_cluster.parse_option_for_nodes')
    def test_do_stop(self, mock_parse_nodes, mock_node_ready_to_stop_cluster_service, mock_dc,
                     mock_set_dlm, mock_service_manager, mock_info, mock_debug):
        mock_parse_nodes.return_value = ["node1", "node2"]
        mock_node_ready_to_stop_cluster_service.side_effect = [True, False]
        mock_service_manager_inst = mock.Mock()
        mock_service_manager.return_value = mock_service_manager_inst
        mock_service_manager_inst.stop_service.side_effect = [["node1"], ["node1"], ["node1"]]
        mock_service_manager_inst.service_is_active.return_value = True

        context_inst = mock.Mock()
        self.ui_cluster_inst.do_stop(context_inst, "node1", "node2")

        mock_parse_nodes.assert_called_once_with(context_inst, "node1", "node2")
        mock_node_ready_to_stop_cluster_service.assert_has_calls([mock.call("node1"), mock.call("node2")])
        mock_debug.assert_called_once_with("stop node list: ['node1']")
        mock_dc.assert_called_once_with("node1")
        mock_set_dlm.assert_called_once_with("node1")
        mock_service_manager_inst.stop_service.assert_has_calls([
            mock.call("pacemaker", node_list=["node1"]),
            mock.call("corosync-qdevice.service", node_list=["node1"]),
            mock.call("corosync", node_list=["node1"]),
            ])
        mock_info.assert_called_once_with("The cluster stack stopped on node1")

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.ui_cluster.ServiceManager')
    def test_node_ready_to_stop_cluster_service_corosync(self, mock_service_manager, mock_info):
        mock_service_manager_inst = mock.Mock()
        mock_service_manager.return_value = mock_service_manager_inst
        mock_service_manager_inst.service_is_active.side_effect = [False, True, False]
        res = self.ui_cluster_inst._node_ready_to_stop_cluster_service("node1")
        assert res is False
        mock_service_manager_inst.service_is_active.assert_has_calls([
            mock.call("corosync.service", remote_addr="node1"),
            mock.call("sbd.service", remote_addr="node1"),
            mock.call("pacemaker.service", remote_addr="node1"),
            ])
        mock_service_manager_inst.stop_service.assert_called_once_with("corosync", remote_addr="node1")
        mock_info.assert_called_once_with("The cluster stack stopped on node1")

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.ui_cluster.ServiceManager')
    def test_node_ready_to_stop_cluster_service_pacemaker(self, mock_service_manager, mock_info):
        mock_service_manager_inst = mock.Mock()
        mock_service_manager.return_value = mock_service_manager_inst
        mock_service_manager_inst.service_is_active.side_effect = [True, True, False]
        res = self.ui_cluster_inst._node_ready_to_stop_cluster_service("node1")
        assert res is False
        mock_service_manager_inst.service_is_active.assert_has_calls([
            mock.call("corosync.service", remote_addr="node1"),
            mock.call("sbd.service", remote_addr="node1"),
            mock.call("pacemaker.service", remote_addr="node1"),
            ])
        mock_service_manager_inst.stop_service.assert_called_once_with("corosync", remote_addr="node1")
        mock_info.assert_called_once_with("The cluster stack stopped on node1")

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.ui_cluster.ServiceManager')
    def test_node_ready_to_stop_cluster_service(self, mock_service_manager, mock_info):
        mock_service_manager_inst = mock.Mock()
        mock_service_manager.return_value = mock_service_manager_inst
        mock_service_manager_inst.service_is_active.side_effect = [True, True, True]
        res = self.ui_cluster_inst._node_ready_to_stop_cluster_service("node1")
        assert res is True
        mock_service_manager_inst.service_is_active.assert_has_calls([
            mock.call("corosync.service", remote_addr="node1"),
            mock.call("sbd.service", remote_addr="node1"),
            mock.call("pacemaker.service", remote_addr="node1"),
            ])
        mock_info.assert_not_called()
