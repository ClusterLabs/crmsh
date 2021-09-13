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
    def test_do_start_already_started(self, mock_active, mock_info):
        context_inst = mock.Mock()
        mock_active.return_value = True
        self.ui_cluster_inst.do_start(context_inst)
        mock_active.assert_called_once_with("pacemaker.service")
        mock_info.assert_called_once_with("Cluster services already started")

    @mock.patch('crmsh.bootstrap.start_pacemaker')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.utils.is_qdevice_configured')
    @mock.patch('crmsh.utils.start_service')
    @mock.patch('crmsh.utils.service_is_active')
    def test_do_start(self, mock_active, mock_start, mock_qdevice_configured, mock_info, mock_start_pacemaker):
        context_inst = mock.Mock()
        mock_active.return_value = False
        mock_qdevice_configured.return_value = True

        self.ui_cluster_inst.do_start(context_inst)

        mock_active.assert_called_once_with("pacemaker.service")
        mock_start.assert_has_calls([mock.call("corosync-qdevice")])
        mock_qdevice_configured.assert_called_once_with()
        mock_info.assert_called_once_with("Cluster services started")

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.utils.service_is_active')
    def test_do_stop_already_stopped(self, mock_active, mock_info):
        context_inst = mock.Mock()
        mock_active.return_value = False
        self.ui_cluster_inst.do_stop(context_inst)
        mock_active.assert_called_once_with("corosync.service")
        mock_info.assert_called_once_with("Cluster services already stopped")

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.utils.stop_service')
    @mock.patch('crmsh.utils.service_is_active')
    def test_do_stop(self, mock_active, mock_stop, mock_info):
        context_inst = mock.Mock()
        mock_active.side_effect = [True, True]

        self.ui_cluster_inst.do_stop(context_inst)

        mock_active.assert_has_calls([mock.call("corosync.service"), mock.call("corosync-qdevice")])
        mock_stop.assert_has_calls([mock.call("corosync-qdevice"), mock.call("corosync")])
        mock_info.assert_called_once_with("Cluster services stopped")
