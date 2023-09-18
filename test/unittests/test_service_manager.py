import unittest
from unittest import mock

import crmsh.sh
from crmsh.service_manager import ServiceManager


@mock.patch("crmsh.service_manager.ServiceManager._call_with_parallax")
class TestServiceManager(unittest.TestCase):
    """
    Unitary tests for class ServiceManager
    """

    def setUp(self) -> None:
        self.service_manager = ServiceManager(mock.Mock(crmsh.sh.AutoShell))
        self.service_manager._run_on_single_host = mock.Mock(self.service_manager._run_on_single_host)
        self.service_manager._call = mock.Mock(self.service_manager._call)

    def test_call_single_node(self, mock_call_with_parallax: mock.MagicMock):
        self.service_manager = ServiceManager(mock.Mock(crmsh.sh.AutoShell))
        self.service_manager._run_on_single_host = mock.Mock(self.service_manager._run_on_single_host)
        self.service_manager._run_on_single_host.return_value = 0
        self.assertEqual(['node1'], self.service_manager._call('node1', list(), 'foo'))
        self.service_manager._run_on_single_host.assert_called_once_with('foo', 'node1')
        mock_call_with_parallax.assert_not_called()

    def test_call_single_node_failure(self, mock_call_with_parallax: mock.MagicMock):
        self.service_manager = ServiceManager(mock.Mock(crmsh.sh.AutoShell))
        self.service_manager._run_on_single_host = mock.Mock(self.service_manager._run_on_single_host)
        self.service_manager._run_on_single_host.return_value = 1
        self.assertEqual(list(), self.service_manager._call('node1', list(), 'foo'))
        self.service_manager._run_on_single_host.assert_called_once_with('foo', 'node1')
        mock_call_with_parallax.assert_not_called()

    def test_call_multiple_node(self, mock_call_with_parallax: mock.MagicMock):
        self.service_manager = ServiceManager(mock.Mock(crmsh.sh.AutoShell))
        self.service_manager._run_on_single_host = mock.Mock(self.service_manager._run_on_single_host)
        mock_call_with_parallax.return_value = {'node1': (0, '', ''), 'node2': (1, 'out', 'err')}
        self.assertEqual(['node1'], self.service_manager._call(None, ['node1', 'node2'], 'foo'))
        self.service_manager._run_on_single_host.assert_not_called()
        mock_call_with_parallax.assert_called_once_with('foo', ['node1', 'node2'])

    def test_run_on_single_host_return_1(self, mock_call_with_parallax: mock.MagicMock):
        self.service_manager = ServiceManager(mock.Mock(crmsh.sh.AutoShell))
        self.service_manager._shell.get_stdout_stderr_no_input.return_value = (1, 'bar', 'err')
        self.assertEqual(1, self.service_manager._run_on_single_host('foo', 'node1'))
        self.service_manager._shell.get_stdout_stderr_no_input.assert_called_once_with('node1', 'foo')

    def test_run_on_single_host_return_255(self, mock_call_with_parallax: mock.MagicMock):
        self.service_manager = ServiceManager(mock.Mock(crmsh.sh.AutoShell))
        self.service_manager._shell.get_stdout_stderr_no_input.return_value = (255, 'bar', 'err')
        with self.assertRaises(ValueError):
            self.service_manager._run_on_single_host('foo', 'node1')
        self.service_manager._shell.get_stdout_stderr_no_input.assert_called_once_with('node1', 'foo')

    def test_start_service(self, mock_call_with_parallax: mock.MagicMock):
        self.service_manager._call.return_value = ['node1']
        self.assertEqual(['node1'], self.service_manager.start_service('service1', remote_addr='node1'))
        self.service_manager._call.assert_called_once_with('node1', [], "systemctl start 'service1'")

    def test_start_service_on_multiple_host(self, mock_call_with_parallax: mock.MagicMock):
        self.service_manager._call.return_value = ['node1', 'node2']
        self.assertEqual(['node1', 'node2'], self.service_manager.start_service('service1', node_list=['node1', 'node2']))
        self.service_manager._call.assert_called_once_with(None, ['node1', 'node2'], "systemctl start 'service1'")

    def test_start_and_enable_service(self, mock_call_with_parallax: mock.MagicMock):
        self.service_manager._call.return_value = ['node1']
        self.assertEqual(['node1'], self.service_manager.start_service('service1', enable=True, remote_addr='node1'))
        self.service_manager._call.assert_called_once_with('node1', [], "systemctl enable --now 'service1'")

    def test_stop_service(self, mock_call_with_parallax: mock.MagicMock):
        self.service_manager._call.return_value = ['node1']
        self.assertEqual(['node1'], self.service_manager.stop_service('service1', remote_addr='node1'))
        self.service_manager._call.assert_called_once_with('node1', [], "systemctl stop 'service1'")

    def test_enable_service(self, mock_call_with_parallax: mock.MagicMock):
        self.service_manager._call.return_value = ['node1']
        self.assertEqual(['node1'], self.service_manager.enable_service('service1', remote_addr='node1'))
        self.service_manager._call.assert_called_once_with('node1', [], "systemctl enable 'service1'")

    def test_disable_service(self, mock_call_with_parallax: mock.MagicMock):
        self.service_manager._call.return_value = ['node1']
        self.assertEqual(['node1'], self.service_manager.disable_service('service1', remote_addr='node1'))
        self.service_manager._call.assert_called_once_with('node1', [], "systemctl disable 'service1'")
