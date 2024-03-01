import unittest
from unittest import mock

import crmsh.report.sh
import crmsh.sh

import subprocess


class TestFindShell(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_cluster_shell = mock.Mock(crmsh.sh.ClusterShell)
        self.patcher_local_shell = mock.patch('crmsh.report.sh.Shell.local_shell')
        self.patcher_try_create_report_shell = mock.patch('crmsh.report.sh.Shell._try_create_report_shell')
        self.mock_local_shell = self.patcher_local_shell.start()
        self.mock_local_shell.return_value = mock.Mock(crmsh.sh.LocalShell)
        self.mock_try_create_report_shell = self.patcher_try_create_report_shell.start()

    def tearDown(self) -> None:
        self.patcher_local_shell.stop()
        self.patcher_try_create_report_shell.stop()

    def test_cluster_shell_available(self):
        self.mock_cluster_shell.can_run_as.return_value = True
        self.assertIsInstance(
                crmsh.report.sh.Shell.find_shell(self.mock_cluster_shell, 'node1', None),
                crmsh.report.sh.ClusterShellAdaptor,
        )
        self.assertIsInstance(
                crmsh.report.sh.Shell.find_shell(self.mock_cluster_shell, 'node1', 'alice'),
                crmsh.report.sh.ClusterShellAdaptor,
        )

    def test_specified_user_work(self):
        self.mock_cluster_shell.can_run_as.return_value = False
        self.mock_try_create_report_shell.return_value = mock.Mock(crmsh.report.sh.Shell)
        ret = crmsh.report.sh.Shell.find_shell(self.mock_cluster_shell, 'node1', 'alice')
        self.mock_local_shell.assert_called_once()
        self.mock_try_create_report_shell.assert_called_once_with(
            self.mock_local_shell.return_value,
            'node1', 'alice',
        )
        self.assertIs(ret, self.mock_try_create_report_shell.return_value)

class TestTryCreateReportShell(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_local_shell = mock.Mock(crmsh.sh.LocalShell)
        self.patcher_ssh_shell = mock.patch('crmsh.sh.SSHShell')
        self.mock_ssh_shell = self.patcher_ssh_shell.start().return_value

    def tearDown(self) -> None:
        self.patcher_ssh_shell.stop()

    def test_success(self):
        self.mock_ssh_shell.can_run_as.return_value = True
        self.mock_ssh_shell.subprocess_run_without_input.return_value = mock.Mock(returncode=0)
        ret = crmsh.report.sh.Shell._try_create_report_shell(self.mock_local_shell, 'node1', 'alice')
        self.mock_ssh_shell.can_run_as.assert_called_once_with('node1', 'alice')
        self.mock_ssh_shell.subprocess_run_without_input.assert_called_once_with(
            'node1', 'alice',
            'sudo true',
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.assertIsInstance(ret, crmsh.report.sh.Shell)

    def test_failure_no_sudoer(self):
        self.mock_ssh_shell.can_run_as.return_value = True
        self.mock_ssh_shell.subprocess_run_without_input.return_value = mock.Mock(returncode=1)
        ret = crmsh.report.sh.Shell._try_create_report_shell(self.mock_local_shell, 'node1', 'alice')
        self.mock_ssh_shell.can_run_as.assert_called_once_with('node1', 'alice')
        self.mock_ssh_shell.subprocess_run_without_input.assert_called_once_with(
            'node1', 'alice',
            'sudo true',
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.assertIsNone(ret)

    def test_failure_no_ssh(self):
        self.mock_ssh_shell.can_run_as.return_value = False
        ret = crmsh.report.sh.Shell._try_create_report_shell(self.mock_local_shell, 'node1', 'alice')
        self.mock_ssh_shell.can_run_as.assert_called_once_with('node1', 'alice')
        self.mock_ssh_shell.subprocess_run_without_input.assert_not_called()
        self.assertIsNone(ret)
