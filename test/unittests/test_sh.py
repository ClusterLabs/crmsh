import subprocess
import unittest
from unittest import mock

import crmsh.sh
from crmsh.user_of_host import UserOfHost


class TestLocalShell(unittest.TestCase):
    def setUp(self) -> None:
        self.local_shell = crmsh.sh.LocalShell()
        self.local_shell.get_effective_user_name = mock.Mock(self.local_shell.get_effective_user_name)
        self.local_shell.geteuid = mock.Mock(self.local_shell.geteuid)
        self.local_shell.hostname = mock.Mock(self.local_shell.hostname)

    @mock.patch('subprocess.run')
    def test_su_subprocess_run(self, mock_run: mock.MagicMock):
        self.local_shell.get_effective_user_name.return_value = 'root'
        self.local_shell.geteuid.return_value = 0
        self.local_shell.su_subprocess_run(
            'alice', 'foo',
            input=b'bar',
        )
        mock_run.assert_called_once_with(
            ['su', 'alice', '--login', '-c', 'foo'],
            input=b'bar',
        )

    @mock.patch('subprocess.run')
    def test_su_subprocess_run_as_root(self, mock_run: mock.MagicMock):
        self.local_shell.get_effective_user_name.return_value = 'root'
        self.local_shell.geteuid.return_value = 0
        self.local_shell.su_subprocess_run(
            'root', 'foo',
            input=b'bar',
        )
        mock_run.assert_called_once_with(
            ['/bin/sh', '-c', 'foo'],
            input=b'bar',
        )

    @mock.patch('subprocess.run')
    def test_su_subprocess_run_unauthorized(self, mock_run: mock.MagicMock):
        self.local_shell.get_effective_user_name.return_value = 'bob'
        self.local_shell.geteuid.return_value = 1001
        with self.assertRaises(crmsh.sh.AuthorizationError) as ctx:
            self.local_shell.su_subprocess_run(
                'root', 'foo',
                input=b'bar',
            )
        self.assertIsInstance(ctx.exception, ValueError)

    def test_get_stdout_stderr_decoded_and_stripped(self):
        self.local_shell.get_rc_stdout_stderr_raw = mock.Mock(self.local_shell.get_rc_stdout_stderr_raw)
        self.local_shell.get_rc_stdout_stderr_raw.return_value = 1, b' out \n', b'\terr\t\n'
        rc, out, err = self.local_shell.get_rc_stdout_stderr('alice', 'foo', 'input')
        self.assertEqual(1, rc)
        self.assertEqual('out', out)
        self.assertEqual('err', err)
        self.local_shell.get_rc_stdout_stderr_raw.assert_called_once_with(
            'alice', 'foo', b'input',
        )

    def test_get_stdout_or_raise_error(self):
        self.local_shell.su_subprocess_run = mock.Mock(self.local_shell.su_subprocess_run)
        self.local_shell.su_subprocess_run.return_value = subprocess.CompletedProcess(
            args=mock.Mock(),
            returncode=1,
            stdout=b'foo',
            stderr=b' bar ',
        )
        with self.assertRaises(crmsh.sh.CommandFailure) as ctx:
            self.local_shell.get_stdout_or_raise_error('root', 'foo')
        self.assertIsInstance(ctx.exception, ValueError)


class TestSSHShell(unittest.TestCase):
    def setUp(self) -> None:
        self.ssh_shell = crmsh.sh.SSHShell(mock.Mock(crmsh.sh.LocalShell), 'alice')
        self.ssh_shell.local_shell.hostname.return_value = 'node1'
        self.ssh_shell.local_shell.get_effective_user_name.return_value = 'root'
        self.ssh_shell.local_shell.can_run_as.return_value = True

    def test_can_run_as(self):
        self.ssh_shell.local_shell.get_rc_and_error.return_value = 255, 'bar'
        self.assertFalse(self.ssh_shell.can_run_as('node2', 'root'))
        self.ssh_shell.local_shell.can_run_as.assert_not_called()

    def test_can_run_as_local(self):
        self.assertTrue(self.ssh_shell.can_run_as(None, 'root'))
        self.ssh_shell.local_shell.can_run_as.assert_called_once_with('root')

    def test_subprocess_run_without_input(self):
        self.ssh_shell.subprocess_run_without_input(
            'node2', 'bob',
            'foo',
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        args, kwargs = self.ssh_shell.local_shell.su_subprocess_run.call_args
        self.assertEqual('alice', args[0])
        self.assertIn('bob@node2', args[1])
        self.assertEqual(b'foo', kwargs['input'])
        self.assertEqual(subprocess.PIPE, kwargs['stdout'])
        self.assertEqual(subprocess.PIPE, kwargs['stderr'])

    def test_subprocess_run_without_input_with_input_kwargs(self):
        with self.assertRaises(AssertionError):
            self.ssh_shell.subprocess_run_without_input(
                'node2', 'bob',
                'foo',
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                input=b'bar'
            )
        self.ssh_shell.local_shell.su_subprocess_run.assert_not_called()
        with self.assertRaises(AssertionError):
            self.ssh_shell.subprocess_run_without_input(
                'node2', 'bob',
                'foo',
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
            )
        self.ssh_shell.local_shell.su_subprocess_run.assert_not_called()

    @mock.patch('subprocess.run')
    def test_subprocess_run_without_input_local(self, mock_run):
        self.ssh_shell.subprocess_run_without_input(
            'node1', 'bob',
            'foo',
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.ssh_shell.local_shell.su_subprocess_run.assert_not_called()
        mock_run.assert_called_once_with(
            ['sudo', '-H', '-u', 'bob', '/bin/sh'],
            input=b'foo',
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


class TestClusterShell(unittest.TestCase):
    def setUp(self) -> None:
        self.cluster_shell = crmsh.sh.ClusterShell(mock.Mock(crmsh.sh.LocalShell), mock.Mock(UserOfHost))
        self.cluster_shell.local_shell.hostname.return_value = 'node1'
        self.cluster_shell.local_shell.get_effective_user_name.return_value = 'root'
        self.cluster_shell.local_shell.can_run_as.return_value = True
        self.cluster_shell.user_of_host.user_pair_for_ssh.return_value = ('alice', 'bob')

    def test_subprocess_run_without_input(self):
        self.cluster_shell.subprocess_run_without_input(
            'node2',
            None,
            'foo',
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.cluster_shell.user_of_host.user_pair_for_ssh.assert_called_once_with('node2')
        args, kwargs = self.cluster_shell.local_shell.su_subprocess_run.call_args
        self.assertEqual('alice', args[0])
        self.assertIn('bob@node2', args[1])
        self.assertIn('-u root', args[1])
        self.assertEqual(b'foo', kwargs['input'])
        self.assertEqual(subprocess.PIPE, kwargs['stdout'])
        self.assertEqual(subprocess.PIPE, kwargs['stderr'])

    def test_subprocess_run_without_input_with_input_kwargs(self):
        with self.assertRaises(AssertionError):
            self.cluster_shell.subprocess_run_without_input(
                'node2',
                None,
                'foo',
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                input=b'bar',
            )
        self.cluster_shell.local_shell.su_subprocess_run.assert_not_called()
        with self.assertRaises(AssertionError):
            self.cluster_shell.subprocess_run_without_input(
                'node2',
                None,
                'foo',
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
            )
        self.cluster_shell.local_shell.su_subprocess_run.assert_not_called()
