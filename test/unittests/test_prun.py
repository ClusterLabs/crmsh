import typing

import crmsh.constants
import crmsh.prun.prun
import crmsh.prun.runner

import unittest
from unittest import mock


class TestPrun(unittest.TestCase):
    @mock.patch("os.geteuid")
    @mock.patch("crmsh.userdir.getuser")
    @mock.patch("crmsh.prun.prun._is_local_host")
    @mock.patch("crmsh.utils.UserOfHost.user_pair_for_ssh")
    @mock.patch("crmsh.prun.runner.Runner.run")
    @mock.patch("crmsh.prun.runner.Runner.add_task")
    def test_prun(
            self,
            mock_runner_add_task: mock.MagicMock,
            mock_runner_run: mock.MagicMock,
            mock_user_pair_for_ssh: mock.MagicMock,
            mock_is_local_host: mock.MagicMock,
            mock_getuser: mock.MagicMock,
            mock_geteuid: mock.MagicMock,
    ):
        host_cmdline = {"host1": "foo", "host2": "bar"}
        mock_user_pair_for_ssh.return_value = "alice", "bob"
        mock_is_local_host.return_value = False
        mock_getuser.return_value = 'root'
        mock_geteuid.return_value = 0
        results = crmsh.prun.prun.prun(host_cmdline)
        mock_user_pair_for_ssh.assert_has_calls([
            mock.call("host1"),
            mock.call("host2"),
        ])
        mock_is_local_host.assert_has_calls([
            mock.call("host1"),
            mock.call("host2"),
        ])
        mock_runner_add_task.assert_has_calls([
            mock.call(TaskArgumentsEq(
                ['su', 'alice', '--login', '-c', 'ssh {} bob@host1 sudo -H /bin/sh'.format(crmsh.constants.SSH_OPTION)],
                b'foo',
                stdout=crmsh.prun.runner.Task.Capture,
                stderr=crmsh.prun.runner.Task.Capture,
                context={"host": 'host1', "ssh_user": 'bob'},
            )),
            mock.call(TaskArgumentsEq(
                ['su', 'alice', '--login', '-c', 'ssh {} bob@host2 sudo -H /bin/sh'.format(crmsh.constants.SSH_OPTION)],
                b'bar',
                stdout=crmsh.prun.runner.Task.Capture,
                stderr=crmsh.prun.runner.Task.Capture,
                context={"host": 'host2', "ssh_user": 'bob'},
            )),
        ])
        mock_runner_run.assert_called_once()
        self.assertTrue(isinstance(results, typing.Dict))
        self.assertSetEqual({"host1", "host2"}, set(results.keys()))

    @mock.patch("os.geteuid")
    @mock.patch("crmsh.userdir.getuser")
    @mock.patch("crmsh.prun.prun._is_local_host")
    @mock.patch("crmsh.utils.UserOfHost.user_pair_for_ssh")
    @mock.patch("crmsh.prun.runner.Runner.run")
    @mock.patch("crmsh.prun.runner.Runner.add_task")
    def test_prun_root(
            self,
            mock_runner_add_task: mock.MagicMock,
            mock_runner_run: mock.MagicMock,
            mock_user_pair_for_ssh: mock.MagicMock,
            mock_is_local_host: mock.MagicMock,
            mock_getuser: mock.MagicMock,
            mock_geteuid: mock.MagicMock,
    ):
        host_cmdline = {"host1": "foo", "host2": "bar"}
        mock_user_pair_for_ssh.return_value = "root", "root"
        mock_is_local_host.return_value = False
        mock_getuser.return_value = 'root'
        mock_geteuid.return_value = 0
        results = crmsh.prun.prun.prun(host_cmdline)
        mock_geteuid.assert_not_called()
        mock_user_pair_for_ssh.assert_has_calls([
            mock.call("host1"),
            mock.call("host2"),
        ])
        mock_is_local_host.assert_has_calls([
            mock.call("host1"),
            mock.call("host2"),
        ])
        mock_runner_add_task.assert_has_calls([
            mock.call(TaskArgumentsEq(
                ['/bin/sh', '-c', 'ssh {} root@host1 sudo -H /bin/sh'.format(crmsh.constants.SSH_OPTION)],
                b'foo',
                stdout=crmsh.prun.runner.Task.Capture,
                stderr=crmsh.prun.runner.Task.Capture,
                context={"host": 'host1', "ssh_user": 'root'},
            )),
            mock.call(TaskArgumentsEq(
                ['/bin/sh', '-c', 'ssh {} root@host2 sudo -H /bin/sh'.format(crmsh.constants.SSH_OPTION)],
                b'bar',
                stdout=crmsh.prun.runner.Task.Capture,
                stderr=crmsh.prun.runner.Task.Capture,
                context={"host": 'host2', "ssh_user": 'root'},
            )),
        ])
        mock_runner_run.assert_called_once()
        self.assertTrue(isinstance(results, typing.Dict))
        self.assertSetEqual({"host1", "host2"}, set(results.keys()))


class TaskArgumentsEq(crmsh.prun.runner.Task):
    def __eq__(self, other):
        if not isinstance(other, crmsh.prun.runner.Task):
            return False
        return self.args == other.args \
            and self.input == other.input \
            and self.stdout_config == other.stdout_config \
            and self.stderr_config == other.stderr_config \
            and self.context == other.context
