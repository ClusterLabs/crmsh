"""
Unitary tests for crmsh/join_lock.py

:author: xinliang
:organization: SUSE Linux GmbH
:contact: XLiang@suse.de

:since: 2020-11-15
"""

# pylint:disable=C0103,C0111,W0212,W0611

import os
import unittest

try:
    from unittest import mock
except ImportError:
    import mock

from crmsh import join_lock, config


class TestJoinLock(unittest.TestCase):
    """
    Unitary tests for crmsh.join_lock.JoinLock
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
        self.lock_inst = join_lock.JoinLock("node1")

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    def test_join_timeout_error_format(self):
        config.core.join_timeout = "pwd"
        with self.assertRaises(ValueError) as err:
            self.lock_inst.join_timeout
        self.assertEqual("Invalid format of core.join_timeout(should be a number)", str(err.exception))

    def test_join_timeout_min_error(self):
        config.core.join_timeout = "12"
        with self.assertRaises(ValueError) as err:
            self.lock_inst.join_timeout
        self.assertEqual("Minimum value of core.join_timeout should be 120", str(err.exception))

    def test_join_timeout(self):
        config.core.join_timeout = "130"
        self.assertEqual(self.lock_inst.join_timeout, 130)

    @mock.patch('crmsh.utils.get_stdout_stderr')
    def test_run_error(self, mock_run):
        mock_run.return_value = (255, "output", "error data")
        with self.assertRaises(join_lock.SSHError) as err:
            self.lock_inst._run("test_cmd")
        self.assertEqual("error data", str(err.exception))
        mock_run.assert_called_once_with('ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@node1 "test_cmd"')

    @mock.patch('crmsh.utils.get_stdout_stderr')
    def test_run(self, mock_run):
        mock_run.return_value = (0, "output data", None)
        rc, out, err = self.lock_inst._run("test_cmd")
        self.assertEqual(mock_run.return_value, (rc, out, err))
        mock_run.assert_called_once_with('ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@node1 "test_cmd"')

    @mock.patch('crmsh.join_lock.JoinLock._run')
    def test_create_lock_dir(self, mock_run):
        mock_run.return_value = (0, None, None)
        rc = self.lock_inst._create_lock_dir()
        self.assertEqual(rc, True)
        mock_run.assert_called_once_with(join_lock.JoinLock.MKDIR_CMD)

    @mock.patch('crmsh.join_lock.JoinLock._run')
    def test_get_online_nodelist_error(self, mock_run):
        mock_run.return_value = (1, None, "error data")
        with self.assertRaises(RuntimeError) as err:
            self.lock_inst._get_online_nodelist()
        self.assertEqual("error data", str(err.exception))
        mock_run.assert_called_once_with("crm_node -l")

    @mock.patch('crmsh.join_lock.JoinLock._run')
    def test_get_online_nodelist(self, mock_run):
        output = """
        1084783297 15sp2-1 member
        1084783193 15sp2-2 lost
        1084783331 15sp2-3 member
        """
        mock_run.return_value = (0, output, None)
        res = self.lock_inst._get_online_nodelist()
        self.assertEqual(res, ["15sp2-1", "15sp2-3"])
        mock_run.assert_called_once_with("crm_node -l")

    @mock.patch('crmsh.join_lock.JoinLock._create_lock_dir')
    @mock.patch('crmsh.join_lock.JoinLock.join_timeout', new_callable=mock.PropertyMock)
    @mock.patch('time.time')
    def test_lock_or_wait_break(self, mock_time, mock_time_out, mock_create):
        mock_time.return_value = 10000
        mock_time_out.return_value = 120
        mock_create.return_value = True

        self.lock_inst._lock_or_wait()
        self.assertEqual(self.lock_inst.lock_owner, True)

        mock_time.assert_called_once_with()
        mock_time_out.assert_called_once_with()

    @mock.patch('time.sleep')
    @mock.patch('crmsh.bootstrap.warn')
    @mock.patch('crmsh.join_lock.JoinLock._get_online_nodelist')
    @mock.patch('crmsh.join_lock.JoinLock._create_lock_dir')
    @mock.patch('crmsh.join_lock.JoinLock.join_timeout', new_callable=mock.PropertyMock)
    @mock.patch('time.time')
    def test_lock_or_wait_timed_out(self, mock_time, mock_time_out, mock_create,
            mock_get_nodelist, mock_warn, mock_sleep):
        mock_time.side_effect = [10000, 10120, 10500]
        mock_time_out.side_effect = [120, 120, 120]
        mock_create.side_effect = [False, False]
        mock_get_nodelist.side_effect = ["node1", "node1"]

        with self.assertRaises(TimeoutError) as err:
            self.lock_inst._lock_or_wait()
        self.assertEqual("Join process failed after 120 seconds. Cannot continue since the lock directory exists at the init node (node1:/tmp/.crmsh_join_lock_directory)", str(err.exception))

        mock_time.assert_has_calls([mock.call(), mock.call(), mock.call()])
        mock_time_out.assert_has_calls([mock.call(), mock.call(), mock.call()])
        mock_create.assert_has_calls([mock.call(), mock.call()])
        mock_get_nodelist.assert_has_calls([mock.call(), mock.call()])
        mock_warn.assert_called_once_with("Other node still joining, wait at most 120s...")
        mock_sleep.assert_has_calls([mock.call(10), mock.call(10)])

    @mock.patch('time.sleep')
    @mock.patch('crmsh.bootstrap.warn')
    @mock.patch('crmsh.join_lock.JoinLock._get_online_nodelist')
    @mock.patch('crmsh.join_lock.JoinLock._create_lock_dir')
    @mock.patch('crmsh.join_lock.JoinLock.join_timeout', new_callable=mock.PropertyMock)
    @mock.patch('time.time')
    def test_lock_or_wait_again(self, mock_time, mock_time_out, mock_create,
            mock_get_nodelist, mock_warn, mock_sleep):
        mock_time.side_effect = [10000, 10010, 10020]
        mock_time_out.side_effect = [120, 120, 120]
        mock_create.side_effect = [False, False, True]
        mock_get_nodelist.side_effect = [["node1"], ["node1", "node2"]]

        self.lock_inst._lock_or_wait()

        mock_time.assert_has_calls([mock.call(), mock.call(), mock.call()])
        mock_time_out.assert_has_calls([mock.call(), mock.call(), mock.call()])
        mock_create.assert_has_calls([mock.call(), mock.call(), mock.call()])
        mock_get_nodelist.assert_has_calls([mock.call(), mock.call()])
        mock_warn.assert_called_once_with("Other node still joining, wait at most 120s...")
        mock_sleep.assert_called_once_with(10)

    @mock.patch('crmsh.join_lock.JoinLock.unlock')
    @mock.patch('crmsh.join_lock.JoinLock._lock_or_wait')
    def test_lock_exception(self, mock_wait, mock_unlock):
        with self.assertRaises(ValueError):
            with self.lock_inst.lock():
                raise ValueError
        mock_wait.assert_called_once_with()
        mock_unlock.assert_called_once_with()

    @mock.patch('crmsh.bootstrap.error')
    @mock.patch('crmsh.join_lock.JoinLock.unlock')
    @mock.patch('crmsh.join_lock.JoinLock._lock_or_wait')
    def test_lock_ssh_error(self, mock_wait, mock_unlock, mock_error):
        mock_wait.side_effect = join_lock.SSHError("ssh error")
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            with self.lock_inst.lock():
                pass

        mock_error.assert_called_once_with("ssh error")
        mock_wait.assert_called_once_with()
        mock_unlock.assert_called_once_with()

    @mock.patch('crmsh.join_lock.JoinLock.unlock')
    @mock.patch('crmsh.join_lock.JoinLock._lock_or_wait')
    def test_lock(self, mock_wait, mock_unlock):
        with self.lock_inst.lock():
            pass
        mock_wait.assert_called_once_with()
        mock_unlock.assert_called_once_with()

    @mock.patch('crmsh.join_lock.JoinLock._run')
    def test_unlock(self, mock_run):
        self.lock_inst.lock_owner = True
        self.lock_inst.unlock()
        mock_run.assert_called_once_with(join_lock.JoinLock.RM_CMD)
