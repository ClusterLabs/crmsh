"""
Unitary tests for crmsh/lock.py

:author: xinliang
:organization: SUSE Linux GmbH
:contact: XLiang@suse.de

:since: 2020-12-18
"""

# pylint:disable=C0103,C0111,W0212,W0611

import unittest

try:
    from unittest import mock
except ImportError:
    import mock

from crmsh import lock, config


class TestLock(unittest.TestCase):
    """
    Unitary tests for crmsh.lock.Lock
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
        self.local_inst = lock.Lock()

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('crmsh.utils.get_stdout_stderr')
    def test_run(self, mock_run):
        mock_run.return_value = (0, "output data", None)
        rc, out, err = self.local_inst._run("test_cmd")
        mock_run.assert_called_once_with("test_cmd")

    @mock.patch('crmsh.lock.Lock._run')
    def test_create_lock_dir_false(self, mock_run):
        mock_run.return_value = (1, None, None)
        rc = self.local_inst._create_lock_dir()
        self.assertEqual(rc, False)
        mock_run.assert_called_once_with("mkdir {}".format(lock.Lock.LOCK_DIR_NON_PRIVILEGED))

    @mock.patch('crmsh.lock.Lock._run')
    def test_create_lock_dir(self, mock_run):
        mock_run.return_value = (0, None, None)
        rc = self.local_inst._create_lock_dir()
        self.assertEqual(rc, True)
        mock_run.assert_called_once_with("mkdir {}".format(lock.Lock.LOCK_DIR_NON_PRIVILEGED))

    @mock.patch('crmsh.lock.Lock._create_lock_dir')
    def test_lock_or_fail(self, mock_create):
        mock_create.return_value = False
        with self.assertRaises(lock.ClaimLockError) as err:
            self.local_inst._lock_or_fail()
        self.assertEqual("Failed to claim lock (the lock directory exists at {})".format(lock.Lock.LOCK_DIR_NON_PRIVILEGED), str(err.exception))
        mock_create.assert_called_once_with()

    @mock.patch('crmsh.lock.Lock._run')
    def test_unlock(self, mock_run):
        self.local_inst.lock_owner = True
        self.local_inst._unlock()
        mock_run.assert_called_once_with("rm -rf {}".format(lock.Lock.LOCK_DIR_NON_PRIVILEGED))

    @mock.patch('crmsh.lock.Lock._unlock')
    @mock.patch('crmsh.lock.Lock._lock_or_fail')
    def test_lock_exception(self, mock_lock, mock_unlock):
        mock_lock.side_effect = lock.ClaimLockError

        with self.assertRaises(lock.ClaimLockError):
            with self.local_inst.lock():
                pass

        mock_lock.assert_called_once_with()
        mock_unlock.assert_called_once_with()

    @mock.patch('crmsh.lock.Lock._unlock')
    @mock.patch('crmsh.lock.Lock._lock_or_fail')
    def test_lock(self, mock_lock, mock_unlock):
        with self.local_inst.lock():
            pass
        mock_lock.assert_called_once_with()
        mock_unlock.assert_called_once_with()


class TestRemoteLock(unittest.TestCase):
    """
    Unitary tests for crmsh.lock.RemoteLock
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
        self.lock_inst = lock.RemoteLock("alice", "node1")
        self.lock_inst_no_wait = lock.RemoteLock("alice", "node1", wait=False)

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('crmsh.utils.get_stdout_stderr')
    def test_run_ssh_error(self, mock_run):
        mock_run.return_value = (255, None, "ssh error")
        with self.assertRaises(lock.SSHError) as err:
            self.lock_inst._run("cmd")
        self.assertEqual("ssh error", str(err.exception))
        mock_run.assert_called_once_with("ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no alice@node1 \"cmd\"")

    @mock.patch('crmsh.utils.get_stdout_stderr')
    def test_run(self, mock_run):
        mock_run.return_value = (0, None, None)
        res = self.lock_inst._run("cmd")
        self.assertEqual(res, mock_run.return_value)
        mock_run.assert_called_once_with("ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no alice@node1 \"cmd\"")

    def test_lock_timeout_error_format(self):
        config.core.lock_timeout = "pwd"
        with self.assertRaises(ValueError) as err:
            self.lock_inst.lock_timeout
        self.assertEqual("Invalid format of core.lock_timeout(should be a number)", str(err.exception))

    def test_lock_timeout_min_error(self):
        config.core.lock_timeout = "12"
        with self.assertRaises(ValueError) as err:
            self.lock_inst.lock_timeout
        self.assertEqual("Minimum value of core.lock_timeout should be 120", str(err.exception))

    def test_lock_timeout(self):
        config.core.lock_timeout = "130"
        self.assertEqual(self.lock_inst.lock_timeout, 130)

    @mock.patch('crmsh.lock.RemoteLock._run')
    def test_get_online_nodelist_error(self, mock_run):
        mock_run.return_value = (1, None, "error data")
        with self.assertRaises(ValueError) as err:
            self.lock_inst._get_online_nodelist()
        self.assertEqual("error data", str(err.exception))
        mock_run.assert_called_once_with("crm_node -l")

    @mock.patch('crmsh.lock.RemoteLock._run')
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

    @mock.patch('crmsh.lock.Lock._create_lock_dir')
    @mock.patch('crmsh.lock.RemoteLock.lock_timeout', new_callable=mock.PropertyMock)
    @mock.patch('time.time')
    def test_lock_or_wait_break(self, mock_time, mock_time_out, mock_create):
        mock_time.return_value = 10000
        mock_time_out.return_value = 120
        mock_create.return_value = True

        self.lock_inst._lock_or_wait()

        mock_time.assert_called_once_with()
        mock_time_out.assert_called_once_with()

    @mock.patch('time.sleep')
    @mock.patch('logging.Logger.warning')
    @mock.patch('crmsh.lock.RemoteLock._get_online_nodelist')
    @mock.patch('crmsh.lock.Lock._create_lock_dir')
    @mock.patch('crmsh.lock.RemoteLock.lock_timeout', new_callable=mock.PropertyMock)
    @mock.patch('time.time')
    def test_lock_or_wait_timed_out(self, mock_time, mock_time_out, mock_create,
            mock_get_nodelist, mock_warn, mock_sleep):
        mock_time.side_effect = [10000, 10121]
        mock_time_out.return_value = 120
        mock_create.return_value = False
        mock_get_nodelist.return_value = ["node2"]

        with self.assertRaises(lock.ClaimLockError) as err:
            self.lock_inst._lock_or_wait()
        self.assertEqual("Timed out after 120 seconds. Cannot continue since the lock directory exists at the node (node1:{})".format(lock.Lock.LOCK_DIR_NON_PRIVILEGED), str(err.exception))

        mock_time.assert_has_calls([ mock.call(), mock.call()])
        mock_time_out.assert_has_calls([mock.call(), mock.call(), mock.call()])
        mock_create.assert_called_once_with()
        mock_get_nodelist.assert_called_once_with()
        mock_warn.assert_called_once_with('Might have unfinished process on other nodes, wait %ss...', 120)
        mock_sleep.assert_called_once_with(10)

    @mock.patch('time.sleep')
    @mock.patch('logging.Logger.warning')
    @mock.patch('crmsh.lock.RemoteLock._get_online_nodelist')
    @mock.patch('crmsh.lock.Lock._create_lock_dir')
    @mock.patch('crmsh.lock.RemoteLock.lock_timeout', new_callable=mock.PropertyMock)
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
        mock_warn.assert_called_once_with('Might have unfinished process on other nodes, wait %ss...', 120)
        mock_sleep.assert_has_calls([mock.call(10), mock.call(10)])

    @mock.patch('crmsh.lock.Lock._unlock')
    @mock.patch('crmsh.lock.RemoteLock._lock_or_wait')
    def test_lock_exception(self, mock_lock, mock_unlock):
        mock_lock.side_effect = lock.ClaimLockError

        with self.assertRaises(lock.ClaimLockError):
            with self.lock_inst.lock():
                pass

        mock_lock.assert_called_once_with()
        mock_unlock.assert_called_once_with()

    @mock.patch('crmsh.lock.Lock._unlock')
    @mock.patch('crmsh.lock.RemoteLock._lock_or_wait')
    def test_lock(self, mock_lock, mock_unlock):
        with self.lock_inst.lock():
            pass
        mock_lock.assert_called_once_with()
        mock_unlock.assert_called_once_with()

    @mock.patch('crmsh.lock.Lock._unlock')
    @mock.patch('crmsh.lock.RemoteLock._lock_or_fail')
    def test_lock_no_wait(self, mock_lock, mock_unlock):
        with self.lock_inst_no_wait.lock():
            pass
        mock_lock.assert_called_once_with()
        mock_unlock.assert_called_once_with()
