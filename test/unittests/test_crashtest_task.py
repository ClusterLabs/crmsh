import os
import sys

try:
    from unittest import mock, TestCase
except ImportError:
    import mock
from datetime import datetime

from crmsh import utils as crmshutils
from crmsh.crash_test import utils, main, config, task


class TestTaskKill(TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    @mock.patch('crmsh.crash_test.utils.msg_info')
    def setUp(self, mock_msg_info):
        """
        Test setUp.
        """
        ctx = mock.Mock(current_case="sbd", loop=False)
        self.task_kill_inst = task.TaskKill(ctx)
        ctx2 = mock.Mock(current_case="sbd", loop=True)
        self.task_kill_inst_loop = task.TaskKill(ctx2)

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('os.path.isdir')
    def test_enable_report_error(self, mock_isdir):
        mock_isdir.return_value = False
        main.ctx = mock.Mock(report_path="/path")
        with self.assertRaises(task.TaskError) as error:
            self.task_kill_inst.enable_report()
        self.assertEqual("/path is not a directory", str(error.exception))
        mock_isdir.assert_called_once_with("/path")

    @mock.patch('crmsh.crash_test.utils.this_node')
    @mock.patch('crmsh.crash_test.utils.now')
    @mock.patch('os.path.isdir')
    def test_enable_report_looping(self, mock_isdir, mock_now, mock_this_node):
        main.ctx = mock.Mock(report_path="/path", process_name="cpc")
        mock_now.return_value = "20210119-12345"
        mock_this_node.return_value = "node1"
        self.task_kill_inst_loop.enable_report()

    @mock.patch('crmsh.crash_test.utils.this_node')
    @mock.patch('crmsh.crash_test.utils.now')
    @mock.patch('os.path.isdir')
    def test_enable_report(self, mock_isdir, mock_now, mock_this_node):
        main.ctx = mock.Mock(report_path="/path", process_name="cpc")
        mock_now.return_value = "20210119-12345"
        mock_this_node.return_value = "node1"
        self.task_kill_inst.enable_report()

    def test_header(self):
        expected_res = """==============================================
Testcase:          Force kill sbd
Looping Kill:      False
Expected State:    a) sbd process restarted
                   b) Or, this node fenced.
"""
        res = self.task_kill_inst.header()
        self.assertEqual(res, expected_res)

    @mock.patch('crmsh.crash_test.utils.json_dumps')
    def test_to_json(self, mock_dumps):
        self.task_kill_inst.build_base_result = mock.Mock()
        self.task_kill_inst.result = {}
        self.task_kill_inst.prev_task_list = []
        self.task_kill_inst.to_json()
        self.task_kill_inst.build_base_result.assert_called_once_with()
        mock_dumps.assert_called_once_with()

    def test_to_report_return(self):
        self.task_kill_inst.report = False
        self.task_kill_inst.to_report()

    @mock.patch('os.fsync')
    @mock.patch('builtins.open', create=True)
    @mock.patch('crmsh.crash_test.task.TaskKill.header')
    def test_to_report(self, mock_header, mock_open_file, mock_fsync):
        mock_header.return_value = "#### header"
        self.task_kill_inst.report = True
        self.task_kill_inst.messages = [["info", "data", "2021"]]
        self.task_kill_inst.explain = "explain"
        self.task_kill_inst.report_file = "report_file1"
        file_handle = mock_open_file.return_value.__enter__.return_value

        self.task_kill_inst.to_report()

        file_handle.write.assert_has_calls([
            mock.call("#### header"),
            mock.call("\nLog:\n"),
            mock.call("2021 INFO:data\n"),
            mock.call("\nTestcase Explained:\n"),
            mock.call("explain\n")
            ])

    @mock.patch('crmsh.crash_test.utils.get_process_status')
    @mock.patch('crmsh.crash_test.task.Task.task_pre_check')
    def test_pre_check(self, mock_pre_check, mock_status):
        mock_status.return_value = (False, 100)
        with self.assertRaises(task.TaskError) as err:
            self.task_kill_inst.pre_check()
        self.assertEqual("Process sbd is not running!", str(err.exception))
        mock_pre_check.assert_called_once_with()
        mock_status.assert_called_once_with("sbd")

    @mock.patch('crmsh.crash_test.task.TaskKill.process_monitor')
    @mock.patch('crmsh.crash_test.task.Task.fence_action_monitor')
    @mock.patch('threading.Thread')
    @mock.patch('crmsh.crash_test.task.crmshutils.get_stdout_stderr')
    @mock.patch('crmsh.crash_test.task.Task.info')
    @mock.patch('crmsh.crash_test.utils.get_process_status')
    def test_run(self, mock_status, mock_info, mock_run, mock_thread, mock_fence_monitor, mock_process_monitor):
        mock_status.side_effect = [(False, -1), (True, 100)]
        mock_thread_fence_inst = mock.Mock()
        mock_thread_restart_inst = mock.Mock()
        mock_thread.side_effect = [mock_thread_fence_inst, mock_thread_restart_inst]

        self.task_kill_inst.run()

        mock_status.assert_has_calls([mock.call("sbd"), mock.call("sbd")])
        mock_info.assert_has_calls([
            mock.call('Process sbd(100) is running...'),
            mock.call('Trying to run "killall -9 sbd"')
            ])
        mock_run.assert_called_once_with("killall -9 sbd")
        mock_thread.assert_has_calls([
            mock.call(target=mock_fence_monitor),
            mock.call(target=mock_process_monitor),
            ])
        mock_thread_fence_inst.start.assert_called_once_with()
        mock_thread_restart_inst.start.assert_called_once_with()

    def test_wait_exception(self):
        self.task_kill_inst.fence_start_event = mock.Mock()
        self.task_kill_inst.restart_happen_event = mock.Mock()
        self.task_kill_inst.thread_stop_event = mock.Mock()
        self.task_kill_inst.fence_start_event.wait.return_value = True
        self.task_kill_inst.restart_happen_event.is_set.return_value = False

        with self.assertRaises(task.TaskError) as err:
            self.task_kill_inst.wait()
        self.assertEqual("Process sbd is not restarted!", str(err.exception))

    def test_wait(self):
        self.task_kill_inst.fence_start_event = mock.Mock()
        self.task_kill_inst.restart_happen_event = mock.Mock()
        self.task_kill_inst.thread_stop_event = mock.Mock()
        self.task_kill_inst.fence_start_event.wait.return_value = True
        self.task_kill_inst.restart_happen_event.is_set.return_value = True

        self.task_kill_inst.wait()

        self.task_kill_inst.thread_stop_event.set.assert_called_once_with()

    @mock.patch('time.sleep')
    @mock.patch('crmsh.crash_test.task.Task.info')
    @mock.patch('crmsh.crash_test.utils.get_process_status')
    def test_process_monitor(self, mock_status, mock_info, mock_sleep):
        self.task_kill_inst.thread_stop_event = mock.Mock()
        self.task_kill_inst.thread_stop_event.is_set.side_effect = [False, False]
        self.task_kill_inst.restart_happen_event = mock.Mock()
        mock_status.side_effect = [(False, -1), (True, 100)]

        self.task_kill_inst.process_monitor()

        self.task_kill_inst.thread_stop_event.is_set.assert_has_calls([
            mock.call(),
            mock.call()
            ])
        mock_status.assert_has_calls([
            mock.call("sbd"),
            mock.call("sbd")
            ])
        mock_info.assert_called_once_with("Process sbd(100) is restarted!")
        self.task_kill_inst.restart_happen_event.set.assert_called_once_with()
        mock_sleep.assert_called_once_with(1)


class TestTaskCheck(TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    @mock.patch('crmsh.crash_test.utils.msg_info')
    @mock.patch('crmsh.crash_test.utils.now')
    def setUp(self, mock_now, mock_msg_info):
        """
        Test setUp.
        """
        mock_now.return_value = "2019/07/10 01:15:15"
        main.ctx = mock.Mock(task_list=[{"process_name": "xin", "age": 38}])
        self.task_check_inst = task.TaskCheck("task check job1", quiet=False)
        self.task_check_inst_quiet = task.TaskCheck("task check job1", quiet=True)

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('crmsh.crash_test.utils.MyLoggingFormatter')
    @mock.patch('crmsh.crash_test.utils.get_handler')
    @mock.patch('crmsh.crash_test.utils.manage_handler')
    def test_to_stdout(self, mock_manage_handler, mock_get_handler, mock_myformatter):
        mock_manage_handler.return_value.__enter__ = mock.Mock()
        mock_manage_handler.return_value.__exit__ = mock.Mock()

        task.logger = mock.Mock()
        task.logger.info = mock.Mock()
        task.logger.log = mock.Mock()

        get_handler_inst1 = mock.Mock()
        get_handler_inst1.setFormatter = mock.Mock()
        get_handler_inst2 = mock.Mock()
        get_handler_inst2.setFormatter = mock.Mock()
        mock_get_handler.side_effect = [get_handler_inst1, get_handler_inst2]

        myformatter_inst1 = mock.Mock()
        myformatter_inst2 = mock.Mock()
        mock_myformatter.side_effect = [myformatter_inst1, myformatter_inst2]

        self.task_check_inst.messages = [("info", "info message"), ("warn", "warn message")]
        utils.CGREEN = ""
        utils.CEND = ""
        utils.CRED = ""

        self.task_check_inst.to_stdout()

        mock_manage_handler.assert_called_once_with("file", keep=False)
        mock_get_handler.assert_has_calls([
            mock.call(task.logger, "stream"),
            mock.call(task.logger, "stream")
            ])
        get_handler_inst1.setFormatter.assert_called_once_with(myformatter_inst1)
        get_handler_inst2.setFormatter.assert_called_once_with(myformatter_inst2)
        mock_myformatter.assert_has_calls([
            mock.call(flush=False),
            mock.call()
            ])
        task.logger.info.assert_called_once_with('task check job1 [Pass]', extra={'timestamp': '[2019/07/10 01:15:15]'})
        task.logger.log.assert_has_calls([
            mock.call(20, 'info message', extra={'timestamp': '  '}).
            mock.call(30, 'warn message', extra={'timestamp': '  '})
            ])

    @mock.patch('crmsh.crash_test.utils.json_dumps')
    def test_to_json(self, mock_dumps):
        self.task_check_inst.build_base_result = mock.Mock()
        self.task_check_inst.result = {}
        self.task_check_inst.to_json()
        self.task_check_inst.build_base_result.assert_called_once_with()
        mock_dumps.assert_called_once_with()

    def test_print_result(self):
        self.task_check_inst.to_stdout = mock.Mock()
        self.task_check_inst.to_json = mock.Mock()
        self.task_check_inst.print_result()
        self.task_check_inst.to_stdout.assert_called_once_with()
        self.task_check_inst.to_json.assert_called_once_with()

    def test_print_result_quiet(self):
        self.task_check_inst.quiet = True
        self.task_check_inst.to_stdout = mock.Mock()
        self.task_check_inst.print_result()
        self.task_check_inst.to_stdout.assert_not_called()

    def test_run(self):
        self.task_check_inst.print_result = mock.Mock()
        with self.task_check_inst.run():
            pass
        self.task_check_inst.print_result.assert_called_once_with()


class TestTaskSplitBrain(TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    @mock.patch('crmsh.crash_test.utils.msg_info')
    def setUp(self, mock_msg_info):
        """
        Test setUp.
        """
        self.task_sp_inst = task.TaskSplitBrain()
        self.task_sp_inst.fence_action = "reboot"
        self.task_sp_inst.fence_timeout = 60

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    def test_header(self):
        expected_res = """==============================================
Testcase:          Simulate split brain by blocking corosync ports
Expected Result:   One of nodes get fenced
Fence action:      reboot
Fence timeout:     60
"""
        res = self.task_sp_inst.header()
        self.assertEqual(res, expected_res)

    @mock.patch('crmsh.crash_test.utils.json_dumps')
    @mock.patch('crmsh.crash_test.task.Task.build_base_result')
    def test_to_json(self, mock_result, mock_json):
        self.task_sp_inst.result = {}
        self.task_sp_inst.to_json()
        mock_result.assert_called_once_with()
        mock_json.assert_called_once_with()

    @mock.patch('crmsh.crash_test.task.crmshutils.get_stdout_stderr')
    @mock.patch('crmsh.crash_test.task.Task.task_pre_check')
    def test_pre_check_no_cmd(self, mock_pre_check, mock_run):
        mock_run.return_value = (1, None, "error")
        with self.assertRaises(task.TaskError) as err:
            self.task_sp_inst.pre_check()
        self.assertEqual("error", str(err.exception))
        mock_run.assert_called_once_with("which iptables")
        mock_pre_check.assert_called_once_with()

    @mock.patch('crmsh.crash_test.utils.online_nodes')
    @mock.patch('crmsh.crash_test.task.crmshutils.get_stdout_stderr')
    @mock.patch('crmsh.crash_test.task.Task.task_pre_check')
    def test_pre_check_error(self, mock_pre_check, mock_run, mock_online_nodes):
        mock_run.return_value = (0, None, None)
        mock_online_nodes.return_value = ["node1"]
        with self.assertRaises(task.TaskError) as err:
            self.task_sp_inst.pre_check()
        self.assertEqual("At least two nodes online!", str(err.exception))
        mock_run.assert_called_once_with("which iptables")
        mock_online_nodes.assert_called_once_with()

    @mock.patch('crmsh.crash_test.task.crmshutils.service_is_active')
    def test_do_block_firewalld_disactive(self, mock_active):
        mock_active.return_value = False
        self.task_sp_inst.do_block_iptables = mock.Mock()
        self.task_sp_inst.un_block = mock.Mock()
        with self.task_sp_inst.do_block():
            pass
        mock_active.assert_called_once_with("firewalld.service")
        self.task_sp_inst.do_block_iptables.assert_called_once_with()
        self.task_sp_inst.un_block.assert_called_once_with()

    @mock.patch('crmsh.crash_test.task.crmshutils.service_is_active')
    def test_do_block_firewalld_active(self, mock_active):
        mock_active.return_value = True
        self.task_sp_inst.do_block_firewalld = mock.Mock()
        self.task_sp_inst.un_block = mock.Mock()
        with self.task_sp_inst.do_block():
            pass
        mock_active.assert_called_once_with("firewalld.service")
        self.task_sp_inst.do_block_firewalld.assert_called_once_with()
        self.task_sp_inst.un_block.assert_called_once_with()

    @mock.patch('crmsh.crash_test.utils.corosync_port_list')
    def test_do_block_firewalld_error(self, mock_port_list):
        mock_port_list.return_value = []
        with self.assertRaises(task.TaskError) as err:
            self.task_sp_inst.do_block_firewalld()
        self.assertEqual("Can not get corosync's port", str(err.exception))
        mock_port_list.assert_called_once_with()

    @mock.patch('crmsh.crash_test.task.crmshutils.get_stdout_stderr')
    @mock.patch('crmsh.crash_test.task.Task.info')
    @mock.patch('crmsh.crash_test.utils.corosync_port_list')
    def test_do_block_firewalld(self, mock_port_list, mock_info, mock_run):
        mock_port_list.return_value = ["1234"]
        self.task_sp_inst.do_block_firewalld()
        mock_port_list.assert_called_once_with()
        mock_info.assert_called_once_with("Trying to temporarily block port 1234")
        mock_run.assert_called_once_with(config.REMOVE_PORT.format(port=1234))

    @mock.patch('crmsh.crash_test.task.crmshutils.get_stdout_stderr')
    @mock.patch('crmsh.crash_test.task.crmshutils.get_iplist_from_name')
    @mock.patch('crmsh.crash_test.task.Task.info')
    @mock.patch('crmsh.crash_test.utils.peer_node_list')
    def test_do_block_iptables(self, mock_peer_list, mock_info, mock_get_iplist, mock_run):
        mock_peer_list.return_value = ["node1", "node2"]
        mock_get_iplist.side_effect = [["10.10.10.1", "20.20.20.1"], ["10.10.10.2", "20.20.20.2"]]
        self.task_sp_inst.do_block_iptables()
        mock_peer_list.assert_called_once_with()
        mock_info.assert_has_calls([
            mock.call("Trying to temporarily block node1 communication ip"),
            mock.call("Trying to temporarily block node2 communication ip")
            ])
        mock_get_iplist.assert_has_calls([
            mock.call("node1"),
            mock.call("node2")
            ])
        mock_run.assert_has_calls([
            mock.call(config.BLOCK_IP.format(action='I', peer_ip="10.10.10.1")),
            mock.call(config.BLOCK_IP.format(action='I', peer_ip="20.20.20.1")),
            mock.call(config.BLOCK_IP.format(action='I', peer_ip="10.10.10.2")),
            mock.call(config.BLOCK_IP.format(action='I', peer_ip="20.20.20.2"))
            ])

    @mock.patch('crmsh.crash_test.task.TaskSplitBrain.un_block_firewalld')
    def test_un_block_firewalld_enabled(self, mock_unblock_firewalld):
        self.task_sp_inst.firewalld_enabled = True
        self.task_sp_inst.un_block()
        mock_unblock_firewalld.assert_called_once_with()

    @mock.patch('crmsh.crash_test.task.TaskSplitBrain.un_block_iptables')
    def test_un_block(self, mock_unblock_iptables):
        self.task_sp_inst.firewalld_enabled = False
        self.task_sp_inst.un_block()
        mock_unblock_iptables.assert_called_once_with()

    @mock.patch('crmsh.crash_test.task.crmshutils.get_stdout_stderr')
    @mock.patch('crmsh.crash_test.task.Task.info')
    def test_un_block_firewalld(self, mock_info, mock_run):
        self.task_sp_inst.ports = ["5405", "5407"]
        self.task_sp_inst.un_block_firewalld()
        mock_info.assert_called_once_with("Trying to add port 5405,5407")
        mock_run.assert_has_calls([
            mock.call(config.ADD_PORT.format(port=5405)),
            mock.call(config.ADD_PORT.format(port=5407))
            ])

    @mock.patch('crmsh.crash_test.task.crmshutils.get_stdout_stderr')
    @mock.patch('crmsh.crash_test.task.crmshutils.get_iplist_from_name')
    @mock.patch('crmsh.crash_test.task.Task.info')
    def test_un_block_iptables(self, mock_info, mock_get_iplist, mock_run):
        mock_get_iplist.side_effect = [["10.10.10.1", "20.20.20.1"], ["10.10.10.2", "20.20.20.2"]]
        self.task_sp_inst.peer_nodelist = ["node1", "node2"]
        self.task_sp_inst.un_block_iptables()
        mock_info.assert_has_calls([
            mock.call("Trying to recover node1 communication ip"),
            mock.call("Trying to recover node2 communication ip")
            ])
        mock_get_iplist.assert_has_calls([
            mock.call("node1"),
            mock.call("node2")
            ])
        mock_run.assert_has_calls([
            mock.call(config.BLOCK_IP.format(action='D', peer_ip="10.10.10.1")),
            mock.call(config.BLOCK_IP.format(action='D', peer_ip="20.20.20.1")),
            mock.call(config.BLOCK_IP.format(action='D', peer_ip="10.10.10.2")),
            mock.call(config.BLOCK_IP.format(action='D', peer_ip="20.20.20.2"))
            ])

    @mock.patch('crmsh.crash_test.task.Task.fence_action_monitor')
    @mock.patch('threading.Thread')
    def test_run(self, mock_thread, mock_monitor):
        mock_thread_inst = mock.Mock()
        mock_thread.return_value = mock_thread_inst
        self.task_sp_inst.run()
        mock_thread.assert_called_once_with(target=mock_monitor)
        mock_thread_inst.start.assert_called_once_with()

    def test_wait(self):
        self.task_sp_inst.fence_finish_event = mock.Mock()
        self.task_sp_inst.fence_finish_event.wait.return_value = False
        self.task_sp_inst.thread_stop_event = mock.Mock()
        self.task_sp_inst.wait()
        self.task_sp_inst.fence_finish_event.wait.assert_called_once_with(60)
        self.task_sp_inst.thread_stop_event.set.assert_called_once_with()


class TestFence(TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    @mock.patch('crmsh.crash_test.utils.msg_info')
    def setUp(self, mock_msg_info):
        """
        Test setUp.
        """
        ctx = mock.Mock(fence_node="node1", yes=False)
        self.task_fence_inst = task.TaskFence(ctx)
        self.task_fence_inst.fence_action = "reboot"
        self.task_fence_inst.fence_timeout = 60

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    def test_header(self):
        expected_res = """==============================================
Testcase:          Fence node node1
Fence action:      reboot
Fence timeout:     60
"""
        res = self.task_fence_inst.header()
        self.assertEqual(res, expected_res)

    @mock.patch('crmsh.crash_test.utils.json_dumps')
    @mock.patch('crmsh.crash_test.task.Task.build_base_result')
    def test_to_json(self, mock_result, mock_json):
        self.task_fence_inst.result = {}
        self.task_fence_inst.to_json()
        mock_result.assert_called_once_with()
        mock_json.assert_called_once_with()

    @mock.patch('crmsh.crash_test.task.crmshutils.get_stdout_stderr')
    @mock.patch('crmsh.crash_test.task.Task.task_pre_check')
    def test_pre_check_no_cmd(self, mock_pre_check, mock_run):
        mock_run.return_value = (1, None, "error")
        with self.assertRaises(task.TaskError) as err:
            self.task_fence_inst.pre_check()
        self.assertEqual("error", str(err.exception))
        mock_run.assert_called_once_with("which crm_node")
        mock_pre_check.assert_called_once_with()

    @mock.patch('crmsh.crash_test.utils.check_node_status')
    @mock.patch('crmsh.crash_test.task.crmshutils.get_stdout_stderr')
    @mock.patch('crmsh.crash_test.task.Task.task_pre_check')
    def test_pre_check_error(self, mock_pre_check, mock_run, mock_node_status):
        mock_run.side_effect = [(0, None, None), (0, None, None), (0, None, None)]
        mock_node_status.return_value = False
        with self.assertRaises(task.TaskError) as err:
            self.task_fence_inst.pre_check()
        self.assertEqual("Node \"node1\" not in cluster!", str(err.exception))
        mock_run.assert_has_calls([
            mock.call("which crm_node"),
            mock.call("which stonith_admin"),
            mock.call("which crm_attribute")
            ])
        mock_node_status.assert_called_once_with("node1", "member")

    @mock.patch('crmsh.crash_test.task.Task.fence_action_monitor')
    @mock.patch('threading.Thread')
    @mock.patch('crmsh.crash_test.task.crmshutils.get_stdout_stderr')
    @mock.patch('crmsh.crash_test.task.Task.info')
    def test_run(self, mock_info, mock_run, mock_thread, mock_monitor):
        mock_thread_inst = mock.Mock()
        mock_thread.return_value = mock_thread_inst
        self.task_fence_inst.run()
        mock_info.assert_called_once_with("Trying to fence node \"node1\"")
        mock_run.assert_called_once_with("crm_attribute -t status -N 'node1' -n terminate -v true")
        mock_thread.assert_called_once_with(target=mock_monitor)
        mock_thread_inst.start.assert_called_once_with()

    @mock.patch('crmsh.crash_test.task.Task.info')
    @mock.patch('crmsh.crash_test.utils.this_node')
    def test_wait_this_node(self, mock_this_node, mock_info):
        mock_this_node.return_value = "node1"
        self.task_fence_inst.fence_finish_event = mock.Mock()
        self.task_fence_inst.thread_stop_event = mock.Mock()
        self.task_fence_inst.fence_finish_event.wait.return_value = True

        self.task_fence_inst.wait()

        mock_this_node.assert_called_once_with()
        mock_info.assert_called_once_with("Waiting 60s for self reboot...")
        self.task_fence_inst.fence_finish_event.wait.assert_called_once_with(60)

    @mock.patch('crmsh.crash_test.task.Task.info')
    @mock.patch('crmsh.crash_test.utils.this_node')
    def test_wait(self, mock_this_node, mock_info):
        mock_this_node.return_value = "node2"
        self.task_fence_inst.fence_finish_event = mock.Mock()
        self.task_fence_inst.thread_stop_event = mock.Mock()
        self.task_fence_inst.fence_finish_event.wait.return_value = None

        with self.assertRaises(task.TaskError) as err:
            self.task_fence_inst.wait()
        self.assertEqual("Target fence node \"node1\" still alive", str(err.exception))

        mock_this_node.assert_called_once_with()
        mock_info.assert_called_once_with("Waiting 60s for node \"node1\" reboot...")
        self.task_fence_inst.fence_finish_event.wait.assert_called_once_with(60)


class TestTask(TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    @mock.patch('crmsh.crash_test.utils.msg_info')
    @mock.patch('crmsh.crash_test.utils.now')
    def setUp(self, mock_now, mock_info):
        """
        Test setUp.
        """
        mock_now.return_value = "2019/07/10 01:15:15"
        main.ctx = mock.Mock(task_list={"process_name": "xin", "age": 38})
        self.task_inst = task.Task("task description", flush=True)
        mock_now.assert_called_once_with()

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    def test_header(self):
        self.task_inst.header()

    def test_to_report(self):
        self.task_inst.to_report()

    def test_to_json(self):
        self.task_inst.to_json()

    @mock.patch('crmsh.crash_test.task.crmshutils.service_is_active')
    def test_task_pre_check_exception(self, mock_active):
        mock_active.return_value = False
        with self.assertRaises(task.TaskError) as err:
            self.task_inst.task_pre_check()
        self.assertEqual("Cluster not running!", str(err.exception))
        mock_active.assert_called_once_with("pacemaker.service")

    @mock.patch('crmsh.crash_test.task.crmshutils.service_is_active')
    def test_task_pre_check_exception_no_fence(self, mock_active):
        mock_active.return_value = True
        self.task_inst.get_fence_info = mock.Mock()
        self.task_inst.fence_enabled = False
        with self.assertRaises(task.TaskError) as err:
            self.task_inst.task_pre_check()
        self.assertEqual("Require stonith enabled", str(err.exception))
        mock_active.assert_called_once_with("pacemaker.service")
        self.task_inst.get_fence_info.assert_called_once_with()

    @mock.patch('crmsh.crash_test.utils.FenceInfo')
    def test_get_fence_info(self, mock_fence_info):
        mock_fence_info_inst = mock.Mock()
        mock_fence_info.return_value = mock_fence_info_inst
        self.task_inst.get_fence_info()

    @mock.patch('crmsh.crash_test.utils.msg_info')
    def test_info(self, mock_info):
        self.task_inst.msg_append = mock.Mock()
        self.task_inst.info("info message")
        self.task_inst.msg_append.assert_called_once_with("info", "info message")
        mock_info.assert_called_once_with("info message", to_stdout=True)

    @mock.patch('crmsh.crash_test.utils.msg_warn')
    def test_warn(self, mock_warn):
        self.task_inst.msg_append = mock.Mock()
        self.task_inst.warn("warn message")
        self.task_inst.msg_append.assert_called_once_with("warn", "warn message")
        mock_warn.assert_called_once_with("warn message", to_stdout=True)

    @mock.patch('crmsh.crash_test.utils.msg_error')
    def test_error(self, mock_error):
        self.task_inst.msg_append = mock.Mock()
        self.task_inst.error("error message")
        self.task_inst.msg_append.assert_called_once_with("error", "error message")
        mock_error.assert_called_once_with("error message", to_stdout=True)

    @mock.patch('crmsh.crash_test.utils.now')
    def test_msg_append(self, mock_now):
        self.task_inst.to_json = mock.Mock()
        self.task_inst.to_report = mock.Mock()
        self.task_inst.msg_append("error", "warn message")
        mock_now.assert_called_once_with()
        self.task_inst.to_json.assert_called_once_with()
        self.task_inst.to_report.assert_called_once_with()

    def test_build_base_result(self):
        self.task_inst.build_base_result()
        expected_result = {
            "Timestamp": self.task_inst.timestamp,
            "Description": self.task_inst.description,
            "Messages": []
        }
        self.assertDictEqual(expected_result, self.task_inst.result)

    @mock.patch('crmsh.crash_test.utils.warning_ask')
    def test_print_header(self, mock_ask):
        self.task_inst.header = mock.Mock()
        self.task_inst.info = mock.Mock()
        mock_ask.return_value = False

        with self.assertRaises(crmshutils.TerminateSubCommand):
            self.task_inst.print_header()

        self.task_inst.header.assert_called_once_with()
        mock_ask.assert_called_once_with(task.Task.REBOOT_WARNING)
        self.task_inst.info.assert_called_once_with("Testcase cancelled")

    @mock.patch('crmsh.crash_test.utils.str_to_datetime')
    @mock.patch('time.sleep')
    @mock.patch('crmsh.crash_test.task.Task.info')
    @mock.patch('crmsh.crash_test.task.crmshutils.get_stdout_stderr')
    def test_fence_action_monitor(self, mock_run, mock_info, mock_sleep, mock_datetime):
        self.task_inst.thread_stop_event = mock.Mock()
        self.task_inst.thread_stop_event.is_set.side_effect = [False, False, False, False]
        self.task_inst.fence_start_event = mock.Mock()
        self.task_inst.fence_finish_event = mock.Mock()
        output = "Pending Fencing Actions:\n  * reboot of 15sp2-2 pending: client=pacemaker-controld.2430, origin=15sp2-1"
        output2 = "Node 15sp2-2 last kicked at: Tue Jan 19 16:08:37 2021"
        mock_run.side_effect = [(1, None, None), (0, output, None), (1, None, None), (0, output2, None)]
        self.task_inst.timestamp = "2021/01/19 16:08:24"
        mock_datetime.side_effect = [
            datetime.strptime(self.task_inst.timestamp, '%Y/%m/%d %H:%M:%S'),
            datetime.strptime("Tue Jan 19 16:08:37 2021", '%a %b %d %H:%M:%S %Y')
        ]

        self.task_inst.fence_action_monitor()

        self.task_inst.thread_stop_event.is_set.assert_has_calls([
            mock.call(),
            mock.call(),
            mock.call(),
            mock.call()
            ])
        mock_run.assert_has_calls([
            mock.call("crm_mon -1|grep -A1 \"Fencing Actions:\""),
            mock.call("crm_mon -1|grep -A1 \"Fencing Actions:\""),
            mock.call(config.FENCE_HISTORY.format(node="15sp2-2")),
            mock.call(config.FENCE_HISTORY.format(node="15sp2-2"))
            ])
        mock_info.assert_has_calls([
            mock.call("Node \"15sp2-2\" will be fenced by \"15sp2-1\"!"),
            mock.call("Node \"15sp2-2\" was successfully fenced by \"15sp2-1\"")
            ])
        self.task_inst.fence_start_event.set.assert_called_once_with()
        self.task_inst.fence_finish_event.set.assert_called_once_with()

class TestFixSBD(TestCase):
    """
    Class to test TaskFixSBD of task.py
    All tested in test_crash_test.py except verify()
    """

    @mock.patch('builtins.open')
    @mock.patch('os.path.isfile')
    @mock.patch('tempfile.mkstemp')
    @mock.patch('crmsh.crash_test.utils.msg_info')
    def setUp(self, mock_msg_info, mock_mkstemp, mock_isfile, mock_open):
        """
        Test setUp.
        """
        dev = "/dev/disk/by-id/scsi-SATA_ST2000LM007-1R81_WDZ5J42A"
        bak = "/tmp/tmpmby3ty9g"
        edit = "/tmp/tmpnic4t30s"
        mock_isfile.return_value = True
        mock_open.return_value = mock.mock_open(read_data="SBD_DEVICE={}".
                                                format(dev)).return_value
        mock_mkstemp.side_effect = [(1, bak), (2, edit)]

        self.task_fixsbd = task.TaskFixSBD(dev, force=False)
        mock_msg_info.assert_called_once_with('Replace SBD_DEVICE with candidate {}'.
                                              format(dev), to_stdout=False)

    def tearDown(self):
        """
        Test tearDown.
        """
        pass

    @mock.patch('os.fsync')
    @mock.patch('builtins.open')
    @mock.patch('os.path.isfile')
    @mock.patch('crmsh.crash_test.utils.msg_info')
    def test_verify_succeed(self, mock_msg_info, mock_isfile, mock_open, mock_fsync):
        """
        Test verify successful.
        """
        dev = "/dev/disk/by-id/scsi-SATA_ST2000LM007-1R81_WDZ5J42A"
        mock_isfile.return_value = True
        mock_open.return_value = mock.mock_open(read_data="SBD_DEVICE={}".
                                                format(dev)).return_value
        self.task_fixsbd.prev_task_list = []

        self.task_fixsbd.verify()
        mock_isfile.assert_called_once_with(config.SBD_CONF)
        mock_msg_info.assert_called_once_with('SBD DEVICE change succeed',
                                              to_stdout=True)
        mock_fsync.assert_called()

    @mock.patch('builtins.open')
    @mock.patch('os.path.isfile')
    def test_verify_fail(self, mock_isfile, mock_open):
        """
        Test verify failed.
        """
        dev = "/dev/disk/by-id/scsi-SATA_ST2000LM007-1R81_WDZ5J42A"
        dev_cur = "/dev/disk/by-id/scsi-SATA_ST2000LM007-no_change"
        mock_isfile.return_value = True
        mock_open.return_value = mock.mock_open(read_data="SBD_DEVICE={}".
                                                format(dev_cur)).return_value
        self.task_fixsbd.prev_task_list = []

        with self.assertRaises(task.TaskError) as err:
            self.task_fixsbd.verify()
        mock_isfile.assert_called_once_with(config.SBD_CONF)
        self.assertEqual("Fail to replace SBD device {} in {}!".
                         format(dev, config.SBD_CONF), str(err.exception))
