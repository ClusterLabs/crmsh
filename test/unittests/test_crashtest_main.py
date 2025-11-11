import os
import sys

try:
    from unittest import mock, TestCase
except ImportError:
    import mock

from crmsh import utils as crmshutils
from crmsh.crash_test import utils, main, config, task


class TestContext(TestCase):

    def test_context(self):
        main.ctx.name = "xin"
        self.assertEqual(main.ctx.name, "xin")


class TestMain(TestCase):

    @mock.patch('crmsh.crash_test.main.MyArgParseFormatter')
    @mock.patch('argparse.ArgumentParser')
    def test_parse_argument_help(self, mock_parser, mock_myformatter):
        mock_parser_inst = mock.Mock()
        mock_parser.return_value = mock_parser_inst
        ctx = mock.Mock(process_name="crash_test", logfile="logfile1",
                        jsonfile="jsonfile1", report_path="/var/log/report")
        mock_parse_args_inst = mock.Mock(help=True)
        mock_parser_inst.parse_args.return_value = mock_parse_args_inst

        with self.assertRaises(crmshutils.TerminateSubCommand):
            main.parse_argument(ctx)

        mock_parser_inst.print_help.assert_called_once_with()

    @mock.patch('crmsh.crash_test.main.MyArgParseFormatter')
    @mock.patch('argparse.ArgumentParser')
    def test_parse_argument(self, mock_parser, mock_myformatter):
        mock_parser_inst = mock.Mock()
        mock_parser.return_value = mock_parser_inst
        ctx = mock.Mock(process_name="crash_test", logfile="logfile1",
                        jsonfile="jsonfile1", report_path="/var/log/report")
        mock_parse_args_inst = mock.Mock(help=False, env_check=True, sbd=True)
        mock_parser_inst.parse_args.return_value = mock_parse_args_inst

        main.parse_argument(ctx)
        self.assertEqual(ctx.env_check, True)
        self.assertEqual(ctx.sbd, True)

        mock_parser_inst.print_help.assert_not_called()

    def test_setup_basic_context(self):
        ctx = mock.Mock(process_name="crash_test")
        main.setup_basic_context(ctx)
        self.assertEqual(ctx.var_dir, "/var/lib/crmsh/crash_test")
        self.assertEqual(ctx.report_path, "/var/lib/crmsh/crash_test")
        self.assertEqual(ctx.jsonfile, "/var/lib/crmsh/crash_test/crash_test.json")
        self.assertEqual(ctx.logfile, "/var/log/crmsh/crmsh.log")

    @mock.patch('logging.Logger.fatal')
    @mock.patch('crmsh.crash_test.utils.is_root')
    @mock.patch('crmsh.crash_test.main.parse_argument')
    @mock.patch('crmsh.crash_test.main.setup_basic_context')
    def test_run_non_root(self, mock_setup, mock_parse, mock_is_root, mock_log_fatal):
        mock_is_root.return_value = False
        ctx = mock.Mock(process_name="crash_test")

        with self.assertRaises(crmshutils.TerminateSubCommand):
            main.run(ctx)

        mock_setup.assert_called_once_with(ctx)
        mock_parse.assert_called_once_with(ctx)
        mock_is_root.assert_called_once_with()
        mock_log_fatal.assert_called_once_with("{} can only be executed as user root!".format(ctx.process_name))

    @mock.patch('crmsh.crash_test.main.split_brain')
    @mock.patch('crmsh.crash_test.main.fence_node')
    @mock.patch('crmsh.crash_test.main.kill_process')
    @mock.patch('os.makedirs')
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.crash_test.utils.is_root')
    @mock.patch('crmsh.crash_test.main.parse_argument')
    @mock.patch('crmsh.crash_test.main.setup_basic_context')
    def test_run(self, mock_setup, mock_parse, mock_is_root, mock_exists, mock_mkdir,
                 mock_kill, mock_fence, mock_sb):
        mock_is_root.return_value = True
        ctx = mock.Mock(var_dir="/var/lib/crash_test")
        mock_exists.return_value = False

        main.run(ctx)

        mock_setup.assert_called_once_with(ctx)
        mock_parse.assert_called_once_with(ctx)
        mock_is_root.assert_called_once_with()
        mock_exists.assert_called_once_with(ctx.var_dir)
        mock_mkdir.assert_called_once_with(ctx.var_dir, exist_ok=True)
        mock_kill.assert_called_once_with(ctx)
        mock_fence.assert_called_once_with(ctx)
        mock_sb.assert_called_once_with(ctx)

    @mock.patch('crmsh.crash_test.task.TaskKill')
    def test_kill_porcess_return_pacemaker_loop(self, mock_task_kill):
        ctx = mock.Mock(pacemakerd=True, loop=True, sbd=None, corosync=None)
        main.kill_process(ctx)
        mock_task_kill.assert_not_called()

    @mock.patch('crmsh.crash_test.task.TaskKill')
    def test_kill_porcess_return(self, mock_task_kill):
        ctx = mock.Mock(pacemakerd=False, sbd=False, corosync=False)
        main.kill_process(ctx)
        mock_task_kill.assert_not_called()

    @mock.patch('crmsh.crash_test.task.TaskKill')
    def test_kill_process(self, mock_task_kill):
        mock_task_kill_inst = mock.Mock()
        mock_task_kill.return_value = mock_task_kill_inst
        mock_task_kill_inst.wait.side_effect = task.TaskError("error data")
        ctx = mock.Mock(sbd=True)

        with self.assertRaises(crmshutils.TerminateSubCommand):
            main.kill_process(ctx)

        mock_task_kill_inst.pre_check.assert_called_once_with()
        mock_task_kill_inst.print_header.assert_called_once_with()
        mock_task_kill_inst.enable_report.assert_called_once_with()
        mock_task_kill_inst.run.assert_called_once_with()
        mock_task_kill_inst.wait.assert_called_once_with()
        mock_task_kill_inst.error.assert_called_once_with("error data")

    def test_split_brain_return(self):
        ctx = mock.Mock(sp_iptables=None)
        main.split_brain(ctx)

    @mock.patch('crmsh.crash_test.task.TaskSplitBrain')
    def test_split_brain(self, mock_sp):
        ctx = mock.Mock(sp_iptables=True, force=False)
        mock_sp_inst = mock.Mock()
        mock_sp.return_value = mock_sp_inst
        mock_sp_inst.do_block.return_value.__enter__ = mock.Mock()
        mock_sp_inst.do_block.return_value.__exit__ = mock.Mock()

        main.split_brain(ctx)

        mock_sp.assert_called_once_with(False)
        mock_sp_inst.pre_check.assert_called_once_with()
        mock_sp_inst.print_header.assert_called_once_with()
        mock_sp_inst.do_block.assert_called_once_with()
        mock_sp_inst.run.assert_called_once_with()
        mock_sp_inst.wait.assert_called_once_with()

    @mock.patch('crmsh.crash_test.task.TaskSplitBrain')
    def test_split_brain_exception(self, mock_sp):
        ctx = mock.Mock(sp_iptables=True)
        mock_sp_inst = mock.Mock()
        mock_sp.return_value = mock_sp_inst
        mock_sp_inst.pre_check.side_effect = task.TaskError("error data")

        with self.assertRaises(crmshutils.TerminateSubCommand):
            main.split_brain(ctx)

        mock_sp_inst.error.assert_called_once_with("error data")

    def test_fence_node_return(self):
        ctx = mock.Mock(fence_node=None)
        main.fence_node(ctx)

    @mock.patch('crmsh.crash_test.task.TaskFence')
    def test_fence_node(self, mock_task_fence):
        mock_task_fence_inst = mock.Mock()
        mock_task_fence.return_value = mock_task_fence_inst
        mock_task_fence_inst.wait.side_effect = task.TaskError("error data")
        ctx = mock.Mock(fence_node=True)

        with self.assertRaises(crmshutils.TerminateSubCommand):
            main.fence_node(ctx)

        mock_task_fence_inst.pre_check.assert_called_once_with()
        mock_task_fence_inst.print_header.assert_called_once_with()
        mock_task_fence_inst.run.assert_called_once_with()
        mock_task_fence_inst.wait.assert_called_once_with()
        mock_task_fence_inst.error.assert_called_once_with("error data")

    @classmethod
    def test_MyArgParseFormatter(cls):
        main.MyArgParseFormatter("test")
