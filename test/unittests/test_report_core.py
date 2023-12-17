from crmsh import config
from crmsh.report import core, constants, utils, collect
import crmsh.log

import sys
import argparse
import unittest
from unittest import mock


class TestCapitalizedHelpFormatter(unittest.TestCase):
    def setUp(self):
        # Initialize the ArgumentParser with the CapitalizedHelpFormatter
        self.parser = argparse.ArgumentParser(
            formatter_class=core.CapitalizedHelpFormatter,
            usage="usage: test"
        )
        self.parser.add_argument('--test', help='Test option')

    def test_usage(self):
        # Test that the usage is capitalized
        usage_text = self.parser.format_usage()
        self.assertTrue(usage_text.startswith('Usage: '))

    def test_section_heading(self):
        # Test that section headings are capitalized
        section_text = self.parser.format_help()
        self.assertTrue('Option' in section_text)


class TestContext(unittest.TestCase):

    @mock.patch('crmsh.report.utils.parse_to_timestamp')
    @mock.patch('crmsh.report.utils.now')
    @mock.patch('crmsh.report.core.config')
    def setUp(self, mock_config, mock_now, mock_parse_to_timestamp):
        mock_config.report = mock.Mock(
            from_time="20230101",
            compress=False,
            collect_extra_logs="file1 file2",
            remove_exist_dest=False,
            single_node=False
        )
        mock_now.return_value = "12345"
        mock_parse_to_timestamp.return_value = "54321"
        self.context = core.Context()
        self.context.load()

    def test_attribute_setting(self):
        self.context.name = "value"
        self.assertEqual(self.context.name, "value")
        self.context["age"] = 19
        self.assertEqual(self.context.age, 19)
        self.context.extra_log_list = ["file3", "file2"]
        self.assertEqual(len(self.context.extra_log_list), 3)

    @mock.patch('json.dumps')
    def test_str(self, mock_dumps):
        mock_dumps.return_value = "json str"
        self.assertEqual(self.context.name, "crm_report")
        self.assertEqual(self.context.from_time, "54321")
        self.assertEqual(str(self.context), "json str")


class TestRun(unittest.TestCase):

    @mock.patch('os.path.isdir')
    def test_process_dest_dest_not_exist(self, mock_isdir):
        mock_isdir.return_value = False
        mock_ctx_inst = mock.Mock(dest="/opt/test/report")
        with self.assertRaises(utils.ReportGenericError) as err:
            core.process_dest(mock_ctx_inst)
        self.assertEqual("Directory /opt/test does not exist", str(err.exception))

    @mock.patch('crmsh.utils.is_filename_sane')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.isdir')
    def test_process_dest_filename_not_sane(self, mock_isdir, mock_basename, mock_sane):
        mock_isdir.return_value = True
        mock_sane.return_value = False
        mock_basename.return_value = "report*"
        mock_ctx_inst = mock.Mock(dest="/opt/test/report*")
        with self.assertRaises(utils.ReportGenericError) as err:
            core.process_dest(mock_ctx_inst)
        self.assertEqual("report* is invalid file name", str(err.exception))

    @mock.patch('crmsh.report.core.pick_compress_prog')
    @mock.patch('shutil.rmtree')
    @mock.patch('crmsh.utils.is_filename_sane')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.isdir')
    def test_process_dest_dir_exists_rmtree(self, mock_isdir, mock_basename, mock_sane, mock_rmtree, mock_pick):
        mock_isdir.side_effect = [True, True]
        mock_sane.return_value = True
        mock_basename.return_value = "report"
        mock_ctx_inst = mock.Mock(dest="/opt/test/report", no_compress=True, rm_exist_dest=True)
        core.process_dest(mock_ctx_inst)
        mock_rmtree.assert_called_once_with("/opt/test/report")

    @mock.patch('crmsh.report.core.pick_compress_prog')
    @mock.patch('crmsh.utils.is_filename_sane')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.isdir')
    def test_process_dest_dir_exists(self, mock_isdir, mock_basename, mock_sane, mock_pick):
        mock_isdir.side_effect = [True, True]
        mock_sane.return_value = True
        mock_basename.return_value = "report"
        mock_ctx_inst = mock.Mock(dest="/opt/test/report", no_compress=True, rm_exist_dest=False)
        with self.assertRaises(utils.ReportGenericError) as err:
            core.process_dest(mock_ctx_inst)
        self.assertEqual("Destination directory /opt/test/report exists, please cleanup or use -Z option", str(err.exception))

    @mock.patch('crmsh.report.core.pick_compress_prog')
    @mock.patch('crmsh.utils.is_filename_sane')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.isdir')
    @mock.patch('crmsh.report.utils.now')
    def test_process_dest(self, mock_now, mock_isdir, mock_basename, mock_is_sane, mock_pick):
        mock_now.return_value = "Mon-28-Aug-2023"
        mock_isdir.side_effect = [True, False]
        mock_is_sane.return_value = True
        mock_basename.return_value = f"report.{mock_now.return_value}"
        mock_ctx_inst = mock.Mock(dest=None, no_compress=False, compress_suffix=".bz2", name="report")

        core.process_dest(mock_ctx_inst)

        self.assertEqual(mock_ctx_inst.dest_dir, ".")
        mock_is_sane.assert_called_once_with(mock_basename.return_value)
        self.assertEqual(mock_ctx_inst.dest_path, "./report.Mon-28-Aug-2023.tar.bz2")

    @mock.patch('crmsh.report.core.pick_first_compress')
    def test_pick_compress_prog(self, mock_pick):
        mock_pick.return_value = (None, None)
        mock_ctx_inst = mock.Mock()
        core.pick_compress_prog(mock_ctx_inst)
        self.assertEqual(mock_ctx_inst.compress_prog, "cat")

    @mock.patch('shutil.which')
    def test_pick_first_compress_return(self, mock_which):
        mock_which.return_value = True
        prog, ext = core.pick_first_compress()
        self.assertEqual(prog, "gzip")
        self.assertEqual(ext, ".gz")
        mock_which.assert_called_once_with("gzip")

    @mock.patch('logging.Logger.warning')
    @mock.patch('shutil.which')
    def test_pick_first_compress(self, mock_which, mock_warn):
        mock_which.side_effect = [False, False, False, False]
        prog, ext = core.pick_first_compress()
        self.assertIsNone(prog)
        self.assertIsNone(ext)

    @mock.patch('crmsh.report.utils.get_timespan_str')
    @mock.patch('logging.Logger.info')
    def test_finalword(self, mock_info, mock_get_timespan):
        mock_ctx_inst = mock.Mock(dest_path="./crm_report-Tue-15-Aug-2023.tar.bz2", node_list=["node1", "node2"])
        mock_get_timespan.return_value = "2023-08-14 18:17 - 2023-08-15 06:17"
        core.finalword(mock_ctx_inst)
        mock_info.assert_has_calls([
            mock.call(f"The report is saved in {mock_ctx_inst.dest_path}"),
            mock.call(f"Report timespan: {mock_get_timespan.return_value}"),
            mock.call(f"Including nodes: {' '.join(mock_ctx_inst.node_list)}"),
            mock.call("Thank you for taking time to create this report")
            ])

    @mock.patch('os.path.basename')
    @mock.patch('crmsh.report.core.logger', spec=crmsh.log.DEBUG2Logger)
    @mock.patch('crmsh.utils.mkdirp')
    @mock.patch('crmsh.report.core.is_collector')
    @mock.patch('crmsh.report.core.tmpfiles.create_dir')
    def test_setup_workdir_collector(self, mock_create_dir, mock_collector, mock_mkdirp, mock_logger, mock_basename):
        mock_create_dir.return_value = "/tmp/tmp_dir"
        mock_ctx_inst = mock.Mock(dest="/opt/report", work_dir="/opt/work_dir", me="node1")
        mock_collector.return_value = True
        mock_basename.return_value = "report"
        core.setup_workdir(mock_ctx_inst)
        mock_logger.debug2.assert_called_once_with(f"Setup work directory in {mock_ctx_inst.work_dir}")

    @mock.patch('os.path.basename')
    @mock.patch('crmsh.report.core.logger', spec=crmsh.log.DEBUG2Logger)
    @mock.patch('crmsh.utils.mkdirp')
    @mock.patch('crmsh.report.core.is_collector')
    @mock.patch('crmsh.report.core.tmpfiles.create_dir')
    def test_setup_workdir(self, mock_create_dir, mock_collector, mock_mkdirp, mock_logger, mock_basename):
        mock_create_dir.return_value = "/tmp/tmp_dir"
        mock_ctx_inst = mock.Mock(dest="/opt/report", work_dir="/opt/work_dir")
        mock_collector.return_value = False
        mock_basename.return_value = "report"
        core.setup_workdir(mock_ctx_inst)
        mock_logger.debug2.assert_called_once_with(f"Setup work directory in {mock_ctx_inst.work_dir}")

    @mock.patch('os.path.isdir')
    @mock.patch('crmsh.report.core.load_from_crmsh_config')
    def test_load_context_attributes(self, mock_load, mock_isdir):
        mock_ctx_inst = mock.Mock(cib_dir="/var/lib/pacemaker/cib")
        mock_isdir.return_value = True

        core.load_context_attributes(mock_ctx_inst)

        self.assertEqual(mock_ctx_inst.pcmk_lib_dir, "/var/lib/pacemaker")
        self.assertEqual(mock_ctx_inst.cores_dir_list, ["/var/lib/pacemaker/cores", constants.COROSYNC_LIB])

    @mock.patch('os.path.isdir')
    @mock.patch('crmsh.report.core.config')
    def test_load_from_crmsh_config(self, mock_config, mock_isdir):
        mock_config.path = mock.Mock(
            crm_config="/var/lib/pacemaker/cib",
            crm_daemon_dir="/usr/lib/pacemaker",
            pe_state_dir="/var/lib/pacemaker/pe"
        )
        mock_isdir.side_effect = [True, True, True]
        mock_ctx_inst = mock.Mock()

        core.load_from_crmsh_config(mock_ctx_inst)

        self.assertEqual(mock_ctx_inst.cib_dir, mock_config.path.crm_config)
        self.assertEqual(mock_ctx_inst.pcmk_exec_dir, mock_config.path.crm_daemon_dir)
        self.assertEqual(mock_ctx_inst.pe_dir, mock_config.path.pe_state_dir)

    @mock.patch('os.path.isdir')
    @mock.patch('crmsh.report.core.config')
    def test_load_from_crmsh_config_exception(self, mock_config, mock_isdir):
        mock_config.path = mock.Mock(
            crm_config="/var/lib/pacemaker/cib",
        )
        mock_isdir.return_value = False
        mock_ctx_inst = mock.Mock()

        with self.assertRaises(utils.ReportGenericError) as err:
            core.load_from_crmsh_config(mock_ctx_inst)
        self.assertEqual(f"Cannot find CIB directory", str(err.exception))

    def test_adjust_verbosity_debug(self):
        mock_ctx_inst = mock.Mock(debug=1)
        core.adjust_verbosity(mock_ctx_inst)

    def test_adjust_verbosity(self):
        mock_ctx_inst = mock.Mock(debug=0)
        config.core.debug = True
        core.adjust_verbosity(mock_ctx_inst)

    @mock.patch('crmsh.report.core.adjust_verbosity')
    @mock.patch('crmsh.report.core.config')
    @mock.patch('json.loads')
    @mock.patch('crmsh.report.core.logger', spec=crmsh.log.DEBUG2Logger)
    def test_load_context(self, mock_logger, mock_json_loads, mock_config, mock_verbosity):
        class Context:
            def __str__(self):
                return "data"
            def __setitem__(self, key, value):
                self.__dict__[key] = value

        sys.argv = ["arg1", "arg2", "arg3"]
        mock_config.report = mock.Mock(verbosity=None)
        mock_json_loads.return_value = {"key": "value", "debug": "true"}
        mock_ctx_inst = Context()
        core.load_context(mock_ctx_inst)
        mock_logger.debug2.assert_called_once_with("Loading context from collector: data")

    @mock.patch('crmsh.report.core.adjust_verbosity')
    @mock.patch('crmsh.report.core.process_arguments')
    @mock.patch('crmsh.utils.check_empty_option_value')
    @mock.patch('crmsh.report.core.add_arguments')
    def test_parse_arguments(self, mock_parse, mock_check_space, mock_process, mock_verbosity):
        mock_args = mock.Mock(option1="value1")
        mock_parse.return_value = mock_args
        mock_ctx_inst = mock.Mock()

        core.parse_arguments(mock_ctx_inst)
        self.assertEqual(mock_ctx_inst.option1, "value1")

        mock_check_space.assert_called_once_with(mock_args)
        mock_process.assert_called_once_with(mock_ctx_inst)

    def test_is_collector(self):
        sys.argv = ["report", "__collector"]
        self.assertEqual(core.is_collector(), True)

    @mock.patch('crmsh.report.core.push_data')
    @mock.patch('crmsh.report.core.collect_logs_and_info')
    @mock.patch('crmsh.report.core.setup_workdir')
    @mock.patch('crmsh.report.core.load_context')
    @mock.patch('crmsh.report.core.is_collector')
    @mock.patch('crmsh.report.core.Context')
    def test_run_impl_collector(self, mock_context, mock_collector, mock_load, mock_setup, mock_collect_info, mock_push):
        mock_context.return_value = mock.Mock()
        mock_ctx_inst = mock_context.return_value
        mock_collector.side_effect = [True, True]

        core.run_impl()

        mock_context.assert_called_once_with()
        mock_collector.assert_has_calls([mock.call(), mock.call()])
        mock_load.assert_called_once_with(mock_ctx_inst)
        mock_setup.assert_called_once_with(mock_ctx_inst)
        mock_collect_info.assert_called_once_with(mock_ctx_inst)
        mock_push.assert_called_once_with(mock_ctx_inst)

    @mock.patch('crmsh.report.core.process_results')
    @mock.patch('crmsh.report.core.collect_for_nodes')
    @mock.patch('crmsh.report.core.find_ssh_user')
    @mock.patch('crmsh.report.core.setup_workdir')
    @mock.patch('crmsh.report.core.load_context_attributes')
    @mock.patch('crmsh.report.core.parse_arguments')
    @mock.patch('crmsh.report.core.is_collector')
    @mock.patch('crmsh.report.core.Context')
    def test_run_impl(self, mock_context, mock_collector, mock_parse, mock_load, mock_setup, mock_find_ssh, mock_collect, mock_process_results):
        mock_context.return_value = mock.Mock()
        mock_ctx_inst = mock_context.return_value
        mock_collector.side_effect = [False, False]

        core.run_impl()

        mock_context.assert_called_once_with()
        mock_collector.assert_has_calls([mock.call(), mock.call()])
        mock_parse.assert_called_once_with(mock_ctx_inst)
        mock_load.assert_called_once_with(mock_ctx_inst)
        mock_setup.assert_called_once_with(mock_ctx_inst)
        mock_find_ssh.assert_called_once_with(mock_ctx_inst)
        mock_collect.assert_called_once_with(mock_ctx_inst)
        mock_process_results.assert_called_once_with(mock_ctx_inst)

    @mock.patch('logging.Logger.error')
    @mock.patch('crmsh.report.core.run_impl')
    def test_run_exception_generic(self, mock_run, mock_log_error):
        mock_run.side_effect = utils.ReportGenericError("error")
        with self.assertRaises(SystemExit) as err:
            core.run()
        mock_log_error.assert_called_once_with("error")

    @mock.patch('crmsh.report.utils.print_traceback')
    @mock.patch('crmsh.report.core.run_impl')
    def test_run_exception(self, mock_run, mock_print):
        mock_run.side_effect = UnicodeDecodeError("encoding", b'', 0, 1, "error")
        with self.assertRaises(SystemExit) as err:
            core.run()
        mock_print.assert_called_once_with()

    @mock.patch('argparse.HelpFormatter')
    @mock.patch('argparse.ArgumentParser')
    def test_add_arguments_help(self, mock_argparse, mock_formatter):
        mock_argparse_inst = mock.Mock()
        mock_argparse.return_value = mock_argparse_inst
        mock_args_inst = mock.Mock(help=True)
        mock_argparse_inst.parse_args.return_value = mock_args_inst

        with self.assertRaises(SystemExit):
            core.add_arguments()

        mock_argparse_inst.print_help.assert_called_once_with()

    @mock.patch('crmsh.report.core.config')
    @mock.patch('argparse.HelpFormatter')
    @mock.patch('argparse.ArgumentParser')
    def test_add_arguments(self, mock_argparse, mock_formatter, mock_config):
        mock_argparse_inst = mock.Mock()
        mock_argparse.return_value = mock_argparse_inst
        mock_args_inst = mock.Mock(help=False, debug=True)
        mock_argparse_inst.parse_args.return_value = mock_args_inst
        mock_config.report = mock.Mock(verbosity=False)

        core.add_arguments()

    @mock.patch('crmsh.report.core.logger', spec=crmsh.log.DEBUG2Logger)
    @mock.patch('crmsh.utils.to_ascii')
    @mock.patch('crmsh.report.core.ShellUtils')
    def test_push_data(self, mock_sh_utils, mock_to_ascii, mock_logger):
        mock_sh_utils_inst = mock.Mock()
        mock_sh_utils.return_value = mock_sh_utils_inst
        mock_sh_utils_inst.get_stdout_stderr.return_value = (0, "data", "error")
        mock_to_ascii.return_value = "error"
        mock_ctx_inst = mock.Mock(work_dir="/opt/work_dir", main_node="node1", me="node1")

        with self.assertRaises(utils.ReportGenericError) as err:
            core.push_data(mock_ctx_inst)
        self.assertEqual("error", str(err.exception))

        mock_logger.debug2.assert_called_once_with("Pushing data from node1:/opt/work_dir to node1")
        mock_sh_utils_inst.get_stdout_stderr.assert_called_once_with("cd /opt/work_dir/.. && tar -h -c node1", raw=True)

    @mock.patch('crmsh.report.core.finalword')
    @mock.patch('shutil.move')
    @mock.patch('crmsh.report.utils.create_description_template')
    @mock.patch('crmsh.report.utils.analyze')
    def test_process_results_no_compress(self, mock_analyze, mock_create, mock_move, mock_final):
        mock_ctx_inst = mock.Mock(speed_up=True, work_dir="/opt/work_dir", dest_dir="/opt/user", no_compress=True)
        core.process_results(mock_ctx_inst)
        mock_analyze.assert_called_once_with(mock_ctx_inst)
        mock_create.assert_called_once_with(mock_ctx_inst)
        mock_final.assert_called_once_with(mock_ctx_inst)
        mock_move.assert_called_once_with(mock_ctx_inst.work_dir, mock_ctx_inst.dest_dir)

    @mock.patch('crmsh.report.core.finalword')
    @mock.patch('crmsh.report.core.sh.cluster_shell')
    @mock.patch('crmsh.report.core.logger', spec=crmsh.log.DEBUG2Logger)
    @mock.patch('crmsh.report.utils.create_description_template')
    @mock.patch('crmsh.report.utils.analyze')
    @mock.patch('crmsh.report.utils.do_sanitize')
    def test_process_results(self, mock_sanitize, mock_analyze, mock_create, mock_debug2, mock_run, mock_final):
        mock_run_inst = mock.Mock()
        mock_run.return_value = mock_run_inst
        mock_run_inst.get_stdout_or_raise_error = mock.Mock()
        mock_ctx_inst = mock.Mock(speed_up=False, work_dir="/opt/work_dir", dest_dir="/opt/user", no_compress=False, dest="report", compress_prog="tar", compress_suffix=".bz2")
        core.process_results(mock_ctx_inst)
        mock_sanitize.assert_called_once_with(mock_ctx_inst)
        mock_analyze.assert_called_once_with(mock_ctx_inst)
        mock_create.assert_called_once_with(mock_ctx_inst)
        mock_final.assert_called_once_with(mock_ctx_inst)

    @mock.patch('crmsh.report.utils.print_traceback')
    @mock.patch('crmsh.report.core.getmembers')
    @mock.patch('multiprocessing.cpu_count')
    @mock.patch('multiprocessing.Pool')
    def test_collect_logs_and_info(self, mock_pool, mock_cpu_count, mock_getmember, mock_print):
        mock_cpu_count.return_value = 4
        mock_pool_inst = mock.Mock()
        mock_pool.return_value = mock_pool_inst
        mock_pool_inst.apply_async = mock.Mock()
        mock_async_inst1 = mock.Mock()
        mock_async_inst2 = mock.Mock()
        mock_pool_inst.apply_async.side_effect = [mock_async_inst1, mock_async_inst2]
        mock_async_inst1.get = mock.Mock()
        mock_async_inst2.get = mock.Mock(side_effect=ValueError)
        mock_pool_inst.close = mock.Mock()
        mock_pool_inst.join = mock.Mock()
        mock_getmember.return_value = [("collect_func1", None), ("collect_func2", None)]
        collect.collect_func1 = mock.Mock()
        collect.collect_func2 = mock.Mock()
        mock_ctx_inst = mock.Mock()

        core.collect_logs_and_info(mock_ctx_inst)
        mock_pool.assert_called_once_with(3)

    @mock.patch('multiprocessing.Process')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.report.core.start_collector')
    def test_collect_for_nodes(self, mock_start_collector, mock_info, mock_process):
        mock_ctx_inst = mock.Mock(
            node_list=["node1", "node2"],
            ssh_askpw_node_list=["node2"],
            ssh_user=""
        )
        mock_process_inst = mock.Mock()
        mock_process.return_value = mock_process_inst
        core.collect_for_nodes(mock_ctx_inst)

    def test_process_arguments_value_error(self):
        mock_ctx_inst = mock.Mock(from_time=123, to_time=100)
        with self.assertRaises(ValueError) as err:
            core.process_arguments(mock_ctx_inst)
            self.assertEqual("The start time must be before the finish time", str(err.exception))

    @mock.patch('crmsh.utils.list_cluster_nodes')
    def test_process_node_list_exception(self, mock_list_nodes):
        mock_ctx_inst = mock.Mock(node_list=[])
        mock_list_nodes.return_value = []
        with self.assertRaises(utils.ReportGenericError) as err:
            core.process_node_list(mock_ctx_inst)
            self.assertEqual("Could not figure out a list of nodes; is this a cluster node?", str(err.exception))

    @mock.patch('crmsh.utils.list_cluster_nodes')
    def test_process_node_list_single(self, mock_list_nodes):
        mock_ctx_inst = mock.Mock(node_list=["node1", "node2"], single=True, me="node1")
        core.process_node_list(mock_ctx_inst)

    @mock.patch('logging.Logger.error')
    @mock.patch('crmsh.utils.ping_node')
    @mock.patch('crmsh.utils.list_cluster_nodes')
    def test_process_node_list(self, mock_list_nodes, mock_ping, mock_error):
        mock_ctx_inst = mock.Mock(node_list=["node1", "node2"], single=False, me="node1")
        mock_ping.side_effect = ValueError("error")
        core.process_node_list(mock_ctx_inst)
        self.assertEqual(mock_ctx_inst.node_list, ["node1"])

    @mock.patch('crmsh.report.core.process_node_list')
    @mock.patch('crmsh.report.core.process_dest')
    def test_process_arguments(self, mock_dest, mock_node_list):
        mock_ctx_inst = mock.Mock(from_time=123, to_time=150)
        core.process_arguments(mock_ctx_inst)

    @mock.patch('crmsh.report.core.logger', spec=crmsh.log.DEBUG2Logger)
    @mock.patch('crmsh.utils.check_ssh_passwd_need')
    @mock.patch('crmsh.report.core.userdir.getuser')
    @mock.patch('crmsh.report.core.userdir.get_sudoer')
    def test_find_ssh_user_not_found(self, mock_get_sudoer, mock_getuser, mock_check_ssh, mock_logger):
        mock_get_sudoer.return_value = ""
        mock_getuser.return_value = "user2"
        mock_check_ssh.return_value = True
        mock_ctx_inst = mock.Mock(ssh_user="", ssh_askpw_node_list=[], node_list=["node1", "node2"], me="node1")
        core.find_ssh_user(mock_ctx_inst)
        mock_logger.warning.assert_called_once_with(f"passwordless ssh to node(s) ['node2'] does not work")

    @mock.patch('crmsh.report.core.logger', spec=crmsh.log.DEBUG2Logger)
    @mock.patch('logging.Logger.warning')
    @mock.patch('logging.Logger.debug')
    @mock.patch('crmsh.utils.check_ssh_passwd_need')
    @mock.patch('crmsh.utils.this_node')
    @mock.patch('crmsh.report.core.userdir.getuser')
    @mock.patch('crmsh.report.core.userdir.get_sudoer')
    def test_find_ssh_user(self, mock_get_sudoer, mock_getuser, mock_this_node, mock_check_ssh, mock_debug, mock_warn, mock_debug2):
        mock_get_sudoer.return_value = "user1"
        mock_getuser.return_value = "user2"
        mock_this_node.return_value = "node1"
        mock_check_ssh.return_value = False
        mock_ctx_inst = mock.Mock(ssh_user="", ssh_askpw_node_list=[], node_list=["node1", "node2"])
        core.find_ssh_user(mock_ctx_inst)
        self.assertEqual("sudo", mock_ctx_inst.sudo)
        self.assertEqual("user1", mock_ctx_inst.ssh_user)

    @mock.patch('logging.Logger.warning')
    @mock.patch('crmsh.report.core.ShellUtils')
    def test_start_collector_return(self, mock_sh_utils, mock_warn):
        mock_sh_utils_inst = mock.Mock()
        mock_sh_utils.return_value = mock_sh_utils_inst
        mock_sh_utils_inst.get_stdout_stderr.return_value = (0, '', None)
        mock_ctx_inst = mock.Mock(me="node1")
        core.start_collector("node1", mock_ctx_inst)
        mock_sh_utils_inst.get_stdout_stderr.assert_called_once_with(f"{constants.BIN_COLLECTOR} '{mock_ctx_inst}'")

    @mock.patch('logging.Logger.warning')
    @mock.patch('crmsh.report.core.ShellUtils')
    @mock.patch('crmsh.report.core.sh.LocalShell')
    @mock.patch('crmsh.utils.this_node')
    def test_start_collector_warn(self, mock_this_node, mock_sh, mock_sh_utils, mock_warn):
        mock_sh_utils_inst = mock.Mock()
        mock_sh_utils.return_value = mock_sh_utils_inst
        mock_sh_utils_inst.get_stdout = mock.Mock()
        mock_sh_inst = mock.Mock()
        mock_sh.return_value = mock_sh_inst
        mock_sh_inst.get_rc_stdout_stderr.return_value = (1, '', "error")
        mock_ctx_inst = mock.Mock(ssh_user='', sudo='')
        mock_this_node.return_value = "node2"
        core.start_collector("node1", mock_ctx_inst)
        mock_warn.assert_called_once_with("error")

    @mock.patch('ast.literal_eval')
    @mock.patch('crmsh.report.core.sh.LocalShell')
    @mock.patch('crmsh.report.core.ShellUtils')
    @mock.patch('crmsh.utils.this_node')
    def test_start_collector(self, mock_this_node, mock_sh_utils, mock_sh, mock_eval):
        mock_sh_utils_inst = mock.Mock()
        mock_sh_utils.return_value = mock_sh_utils_inst
        mock_sh_utils_inst.get_stdout = mock.Mock()
        mock_sh_inst = mock.Mock()
        mock_sh.return_value = mock_sh_inst
        mock_sh_inst.get_rc_stdout_stderr.return_value = (0, f"line1\n{constants.COMPRESS_DATA_FLAG}data", None)
        mock_ctx_inst = mock.Mock(ssh_user='', sudo='')
        mock_this_node.return_value = "node2"
        mock_eval.return_value = "data"
        core.start_collector("node1", mock_ctx_inst)
