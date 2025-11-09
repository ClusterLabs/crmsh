import os
import sys
import datetime
import tempfile
from crmsh import config
from crmsh import utils as crmutils
from crmsh.report import utils, constants
import crmsh.log

import unittest
from unittest import mock


class TestPackage(unittest.TestCase):

    @mock.patch('crmsh.report.utils.get_pkg_mgr')
    def setUp(self, mock_get_pkg_mgr):
        mock_get_pkg_mgr.side_effect = [None, "rpm", "deb"]
        self.inst_none = utils.Package("xxx1 xxx2")
        self.inst = utils.Package("rpm1 rpm2")
        self.inst_deb = utils.Package("deb1 deb2")

    def test_version_return(self):
        res = self.inst_none.version()
        self.assertEqual(res, "")

    @mock.patch('crmsh.report.utils.Package.pkg_ver_rpm')
    def test_version(self, mock_ver_rpm):
        mock_ver_rpm.return_value = "version1"
        res = self.inst.version()
        self.assertEqual(res, "version1")

    @mock.patch('crmsh.report.utils.ShellUtils')
    def test_version_rpm(self, mock_run):
        mock_run_inst = mock.Mock()
        mock_run.return_value = mock_run_inst
        data = "rpm1-4.5.0\nrpm2 not installed"
        mock_run_inst.get_stdout_stderr.return_value = (0, data, None)
        res = self.inst.pkg_ver_rpm()
        self.assertEqual(res, "rpm1-4.5.0")

    @mock.patch('crmsh.report.utils.ShellUtils')
    def test_version_deb(self, mock_run):
        mock_run_inst = mock.Mock()
        mock_run.return_value = mock_run_inst
        data = "deb1-4.5.0\nno packages found"
        mock_run_inst.get_stdout_stderr.return_value = (0, data, None)
        res = self.inst_deb.pkg_ver_deb()
        self.assertEqual(res, "deb1-4.5.0")

    def test_verify_return(self):
        res = self.inst_none.verify()
        self.assertEqual(res, "")

    @mock.patch('crmsh.report.utils.Package.verify_rpm')
    def test_verify(self, mock_verify_rpm):
        mock_verify_rpm.return_value = ""
        res = self.inst.verify()
        self.assertEqual(res, "")

    @mock.patch('crmsh.report.utils.ShellUtils')
    def test_verify_rpm(self, mock_run):
        mock_run_inst = mock.Mock()
        mock_run.return_value = mock_run_inst
        mock_run_inst.get_stdout_stderr.return_value = (0, "verify data\nThis is not installed","")
        res = self.inst.verify_rpm()
        self.assertEqual(res, "verify data")

    @mock.patch('crmsh.report.utils.ShellUtils')
    def test_verify_deb(self, mock_run):
        mock_run_inst = mock.Mock()
        mock_run.return_value = mock_run_inst
        mock_run_inst.get_stdout_stderr.return_value = (0, "verify data\nThis is not installed","")
        res = self.inst_deb.verify_deb()
        self.assertEqual(res, "verify data")


class TestSanitizer(unittest.TestCase):

    def setUp(self):
        mock_ctx_inst_no_sanitize = mock.Mock(sanitize=False)
        self.s_inst_no_sanitize = utils.Sanitizer(mock_ctx_inst_no_sanitize)

        mock_ctx_inst_no_sanitize_set = mock.Mock(sensitive_regex_list=[])
        self.s_inst_no_sanitize_set = utils.Sanitizer(mock_ctx_inst_no_sanitize_set)

        mock_ctx_inst = mock.Mock(sanitize=True, work_dir="/opt", sensitive_regex_list=["test_patt"])
        self.s_inst = utils.Sanitizer(mock_ctx_inst)

    @mock.patch('logging.Logger.warning')
    @mock.patch('crmsh.report.utils.Sanitizer._include_sensitive_data')
    @mock.patch('crmsh.report.utils.Sanitizer._extract_sensitive_value_list')
    @mock.patch('crmsh.report.utils.Sanitizer._parse_sensitive_set')
    @mock.patch('crmsh.report.utils.Sanitizer._load_cib_from_work_dir')
    def test_prepare_return(self, mock_load_cib, mock_parse, mock_extract, mock_include, mock_warning):
        mock_include.return_value = True
        self.s_inst_no_sanitize.prepare()
        mock_load_cib.assert_called_once_with()
        mock_parse.assert_called_once_with()
        mock_warning.assert_has_calls([
            mock.call("Some PE/CIB/log files contain possibly sensitive data"),
            mock.call("Using \"-s\" option can replace sensitive data")
            ])

    @mock.patch('crmsh.report.utils.Sanitizer._get_file_list_in_work_dir')
    @mock.patch('crmsh.report.utils.Sanitizer._include_sensitive_data')
    @mock.patch('crmsh.report.utils.Sanitizer._extract_sensitive_value_list')
    @mock.patch('crmsh.report.utils.Sanitizer._parse_sensitive_set')
    @mock.patch('crmsh.report.utils.Sanitizer._load_cib_from_work_dir')
    def test_prepare(self, mock_load_cib, mock_parse, mock_extract, mock_include, mock_get_file):
        mock_include.return_value = True
        self.s_inst.prepare()
        mock_load_cib.assert_called_once_with()
        mock_parse.assert_called_once_with()
        mock_get_file.assert_called_once_with

    @mock.patch('crmsh.report.utils.Sanitizer._include_sensitive_data')
    @mock.patch('crmsh.report.utils.Sanitizer._extract_sensitive_value_list')
    @mock.patch('crmsh.report.utils.Sanitizer._parse_sensitive_set')
    @mock.patch('crmsh.report.utils.Sanitizer._load_cib_from_work_dir')
    def test_prepare_no_sensitive_data(self, mock_load_cib, mock_parse, mock_extract, mock_include):
        mock_include.return_value = False
        self.s_inst.prepare()
        mock_load_cib.assert_called_once_with()
        mock_parse.assert_called_once_with()

    def test_include_sensitive_data(self):
        res = self.s_inst._include_sensitive_data()
        self.assertEqual(res, [])

    @mock.patch('os.walk')
    def test_get_file_list_in_work_dir(self, mock_walk):
        mock_walk.return_value = [
            ("/opt", [], ["file1", "file2"]),
            ("/opt/dir1", [], ["file3"]),
        ]
        self.s_inst._get_file_list_in_work_dir()
        self.assertEqual(self.s_inst.file_list_in_workdir, ['/opt/file1', '/opt/file2', '/opt/dir1/file3'])

    @mock.patch('glob.glob')
    def test_load_cib_from_work_dir_no_cib(self, mock_glob):
        mock_glob.return_value = []
        res = self.s_inst._load_cib_from_work_dir()
        self.assertIsNone(res)

    @mock.patch('glob.glob')
    @mock.patch('crmsh.utils.read_from_file')
    def test_load_cib_from_work_dir(self, mock_read, mock_glob):
        mock_glob.return_value = [f"/opt/node1/{constants.CIB_F}"]
        mock_read.return_value = "data"
        res = self.s_inst._load_cib_from_work_dir()
        self.assertEqual(res, "data")
        mock_read.assert_called_once_with(f"/opt/node1/{constants.CIB_F}")

    @mock.patch('crmsh.report.utils.logger', spec=crmsh.log.DEBUG2Logger)
    def test_parse_sensitive_set_no_set(self, mock_logger):
        config.report.sanitize_rule = ""
        self.s_inst_no_sanitize_set._parse_sensitive_set()
        self.assertEqual(self.s_inst_no_sanitize_set.sensitive_regex_set, set(utils.Sanitizer.DEFAULT_RULE_LIST))
        mock_logger.debug2.assert_called_once_with(f"Regex set to match sensitive data: {set(utils.Sanitizer.DEFAULT_RULE_LIST)}")

    @mock.patch('crmsh.report.utils.logger', spec=crmsh.log.DEBUG2Logger)
    def test_parse_sensitive_set(self, mock_logger):
        config.report.sanitize_rule = "passw.*"
        self.s_inst._parse_sensitive_set()
        self.assertEqual(self.s_inst.sensitive_regex_set, set(['test_patt', 'passw.*']))
        mock_logger.debug2.assert_called_once_with(f"Regex set to match sensitive data: {set(['test_patt', 'passw.*'])}")

    def test_sanitize_return(self):
        self.s_inst_no_sanitize.sanitize()

    @mock.patch('crmsh.report.utils.write_to_file')
    @mock.patch('logging.Logger.debug')
    @mock.patch('crmsh.report.utils.Sanitizer._sub_sensitive_string')
    @mock.patch('crmsh.utils.read_from_file')
    def test_sanitize(self, mock_read, mock_sub, mock_debug, mock_write):
        self.s_inst.file_list_in_workdir = ["file1", "file2"]
        mock_read.side_effect = [None, "data"]
        mock_sub.return_value = "replace_data"
        self.s_inst.sanitize()
        mock_debug.assert_called_once_with("Replace sensitive info for %s", "file2")

    def test_extract_from_cib(self):
        self.s_inst.cib_data = """
		<utilization id="nodes-1-utilization">
          <nvpair id="nodes-1-utilization-password" name="password" value="qwertyui"/>
        </utilization>
        """
        res = self.s_inst._extract_from_cib("passw.*")
        self.assertEqual(res, ["qwertyui"])

    def test_sub_sensitive_string(self):
        data = """
		<utilization id="nodes-1-utilization">
          <nvpair id="nodes-1-utilization-TEL" name="TEL" value="13356789876"/>
          <nvpair id="nodes-1-utilization-password" name="password" value="qwertyui"/>
        </utilization>
        This my tel 13356789876
        """
        self.s_inst.sensitive_value_list_with_raw_option = ["13356789876"]
        self.s_inst.sensitive_key_list = ["passw.*"]
        self.s_inst.sensitive_value_list = ["qwertyui"]
        res = self.s_inst._sub_sensitive_string(data)
        expected_data = """
		<utilization id="nodes-1-utilization">
          <nvpair id="nodes-1-utilization-TEL" name="TEL" value="******"/>
          <nvpair id="nodes-1-utilization-password" name="password" value="******"/>
        </utilization>
        This my tel ******
        """
        self.assertEqual(res, expected_data)

    @mock.patch('logging.Logger.warning')
    def test_extract_sensitive_value_list_warn(self, mock_warn):
        self.s_inst.sensitive_regex_set = set(["TEL:test"])
        self.s_inst._extract_sensitive_value_list()
        mock_warn.assert_called_once_with("For sanitize pattern TEL:test, option should be \"raw\"")

    @mock.patch('crmsh.report.utils.Sanitizer._extract_from_cib')
    def test_extract_sensitive_value_list(self, mock_extract):
        mock_extract.side_effect = [["123456"], ["qwertyui"]]
        self.s_inst.sensitive_regex_set = set(["TEL:raw", "passw.*"])
        self.s_inst._extract_sensitive_value_list()

class TestUtils(unittest.TestCase):

    @mock.patch('os.path.getmtime')
    @mock.patch('crmsh.report.utils.get_timespan_str')
    @mock.patch('crmsh.report.utils.logger', spec=crmsh.log.DEBUG2Logger)
    @mock.patch('glob.glob')
    @mock.patch('crmsh.report.utils.is_our_log')
    def test_arch_logs(self, mock_is_our_log, mock_glob, mock_logger, mock_timespan, mock_getmtime):
        mock_is_our_log.return_value = utils.LogType.GOOD
        mock_glob.return_value = []
        mock_ctx_inst = mock.Mock(from_time=1691938980.0, to_time=1691982180.0)
        mock_timespan.return_value = "0101-0202"
        mock_getmtime.side_effect = [1691938980.0, 1691938980.0]

        return_list, log_type = utils.arch_logs(mock_ctx_inst, "file1")

        self.assertEqual(return_list, ["file1"])
        self.assertEqual(log_type, utils.LogType.GOOD)
        mock_logger.debug2.assert_has_calls([
            mock.call('File %s is %s', 'file1', 'in timespan'),
            mock.call('Found %s logs: %s', 'in timespan', 'file1')
        ])

    @mock.patch('sys.stdout.flush')
    @mock.patch('traceback.print_exc')
    def test_print_traceback(self, mock_trace, mock_flush):
        utils.print_traceback()
        mock_trace.assert_called_once_with()

    @mock.patch('crmsh.report.utils.ts_to_str')
    def test_get_timespan_str(self, mock_ts_to_str):
        mock_ctx_inst = mock.Mock(from_time=1691938980.0, to_time=1691982180.0)
        mock_ts_to_str.side_effect = ["2023-08-13 23:03", "2023-08-14 11:03"]
        res = utils.get_timespan_str(mock_ctx_inst)
        self.assertEqual(res, "2023-08-13 23:03 - 2023-08-14 11:03")
        mock_ts_to_str.assert_has_calls([
            mock.call(mock_ctx_inst.from_time),
            mock.call(mock_ctx_inst.to_time)
            ])

    @mock.patch('crmsh.report.utils.ShellUtils')
    def test_get_cmd_output(self, mock_run):
        mock_run_inst = mock.Mock()
        mock_run.return_value = mock_run_inst
        mock_run_inst.get_stdout_stderr.return_value = (0, "line 1\nerror: foo\nline 2", None)
        res = utils.get_cmd_output("cmd")
        self.assertEqual(res, "line 1\nerror: foo\nline 2\n")
        mock_run_inst.get_stdout_stderr.assert_called_once_with("cmd", timeout=None, mix_stderr=True)

    @mock.patch('crmsh.utils.read_from_file')
    def test_is_our_log_empty(self, mock_read):
        mock_read.return_value = None
        mock_ctx_inst = mock.Mock()
        res = utils.is_our_log(mock_ctx_inst, "/opt/logfile")
        self.assertEqual(res, utils.LogType.EMPTY)
        mock_read.assert_called_once_with("/opt/logfile")

    @mock.patch('crmsh.report.utils.determin_log_format')
    @mock.patch('crmsh.utils.read_from_file')
    def test_is_our_log_irregular(self, mock_read, mock_log_format):
        mock_read.return_value = "This is the log"
        mock_ctx_inst = mock.Mock()
        mock_log_format.return_value = None
        res = utils.is_our_log(mock_ctx_inst, "/opt/logfile")
        self.assertEqual(res, utils.LogType.IRREGULAR)
        mock_read.assert_called_once_with("/opt/logfile")
        mock_log_format.assert_called_once_with(mock_read.return_value)

    @mock.patch('crmsh.report.utils.find_first_timestamp')
    @mock.patch('crmsh.report.utils.head')
    @mock.patch('crmsh.report.utils.determin_log_format')
    @mock.patch('crmsh.utils.read_from_file')
    def test_is_our_log_before(self, mock_read, mock_determine, mock_head, mock_find_first):
        mock_read.return_value = "data"
        mock_determine.return_value = "rfc5424"
        mock_find_first.side_effect = [1000, 1500]
        mock_ctx_inst = mock.Mock(from_time=1600, to_time=1800)
        res = utils.is_our_log(mock_ctx_inst, "/var/log/pacemaker.log")
        self.assertEqual(res, utils.LogType.BEFORE_TIMESPAN)

    @mock.patch('crmsh.report.utils.find_first_timestamp')
    @mock.patch('crmsh.report.utils.head')
    @mock.patch('crmsh.report.utils.determin_log_format')
    @mock.patch('crmsh.utils.read_from_file')
    def test_is_our_log_good(self, mock_read, mock_determine, mock_head, mock_find_first):
        mock_read.return_value = "data"
        mock_determine.return_value = "rfc5424"
        mock_find_first.side_effect = [1000, 1500]
        mock_ctx_inst = mock.Mock(from_time=1200, to_time=1800)
        res = utils.is_our_log(mock_ctx_inst, "/var/log/pacemaker.log")
        self.assertEqual(res, utils.LogType.GOOD)

    @mock.patch('crmsh.report.utils.find_first_timestamp')
    @mock.patch('crmsh.report.utils.head')
    @mock.patch('crmsh.report.utils.determin_log_format')
    @mock.patch('crmsh.utils.read_from_file')
    def test_is_our_log_after(self, mock_read, mock_determine, mock_head, mock_find_first):
        mock_read.return_value = "data"
        mock_determine.return_value = "rfc5424"
        mock_find_first.side_effect = [1000, 1500]
        mock_ctx_inst = mock.Mock(from_time=200, to_time=800)
        res = utils.is_our_log(mock_ctx_inst, "/var/log/pacemaker.log")
        self.assertEqual(res, utils.LogType.AFTER_TIMESPAN)

    @mock.patch('logging.Logger.warning')
    @mock.patch('shutil.which')
    def test_get_pkg_mgr_unknown(self, mock_which, mock_warning):
        mock_which.side_effect = [False, False]
        self.assertEqual(utils.get_pkg_mgr(), "")
        mock_warning.assert_called_once_with("Unknown package manager!")

    @mock.patch('shutil.which')
    def test_get_pkg_mgr(self, mock_which):
        mock_which.return_value = True
        utils.get_pkg_mgr()
        self.assertEqual(utils.get_pkg_mgr(), "rpm")

    @mock.patch('os.walk')
    @mock.patch('os.stat')
    @mock.patch('os.path.isdir')
    def test_find_files_in_timespan(self, mock_isdir, mock_stat, mock_walk):
        mock_isdir.side_effect = [True, False]
        mock_stat.return_value = mock.Mock(st_ctime=1615)
        mock_walk.return_value = [
            ('/mock_dir', [], ['file1.txt', 'file2.txt'])
        ]
        mock_ctx_inst = mock.Mock(from_time=1611, to_time=1620)

        res = utils.find_files_in_timespan(mock_ctx_inst, ['/mock_dir', '/not_exist'])

        expected_result = ['/mock_dir/file1.txt', '/mock_dir/file2.txt']
        self.assertEqual(res, expected_result)

    @mock.patch('crmsh.report.utils.get_timespan_str')
    @mock.patch('crmsh.report.utils.logger', spec=crmsh.log.DEBUG2Logger)
    @mock.patch('crmsh.report.utils.arch_logs')
    def test_dump_logset_return(self, mock_arch, mock_debug, mock_timespan):
        mock_arch.return_value = [[], ""]
        mock_ctx_inst = mock.Mock()
        utils.dump_logset(mock_ctx_inst, "file")

    @mock.patch('crmsh.report.utils.real_path')
    @mock.patch('logging.Logger.debug')
    @mock.patch('crmsh.utils.str2file')
    @mock.patch('os.path.basename')
    @mock.patch('crmsh.report.utils.print_logseg')
    @mock.patch('crmsh.report.utils.arch_logs')
    def test_dump_logset_irrgular(self, mock_arch, mock_print, mock_basename, mock_str2file, mock_debug, mock_real_path):
        mock_real_path.return_value = "file1"
        mock_arch.return_value = [["file1"], utils.LogType.IRREGULAR]
        mock_ctx_inst = mock.Mock(work_dir="/opt/work_dir")
        mock_basename.return_value = "file1"
        mock_print.return_value = "data"
        utils.dump_logset(mock_ctx_inst, "file1")
        mock_print.assert_called_once_with("file1", 0, 0)
        mock_str2file.assert_called_once_with("data", "/opt/work_dir/file1")
        mock_debug.assert_called_once_with("Dump file1 into file1")

    @mock.patch('crmsh.report.utils.real_path')
    @mock.patch('logging.Logger.debug')
    @mock.patch('crmsh.utils.str2file')
    @mock.patch('os.path.basename')
    @mock.patch('crmsh.report.utils.print_logseg')
    @mock.patch('crmsh.report.utils.arch_logs')
    def test_dump_logset_one(self, mock_arch, mock_print, mock_basename, mock_str2file, mock_debug, mock_real_path):
        mock_real_path.return_value = "file1"
        mock_arch.return_value = [["file1"], utils.LogType.GOOD]
        mock_ctx_inst = mock.Mock(work_dir="/opt/work_dir", from_time=10, to_time=20)
        mock_basename.return_value = "file1"
        mock_print.return_value = "data"

        utils.dump_logset(mock_ctx_inst, "file1")

        mock_print.assert_called_once_with("file1", 10, 20)
        mock_str2file.assert_called_once_with("data", "/opt/work_dir/file1")
        mock_debug.assert_called_once_with("Dump file1 into file1")

    @mock.patch('crmsh.report.utils.real_path')
    @mock.patch('logging.Logger.debug')
    @mock.patch('crmsh.utils.str2file')
    @mock.patch('os.path.basename')
    @mock.patch('crmsh.report.utils.print_logseg')
    @mock.patch('crmsh.report.utils.arch_logs')
    def test_dump_logset(self, mock_arch, mock_print, mock_basename, mock_str2file, mock_debug, mock_real_path):
        mock_real_path.return_value = "file1"
        mock_arch.return_value = [["file1", "file2", "file3"], utils.LogType.GOOD]
        mock_ctx_inst = mock.Mock(work_dir="/opt/work_dir", from_time=10, to_time=20)
        mock_basename.return_value = "file1"
        mock_print.side_effect = ["data1\n", "data2\n", "data3\n"]

        utils.dump_logset(mock_ctx_inst, "file1")

        mock_print.assert_has_calls([
            mock.call("file3", 10, 0),
            mock.call("file2", 0, 0),
            mock.call("file1", 0, 20),
        ])
        mock_str2file.assert_called_once_with("data1\ndata2\ndata3", "/opt/work_dir/file1")
        mock_debug.assert_called_once_with("Dump file1 into file1")

    @mock.patch('crmsh.utils.read_from_file')
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.report.utils.logger', spec=crmsh.log.DEBUG2Logger)
    def test_get_distro_info(self, mock_debug2, mock_exists, mock_read):
        mock_exists.return_value = True
        mock_read.return_value = """
VERSION_ID="20230629"
PRETTY_NAME="openSUSE Tumbleweed"
ANSI_COLOR="0;32"
        """
        res = utils.get_distro_info()
        self.assertEqual(res, "openSUSE Tumbleweed")

    @mock.patch('shutil.which')
    @mock.patch('crmsh.report.utils.sh.LocalShell')
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.report.utils.logger', spec=crmsh.log.DEBUG2Logger)
    def test_get_distro_info_lsb(self, mock_debug2, mock_exists, mock_sh, mock_which):
        mock_which.return_value = True
        mock_exists.return_value = False
        mock_sh_inst = mock.Mock()
        mock_sh.return_value = mock_sh_inst
        mock_sh_inst.get_stdout_or_raise_error.return_value = "data"
        res = utils.get_distro_info()
        self.assertEqual(res, "Unknown")

    @mock.patch('crmsh.report.utils.get_timestamp')
    def test_find_first_timestamp_none(self, mock_get_timestamp):
        mock_get_timestamp.side_effect = [None, None]
        data = ["line1", "line2"]
        self.assertIsNone(utils.find_first_timestamp(data, "file1"))
        mock_get_timestamp.assert_has_calls([
            mock.call("line1", "file1"),
            mock.call("line2", "file1")
        ])

    @mock.patch('crmsh.report.utils.get_timestamp')
    def test_find_first_timestamp(self, mock_get_timestamp):
        mock_get_timestamp.return_value = 123456
        data = ["line1", "line2"]
        res = utils.find_first_timestamp(data, "file1")
        self.assertEqual(res, 123456)
        mock_get_timestamp.assert_called_once_with("line1", "file1")

    def test_filter_lines(self):
        data = """line1
line2
line3
line4
line5
        """
        res = utils.filter_lines(data, 2, 4)
        self.assertEqual(res, 'line2\nline3\nline4\n')

    @mock.patch('crmsh.utils.parse_time')
    @mock.patch('crmsh.report.utils.head')
    def test_determin_log_format_none(self, mock_head, mock_parse):
        mock_head.return_value = ["line1", "line2"]
        mock_parse.side_effect = [None, None]
        data = """line1
line2
        """
        self.assertIsNone(utils.determin_log_format(data))

    def test_determin_log_format_rfc5424(self):
        data = """
2003-10-11T22:14:15.003Z mymachine.example.com su
        """
        res = utils.determin_log_format(data)
        self.assertEqual(res, "rfc5424")

    def test_determin_log_format_syslog(self):
        data = """
Feb 12 18:30:08 15sp1-1 kernel:
        """
        res = utils.determin_log_format(data)
        self.assertEqual(res, "syslog")

    @mock.patch('crmsh.utils.parse_time')
    @mock.patch('crmsh.report.utils.head')
    def test_determin_log_format_legacy(self, mock_head, mock_parse):
        mock_head.return_value = ["Legacy 2003-10-11T22:14:15.003Z log"]
        mock_parse.side_effect = [None, None, 123456]
        data = """
Legacy 003-10-11T22:14:15.003Z log data log
        """
        res = utils.determin_log_format(data)
        self.assertEqual(res, "legacy")
        mock_parse.assert_has_calls([
            mock.call("Legacy 2003-10-11T22:14:15.003Z log", quiet=True),
            mock.call("Legacy", quiet=True),
            mock.call("2003-10-11T22:14:15.003Z", quiet=True)
        ])

    def test_get_timestamp_none(self):
        self.assertIsNone(utils.get_timestamp("", "file1"))

    @mock.patch('crmsh.report.utils.get_timestamp_from_time_line')
    def test_get_timespan_rfc5424(self, mock_get_timestamp):
        constants.STAMP_TYPE = "rfc5424"
        mock_get_timestamp.return_value = 12345
        res = utils.get_timestamp("2003-10-11T22:14:15.003Z mymachine.example.com su", "file1")
        self.assertEqual(res, mock_get_timestamp.return_value)
        mock_get_timestamp.assert_called_once_with("2003-10-11T22:14:15.003Z", "rfc5424", "file1")

    @mock.patch('crmsh.report.utils.get_timestamp_from_time_line')
    def test_get_timespan_syslog(self, mock_get_timestamp):
        constants.STAMP_TYPE = "syslog"
        mock_get_timestamp.return_value = 12345
        res = utils.get_timestamp("Feb 12 18:30:08 15sp1-1 kernel:", "file1")
        self.assertEqual(res, mock_get_timestamp.return_value)
        mock_get_timestamp.assert_called_once_with("Feb 12 18:30:08", "syslog", "file1")

    @mock.patch('crmsh.report.utils.get_timestamp_from_time_line')
    def test_get_timespan_legacy(self, mock_get_timestamp):
        constants.STAMP_TYPE = "legacy"
        mock_get_timestamp.return_value = 12345
        res = utils.get_timestamp("legacy 2003-10-11T22:14:15.003Z log data", "file1")
        self.assertEqual(res, mock_get_timestamp.return_value)
        mock_get_timestamp.assert_called_once_with("2003-10-11T22:14:15.003Z", "legacy", "file1")

    @mock.patch('crmsh.report.utils.diff_check')
    def test_do_compare(self, mock_diff):
        mock_ctx_inst = mock.Mock(work_dir="/opt/workdir", node_list=["node1", "node2"])
        mock_diff.side_effect = [[0, ""], [0, ""]]
        rc, out = utils.do_compare(mock_ctx_inst, "file1")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")
        mock_diff.assert_called_once_with("/opt/workdir/node1/file1", "/opt/workdir/node2/file1")

    @mock.patch('os.path.isfile')
    def test_diff_check_return(self, mock_isfile):
        mock_isfile.return_value = False
        rc, out = utils.diff_check("/opt/file1", "/opt/fil2")
        self.assertEqual(rc, 1)
        self.assertEqual(out, "/opt/file1 does not exist\n")

    @mock.patch('crmsh.report.utils.cib_diff')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.isfile')
    def test_diff_check(self, mock_isfile, mock_basename, mock_cib_diff):
        mock_isfile.side_effect = [True, True]
        mock_basename.return_value = "cib.xml"
        mock_cib_diff.return_value = (0, "")
        rc, out = utils.diff_check("/opt/node1/cib.xml", "/opt/node2/cib.xml")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    @mock.patch('crmsh.report.utils.ShellUtils')
    def test_txt_diff(self, mock_run):
        mock_run_inst = mock.Mock()
        mock_run.return_value = mock_run_inst
        mock_run_inst.get_stdout_stderr.return_value = (0, "", None)
        rc, out = utils.txt_diff("txt1", "txt2")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    @mock.patch('os.path.isfile')
    def test_cib_diff_not_running(self, mock_isfile):
        mock_isfile.side_effect = [True, False, False, True]
        rc, out = utils.cib_diff("/opt/node1/cib.xml", "/opt/node2/cib.xml")
        self.assertEqual(rc, 1)
        self.assertEqual(out, "Can't compare cibs from running and stopped systems\n")

    @mock.patch('crmsh.report.utils.ShellUtils')
    @mock.patch('os.path.isfile')
    def test_cib_diff(self, mock_isfile, mock_run):
        mock_run_inst = mock.Mock()
        mock_run.return_value = mock_run_inst
        mock_isfile.side_effect = [True, True]
        mock_run_inst.get_stdout_stderr.return_value = (0, "", None)
        rc, out = utils.cib_diff("/opt/node1/cib.xml", "/opt/node2/cib.xml")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")
        mock_run_inst.get_stdout_stderr.assert_called_once_with("crm_diff -c -n /opt/node1/cib.xml -o /opt/node2/cib.xml")

    @mock.patch('os.symlink')
    @mock.patch('shutil.move')
    @mock.patch('os.remove')
    @mock.patch('os.path.isfile')
    def test_consolidate(self, mock_isfile, mock_remove, mock_move, mock_symlink):
        mock_isfile.side_effect = [True, False]
        mock_ctx_inst = mock.Mock(node_list=["node1", "node2"], work_dir="/opt/workdir")
        utils.consolidate(mock_ctx_inst, "target_file")
        mock_isfile.assert_has_calls([
            mock.call("/opt/workdir/target_file"),
            mock.call("/opt/workdir/target_file")
        ])
        mock_symlink.assert_has_calls([
            mock.call('../target_file', '/opt/workdir/node1/target_file'),
            mock.call('../target_file', '/opt/workdir/node2/target_file')
        ])

    @mock.patch('crmsh.report.utils.Sanitizer')
    def test_do_sanitize(self, mock_sanitizer):
        mock_inst = mock.Mock()
        mock_sanitizer.return_value = mock_inst
        mock_ctx_inst = mock.Mock()
        utils.do_sanitize(mock_ctx_inst)
        mock_inst.prepare.assert_called_once_with()
        mock_inst.sanitize.assert_called_once_with()

    @mock.patch('crmsh.utils.read_from_file')
    def test_print_logseg_empty(self, mock_read):
        mock_read.return_value = ""
        res = utils.print_logseg("log1", 1234, 0)
        self.assertEqual(res, "")

    @mock.patch('crmsh.report.utils.findln_by_timestamp')
    @mock.patch('crmsh.utils.read_from_file')
    def test_print_logseg_none(self, mock_read, mock_findln):
        mock_read.return_value = "data"
        mock_findln.return_value = None
        res = utils.print_logseg("log1", 1234, 0)
        self.assertEqual(res, "")

    @mock.patch('crmsh.report.utils.filter_lines')
    @mock.patch('crmsh.report.utils.logger', spec=crmsh.log.DEBUG2Logger)
    @mock.patch('crmsh.report.utils.findln_by_timestamp')
    @mock.patch('crmsh.utils.read_from_file')
    def test_print_logseg(self, mock_read, mock_findln, mock_logger, mock_filter):
        mock_read.return_value = "line1\nline2\nline3"
        mock_filter.return_value = "line1\nline2\nline3"
        res = utils.print_logseg("log1", 0, 0)
        self.assertEqual(res, mock_filter.return_value)
        mock_logger.debug2.assert_called_once_with("Including segment [%d-%d] from %s", 1, 3, "log1")

    def test_head(self):
        data = "line1\nline2\nline3"
        res = utils.head(2, data)
        self.assertEqual(res, ["line1", "line2"])

    def test_tail(self):
        data = "line1\nline2\nline3"
        res = utils.tail(2, data)
        self.assertEqual(res, ["line2", "line3"])

    @mock.patch('crmsh.utils.get_open_method')
    @mock.patch('builtins.open', create=True)
    def test_write_to_file(self, mock_open, mock_method):
        mock_method.return_value = mock_open
        file_handle = mock_open.return_value.__enter__.return_value
        utils.write_to_file('Hello', 'file.txt')
        mock_open.assert_called_once_with('file.txt', 'w')
        file_handle.write.assert_called_once_with('Hello')

    @mock.patch('gzip.open')
    @mock.patch('crmsh.utils.get_open_method')
    def test_write_to_file_encode(self, mock_method, mock_open):
        mock_method.return_value = mock_open
        file_handle = mock_open.return_value.__enter__.return_value
        utils.write_to_file('Hello', 'file.txt')
        mock_open.assert_called_once_with('file.txt', 'w')
        file_handle.write.assert_called_once_with(b'Hello')

    @mock.patch('crmsh.report.utils.dt_to_str')
    @mock.patch('crmsh.report.utils.ts_to_dt')
    def test_ts_to_str(self, mock_ts_to_dt, mock_dt_to_str):
        mock_ts_to_dt.return_value = datetime.datetime(2020, 2, 19, 21, 44, 7, 977355)
        mock_dt_to_str.return_value = "2020-02-19 21:44"
        res = utils.ts_to_str(1693519260.0)
        self.assertEqual(res, mock_dt_to_str.return_value)

    def test_ts_to_dt(self):
        res = utils.ts_to_dt(crmutils.parse_to_timestamp("2023-09-01 06:01"))
        self.assertEqual(utils.dt_to_str(res), "2023-09-01 06:01:00")

    def test_now(self):
        expected_res = datetime.datetime.now().strftime(constants.TIME_FORMAT)
        res = utils.now()
        self.assertEqual(res, expected_res)

    @mock.patch('crmsh.utils.str2file')
    @mock.patch('crmsh.utils.read_from_file')
    @mock.patch('os.path.isfile')
    @mock.patch('crmsh.report.utils.now')
    def test_create_description_template(self, mock_now, mock_isfile, mock_read, mock_str2file):
        mock_now.return_value = "2023-09-01 06:01"
        sys.argv = ["crm", "report", "option1"]
        mock_ctx_inst = mock.Mock(node_list=["node1"], work_dir="/opt/workdir")
        mock_isfile.return_value = True
        mock_read.return_value = "data"
        utils.create_description_template(mock_ctx_inst)

    @mock.patch('crmsh.utils.str2file')
    @mock.patch('crmsh.report.utils.extract_critical_log')
    @mock.patch('crmsh.report.utils.check_collected_files')
    @mock.patch('crmsh.report.utils.compare_and_consolidate_files')
    @mock.patch('glob.glob')
    def test_analyze(self, mock_glob, mock_compare, mock_check_collected, mock_extract, mock_str2file):
        mock_compare.return_value = "data"
        mock_check_collected.return_value = ""
        mock_extract.return_value = ""
        mock_ctx_inst = mock.Mock(work_dir="/opt/work_dir")
        utils.analyze(mock_ctx_inst)
        mock_str2file.assert_called_once_with("data", f"/opt/work_dir/{constants.ANALYSIS_F}")

    @mock.patch('crmsh.report.utils.consolidate')
    @mock.patch('crmsh.report.utils.do_compare')
    @mock.patch('glob.glob')
    def test_compare_and_consolidate_files(self, mock_glob, mock_compare, mock_consolidate):
        mock_ctx_inst = mock.Mock(work_dir="/opt/work_dir")
        mock_glob.side_effect = [False, True, True, True, True]
        mock_compare.side_effect = [(0, ""), (0, ""), (0, ""), (0, "")]
        res = utils.compare_and_consolidate_files(mock_ctx_inst)
        self.assertEqual(f"Diff {constants.MEMBERSHIP_F}... no {constants.MEMBERSHIP_F} found in /opt/work_dir\nDiff {constants.CRM_MON_F}... OK\nDiff {constants.COROSYNC_F}... OK\nDiff {constants.SYSINFO_F}... OK\nDiff {constants.CIB_F}... OK\n\n", res)

    @mock.patch('crmsh.utils.read_from_file')
    @mock.patch('crmsh.utils.file_is_empty')
    @mock.patch('os.path.isfile')
    def test_check_collected_files(self, mock_isfile, mock_is_empty, mock_read):
        mock_ctx_inst = mock.Mock(node_list=["node1"], work_dir="/opt/work_dir")
        mock_isfile.side_effect = [False, False, True]
        mock_is_empty.return_value = False
        mock_read.return_value = "data"
        res = utils.check_collected_files(mock_ctx_inst)
        self.assertEqual(res, ["Checking problems with permissions/ownership at node1:", "data"])

    @mock.patch('logging.Logger.error')
    @mock.patch('crmsh.utils.parse_to_timestamp')
    def test_parse_to_timestamp_none(self, mock_parse, mock_error):
        mock_parse.return_value = None
        with self.assertRaises(utils.ReportGenericError) as err:
            utils.parse_to_timestamp("xxxxx")
        mock_error.assert_has_calls([
            mock.call(f"Invalid time string 'xxxxx'"),
            mock.call('Try these formats like: 2pm; "2019/9/5 12:30"; "09-Sep-07 2:00"; "[1-9][0-9]*[YmdHM]"')
        ])

    @mock.patch('logging.Logger.error')
    @mock.patch('crmsh.utils.parse_to_timestamp')
    def test_parse_to_timestamp(self, mock_parse, mock_error):
        mock_parse.return_value = 1234567
        res = utils.parse_to_timestamp("2023")
        self.assertEqual(res, mock_parse.return_value)

    def test_parse_to_timestamp_delta(self):
        timedelta = datetime.timedelta(days=10)
        expected_timestamp = (datetime.datetime.now() - timedelta).timestamp()
        res = utils.parse_to_timestamp("10d")
        self.assertEqual(int(res), int(expected_timestamp))

    @mock.patch('crmsh.sh.ShellUtils')
    @mock.patch('glob.glob')
    def test_extract_critical_log(self, mock_glob, mock_run):
        mock_glob.return_value = ["/opt/workdir/pacemaker.log"]
        mock_run_inst = mock.Mock()
        mock_run.return_value = mock_run_inst
        data = """pacemaker-controld[5678]:  warning: data
pacemaker-schedulerd[5677]:  error: Resource"""
        mock_run_inst.get_stdout_stderr.return_value = (0, data, None)
        mock_ctx_inst = mock.Mock(work_dir="/opt/workdir")
        res = utils.extract_critical_log(mock_ctx_inst)
        expected_data = """
WARNINGS or ERRORS in pacemaker.log:
pacemaker-controld[5678]:  warning: data
pacemaker-schedulerd[5677]:  error: Resource"""
        self.assertEqual('\n'.join(res), expected_data)

    def test_findln_by_timestamp_1(self):
        pacemaker_file_path = "pacemaker.log.2"
        with open(pacemaker_file_path) as f:
            data = f.read()
        data_list = data.split('\n')
        constants.STAMP_TYPE = utils.determin_log_format(data)
        first_timestamp = utils.get_timestamp(data_list[0], pacemaker_file_path)
        middle_timestamp = utils.get_timestamp(data_list[1], pacemaker_file_path)
        last_timestamp = utils.get_timestamp(data_list[2], pacemaker_file_path)
        assert first_timestamp < middle_timestamp < last_timestamp

    def test_findln_by_timestamp_irregular(self):
        data = """line1
        line2
        line3
        line4"""
        target_time = "Apr 03 13:10"
        target_time_stamp = crmutils.parse_to_timestamp(target_time)
        result_line = utils.findln_by_timestamp(data, target_time_stamp, "file1")
        self.assertIsNone(result_line)

    def test_findln_by_timestamp(self):
        data = """2024-04-03T11:01:00Z example-host app-name 1234 ID123 - - This is a log message before the target timestamp (11:01:19).
2024-04-03T11:01:19Z example-host app-name 1234 ID123 - - This is the log message exactly at the target timestamp (11:01:19).
2024-04-03T11:01:40Z example-host app-name 1234 ID123 - - This is a log message after the target timestamp (11:01:19).
2024-04-03T13:09:50Z example-host app-name 1234 ID123 - - This is a log message before the target timestamp (13:10).
2024-04-03T13:10:00Z example-host app-name 1234 ID123 - - This is the log message exactly at the target timestamp (13:10).
2024-04-03T13:10:30Z example-host app-name 1234 ID123 - - This is a log message after the target timestamp (13:10)."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_file_path = f.name
            f.write(data.encode())
        try:
            target_time = "2024-04-03T13:00:20Z"
            target_time_stamp = crmutils.parse_to_timestamp(target_time)
            constants.STAMP_TYPE = utils.determin_log_format(data)
            result_line = utils.findln_by_timestamp(data, target_time_stamp, temp_file_path)
            assert result_line == 4

            line_data = data.split('\n')[result_line-1].split()[0]
            result_line_stamp = crmutils.parse_to_timestamp(line_data)
            assert result_line_stamp > target_time_stamp

            pre_line_data = data.split('\n')[result_line-2].split()[0]
            result_pre_line_stamp = crmutils.parse_to_timestamp(pre_line_data)
            assert result_pre_line_stamp < target_time_stamp

            target_time = "2024-04-03T11:01:19Z"
            target_time_stamp = crmutils.parse_to_timestamp(target_time)
            result_line = utils.findln_by_timestamp(data, target_time_stamp, temp_file_path)
            line_data = data.split('\n')[result_line-1].split()[0]
            self.assertEqual(line_data, target_time)
        finally:
            os.remove(temp_file_path)

    @mock.patch('crmsh.utils.parse_to_timestamp')
    def test_get_timestamp_from_time_line_not_syslog(self, mock_parse):
        mock_parse.return_value = 123456
        res = utils.get_timestamp_from_time_line("line1", "rfc5424", "file1")
        self.assertEqual(res, mock_parse.return_value)

    @mock.patch('os.path.getmtime')
    @mock.patch('crmsh.report.utils.datetime')
    @mock.patch('crmsh.utils.parse_to_timestamp')
    def test_get_timestamp_from_time_line_next_year(self, mock_parse, mock_datetime, mock_getmtime):
        mock_parse.return_value = 8888888888888
        mock_getmtime.return_value = 1691938980.0
        mock_datetime.datetime.now.return_value = datetime.datetime(2023, 9, 1, 6, 1)
        mock_datetime.datetime.fromtimestamp.return_value = datetime.datetime(2024, 9, 1, 6, 1)
        res = utils.get_timestamp_from_time_line("line1", "syslog", "file1")
        self.assertIsNone(res)

    @mock.patch('os.path.getmtime')
    @mock.patch('crmsh.report.utils.datetime')
    @mock.patch('crmsh.utils.parse_to_timestamp')
    def test_get_timestamp_from_time_line_that_year(self, mock_parse, mock_datetime, mock_getmtime):
        mock_parse.return_value = 8888888888888
        mock_getmtime.return_value = 1691938980.0
        mock_datetime.datetime.now.return_value = datetime.datetime(2023, 9, 1, 6, 1)
        mock_datetime.datetime.fromtimestamp.return_value = datetime.datetime(2022, 9, 1, 6, 1)
        res = utils.get_timestamp_from_time_line("line1", "syslog", "file1")
        self.assertEqual(res, mock_parse.return_value)
