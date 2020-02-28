import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
import unittest
from hb_report import utils, core
from crmsh import utils as crmutils

try:
    from unittest import mock
except ImportError:
    import mock

class TestPackage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.utils.get_pkg_mgr')
    def setUp(self, mock_pkg_mgr, mock_warn):
        """
        Test setUp.
        """
        mock_pkg_mgr.return_value = "pkg_info"
        self.pkg_inst_err = utils.Package("pkg1 pkg2")

        mock_pkg_mgr.return_value = "rpm"
        self.pkg_inst = utils.Package("pkg1 pkg2")

        mock_pkg_mgr.assert_has_calls([mock.call(), mock.call()])
        mock_warn.assert_called_once_with("The package manager is pkg_info, not support for now")

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    def test_version_empty(self):
        res = self.pkg_inst_err.version()
        assert res == ""

    @mock.patch('hb_report.utils.pkg_ver_rpm')
    def test_version(self, mock_pkg_ver):
        mock_pkg_ver.return_value = "version1"
        res = self.pkg_inst.version()
        assert res == "version1"
        mock_pkg_ver.assert_called_once_with("pkg1 pkg2")

    def test_verify_empty(self):
        res = self.pkg_inst_err.verify()
        assert res == ""

    @mock.patch('hb_report.utils.verify_rpm')
    def test_verify(self, mock_verify):
        mock_verify.return_value = "verify ok"
        res = self.pkg_inst.verify()
        assert res == "verify ok"
        mock_verify.assert_called_once_with("pkg1 pkg2")

class TestUtils(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('hb_report.utils.get_role')
    @mock.patch('hb_report.utils.crmmsg.common_info')
    @mock.patch('hb_report.utils.me')
    def test_log_info(self, mock_me, mock_info, mock_role):
        mock_role.return_value = "Master"
        mock_me.return_value = "host1"

        utils.log_info("This is a test message")

        mock_me.assert_called_once_with()
        mock_role.assert_called_once_with()
        mock_info.assert_called_once_with("host1#Master: This is a test message")

    @mock.patch('hb_report.utils.get_role')
    @mock.patch('hb_report.utils.crmmsg.common_warn')
    @mock.patch('hb_report.utils.me')
    def test_log_warning(self, mock_me, mock_warn, mock_role):
        mock_role.return_value = "Master"
        mock_me.return_value = "host1"

        utils.log_warning("This is a test message")

        mock_me.assert_called_once_with()
        mock_role.assert_called_once_with()
        mock_warn.assert_called_once_with("host1#Master: This is a test message")

    @mock.patch('hb_report.utils.get_role')
    @mock.patch('hb_report.utils.crmmsg.common_err')
    @mock.patch('hb_report.utils.me')
    def test_log_error(self, mock_me, mock_err, mock_role):
        mock_role.return_value = "Master"
        mock_me.return_value = "host1"

        utils.log_error("This is a test message")

        mock_me.assert_called_once_with()
        mock_role.assert_called_once_with()
        mock_err.assert_called_once_with("host1#Master: This is a test message")

    @mock.patch('hb_report.utils.get_role')
    @mock.patch('hb_report.utils.crmmsg.common_err')
    @mock.patch('hb_report.utils.me')
    @mock.patch('sys.exit')
    def test_log_fatal(self, mock_exit, mock_me, mock_error, mock_role):
        mock_role.return_value = "Master"
        mock_me.return_value = "host1"

        utils.log_fatal("This is a test message")

        mock_me.assert_called_once_with()
        mock_role.assert_called_once_with()
        mock_error.assert_called_once_with("host1#Master: This is a test message")
        mock_exit.assert_called_once_with(1)

    @mock.patch('hb_report.utils.core.is_collector')
    def test_get_role_collector(self, mock_is_collector):
        mock_is_collector.return_value = True
        self.assertEqual(utils.get_role(), "Collector")
        mock_is_collector.assert_called_once_with()

    @mock.patch('hb_report.utils.core.is_collector')
    def test_get_role_master(self, mock_is_collector):
        mock_is_collector.return_value = False
        self.assertEqual(utils.get_role(), "Master")
        mock_is_collector.assert_called_once_with()

    @mock.patch('hb_report.utils.crmmsg.common_debug')
    def test_log_debug1_lt_1(self, mock_debug):
        core.ctx = mock.Mock(debug=0)
        utils.log_debug1("test")
        mock_debug.assert_not_called()

    @mock.patch('hb_report.utils.get_role')
    @mock.patch('hb_report.utils.me')
    @mock.patch('hb_report.utils.crmmsg.common_debug')
    def test_log_debug1_ge_1(self, mock_debug, mock_me, mock_role):
        mock_me.return_value = "node1"
        mock_role.return_value = "Master"
        core.ctx = mock.Mock(debug=1)

        utils.log_debug1("test")

        mock_me.assert_called_once_with()
        mock_role.assert_called_once_with()
        mock_debug.assert_called_once_with("node1#Master: test")

    @mock.patch('hb_report.utils.crmmsg.common_debug')
    def test_log_debug2_lt_1(self, mock_debug):
        core.ctx = mock.Mock(debug=1)
        utils.log_debug2("test")
        mock_debug.assert_not_called()

    @mock.patch('hb_report.utils.get_role')
    @mock.patch('hb_report.utils.me')
    @mock.patch('hb_report.utils.crmmsg.common_debug')
    def test_log_debug2_gt_1(self, mock_debug, mock_me, mock_role):
        mock_me.return_value = "node1"
        mock_role.return_value = "Master"
        core.ctx = mock.Mock(debug=2)

        utils.log_debug2("test")

        mock_me.assert_called_once_with()
        mock_role.assert_called_once_with()
        mock_debug.assert_called_once_with("node1#Master: test")

    @mock.patch('os.path.dirname')
    def test_dirname_base(self, mock_dirname):
        mock_dirname.return_value = ''
        result = utils.dirname('.')
        self.assertEqual(result, '.')
        mock_dirname.assert_called_once_with('.')

    @mock.patch('os.path.dirname')
    def test_dirname(self, mock_dirname):
        mock_dirname.return_value = '/usr/local'
        result = utils.dirname('/usr/local/test.bin')
        self.assertEqual(result, '/usr/local')
        mock_dirname.assert_called_once_with('/usr/local/test.bin')

    def test_head(self):
        data1 = "line1\nline2\nline3\nline4\nline5"
        res1 = utils.head(3, data1)
        self.assertEqual(res1, ['line1', 'line2', 'line3'])
        
        data2 = "\nline1\nline2\nline3\nline4\nline5"
        res2 = utils.head(3, data2)
        self.assertEqual(res2, ['', 'line1', 'line2'])

    def test_tail(self):
        data1 = "line1\nline2\nline3\nline4\nline5"
        res1 = utils.tail(2, data1)
        self.assertEqual(list(res1), ['line5', 'line4'])
        
        data2 = "line1\nline2\nline3\nline4\nline5\n"
        res2 = utils.tail(2, data2)
        self.assertEqual(list(res2), ['', 'line5'])

    @mock.patch('hb_report.utils.crmutils.parse_to_timestamp')
    @mock.patch('hb_report.utils.find_stamp_type')
    def test_get_ts_rfc5424(self, mock_find_type, mock_parse):
        core.ctx = mock.Mock()
        delattr(core.ctx, "stamp_type")
        mock_find_type.return_value = "rfc5424"
        mock_parse.return_value = 12345

        line = "2003-10-11T22:14:15.003Z mymachine.example.com"
        res = utils.get_ts(line)
        self.assertEqual(res, mock_parse.return_value)

        mock_find_type.assert_called_once_with(line)
        mock_parse.assert_called_once_with("2003-10-11T22:14:15.003Z", quiet=True)

    @mock.patch('hb_report.utils.crmutils.parse_to_timestamp')
    @mock.patch('hb_report.utils.find_stamp_type')
    def test_get_ts_syslog(self, mock_find_type, mock_parse):
        core.ctx = mock.Mock()
        delattr(core.ctx, "stamp_type")
        mock_find_type.return_value = "syslog"
        mock_parse.return_value = 12345

        line = "Feb 12 18:30:08 15sp1-1 kernel:"
        res = utils.get_ts(line)
        self.assertEqual(res, mock_parse.return_value)

        mock_find_type.assert_called_once_with(line)
        mock_parse.assert_called_once_with("Feb 12 18:30:08", quiet=True)

    @mock.patch('hb_report.utils.is_rfc5424')
    @mock.patch('hb_report.utils.is_syslog')
    def test_find_stamp_type_syslog(self, mock_syslog, mock_5424):
        mock_syslog.return_value = True
        res = utils.find_stamp_type("line")
        self.assertEqual(res, "syslog")
        mock_syslog.assert_called_once_with("line")
        mock_5424.assert_not_called()

    @mock.patch('hb_report.utils.is_rfc5424')
    @mock.patch('hb_report.utils.is_syslog')
    def test_find_stamp_type_rfc5424(self, mock_syslog, mock_5424):
        mock_syslog.return_value = False
        mock_5424.return_value = True
        res = utils.find_stamp_type("line")
        self.assertEqual(res, "rfc5424")
        mock_syslog.assert_called_once_with("line")
        mock_5424.assert_called_once_with("line")

    @mock.patch('hb_report.utils.is_rfc5424')
    @mock.patch('hb_report.utils.is_syslog')
    def test_find_stamp_type_None(self, mock_syslog, mock_5424):
        mock_syslog.return_value = False
        mock_5424.return_value = False
        res = utils.find_stamp_type("line")
        self.assertEqual(res, None)
        mock_syslog.assert_called_once_with("line")
        mock_5424.assert_called_once_with("line")

    @mock.patch('hb_report.utils.get_ts')
    def test_find_first_ts(self, mock_get_ts):
        mock_get_ts.side_effect = [None, 12345]
        data = ["", "line1", "line2"]
        res = utils.find_first_ts(data)
        self.assertEqual(res, 12345)
        mock_get_ts.assert_has_calls([
            mock.call("line1"),
            mock.call("line2")
            ])

    @mock.patch("builtins.open")
    @mock.patch('lzma.open')
    @mock.patch('bz2.open')
    @mock.patch('gzip.open')
    def test_get_open_method(self, mock_gzip, mock_bz2, mock_lzma, mock_open):
        res = utils.get_open_method("file.gz")
        self.assertEqual(res, mock_gzip)

        res = utils.get_open_method("file.bz2")
        self.assertEqual(res, mock_bz2)

        res = utils.get_open_method("file.xz")
        self.assertEqual(res, mock_lzma)

        res = utils.get_open_method("file")
        self.assertEqual(res, mock_open)

    @mock.patch("lzma.open", new_callable=mock.mock_open, read_data="read data")
    @mock.patch('hb_report.utils.crmutils.to_ascii')
    @mock.patch('hb_report.utils.get_open_method')
    def test_read_from_file(self, mock_get_method, mock_to_ascii, mock_lzma):
        mock_get_method.return_value = mock_lzma
        mock_to_ascii.return_value = "data"

        res = utils.read_from_file("file.xz")
        self.assertEqual(res, mock_to_ascii.return_value)

        mock_get_method.assert_called_once_with("file.xz")
        mock_lzma.assert_called_once_with("file.xz", 'rt', encoding='utf-8', errors='replace')
        mock_to_ascii.assert_called_once_with("read data")

    @mock.patch("builtins.open", new_callable=mock.mock_open)
    @mock.patch('hb_report.utils.get_open_method')
    def test_write_to_file_open(self, mock_get_method, mock_open):
        mock_get_method.return_value = mock_open

        utils.write_to_file("tofile", "data")

        mock_get_method.assert_called_once_with("tofile")
        mock_open.assert_called_once_with("tofile", 'w')
        mock_open().write.assert_called_once_with("data")

    @mock.patch("bz2.open", new_callable=mock.mock_open)
    @mock.patch('hb_report.utils.get_open_method')
    def test_write_to_file_bz2(self, mock_get_method, mock_bz2_open):
        mock_get_method.return_value = mock_bz2_open

        utils.write_to_file("tofile.bz2", "data")

        mock_get_method.assert_called_once_with("tofile.bz2")
        mock_bz2_open.assert_called_once_with("tofile.bz2", 'w')
        mock_bz2_open().write.assert_called_once_with("data".encode('utf-8'))

    @mock.patch('hb_report.utils.get_ts')
    def test_line_time(self, mock_get_ts):
        mock_get_ts.return_value = 12345

        data_list = ["Feb 13 13:28:57 15sp1-1 pacemaker-based",
                "Feb 13 13:28:57 15sp1-1 pacemaker-based"]
        res = utils.line_time(data_list, 2)
        self.assertEqual(res, mock_get_ts.return_value)

        mock_get_ts.assert_called_once_with("Feb 13 13:28:57 15sp1-1 pacemaker-based")

    def test_findln_by_time(self):
        core.ctx = mock.Mock()
        delattr(core.ctx, "stamp_type")

        target_time = "Apr 03 13:10"
        target_time_stamp = crmutils.parse_to_timestamp(target_time)
        with open('pacemaker.log') as f:
            data = f.read()
        result_line = utils.findln_by_time(data, target_time_stamp)
        result_line_stamp = utils.line_time(data.split('\n'), result_line)
        assert result_line_stamp > target_time_stamp
        result_pre_line_stamp = utils.line_time(data.split('\n'), result_line-1)
        assert result_pre_line_stamp < target_time_stamp

        target_time = "Apr 03 11:01:19"
        target_time_stamp = crmutils.parse_to_timestamp(target_time)
        result_line = utils.findln_by_time(data, target_time_stamp)
        result_time = ' '.join(data.split('\n')[result_line-1].split()[:3])
        self.assertEqual(result_time, target_time)

    def test_findln_by_time_irregular(self):
        core.ctx = mock.Mock()
        delattr(core.ctx, "stamp_type")

        data = """line1
        line2
        line3
        line4
        line5"""
        target_time = "Apr 03 13:10"
        target_time_stamp = crmutils.parse_to_timestamp(target_time)
        result_line = utils.findln_by_time(data, target_time_stamp)
        self.assertEqual(result_line, None)

    def test_filter_lines(self):
        with open('pacemaker.log') as f:
            data = f.read()
        res = utils.filter_lines(data, 140, 143)
        _, expected = crmutils.get_stdout("sed -n '140, 143p' pacemaker.log")
        self.maxDiff = None
        self.assertEqual(res, expected+'\n')

    @mock.patch('hb_report.utils.log_fatal')
    @mock.patch('hb_report.utils.crmutils.parse_to_timestamp')
    @mock.patch('re.match')
    def test_parse_to_timestamp_fatal(self, mock_match, mock_parse, mock_fatal):
        mock_match.return_value = None
        mock_parse.return_value = None
        mock_fatal.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            utils.parse_to_timestamp("20200202")

        mock_match.assert_called_once_with('^-?([1-9][0-9]*)([YmdHM])$', "20200202")
        mock_parse.assert_called_once_with("20200202")
        mock_fatal.assert_called_once_with('Try these format like: 2pm; 1:00; "2019/9/5 12:30"; "09-Sep-07 2:00"')

    def test_parse_to_timestamp(self):
        res = utils.parse_to_timestamp("-1Y")
        assert res is not None
        res = utils.parse_to_timestamp("-1m")
        assert res is not None
        res = utils.parse_to_timestamp("-1d")
        assert res is not None
        res = utils.parse_to_timestamp("-1H")
        assert res is not None
        res = utils.parse_to_timestamp("-100M")
        assert res is not None

    @mock.patch('socket.gethostname')
    def test_me(self, mock_gethostname):
        mock_gethostname.return_value = "node1"
        res = utils.me()
        self.assertEqual(res, "node1")
        mock_gethostname.assert_called_once_with()

    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.utils.which')
    def test_get_pkg_mgr_none(self, mock_which, mock_warn):
        mock_which.side_effect = [False, False, False, False]
        res = utils.get_pkg_mgr()
        self.assertEqual(res, None)
        mock_which.assert_has_calls([
            mock.call("rpm"),
            mock.call("dpkg"),
            mock.call("pkg_info"),
            mock.call("pkginfo")
            ])
        mock_warn.assert_called_once_with("Unknown package manager!")

    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.utils.which')
    def test_get_pkg_mgr(self, mock_which, mock_warn):
        mock_which.return_value = True
        res = utils.get_pkg_mgr()
        self.assertEqual(res, "rpm")
        mock_which.assert_called_once_with("rpm")
        mock_warn.assert_not_called()

    @mock.patch('re.search')
    @mock.patch('hb_report.utils.crmutils.get_stdout')
    def test_pkg_ver_rpm(self, mock_run, mock_search):
        mock_run.return_value = (0, "data1\nnot installed")
        mock_search.side_effect = [False, True]
        res = utils.pkg_ver_rpm("pkg1 pkg2")
        self.assertEqual(res, "Name | Version-Release | Distribution | Arch\n-----\ndata1\n")
        cmd = "rpm -q --qf '%{name} | %{version}-%{release} | %{distribution} | %{arch}\n'"
        mock_run.assert_called_once_with("{} pkg1 pkg2".format(cmd))
        mock_search.assert_has_calls([
            mock.call('not installed', "data1"),
            mock.call('not installed', "not installed")
            ])

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('re.search')
    @mock.patch('hb_report.utils.crmutils.get_stdout')
    def test_verify_rpm(self, mock_run, mock_search, mock_debug2):
        mock_run.return_value = (0, "data1\nnot installed")
        mock_search.side_effect = [False, True]
        res = utils.verify_rpm("pkg1 pkg2")
        self.assertEqual(res, "data1\n")
        mock_run.assert_called_once_with("rpm --verify pkg1 pkg2")
        mock_search.assert_has_calls([
            mock.call('not installed', "data1"),
            mock.call('not installed', "not installed")
            ])
        mock_debug2.assert_not_called()

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('re.search')
    @mock.patch('hb_report.utils.crmutils.get_stdout')
    def test_verify_rpm_ok(self, mock_run, mock_search, mock_debug2):
        mock_run.return_value = (0, None)
        res = utils.verify_rpm("pkg1 pkg2")
        self.assertEqual(res, "All packages verify successfully\n")
        mock_run.assert_called_once_with("rpm --verify pkg1 pkg2")
        mock_search.assert_not_called()
        mock_debug2.assert_called_once_with("All packages verify successfully")

    @mock.patch("builtins.open", new_callable=mock.mock_open, create=True)
    def test_touch_file(self, mock_open_file):
        utils.touch_file("file1")
        mock_open_file.assert_called_once_with("file1", 'w')
        mock_open_file().close.assert_called_once_with()

    def test_dt_to_str_type_error(self):
        with self.assertRaises(TypeError) as err:
            utils.dt_to_str("error")
        self.assertEqual("expected <class 'datetime.datetime'>", str(err.exception))

    def test_dt_to_str_type(self):
        import datetime
        dt = datetime.datetime(2020, 2, 19, 21, 44, 7, 977355)
        res = utils.dt_to_str(dt)
        self.assertEqual(res, "2020-02-19 21:44")

    @mock.patch('hb_report.utils.dt_to_str')
    @mock.patch('hb_report.utils.ts_to_dt')
    def test_ts_to_str(self, mock_ts_to_dt, mock_dt_to_str):
        mock_ts_to_dt.return_value = "dt data"
        mock_dt_to_str.return_value = "str data"
        res = utils.ts_to_str("123")
        self.assertEqual(res, "str data")
        mock_ts_to_dt.assert_called_once_with("123")
        mock_dt_to_str.assert_called_once_with("dt data")

    @mock.patch('hb_report.utils.crmutils.get_stdout_stderr')
    def test_which(self, mock_run):
        mock_run.return_value = (0, None, None)
        res = utils.which("cmd")
        self.assertTrue(res)
        mock_run.assert_called_once_with("which cmd")

    @mock.patch('hb_report.utils.crmutils.to_ascii')
    @mock.patch('hb_report.utils.log_error')
    @mock.patch('subprocess.Popen')
    def test_get_stdout_stderr(self, mock_popen, mock_error, mock_to_ascii):
        mock_popen_inst = mock.Mock(returncode=0)
        mock_popen.return_value = mock_popen_inst
        mock_popen_inst.communicate.return_value = ("data", None)
        mock_to_ascii.side_effect = ["data", None]

        res = utils.get_stdout_stderr_timeout("cmd")
        self.assertEqual(res, (0, "data", None))

        import subprocess
        mock_popen.assert_called_once_with("cmd", shell=True, stdin=None,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        mock_popen_inst.communicate.assert_called_once_with(None, timeout=5)
        mock_error.assert_not_called()
        mock_to_ascii.assert_has_calls([mock.call("data"), mock.call(None)])

    @mock.patch('hb_report.utils.log_error')
    def test_get_stdout_stderr_timeout(self, mock_error):
        import subprocess
        res = utils.get_stdout_stderr_timeout("sleep 3", timeout=2)
        self.assertEqual(res, (-1, None, None))
        mock_error.assert_called_once_with('Timeout running "sleep 3"')

    @mock.patch('hb_report.utils.tz.tzlocal')
    @mock.patch('hb_report.utils.crmutils.timestamp_to_datetime')
    def test_ts_to_dt(self, mock_to_datetime, mock_tz):
        mock_to_datetime.return_value = "dt"
        mock_tz_inst = mock.Mock()
        mock_tz.return_value = mock_tz_inst
        mock_tz_inst.utcoffset.return_value = "dt"

        res = utils.ts_to_dt("1234")
        self.assertEqual(res, "dtdt")

        mock_to_datetime.assert_called_once_with("1234")
        mock_tz.assert_called_once_with()
        mock_tz_inst.utcoffset.assert_called_once_with("dt")

    @mock.patch('hb_report.utils.log_fatal')
    @mock.patch('os.makedirs')
    @mock.patch('os.path.isdir')
    def test_mkdir(self, mock_isdir, mock_makedirs, mock_fatal):
        mock_isdir.return_value = False
        mock_makedirs.side_effect = OSError("error")

        utils._mkdir("dir")

        mock_isdir.assert_called_once_with("dir")
        mock_makedirs.assert_called_once_with("dir")
        mock_fatal.assert_called_once_with("Failed to create directory: error")

    def test_unique(self):
        a = [3,2,1,3,4,5]
        res = utils.unique(a)
        self.assertEqual(res, [3,2,1,4,5])

    @mock.patch('os.stat')
    def test_is_log_empty(self, mock_stat):
        mock_stat_inst = mock.Mock(st_size=0)
        mock_stat.return_value = mock_stat_inst
        res = utils.is_log_empty("logf")
        self.assertTrue(res)
        mock_stat.assert_called_once_with("logf")
