import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
import re
import unittest
import datetime
from crmsh import corosync
from crmsh import utils as crmutils
from crmsh.config import path
from hb_report import core, const

try:
    from unittest import mock
except ImportError:
    import mock


class TestContext(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """
        self.maxDiff = None
        self.context = core.Context()
        from_time_dt = datetime.datetime.now() - datetime.timedelta(hours=12)
        self.expected_from_time = crmutils.parse_to_timestamp(from_time_dt.strftime("%Y-%m-%d %H:%M"))
        to_time_dt = datetime.datetime.now()
        self.expected_to_time = crmutils.parse_to_timestamp(to_time_dt.strftime("%Y-%m-%d %H:%M"))
        self.expected_extra_logs = ["/var/log/messages", "/var/log/ha-cluster-bootstrap.log"]

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    def test_init(self):
        self.assertEqual(self.context.from_time, self.expected_from_time)
        self.assertEqual(self.context.to_time, self.expected_to_time)
        self.assertEqual(self.context.extra_logs, self.expected_extra_logs)
        self.assertEqual(self.context.sensitive_regex, ["passw.*"])
        self.assertEqual(self.context.regex, ['CRIT:', 'ERROR:', 'error:', 'warning:', 'crit:'])
        self.assertEqual(self.context.ssh_askpw_nodes, [])
        self.assertFalse(self.context.no_compress)
        self.assertFalse(self.context.speed_up)
        self.assertFalse(self.context.rm_exist_dest)
        self.assertFalse(self.context.single)

    def test_str(self):
        self.assertEqual(str(self.context), '{{"from_time": {}, "no_compress": false, "speed_up": false, "extra_logs": ["/var/log/messages", "/var/log/ha-cluster-bootstrap.log"], "rm_exist_dest": false, "single": false, "to_time": {}, "sensitive_regex": ["passw.*"], "regex": ["CRIT:", "ERROR:", "error:", "warning:", "crit:"], "ssh_askpw_nodes": []}}'.format(self.expected_from_time, self.expected_to_time))

    def test_setattr(self):
        self.context.tmp_file_name = "tmp_file"
        self.context.from_time = "2020-01-01"
        self.assertEqual(self.context.from_time, 1577836800.0)
        self.context.to_time = "2020-01-31"
        self.assertEqual(self.context.to_time, 1580428800.0)
        self.context.extra_logs = ["/var/log/test"]
        assert "/var/log/test" in self.context.extra_logs
        self.context.nodes = ["node1", "node2", "node3"]
        self.assertEqual(self.context.nodes, ["node1", "node2", "node3"])

    @mock.patch('hb_report.utils.log_fatal')
    def test_setattr_fatal(self, mock_fatal):
        self.context.ssh_options = ["test"]
        self.context.before_time = "test"
        mock_fatal.assert_has_calls([
            mock.call('Wrong format of ssh option "test"'),
            mock.call('Wrong format of -b option ([1-9][0-9]*[YmdHM])')
            ])

    def test_setitem(self):
        self.context['tmp_name'] = "tmp_name"

    def test_dump(self):
        expected_dump = '''{{
  "from_time": {},
  "no_compress": false,
  "speed_up": false,
  "extra_logs": [
    "/var/log/messages",
    "/var/log/ha-cluster-bootstrap.log"
  ],
  "rm_exist_dest": false,
  "single": false,
  "to_time": {},
  "sensitive_regex": [
    "passw.*"
  ],
  "regex": [
    "CRIT:",
    "ERROR:",
    "error:",
    "warning:",
    "crit:"
  ],
  "ssh_askpw_nodes": []
}}'''.format(self.expected_from_time, self.expected_to_time)
        self.assertEqual(self.context.dumps(), expected_dump)


class TestCore(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """
        self.context = mock.Mock(
                name = "hb_report",
                work_dir="/tmp",
                dest_path="/opt",
                before_time=None,
                from_time=1580859300.0,
                to_time=1580902500.0,
                from_time_str="2020-02-09 06:11",
                to_time_str="2020-02-09 18:11",
                dest=None,
                single=False,
                nodes=["node1", "node2"]
                )

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    def test_is_collector_false(self):
        with mock.patch.object(sys, 'argv', ["hb_report", "test"]):
            self.assertFalse(core.is_collector())
    
    def test_is_collector_true(self):
        with mock.patch.object(sys, 'argv', ["hb_report", "__slave", "context"]):
            self.assertTrue(core.is_collector())

    @mock.patch('hb_report.utils.me')
    def test_include_me_false(self, mock_me):
        mock_me.return_value = "node1.com"
        node_list = ["node2", "node3"]
        self.assertFalse(core.include_me(node_list))
        mock_me.assert_called_once_with()

    @mock.patch('hb_report.utils.me')
    def test_include_me_true(self, mock_me):
        mock_me.return_value = "node1"
        node_list = ["node1", "node2", "node3"]
        self.assertTrue(core.include_me(node_list))
        mock_me.assert_called_once_with()

    @mock.patch('hb_report.core.utils.log_debug1')
    @mock.patch('hb_report.core.utils.me')
    @mock.patch('hb_report.core.include_me')
    @mock.patch('hb_report.core.utils.log_fatal')
    @mock.patch('hb_report.core.crmutils.list_cluster_nodes')
    def test_get_nodes(self, mock_list_nodes, mock_fatal, mock_include, 
            mock_me, mock_debug1):
        context = mock.Mock(nodes=None, single=False)
        mock_list_nodes.return_value = ["node1", "node2"]

        core.get_nodes(context)

        mock_list_nodes.assert_called_once_with()
        mock_fatal.assert_not_called()
        mock_me.assert_not_called()
        mock_include.assert_not_called()
        mock_debug1.assert_called_once_with("Nodes to collect: ['node1', 'node2']")

    @mock.patch('hb_report.core.utils.log_debug1')
    @mock.patch('hb_report.core.utils.me')
    @mock.patch('hb_report.core.include_me')
    @mock.patch('hb_report.core.utils.log_fatal')
    @mock.patch('hb_report.core.crmutils.list_cluster_nodes')
    def test_get_nodes_single(self, mock_list_nodes, mock_fatal, mock_include, 
            mock_me, mock_debug1):
        context = mock.Mock(nodes=None, single=True)
        mock_list_nodes.return_value = ["node1", "node2"]
        mock_include.return_value = True
        mock_me.return_value = "node1"

        core.get_nodes(context)

        mock_list_nodes.assert_called_once_with()
        mock_fatal.assert_not_called()
        mock_me.assert_called_once_with()
        mock_include.assert_called_once_with(['node1', 'node2'])
        mock_debug1.assert_called_once_with("Nodes to collect: ['node1']")

    @mock.patch('hb_report.core.utils.log_debug1')
    @mock.patch('hb_report.core.utils.me')
    @mock.patch('hb_report.core.include_me')
    @mock.patch('hb_report.core.utils.log_fatal')
    @mock.patch('hb_report.core.crmutils.list_cluster_nodes')
    def test_get_nodes_set_by_user(self, mock_list_nodes, mock_fatal, 
            mock_include, mock_me, mock_debug1):
        context = mock.Mock(nodes=["node1", "node2"], single=False)

        core.get_nodes(context)

        mock_list_nodes.assert_not_called()
        mock_fatal.assert_not_called()
        mock_me.assert_not_called()
        mock_include.assert_not_called()
        mock_debug1.assert_called_once_with("Nodes to collect: ['node1', 'node2']")

    @mock.patch('hb_report.core.utils.log_debug1')
    @mock.patch('hb_report.core.utils.me')
    @mock.patch('hb_report.core.include_me')
    @mock.patch('hb_report.core.utils.log_fatal')
    @mock.patch('hb_report.core.crmutils.list_cluster_nodes')
    def test_get_nodes_fatal(self, mock_list_nodes, mock_fatal, 
            mock_include, mock_me, mock_debug1):
        context = mock.Mock(nodes=None, single=False)
        mock_list_nodes.return_value = []
        mock_fatal.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            core.get_nodes(context)

        mock_list_nodes.assert_called_once_with()
        mock_fatal.assert_called_once_with("Could not figure out a list of nodes; is this a cluster node?")
        mock_me.assert_not_called()
        mock_include.assert_not_called()
        mock_debug1.assert_not_called()

    @mock.patch('hb_report.utils.log_fatal')
    def test_process_some_arguments_fatal(self, mock_fatal):
        self.context.to_time = 1580859300.0
        self.context.from_time = 1580902500.0
        mock_fatal.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            core.process_some_arguments(self.context)

        mock_fatal.assert_called_once_with("Start time must be before finish time")

    @mock.patch('hb_report.core.tmpfiles.create')
    @mock.patch('hb_report.utils.ts_to_str')
    @mock.patch('hb_report.utils.now')
    @mock.patch('hb_report.utils.log_fatal')
    def test_process_some_arguments(self, mock_fatal, mock_now, mock_ts_to_str, mock_tmpfiles):
        self.context.before_time = 123
        mock_now.return_value = "Wed-05-Feb-2020"
        mock_ts_to_str.side_effect = ["time_str_from", "time_str_to"]
        mock_tmpfiles.side_effect = [(1, "/tmp/tmp1"), (2, "/tmp/tmp2")]

        core.process_some_arguments(self.context)

        mock_fatal.assert_not_called()
        mock_now.assert_called_once_with("%a-%d-%b-%Y")
        mock_ts_to_str.assert_has_calls([
            mock.call(self.context.from_time),
            mock.call(self.context.to_time)
            ])
        mock_tmpfiles.assert_has_calls([
            mock.call(time=self.context.from_time),
            mock.call(time=self.context.to_time)
            ])

    @mock.patch('hb_report.core.process_results')
    @mock.patch('hb_report.core.collect_for_nodes')
    @mock.patch('hb_report.core.ssh_issue')
    @mock.patch('hb_report.core.get_nodes')
    @mock.patch('hb_report.core.setup_workdir')
    @mock.patch('hb_report.core.load_from_config')
    @mock.patch('hb_report.core.parse_argument')
    @mock.patch('hb_report.core.is_collector')
    def test_run_master(self, mock_collector, mock_parse, mock_load, mock_workdir,
            mock_get_nodes, mock_ssh, mock_collect_for_nodes, mock_process_results):
        mock_collector.side_effect = [False, False]

        core.run(self.context)

        mock_collector.assert_has_calls([
            mock.call(),
            mock.call()
            ])
        mock_parse.assert_called_once_with(self.context)
        mock_load.assert_called_once_with(self.context)
        mock_workdir.assert_called_once_with(self.context)
        mock_get_nodes.assert_called_once_with(self.context)
        mock_ssh.assert_called_once_with(self.context)
        mock_collect_for_nodes.assert_called_once_with(self.context)
        mock_process_results.assert_called_once_with(self.context)

    @mock.patch('hb_report.core.push_data')
    @mock.patch('hb_report.core.collect_other_logs_and_info')
    @mock.patch('hb_report.core.collect_journal_general')
    @mock.patch('hb_report.core.collect_journal_ha')
    @mock.patch('hb_report.core.setup_workdir')
    @mock.patch('hb_report.core.load_context')
    @mock.patch('hb_report.core.is_collector')
    def test_run_collector(self, mock_collector, mock_load, mock_workdir,
            mock_journal_ha, mock_journal_general, mock_other_logs_and_info, mock_push):
        mock_collector.side_effect = [True, True]

        core.run(self.context)

        mock_collector.assert_has_calls([
            mock.call(),
            mock.call()
            ])
        mock_load.assert_called_once_with(self.context)
        mock_workdir.assert_called_once_with(self.context)
        mock_journal_ha.assert_called_once_with(self.context)
        mock_journal_general.assert_called_once_with(self.context)
        mock_other_logs_and_info.assert_called_once_with(self.context)
        mock_push.assert_called_once_with(self.context)

    @mock.patch('hb_report.utils.log_fatal')
    @mock.patch('os.path.isdir')
    def test_get_ocf_root_fatal(self, mock_isdir, mock_fatal):
        mock_isdir.return_value = False
        mock_fatal.side_effect = SystemExit
        with self.assertRaises(SystemExit):
            core.get_ocf_root(self.context)
        mock_isdir.assert_called_once_with(self.context.ocf_root)
        mock_fatal.assert_called_once_with("Cannot find ocf root directory!")
    
    @mock.patch('hb_report.utils.log_fatal')
    @mock.patch('os.path.isdir')
    def test_get_ocf_root(self, mock_isdir, mock_fatal):
        mock_isdir.return_value = True
        core.get_ocf_root(self.context)
        mock_isdir.assert_called_once_with(self.context.ocf_root)
        mock_fatal.assert_not_called()

    @mock.patch('hb_report.utils.log_fatal')
    @mock.patch('os.path.exists')
    def test_get_ha_varlib_fatal(self, mock_exists, mock_fatal):
        self.context.ocf_root = "/usr/lib/ocf"
        mock_exists.return_value = False
        mock_fatal.side_effect = SystemExit
        
        with self.assertRaises(SystemExit):
            core.get_ha_varlib(self.context)
        
        ocf_lib_file = "{}/lib/heartbeat/ocf-directories".format(self.context.ocf_root)
        mock_exists.assert_called_once_with(ocf_lib_file)
        mock_fatal.assert_called_once_with("File {} not exist".format(ocf_lib_file))

    @mock.patch('re.search')
    @mock.patch("builtins.open", new_callable=mock.mock_open, read_data="HA_VARLIB:=/tmp")
    @mock.patch('hb_report.utils.log_fatal')
    @mock.patch('os.path.exists')
    def test_get_ha_varlib(self, mock_exists, mock_fatal, mock_open_file, mock_search):
        self.context.ocf_root = "/usr/lib/ocf"
        mock_exists.return_value = True
        mock_search_inst = mock.Mock()
        mock_search.return_value = mock_search_inst

        core.get_ha_varlib(self.context)

        ocf_lib_file = "{}/lib/heartbeat/ocf-directories".format(self.context.ocf_root)
        mock_exists.assert_called_once_with(ocf_lib_file)
        mock_fatal.assert_not_called()
        mock_open_file.assert_called_once_with(ocf_lib_file)
        mock_search.assert_called_once_with(r'HA_VARLIB:=(.*)}', 'HA_VARLIB:=/tmp')
        mock_search_inst.group.assert_called_once_with(1)

    @mock.patch('hb_report.utils.log_fatal')
    @mock.patch('os.path.isdir')
    def test_get_pe_dir_fatal(self, mock_isdir, mock_fatal):
        mock_isdir.return_value = False
        mock_fatal.side_effect = SystemExit
        with self.assertRaises(SystemExit):
            core.get_pe_dir(self.context)
        mock_isdir.assert_called_once_with(self.context.pe_dir)
        mock_fatal.assert_called_once_with("Cannot find PE files directory!")

    @mock.patch('hb_report.utils.log_fatal')
    @mock.patch('os.path.isdir')
    def test_get_pe_dir(self, mock_isdir, mock_fatal):
        mock_isdir.return_value = True
        core.get_pe_dir(self.context)
        mock_isdir.assert_called_once_with(self.context.pe_dir)
        mock_fatal.assert_not_called()

    @mock.patch('hb_report.utils.log_fatal')
    @mock.patch('os.path.isdir')
    def test_get_cib_dir_fatal(self, mock_isdir, mock_fatal):
        mock_isdir.return_value = False
        mock_fatal.side_effect = SystemExit
        with self.assertRaises(SystemExit):
            core.get_cib_dir(self.context)
        mock_isdir.assert_called_once_with(self.context.cib_dir)
        mock_fatal.assert_called_once_with("Cannot find CIB files directory!")

    @mock.patch('hb_report.utils.log_fatal')
    @mock.patch('os.path.isdir')
    def test_get_cib_dir(self, mock_isdir, mock_fatal):
        mock_isdir.return_value = True
        core.get_cib_dir(self.context)
        mock_isdir.assert_called_once_with(self.context.cib_dir)
        mock_fatal.assert_not_called()

    @mock.patch('os.path.isdir')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('os.path.dirname')
    def test_get_cores_dir(self, mock_dirname, mock_debug2, mock_join, mock_isdir):
        self.context.cib_dir = "/var/lib/pacemaker/cib"
        mock_dirname.return_value = "/var/lib/pacemaker"
        mock_join.return_value = "/var/lib/pacemaker/cores"
        mock_isdir.return_value = True

        core.get_cores_dir(self.context)

        mock_dirname.assert_called_once_with(self.context.cib_dir)
        mock_debug2.assert_called_once_with("Setting PCMK_LIB to {}".format(mock_dirname.return_value))
        mock_join.assert_called_once_with(mock_dirname.return_value, "cores")
        mock_isdir.assert_called_once_with(const.COROSYNC_LIB)

    @mock.patch('hb_report.core.corosync.get_value')
    @mock.patch('hb_report.core.corosync.conf')
    @mock.patch('os.path.exists')
    def test_load_from_corosync_conf_return(self, mock_exists, mock_conf, mock_value):
        mock_conf.return_value = "/etc/corosync/corosync.conf"
        mock_exists.return_value = False

        core.load_from_corosync_conf(self.context)

        mock_conf.assert_called_once_with()
        mock_exists.assert_called_once_with(mock_conf.return_value)
        mock_value.assert_not_called()

    @mock.patch('hb_report.core.crmutils.get_boolean')
    @mock.patch('hb_report.core.corosync.get_value')
    @mock.patch('hb_report.core.corosync.conf')
    @mock.patch('os.path.exists')
    def test_load_from_corosync_conf(self, mock_exists, mock_conf, mock_value, mock_boolean):
        mock_conf.return_value = "/etc/corosync/corosync.conf"
        mock_exists.return_value = True
        mock_value.side_effect = ["yes", "/var/log/corosync.log", None]
        mock_boolean.return_value = True

        core.load_from_corosync_conf(self.context)

        mock_conf.assert_called_once_with()
        mock_exists.assert_called_once_with(mock_conf.return_value)
        mock_value.assert_has_calls([
            mock.call("logging.to_logfile"),
            mock.call("logging.logfile"),
            mock.call("logging.syslog_facility")
            ])
        mock_boolean.assert_called_once_with("yes")

    @mock.patch('hb_report.core.load_from_corosync_conf')
    @mock.patch('hb_report.core.get_cores_dir')
    @mock.patch('hb_report.core.get_cib_dir')
    @mock.patch('hb_report.core.get_pe_dir')
    @mock.patch('hb_report.core.get_ha_varlib')
    @mock.patch('hb_report.core.get_ocf_root')
    def test_load_from_config(self, mock_ocf, mock_varlib, mock_pe, mock_cib, 
            mock_cores, mock_corosync):
        core.load_from_config(self.context)

        mock_ocf.assert_called_once_with(self.context)
        mock_varlib.assert_called_once_with(self.context)
        mock_pe.assert_called_once_with(self.context)
        mock_cib.assert_called_once_with(self.context)
        mock_cores.assert_called_once_with(self.context)
        mock_corosync.assert_called_once_with(self.context)

    def test_load_context(self):
        self.context = core.Context()
        with mock.patch.object(sys, 'argv', ["hb_report", "test", str(self.context)]):
            core.load_context(self.context)

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.utils._mkdir')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.core.is_collector')
    @mock.patch('hb_report.core.tmpfiles.create_dir')
    @mock.patch('hb_report.core.valid_dest')
    def test_setup_workdir_master(self, mock_valid_dest, mock_tmpdir, mock_collector,
            mock_join, mock_basename, mock_mkdir, mock_debug2):
        self.context.dest = "/opt/hb_report1"
        mock_tmpdir.return_value = "/tmp/tmpdir"
        mock_collector.return_value = False
        mock_basename.return_value = "hb_report1"
        mock_join.return_value = "/tmp/tmpdir/hb_report1"

        core.setup_workdir(self.context)

        mock_valid_dest.assert_called_once_with(self.context)
        mock_tmpdir.assert_called_once_with()
        mock_collector.assert_called_once_with()
        mock_basename.assert_called_once_with(self.context.dest)
        mock_join.assert_called_once_with("/tmp/tmpdir", "hb_report1")
        mock_mkdir.assert_called_once_with(self.context.work_dir)
        mock_debug2.assert_called_once_with('Setup work directory in {}'.format(self.context.work_dir))

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.utils._mkdir')
    @mock.patch('hb_report.utils.me')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.core.is_collector')
    @mock.patch('hb_report.core.tmpfiles.create_dir')
    @mock.patch('hb_report.core.valid_dest')
    def test_setup_workdir_collecter(self, mock_valid_dest, mock_tmpdir, mock_collector,
            mock_join, mock_basename, mock_me, mock_mkdir, mock_debug2):
        self.context.dest = "/opt/hb_report1"
        mock_tmpdir.return_value = "/tmp/tmpdir"
        mock_collector.return_value = True
        mock_me.side_effect = ["node1", "node1"]
        mock_basename.return_value = "hb_report1"
        mock_join.return_value = "/tmp/tmpdir/hb_report1/node1"

        core.setup_workdir(self.context)

        mock_valid_dest.assert_called_once_with(self.context)
        mock_tmpdir.assert_called_once_with()
        mock_collector.assert_called_once_with()
        mock_basename.assert_called_once_with(self.context.dest)
        mock_me.assert_has_calls([mock.call(), mock.call()])
        mock_join.assert_called_once_with("/tmp/tmpdir", "hb_report1", "node1")
        mock_mkdir.assert_called_once_with(self.context.work_dir)
        mock_debug2.assert_called_once_with('Setup work directory in {}'.format(self.context.work_dir))

    @mock.patch('hb_report.core.collect_journal')
    @mock.patch('os.path.join')
    def test_collect_journal_ha(self, mock_join, mock_collect_journal):
        mock_join.return_value = "{}/{}".format(self.context.work_dir, const.HALOG_F)

        core.collect_journal_ha(self.context)

        mock_join.assert_called_once_with(self.context.work_dir, const.HALOG_F)
        cmd = 'journalctl -u pacemaker -u corosync -u sbd \
            --since "{}" --until "{}" \
            -o short-iso --no-pager | tail -n +2'.\
            format(self.context.from_time_str, self.context.to_time_str)
        mock_collect_journal.assert_called_once_with(self.context, cmd, mock_join.return_value)

    @mock.patch('hb_report.core.collect_journal')
    @mock.patch('os.path.join')
    def test_collect_journal_general(self, mock_join, mock_collect_journal):
        mock_join.return_value = "{}/{}".format(self.context.work_dir, const.JOURNAL_F)

        core.collect_journal_general(self.context)

        mock_join.assert_called_once_with(self.context.work_dir, const.JOURNAL_F)
        cmd = 'journalctl --since "{}" --until "{}" \
            -o short-iso --no-pager | tail -n +2'.\
            format(self.context.from_time_str, self.context.to_time_str)
        mock_collect_journal.assert_called_once_with(self.context, cmd, mock_join.return_value)

    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.utils.which')
    def test_collect_journal_no_cmd(self, mock_which, mock_warning):
        mock_which.return_value = False

        core.collect_journal(self.context, "cmd", "outf")

        mock_which.assert_called_once_with("journalctl")
        mock_warning.assert_called_once_with("Command journalctl not found")

    @mock.patch('hb_report.utils.log_error')
    @mock.patch('hb_report.core.crmutils.str2file')
    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('os.path.basename')
    @mock.patch('hb_report.core.crmutils.get_stdout_stderr')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.utils.which')
    def test_collect_journal_error(self, mock_which, mock_warning, mock_debug2, mock_run,
            mock_basename, mock_debug1, mock_str2file, mock_error):
        mock_which.return_value = True
        mock_run.return_value = (1, None, "error")

        core.collect_journal(self.context, "cmd", "outf")

        mock_which.assert_called_once_with("journalctl")
        mock_warning.assert_not_called()
        mock_debug2.assert_called_once_with("Running command: cmd")
        mock_run.assert_called_once_with("cmd")
        mock_debug1.assert_not_called()
        mock_str2file.assert_not_called()
        mock_error.assert_called_once_with("error")

    @mock.patch('hb_report.utils.log_error')
    @mock.patch('hb_report.core.crmutils.str2file')
    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('os.path.basename')
    @mock.patch('hb_report.core.crmutils.get_stdout_stderr')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.utils.which')
    def test_collect_journal(self, mock_which, mock_warning, mock_debug2, mock_run,
            mock_basename, mock_debug1, mock_str2file, mock_error):
        mock_which.return_value = True
        mock_run.return_value = (0, "data", None)
        mock_basename.return_value = "outf"

        core.collect_journal(self.context, "cmd", "outf")

        mock_which.assert_called_once_with("journalctl")
        mock_warning.assert_not_called()
        mock_debug2.assert_called_once_with("Running command: cmd")
        mock_run.assert_called_once_with("cmd")
        mock_debug1.assert_called_once_with("Dump {} into {}".format(mock_basename.return_value, self.context.dest_path))
        mock_str2file.assert_called_once_with("data", "outf")
        mock_error.assert_not_called()

    @mock.patch('hb_report.utils.log_fatal')
    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('hb_report.core.crmutils.get_stdout_stderr')
    @mock.patch('hb_report.utils.me')
    @mock.patch('hb_report.utils.log_debug2')
    def test_push_data_error(self, mock_debug2, mock_me, mock_run, mock_debug1, mock_fatal):
        mock_me.return_value = "node1"
        mock_run.return_value = (1, None, "error")

        core.push_data(self.context)

        mock_debug2.assert_called_once_with("Pushing data from {}".format(self.context.work_dir))
        mock_me.assert_called_once_with()
        cmd = r'cd {}/.. && tar -h -cf - {}'.format(self.context.work_dir, mock_me.return_value)
        mock_run.assert_called_once_with(cmd, raw=True)
        mock_debug1.assert_not_called()
        mock_fatal.assert_called_once_with("error")

    @mock.patch('hb_report.utils.log_fatal')
    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('hb_report.core.crmutils.get_stdout_stderr')
    @mock.patch('hb_report.utils.me')
    @mock.patch('hb_report.utils.log_debug2')
    def test_push_data(self, mock_debug2, mock_me, mock_run, mock_debug1, mock_fatal):
        mock_me.return_value = "node1"
        mock_run.return_value = (0, "data", None)

        core.push_data(self.context)

        mock_debug2.assert_called_once_with("Pushing data from {}".format(self.context.work_dir))
        mock_me.assert_called_once_with()
        cmd = r'cd {}/.. && tar -h -cf - {}'.format(self.context.work_dir, mock_me.return_value)
        mock_run.assert_called_once_with(cmd, raw=True)
        mock_debug1.assert_called_once_with("="*45)
        mock_fatal.assert_not_called()

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('os.getuid')
    @mock.patch('hb_report.core.find_ssh_user')
    def test_ssh_issue_root(self, mock_find_ssh_user, mock_getuid, mock_debug2):
        self.context.ssh_options = None
        self.context.ssh_user = "root"
        mock_getuid.return_value = 0

        core.ssh_issue(self.context)

        mock_find_ssh_user.assert_called_once_with(self.context)
        mock_getuid.assert_called_once_with()
        mock_debug2.assert_not_called()
    
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('os.getuid')
    @mock.patch('hb_report.core.find_ssh_user')
    def test_ssh_issue(self, mock_find_ssh_user, mock_getuid, mock_debug2):
        self.context.ssh_options = ["opt1", "opt2"]
        self.context.ssh_user = None
        mock_getuid.return_value = 2

        core.ssh_issue(self.context)

        mock_find_ssh_user.assert_called_once_with(self.context)
        mock_getuid.assert_has_calls([mock.call(), mock.call()])
        mock_debug2.assert_has_calls([
            mock.call("ssh user other than root, use sudo"),
            mock.call("Local user other than root, use sudo")
            ])

    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.core.crmutils.check_ssh_passwd_need')
    @mock.patch('hb_report.utils.me')
    def test_find_ssh_user_no_ssh_user_not_found(self, mock_me, mock_need_passed, mock_debug2, mock_warning):
        self.context.ssh_askpw_nodes = []
        self.context.ssh_user = None
        self.context.nodes = ["node1", "node2", "node3"]
        mock_me.side_effect = ["node1", "node1", "node1"]
        mock_need_passed.side_effect = [True, True, True, True, True, True]

        core.find_ssh_user(self.context)

        mock_me.assert_has_calls([mock.call(), mock.call(), mock.call()])
        mock_need_passed.assert_has_calls([
            mock.call(["node2"]),
            mock.call(["root@node2"]),
            mock.call(["hacluster@node2"]),
            mock.call(["node3"]),
            mock.call(["root@node3"]),
            mock.call(["hacluster@node3"]),
            ])
        mock_debug2.assert_has_calls([
            mock.call("ssh node2 failed"),
            mock.call("ssh root@node2 failed"),
            mock.call("ssh hacluster@node2 failed"),
            mock.call("ssh node3 failed"),
            mock.call("ssh root@node3 failed"),
            mock.call("ssh hacluster@node3 failed")
            ])
        mock_warning.assert_called_once_with("Passwordless ssh to node(s) ['node2', 'node3'] does not work")

    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.core.crmutils.check_ssh_passwd_need')
    @mock.patch('hb_report.utils.me')
    def test_find_ssh_user_no_ssh_user_root(self, mock_me, mock_need_passed, mock_debug2, mock_warning):
        self.context.ssh_askpw_nodes = []
        self.context.ssh_user = None
        self.context.nodes = ["node1", "node2", "node3"]
        mock_me.side_effect = ["node1", "node1", "node1"]
        mock_need_passed.side_effect = [True, False, False]

        core.find_ssh_user(self.context)

        mock_me.assert_has_calls([mock.call(), mock.call(), mock.call()])
        mock_need_passed.assert_has_calls([
            mock.call(["node2"]),
            mock.call(["root@node2"]),
            mock.call(["root@node3"])
            ])
        mock_debug2.assert_has_calls([
            mock.call("ssh node2 failed"),
            mock.call("ssh root@node2 OK"),
            mock.call("ssh root@node3 OK")
            ])
        mock_warning.assert_not_called()

    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.core.crmutils.check_ssh_passwd_need')
    @mock.patch('hb_report.utils.me')
    def test_find_ssh_user_has_ssh_user(self, mock_me, mock_need_passed, mock_debug2, mock_warning):
        self.context.ssh_askpw_nodes = []
        self.context.ssh_user = "test"
        self.context.nodes = ["node1", "node2", "node3"]
        mock_me.side_effect = ["node1", "node1", "node1"]
        mock_need_passed.side_effect = [False, False]

        core.find_ssh_user(self.context)

        mock_me.assert_has_calls([mock.call(), mock.call(), mock.call()])
        mock_need_passed.assert_has_calls([
            mock.call(["test@node2"]),
            mock.call(["test@node3"])
            ])
        mock_debug2.assert_has_calls([
            mock.call("ssh test@node2 OK"),
            mock.call("ssh test@node3 OK")
            ])
        mock_warning.assert_not_called()

    def test_say_ssh_user_no_ssh_user(self):
        self.context.ssh_user = None
        res = core.say_ssh_user(self.context)
        self.assertEqual(res, "your user")

    def test_say_ssh_user(self):
        self.context.ssh_user = "test"
        res = core.say_ssh_user(self.context)
        self.assertEqual(res, "test")

    @mock.patch('hb_report.core.Process')
    @mock.patch('hb_report.core.start_slave_collector')
    @mock.patch('hb_report.core.say_ssh_user')
    @mock.patch('hb_report.utils.log_info')
    def test_collect_for_nodes(self, mock_info, mock_ssh_user, mock_start_slave, mock_process):
        self.context.ssh_askpw_nodes = ["node2"]
        mock_ssh_user.return_value = "test"
        mock_process_inst = mock.Mock()
        mock_process.return_value = mock_process_inst

        core.collect_for_nodes(self.context)

        mock_ssh_user.assert_called_once_with(self.context)
        mock_info.assert_has_calls([
            mock.call("Please provide password for test at node2"),
            mock.call("Note that collecting data will take a while.")
            ])
        mock_start_slave.assert_called_once_with(self.context, "node2")
        mock_process.assert_called_once_with(target=mock_start_slave, args=(self.context, "node1"))
        mock_process_inst.start.assert_called_once_with()
        mock_process_inst.join.assert_called_once_with()

    @mock.patch('hb_report.utils.log_debug1')
    def test_sanitize_speed_up(self, mock_debug1):
        self.context.speed_up = True
        core.sanitize(self.context)
        mock_debug1.assert_called_once_with("Skip check sensitive info")

    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.core.sanitize_one')
    @mock.patch('os.path.isfile')
    @mock.patch('glob.glob')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.utils.log_debug2')
    def test_sanitize(self, mock_debug2, mock_join, mock_glob, mock_isfile,
            mock_sanitize_one, mock_warning):
        self.context.speed_up = False
        self.context.sensitive_regex = ["passw.*"]
        mock_join.side_effect = [
                "{}/pengine/*".format(self.context.work_dir),
                "{}/{}".format(self.context.work_dir, const.CIB_F),
                "{}/{}".format(self.context.work_dir, const.PCMK_LOG_F),
                "{}/{}".format(self.context.work_dir, const.CIB_TXT_F)
                ]
        mock_glob.return_value = ["{}/pengine/pe{}".format(self.context.work_dir, x) for x in range(2)]
        mock_isfile.side_effect = [True, True, True, True, True]
        mock_sanitize_one.side_effect = [0, 0, 1]

        core.sanitize(self.context)

        mock_debug2.assert_called_once_with("Check or replace sensitive info from cib, pe and log files")
        mock_join.assert_has_calls([
            mock.call(self.context.work_dir, "pengine", "*"),
            mock.call(self.context.work_dir, const.CIB_F),
            mock.call(self.context.work_dir, const.PCMK_LOG_F),
            mock.call(self.context.work_dir, const.CIB_TXT_F)
            ])
        mock_glob.assert_called_once_with("{}/pengine/*".format(self.context.work_dir))
        mock_isfile.assert_has_calls([
            mock.call("{}/{}".format(self.context.work_dir, const.CIB_F)),
            mock.call("{}/{}".format(self.context.work_dir, const.PCMK_LOG_F)),
            mock.call("{}/{}".format(self.context.work_dir, const.CIB_TXT_F)),
            mock.call("{}/pengine/pe0".format(self.context.work_dir)),
            mock.call("{}/pengine/pe1".format(self.context.work_dir))
            ])
        mock_sanitize_one.assert_has_calls([
            mock.call(self.context, "{}/{}".format(self.context.work_dir, const.CIB_F)),
            mock.call(self.context, "{}/{}".format(self.context.work_dir, const.PCMK_LOG_F)),
            mock.call(self.context, "{}/{}".format(self.context.work_dir, const.CIB_TXT_F))
            ])
        mock_warning.assert_has_calls([
            mock.call("Some PE/CIB/log files contain possibly sensitive data"),
            mock.call('Using "-s" option can replace sensitive data')
            ])

    @mock.patch('hb_report.core.include_sensitive_data')
    @mock.patch('hb_report.utils.read_from_file')
    def test_sanitize_one_no_data(self, mock_read, mock_include):
        mock_read.return_value = None
        core.sanitize_one(self.context, "file")
        mock_read.assert_called_once_with("file")
        mock_include.assert_not_called()

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.core.include_sensitive_data')
    @mock.patch('hb_report.utils.read_from_file')
    def test_sanitize_one_no_sensitive_data(self, mock_read, mock_include, mock_debug2):
        mock_read.return_value = "data"
        mock_include.return_value = False

        core.sanitize_one(self.context, "file")

        mock_read.assert_called_once_with("file")
        mock_include.assert_called_once_with(self.context, "data")
        mock_debug2.assert_not_called()

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.core.include_sensitive_data')
    @mock.patch('hb_report.utils.read_from_file')
    def test_sanitize_one_no_sanitize_flag(self, mock_read, mock_include, mock_debug2):
        self.context.sanitize = False
        mock_read.return_value = "data"
        mock_include.return_value = True

        rc = core.sanitize_one(self.context, "file")
        self.assertEqual(rc, 1)

        mock_read.assert_called_once_with("file")
        mock_include.assert_called_once_with(self.context, "data")
        mock_debug2.assert_not_called()

    @mock.patch('hb_report.utils.write_to_file')
    @mock.patch('os.path.basename')
    @mock.patch('hb_report.core.sub_sensitive_string')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.core.include_sensitive_data')
    @mock.patch('hb_report.utils.read_from_file')
    def test_sanitize_one_txt(self, mock_read, mock_include, mock_debug2, mock_sub,
            mock_basename, mock_write):
        self.context.sanitize = True
        mock_read.return_value = "data"
        mock_include.return_value = True
        mock_basename.return_value = const.CIB_TXT_F
        mock_sub.return_value = "sub data"

        core.sanitize_one(self.context, "file")

        mock_read.assert_called_once_with("file")
        mock_include.assert_called_once_with(self.context, "data")
        mock_debug2.assert_called_once_with("Replace sensitive info for file")
        mock_basename.assert_called_once_with("file")
        mock_sub.assert_called_once_with(self.context, "data", "txt")
        mock_write.assert_called_once_with("file", mock_sub.return_value)

    @mock.patch('hb_report.utils.write_to_file')
    @mock.patch('os.path.basename')
    @mock.patch('hb_report.core.sub_sensitive_string')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.core.include_sensitive_data')
    @mock.patch('hb_report.utils.read_from_file')
    def test_sanitize_one_xml(self, mock_read, mock_include, mock_debug2, mock_sub,
            mock_basename, mock_write):
        self.context.sanitize = True
        mock_read.return_value = "data"
        mock_include.return_value = True
        mock_basename.return_value = "xxx"
        mock_sub.return_value = "sub data"

        core.sanitize_one(self.context, "file")

        mock_read.assert_called_once_with("file")
        mock_include.assert_called_once_with(self.context, "data")
        mock_debug2.assert_called_once_with("Replace sensitive info for file")
        mock_basename.assert_called_once_with("file")
        mock_sub.assert_called_once_with(self.context, "data", "xml")
        mock_write.assert_called_once_with("file", mock_sub.return_value)

    @mock.patch('re.sub')
    @mock.patch('hb_report.core.include_sensitive_data')
    def test_sub_sensitive_string(self, mock_include, mock_sub):
        self.context.sanitize_pattern_string = "passw.*"
        mock_include.side_effect = [True, False]
        mock_sub.return_value = "sub data"

        data = "data1\ndata2\n"
        res = core.sub_sensitive_string(self.context, data, "xml")
        self.assertEqual(res, "sub data\ndata2\n")

        mock_include.assert_has_calls([
            mock.call(self.context, "data1"),
            mock.call(self.context, "data2")
            ])
        mock_sub.assert_called_once_with(' value=".*" ', ' value="******" ', "data1")

    @mock.patch('re.search')
    def test_include_sensitive_data_true_xml(self, mock_search):
        self.context.sanitize_pattern_string = "test"
        mock_search.return_value = True

        rc = core.include_sensitive_data(self.context, "data")
        self.assertTrue(rc)

        mock_search.assert_called_once_with('name="test"', "data")

    @mock.patch('re.search')
    def test_include_sensitive_data_true_txt(self, mock_search):
        self.context.sanitize_pattern_string = "test"
        mock_search.side_effect = [False, True]

        rc = core.include_sensitive_data(self.context, "data")
        self.assertTrue(rc)

        mock_search.assert_has_calls([
            mock.call('name="test"', "data"),
            mock.call('(test)=[^\"]', "data")
            ])

    @mock.patch('re.search')
    def test_include_sensitive_data_false(self, mock_search):
        self.context.sanitize_pattern_string = "test"
        mock_search.side_effect = [False, False]

        rc = core.include_sensitive_data(self.context, "data")
        self.assertFalse(rc)

        mock_search.assert_has_calls([
            mock.call('name="test"', "data"),
            mock.call('(test)=[^\"]', "data")
            ])

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.utils.read_from_file')
    def test_is_our_log_empty(self, mock_read, mock_debug2):
        mock_read.return_value = ''
        rc = core.is_our_log(self.context, "logfile")
        self.assertEqual(rc, 2)
        mock_read.assert_called_once_with("logfile")
        mock_debug2.assert_called_once_with('Found empty file "logfile"; exclude')

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.utils.find_first_ts')
    @mock.patch('hb_report.utils.tail')
    @mock.patch('hb_report.utils.head')
    @mock.patch('hb_report.utils.read_from_file')
    def test_is_our_log_irregular(self, mock_read, mock_head, mock_tail, mock_first, mock_debug2):
        mock_read.return_value = "data"
        mock_head.return_value = ["data", "data"]
        mock_tail.return_value = ["data", "data"]
        mock_first.side_effect = [None, None]

        rc = core.is_our_log(self.context, "logfile")
        self.assertEqual(rc, 1)

        mock_read.assert_called_once_with("logfile")
        mock_head.assert_called_once_with(10, "data")
        mock_tail.assert_called_once_with(10, "data")
        mock_first.assert_has_calls([
            mock.call(mock_head.return_value),
            mock.call(mock_tail.return_value)
            ])
        mock_debug2.assert_called_once_with('Found irregular file "logfile"; include')

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.utils.find_first_ts')
    @mock.patch('hb_report.utils.tail')
    @mock.patch('hb_report.utils.head')
    @mock.patch('hb_report.utils.read_from_file')
    def test_is_our_log_outdate_case1(self, mock_read, mock_head, mock_tail, mock_first, mock_debug2):
        mock_read.return_value = "data"
        mock_head.return_value = ["data", "data"]
        mock_tail.return_value = ["data", "data"]
        mock_first.side_effect = [1, 1]

        rc = core.is_our_log(self.context, "logfile")
        self.assertEqual(rc, 3)

        mock_read.assert_called_once_with("logfile")
        mock_head.assert_called_once_with(10, "data")
        mock_tail.assert_called_once_with(10, "data")
        mock_first.assert_has_calls([
            mock.call(mock_head.return_value),
            mock.call(mock_tail.return_value)
            ])
        mock_debug2.assert_called_once_with('Found before timespan file "logfile"; exclude')

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.utils.find_first_ts')
    @mock.patch('hb_report.utils.tail')
    @mock.patch('hb_report.utils.head')
    @mock.patch('hb_report.utils.read_from_file')
    def test_is_our_log_outdate_case2(self, mock_read, mock_head, mock_tail, mock_first, mock_debug2):
        mock_read.return_value = "data"
        mock_head.return_value = ["data", "data"]
        mock_tail.return_value = ["data", "data"]
        mock_first.side_effect = [self.context.to_time+1, self.context.to_time+10]

        rc = core.is_our_log(self.context, "logfile")
        self.assertEqual(rc, 4)

        mock_read.assert_called_once_with("logfile")
        mock_head.assert_called_once_with(10, "data")
        mock_tail.assert_called_once_with(10, "data")
        mock_first.assert_has_calls([
            mock.call(mock_head.return_value),
            mock.call(mock_tail.return_value)
            ])
        mock_debug2.assert_called_once_with('Found after timespan file "logfile"; exclude')

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.utils.find_first_ts')
    @mock.patch('hb_report.utils.tail')
    @mock.patch('hb_report.utils.head')
    @mock.patch('hb_report.utils.read_from_file')
    def test_is_our_log_case1(self, mock_read, mock_head, mock_tail, mock_first, mock_debug2):
        mock_read.return_value = "data"
        mock_head.return_value = ["data", "data"]
        mock_tail.return_value = ["data", "data"]
        mock_first.side_effect = [self.context.to_time, self.context.to_time+1]

        rc = core.is_our_log(self.context, "logfile")
        self.assertEqual(rc, 0)

        mock_read.assert_called_once_with("logfile")
        mock_head.assert_called_once_with(10, "data")
        mock_tail.assert_called_once_with(10, "data")
        mock_first.assert_has_calls([
            mock.call(mock_head.return_value),
            mock.call(mock_tail.return_value)
            ])
        mock_debug2.assert_called_once_with('Found in timespan file "logfile"; include')

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.utils.find_first_ts')
    @mock.patch('hb_report.utils.tail')
    @mock.patch('hb_report.utils.head')
    @mock.patch('hb_report.utils.read_from_file')
    def test_is_our_log_case2(self, mock_read, mock_head, mock_tail, mock_first, mock_debug2):
        mock_read.return_value = "data"
        mock_head.return_value = ["data", "data"]
        mock_tail.return_value = ["data", "data"]
        mock_first.side_effect = [self.context.from_time, self.context.from_time+1]

        rc = core.is_our_log(self.context, "logfile")
        self.assertEqual(rc, 0)

        mock_read.assert_called_once_with("logfile")
        mock_head.assert_called_once_with(10, "data")
        mock_tail.assert_called_once_with(10, "data")
        mock_first.assert_has_calls([
            mock.call(mock_head.return_value),
            mock.call(mock_tail.return_value)
            ])
        mock_debug2.assert_called_once_with('Found in timespan file "logfile"; include')

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.core.is_our_log')
    @mock.patch('os.path.getmtime')
    @mock.patch('builtins.sorted')
    @mock.patch('glob.glob')
    def test_arch_logs(self, mock_glob, mock_sorted, mock_getmtime, mock_is_our_log, mock_debug2):
        mock_glob.return_value = ["file1.gz", "file2.gz"]
        mock_sorted.return_value = ["file0", "file1.gz", "file2.gz"]
        mock_is_our_log.side_effect = [2, 0, 1]

        rc, res = core.arch_logs(self.context, "file0")
        self.assertEqual(res, ["file1.gz", "file2.gz"])

        mock_glob.assert_called_once_with("file0*[0-9z]")
        mock_sorted.assert_called_once_with(
                ["file0", "file1.gz", "file2.gz"],
                key=mock_getmtime,
                reverse=True)
        mock_is_our_log.assert_has_calls([
            mock.call(self.context, "file0"),
            mock.call(self.context, "file1.gz"),
            mock.call(self.context, "file2.gz")
            ])
        mock_debug2.assert_called_once_with("Found logs {}".format(res))

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.core.is_our_log')
    @mock.patch('os.path.getmtime')
    @mock.patch('builtins.sorted')
    @mock.patch('glob.glob')
    def test_arch_logs_before(self, mock_glob, mock_sorted, mock_getmtime, mock_is_our_log, mock_debug2):
        mock_glob.return_value = ["file1.gz", "file2.gz"]
        mock_sorted.return_value = ["file0", "file1.gz", "file2.gz"]
        mock_is_our_log.return_value = 3

        rc, res = core.arch_logs(self.context, "file0")
        self.assertEqual((rc, res), (-1, []))

        mock_glob.assert_called_once_with("file0*[0-9z]")
        mock_sorted.assert_called_once_with(
                ["file0", "file1.gz", "file2.gz"],
                key=mock_getmtime,
                reverse=True)
        mock_is_our_log.assert_called_once_with(self.context, "file0")
        mock_debug2.assert_not_called()

    @mock.patch('hb_report.utils.ts_to_str')
    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.utils.findln_by_time')
    @mock.patch('hb_report.utils.read_from_file')
    def test_print_logseg_from_none(self, mock_read, mock_findln, mock_warn, mock_ts_to_str):
        mock_read.return_value = "data"
        mock_findln.return_value = None
        mock_ts_to_str.return_value = "20190101"

        core.print_logseg("file1", 1, 1)

        mock_read.assert_called_once_with("file1")
        mock_findln.assert_called_once_with(mock_read.return_value, 1)
        mock_ts_to_str.assert_called_once_with(1)
        mock_warn.assert_called_once_with("Couldn't find line in file1 for time 20190101")

    @mock.patch('hb_report.utils.ts_to_str')
    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.utils.findln_by_time')
    @mock.patch('hb_report.utils.read_from_file')
    def test_print_logseg_to_none(self, mock_read, mock_findln, mock_warn, mock_ts_to_str):
        mock_read.return_value = "data"
        mock_findln.side_effect = [23, None]
        mock_ts_to_str.return_value = "20190102"

        core.print_logseg("file1", 1, 2)

        mock_read.assert_called_once_with("file1")
        mock_findln.assert_has_calls([
            mock.call(mock_read.return_value, 1),
            mock.call(mock_read.return_value, 2)
            ])
        mock_ts_to_str.assert_called_once_with(2)
        mock_warn.assert_called_once_with("Couldn't find line in file1 for time 20190102")

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.utils.filter_lines')
    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.utils.findln_by_time')
    @mock.patch('hb_report.utils.read_from_file')
    def test_print_logseg(self, mock_read, mock_findln, mock_warn, mock_filter, mock_debug2):
        mock_read.return_value = "data"
        mock_findln.side_effect = [23, 46]
        mock_filter.return_value = "data1\ndata2"

        res = core.print_logseg("file1", 1, 2)
        self.assertEqual(res, mock_filter.return_value)

        mock_read.assert_called_once_with("file1")
        mock_findln.assert_has_calls([
            mock.call(mock_read.return_value, 1),
            mock.call(mock_read.return_value, 2)
            ])
        mock_debug2.assert_called_once_with("Including segment [23-46] from file1")
        mock_filter.assert_called_once_with("data", 23, 46)

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.utils.filter_lines')
    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.utils.findln_by_time')
    @mock.patch('hb_report.utils.read_from_file')
    def test_print_logseg_direct(self, mock_read, mock_findln, mock_warn, mock_filter, mock_debug2):
        mock_read.return_value = "data1\ndata2"
        mock_filter.return_value = "data1\ndata2"

        res = core.print_logseg("file1", 0, 0)
        self.assertEqual(res, mock_filter.return_value)

        mock_read.assert_called_once_with("file1")
        mock_findln.assert_not_called()
        mock_debug2.assert_called_once_with("Including segment [1-2] from file1")
        mock_filter.assert_called_once_with(mock_read.return_value, 1, 2)

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.core.arch_logs')
    def test_dump_logset_none(self, mock_arch, mock_debug2):
        mock_arch.return_value = (-1, [])
        core.dump_logset(self.context, "/var/log/pacemaker.log")
        mock_arch.assert_called_once_with(self.context, "/var/log/pacemaker.log")
        mock_debug2.assert_called_once_with("No suitable log set found for log /var/log/pacemaker.log")

    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('hb_report.core.crmutils.str2file')
    @mock.patch('os.path.join')
    @mock.patch('os.path.basename')
    @mock.patch('hb_report.core.print_logseg')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.core.arch_logs')
    def test_dump_logset_irregular(self, mock_arch, mock_debug2, mock_printlog,
            mock_basename, mock_join, mock_str2file, mock_debug1):
        mock_arch.return_value = (1, ["/var/log/pacemaker.log"])
        mock_printlog.return_value = "data\n"
        mock_basename.side_effect = ["pacemaker.log", "pacemaker.log"]
        mock_join.return_value = "{}/pacemaker.log".format(self.context.work_dir)
        
        core.dump_logset(self.context, "/var/log/pacemaker.log")

        mock_arch.assert_called_once_with(self.context, "/var/log/pacemaker.log")
        mock_printlog.assert_called_once_with("/var/log/pacemaker.log", 0, 0)
        mock_debug2.assert_called_once_with("Including complete /var/log/pacemaker.log logfile")
        mock_basename.assert_has_calls([
            mock.call("/var/log/pacemaker.log"),
            mock.call("/var/log/pacemaker.log")
            ])
        mock_join.assert_called_once_with(self.context.work_dir, "pacemaker.log")
        mock_str2file.assert_called_once_with("data", mock_join.return_value)
        mock_debug1.assert_called_once_with("Dump logset {} into {}/pacemaker.log".\
                format(mock_arch.return_value[1], self.context.dest_path))

    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('hb_report.core.crmutils.str2file')
    @mock.patch('os.path.join')
    @mock.patch('os.path.basename')
    @mock.patch('hb_report.core.print_logseg')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.core.arch_logs')
    def test_dump_logset_one_file(self, mock_arch, mock_debug2, mock_printlog,
            mock_basename, mock_join, mock_str2file, mock_debug1):
        mock_arch.return_value = (0, ["/var/log/pacemaker.log"])
        mock_printlog.return_value = "data\n"
        mock_basename.side_effect = ["pacemaker.log", "pacemaker.log"]
        mock_join.return_value = "{}/pacemaker.log".format(self.context.work_dir)

        core.dump_logset(self.context, "/var/log/pacemaker.log")

        mock_arch.assert_called_once_with(self.context, "/var/log/pacemaker.log")
        mock_printlog.assert_called_once_with("/var/log/pacemaker.log", self.context.from_time, self.context.to_time)
        mock_basename.assert_has_calls([
            mock.call("/var/log/pacemaker.log"),
            mock.call("/var/log/pacemaker.log")
            ])
        mock_join.assert_called_once_with(self.context.work_dir, "pacemaker.log")
        mock_str2file.assert_called_once_with("data", mock_join.return_value)
        mock_debug1.assert_called_once_with("Dump logset {} into {}/pacemaker.log".\
                format(mock_arch.return_value[1], self.context.dest_path))

    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('hb_report.core.crmutils.str2file')
    @mock.patch('os.path.join')
    @mock.patch('os.path.basename')
    @mock.patch('hb_report.core.print_logseg')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.core.arch_logs')
    def test_dump_logset(self, mock_arch, mock_debug2, mock_printlog, mock_basename,
            mock_join, mock_str2file, mock_debug1):
        mock_arch.return_value = (0, ["/var/log/pacemaker.log",
                "/var/log/pacemaker1.log", "/var/log/pacemaker2.log"])
        mock_printlog.side_effect = ["data1\n", "data2\n", "data3\n"]
        mock_basename.side_effect = ["pacemaker.log", "pacemaker.log"]
        mock_join.return_value = "{}/pacemaker.log".format(self.context.work_dir)

        core.dump_logset(self.context, "/var/log/pacemaker.log")

        mock_arch.assert_called_once_with(self.context, "/var/log/pacemaker.log")
        mock_printlog.assert_has_calls([
            mock.call("/var/log/pacemaker2.log", self.context.from_time, 0),
            mock.call("/var/log/pacemaker1.log", 0, 0),
            mock.call("/var/log/pacemaker.log", 0, self.context.to_time),
            ])
        mock_debug2("Including complete /var/log/pacemaker1.log logfile")
        mock_basename.assert_has_calls([
            mock.call("/var/log/pacemaker.log"),
            mock.call("/var/log/pacemaker.log")
            ])
        mock_join.assert_called_once_with(self.context.work_dir, "pacemaker.log")
        mock_str2file.assert_called_once_with("data1\ndata2\ndata3", mock_join.return_value)
        mock_debug1.assert_called_once_with("Dump logset {} into {}/pacemaker.log".\
                format(mock_arch.return_value[1], self.context.dest_path))

    @mock.patch('hb_report.core.sanitize')
    @mock.patch('hb_report.core.Process')
    @mock.patch('hb_report.collect.sys_stats')
    @mock.patch('hb_report.collect.sys_info')
    def test_collect_other_logs_and_info(self, mock_sys_info, mock_sys_stats, mock_process, mock_sanitize):
        const.COLLECT_FUNCTIONS = ("sys_info", "sys_stats")
        mock_process_inst1 = mock.Mock()
        mock_process_inst2 = mock.Mock()
        mock_process.side_effect = [mock_process_inst1, mock_process_inst2]

        core.collect_other_logs_and_info(self.context)

        mock_process.assert_has_calls([
            mock.call(target=mock_sys_info, args=(self.context,)),
            mock.call(target=mock_sys_stats, args=(self.context,))
            ])
        mock_process_inst1.start.assert_called_once_with()
        mock_process_inst1.join.assert_called_once_with()
        mock_process_inst2.start.assert_called_once_with()
        mock_process_inst2.join.assert_called_once_with()
        mock_sanitize.assert_called_once_with(self.context)

    @mock.patch('hb_report.utils.log_fatal')
    @mock.patch('os.path.isdir')
    @mock.patch('hb_report.utils.dirname')
    def test_valid_dest_invalid_dir(self, mock_dir, mock_isdir, mock_fatal):
        self.context.dest = "dir/file"
        mock_dir.return_value = "dir"
        mock_isdir.return_value = False
        mock_fatal.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            core.valid_dest(self.context)

        mock_dir.assert_called_once_with(self.context.dest)
        mock_isdir.assert_called_once_with(mock_dir.return_value)
        mock_fatal.assert_called_once_with('{} is invalid directory name'.format(mock_dir.return_value))

    @mock.patch('hb_report.utils.log_fatal')
    @mock.patch('hb_report.core.crmutils.is_filename_sane')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.isdir')
    @mock.patch('hb_report.utils.dirname')
    def test_valid_dest_invalid_filename(self, mock_dir, mock_isdir, mock_basename,
            mock_sane, mock_fatal):
        self.context.dest = "dir/file"
        mock_dir.return_value = "dir"
        mock_isdir.return_value = True
        mock_basename.return_value = "file"
        mock_sane.return_value = False
        mock_fatal.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            core.valid_dest(self.context)

        mock_dir.assert_called_once_with(self.context.dest)
        mock_isdir.assert_called_once_with(mock_dir.return_value)
        mock_basename.assert_called_once_with(self.context.dest)
        mock_sane.assert_called_once_with(mock_basename.return_value)
        mock_fatal.assert_called_once_with('{} is invalid file name'.format(mock_basename.return_value))

    @mock.patch('hb_report.utils.log_fatal')
    @mock.patch('hb_report.core.crmutils.is_filename_sane')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.isdir')
    @mock.patch('hb_report.utils.dirname')
    def test_valid_dest_no_remove(self, mock_dir, mock_isdir, mock_basename, mock_sane, mock_fatal):
        self.context.dest = "dir"
        self.context.no_compress = True
        self.context.rm_exist_dest = False
        mock_dir.return_value = "dir"
        mock_isdir.side_effect = [True, True]
        mock_basename.return_value = "dir"
        mock_sane.return_value = True
        mock_fatal.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            core.valid_dest(self.context)

        mock_dir.assert_called_once_with(self.context.dest)
        mock_isdir.assert_has_calls([
            mock.call(mock_dir.return_value),
            mock.call(self.context.dest)
            ])
        mock_basename.assert_called_once_with(self.context.dest)
        mock_sane.assert_called_once_with(mock_basename.return_value)
        mock_fatal.assert_called_once_with('Destination directory {} exists, please cleanup or use -Z option'.format(self.context.dest))

    @mock.patch('hb_report.utils.log_fatal')
    @mock.patch('shutil.rmtree')
    @mock.patch('hb_report.core.crmutils.is_filename_sane')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.isdir')
    @mock.patch('hb_report.utils.dirname')
    def test_valid_dest(self, mock_dir, mock_isdir, mock_basename, mock_sane, mock_rmtree, mock_fatal):
        self.context.dest = "dir"
        self.context.no_compress = True
        self.context.rm_exist_dest = True
        mock_dir.return_value = "dir"
        mock_isdir.side_effect = [True, True]
        mock_basename.return_value = "dir"
        mock_sane.return_value = True

        core.valid_dest(self.context)

        mock_dir.assert_called_once_with(self.context.dest)
        mock_isdir.assert_has_calls([
            mock.call(mock_dir.return_value),
            mock.call(self.context.dest)
            ])
        mock_basename.assert_called_once_with(self.context.dest)
        mock_sane.assert_called_once_with(mock_basename.return_value)
        mock_rmtree.assert_called_once_with(self.context.dest)
        mock_fatal.assert_not_called()

    @mock.patch('builtins.eval')
    @mock.patch('hb_report.core.crmutils.get_stdout_stderr')
    @mock.patch('hb_report.utils.me')
    def test_start_slave_collector_local(self, mock_me, mock_stdout_stderr, mock_eval):
        self.context.local_sudo = "sudo"
        mock_me.return_value = "node1"
        mock_stdout_stderr.return_value = (0, "{}hb_report data\nlog1\nlog2".format(const.COMPRESS_DATA_FLAG), None)
        mock_eval.return_value = "hb_report data".encode('utf-8')
 
        core.start_slave_collector(self.context, "node1")

        mock_me.assert_called_once_with()
        cmd_slave = r"{} __slave '{}'".format(self.context.name, self.context)
        cmd1 = r'{} {}'.format(self.context.local_sudo, cmd_slave)
        cmd2 = r"(cd {} && tar xf -)".format(self.context.work_dir)
        mock_stdout_stderr.assert_has_calls([
            mock.call(cmd1),
            mock.call(cmd2, input_s=mock_eval.return_value)
            ])

    @mock.patch('hb_report.utils.log_error')
    @mock.patch('hb_report.core.crmutils.get_stdout_stderr')
    @mock.patch('hb_report.utils.me')
    def test_start_slave_collector(self, mock_me, mock_stdout_stderr, mock_error):
        self.context.sudo = "sudo"
        self.context.ssh_options = ""
        mock_me.return_value = "node1"
        mock_stdout_stderr.return_value = (255, None, "ssh error")

        core.start_slave_collector(self.context, "node2")

        mock_me.assert_called_once_with()
        cmd_slave = r"{} __slave '{}'".format(self.context.name, self.context)
        cmd = r'ssh -o {} {} "{} {}"'.format(' -o '.join(self.context.ssh_options), "node2", self.context.sudo, cmd_slave.replace('"', '\\"'))
        mock_stdout_stderr.assert_called_once_with(cmd)
        mock_error.assert_called_once_with("ssh error")

    @mock.patch('hb_report.core.crmutils.is_program')
    def test_pick_first_none(self, mock_is_program):
        mock_is_program.side_effect = [False, False]
        res = core.pick_first(["bzip2", "gzip"])
        self.assertEqual(res, None)
        mock_is_program.assert_has_calls([mock.call("bzip2"), mock.call("gzip")])

    @mock.patch('hb_report.core.crmutils.is_program')
    def test_pick_first(self, mock_is_program):
        mock_is_program.return_value = True
        res = core.pick_first(["bzip2", "gzip"])
        self.assertEqual(res, "bzip2")
        mock_is_program.assert_called_once_with("bzip2")

    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.core.pick_first')
    def test_pick_compress_no_prog(self, mock_pick, mock_warning):
        compress_prog_ext_dict = {
            "bzip2": ".bz2",
            "gzip": ".gz",
            "xz":".xz"
        }
        mock_pick.return_value = None
        core.pick_compress(self.context)
        self.assertEqual(self.context.compress_prog, "cat")
        mock_pick.assert_called_once_with(compress_prog_ext_dict.keys())
        mock_warning.assert_called_once_with("Could not find a compression program; the resulting tarball may be huge")

    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.core.pick_first')
    def test_pick_compress(self, mock_pick, mock_warning):
        compress_prog_ext_dict = {
            "bzip2": ".bz2",
            "gzip": ".gz",
            "xz":".xz"
        }
        mock_pick.return_value = "bzip2"
        core.pick_compress(self.context)
        self.assertEqual(self.context.compress_ext, ".bz2")
        mock_pick.assert_called_once_with(compress_prog_ext_dict.keys())
        mock_warning.assert_not_called()

    @mock.patch('hb_report.utils.log_info')
    def test_finalword_no_compress(self, mock_info):
        self.context.no_compress = True
        self.context.dest_dir = "/opt"
        self.context.dest = "report"

        core.finalword(self.context)

        dest_path = "{}/{}".format(self.context.dest_dir, self.context.dest)
        mock_info.assert_has_calls([
            mock.call("The report is saved in {}".format(dest_path)),
            mock.call("Report timespan: {} - {}".format(self.context.from_time_str, self.context.to_time_str)),
            mock.call("Thank you for taking time to create this report.")
            ])

    @mock.patch('hb_report.utils.log_info')
    def test_finalword(self, mock_info):
        self.context.no_compress = False
        self.context.dest_dir = "/opt"
        self.context.dest = "report"
        self.context.compress_ext = ".bz2"

        core.finalword(self.context)

        dest_path = "{}/{}.tar{}".format(self.context.dest_dir, self.context.dest, self.context.compress_ext)
        mock_info.assert_has_calls([
            mock.call("The report is saved in {}".format(dest_path)),
            mock.call("Report timespan: {} - {}".format(self.context.from_time_str, self.context.to_time_str)),
            mock.call("Thank you for taking time to create this report.")
            ])

    @mock.patch('hb_report.core.finalword')
    @mock.patch('shutil.move')
    @mock.patch('hb_report.core.analyze')
    def test_process_results_no_compress(self, mock_analyze, mock_move, mock_finalword):
        self.context.no_compress = True
        self.context.dest_dir = "/opt"
        core.process_results(self.context)
        mock_analyze.assert_called_once_with(self.context)
        mock_move.assert_called_once_with(self.context.work_dir, self.context.dest_dir)
        mock_finalword.assert_called_once_with(self.context)

    @mock.patch('hb_report.core.finalword')
    @mock.patch('hb_report.core.crmutils.get_stdout')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.core.pick_compress')
    @mock.patch('hb_report.core.analyze')
    def test_process_results(self, mock_analyze, mock_pick, mock_debug2, mock_run, mock_finalword):
        self.context.no_compress = False
        self.context.dest = "report"
        self.context.dest_dir = "/opt"
        self.context.compress_prog = "cat"
        self.context.compress_ext = ""
        cmd_meta = {
            "w_dir": self.context.work_dir,
            "dest": self.context.dest,
            "d_dir": self.context.dest_dir,
            "comp_prog": self.context.compress_prog,
            "comp_ext": self.context.compress_ext
        }

        core.process_results(self.context)

        cmd = r"(cd {w_dir}/.. && tar cf - {dest})|{comp_prog} > {d_dir}/{dest}.tar{comp_ext}".format(**cmd_meta)
        mock_analyze.assert_called_once_with(self.context)
        mock_pick.assert_called_once_with(self.context)
        mock_debug2.assert_called_once_with("Running: {}".format(cmd))
        mock_run.assert_called_once_with(cmd)
        mock_finalword.assert_called_once_with(self.context)

    @mock.patch('hb_report.core.crmutils.get_stdout_stderr')
    def test_text_diff(self, mock_run):
        mock_run.return_value = (0, "Diff text", None)
        rc, data = core.text_diff("file1", "file2")
        self.assertEqual((rc, data), (True, "Diff text\n"))
        mock_run.assert_called_once_with("diff -bBu file1 file2")

    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.utils.which')
    def test_cib_diff_no_cmd(self, mock_which, mock_warning):
        mock_which.return_value = False
        rc, data = core.cib_diff("cib1", "cib2")
        self.assertEqual((rc, data), (False, ""))
        mock_which.assert_called_once_with("crm_diff")
        mock_warning.assert_called_once_with("crm_diff(8) not found, cannot diff CIBs")

    @mock.patch('hb_report.core.crmutils.get_stdout_stderr')
    @mock.patch('os.path.isfile')
    @mock.patch('os.path.join')
    @mock.patch('os.path.dirname')
    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.utils.which')
    def test_cib_diff_cant_compare(self, mock_which, mock_warning, mock_dirname,
            mock_join, mock_isfile, mock_run):
        mock_which.return_value = True
        mock_dirname.side_effect = ["dir1", "dir2"]
        mock_join.side_effect = ["dir1/RUNNING","dir2/RUNNING", "dir1/STOPPED", "dir2/STOPPED"]
        mock_isfile.side_effect = [False, False]

        rc, data = core.cib_diff("cib1", "cib2")
        self.assertEqual((rc, data), (False, "Can't compare cibs from running and stopped systems\n"))

        mock_which.assert_called_once_with("crm_diff")
        mock_dirname.assert_has_calls([mock.call("cib1"), mock.call("cib2")])
        mock_join.assert_has_calls([
            mock.call("dir1", "RUNNING"),
            mock.call("dir2", "RUNNING"),
            mock.call("dir1", "STOPPED"),
            mock.call("dir2", "STOPPED")
            ])
        mock_isfile.assert_has_calls([
            mock.call("dir1/RUNNING"),
            mock.call("dir1/STOPPED")
            ])
        mock_run.assert_not_called()
        mock_warning.assert_not_called()

    @mock.patch('hb_report.core.crmutils.get_stdout_stderr')
    @mock.patch('os.path.isfile')
    @mock.patch('os.path.join')
    @mock.patch('os.path.dirname')
    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.utils.which')
    def test_cib_diff(self, mock_which, mock_warning, mock_dirname, mock_join,
            mock_isfile, mock_run):
        mock_which.return_value = True
        mock_dirname.side_effect = ["dir1", "dir2"]
        mock_join.side_effect = ["dir1/RUNNING","dir2/RUNNING", "dir1/STOPPED", "dir2/STOPPED"]
        mock_isfile.side_effect = [True, True, True, True]
        mock_run.return_value = (0, "Diff data", None)

        rc, data = core.cib_diff("cib1", "cib2")
        self.assertEqual((rc, data), (True, "Diff data\n"))

        mock_which.assert_called_once_with("crm_diff")
        mock_dirname.assert_has_calls([mock.call("cib1"), mock.call("cib2")])
        mock_join.assert_has_calls([
            mock.call("dir1", "RUNNING"),
            mock.call("dir2", "RUNNING"),
            mock.call("dir1", "STOPPED"),
            mock.call("dir2", "STOPPED")
            ])
        mock_isfile.assert_has_calls([mock.call(m) for m in mock_join.side_effect])
        mock_run.assert_called_once_with("crm_diff -c -n cib1 -o cib2")
        mock_warning.assert_not_called()

    @mock.patch('os.path.exists')
    def test_diff_check_not_exist(self, mock_exists):
        mock_exists.return_value = False
        rc, data = core.diff_check("file1", "file2")
        self.assertEqual((rc, data), (False, "file1 does not exist\n"))
        mock_exists.assert_called_once_with("file1")

    @mock.patch('hb_report.core.cib_diff')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.exists')
    def test_diff_check_cib(self, mock_exists, mock_basename, mock_cib_diff):
        mock_exists.side_effect = [True, True]
        mock_basename.return_value = const.CIB_F
        mock_cib_diff.return_value = (True, "Diff data")

        rc, data = core.diff_check("cib1", "cib2")
        self.assertEqual((rc, data), (True, "Diff data"))

        mock_exists.assert_has_calls([mock.call("cib1"), mock.call("cib2")])
        mock_basename.assert_called_once_with("cib1")
        mock_cib_diff.assert_called_once_with("cib1", "cib2")

    @mock.patch('hb_report.core.text_diff')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.exists')
    def test_diff_check_text(self, mock_exists, mock_basename, mock_text_diff):
        mock_exists.side_effect = [True, True]
        mock_basename.return_value = "text1"
        mock_text_diff.return_value = (True, "Diff data")

        rc, data = core.diff_check("text1", "text2")
        self.assertEqual((rc, data), (True, "Diff data"))

        mock_exists.assert_has_calls([mock.call("text1"), mock.call("text2")])
        mock_basename.assert_called_once_with("text1")
        mock_text_diff.assert_called_once_with("text1", "text2")

    @mock.patch("builtins.open", new_callable=mock.mock_open, read_data="verify data")
    @mock.patch('os.path.isfile')
    @mock.patch('os.path.join')
    def test_check_crmvfy(self, mock_join, mock_isfile, mock_open_file):
        mock_join.side_effect = [
                "{}/node1/{}".format(self.context.work_dir, const.CRM_VERIFY_F),
                "{}/node2/{}".format(self.context.work_dir, const.CRM_VERIFY_F),
                ]
        mock_isfile.side_effect = [True, False]

        res = core.check_crmvfy(self.context)
        self.assertEqual(res, "WARN: crm_verify reported warnings at node1:\nverify data")

        mock_join.assert_has_calls([
            mock.call(self.context.work_dir, "node1", const.CRM_VERIFY_F),
            mock.call(self.context.work_dir, "node2", const.CRM_VERIFY_F)
            ])
        mock_isfile.assert_has_calls([mock.call(m) for m in mock_join.side_effect])
        mock_open_file.assert_called_once_with("{}/node1/{}".format(self.context.work_dir, const.CRM_VERIFY_F))

    @mock.patch('glob.glob')
    @mock.patch('os.path.join')
    def test_check_cores(self, mock_join, mock_glob):
        mock_join.return_value = "{}/*/cores/*".format(self.context.work_dir)
        mock_glob.return_value = ["work_dir/node1/cores/core1", "work_dir/node1/cores/core2"]

        res = core.check_cores(self.context)
        self.assertEqual(res, "WARN: coredupmps found at:\n  work_dir/node1/cores/core1\n  work_dir/node1/cores/core2\n")

        mock_join.assert_called_once_with(self.context.work_dir, "*/cores/*")
        mock_glob.assert_called_once_with(mock_join.return_value)

    @mock.patch('glob.glob')
    @mock.patch('os.path.join')
    @mock.patch('os.path.basename')
    def test_check_logs_empty(self, mock_basename, mock_join, mock_glob):
        self.context.extra_logs = ["/var/log/pacemaker1.log", "/var/log/pacemaker2.log"]
        mock_basename.side_effect = ["pacemaker1.log", "pacemaker2.log"]
        mock_join.side_effect = [
                "{}/*/{}".format(self.context.work_dir, "pacemaker1.log"),
                "{}/*/{}".format(self.context.work_dir, "pacemaker2.log"),
                "{}/*/{}".format(self.context.work_dir, const.HALOG_F)
                ]
        mock_glob.side_effect = [[], [], []]

        res = core.check_logs(self.context)
        self.assertEqual(res, "")

        mock_basename.assert_has_calls([
            mock.call("/var/log/pacemaker1.log"),
            mock.call("/var/log/pacemaker2.log")
            ])
        mock_join.assert_has_calls([
            mock.call(self.context.work_dir, '*/{}'.format("pacemaker1.log")),
            mock.call(self.context.work_dir, '*/{}'.format("pacemaker2.log")),
            mock.call(self.context.work_dir, '*/{}'.format(const.HALOG_F))
            ])
        mock_glob.assert_has_calls([mock.call(m) for m in mock_join.side_effect])

    @mock.patch('hb_report.core.filter_log')
    @mock.patch('glob.glob')
    @mock.patch('os.path.join')
    @mock.patch('os.path.basename')
    def test_check_logs(self, mock_basename, mock_join, mock_glob, mock_filter_log):
        self.context.regex = ["patt1", "patt2"]
        self.context.extra_logs = ["/var/log/pacemaker1.log", "/var/log/pacemaker2.log"]
        mock_basename.side_effect = ["pacemaker1.log", "pacemaker2.log"]
        mock_join.side_effect = [
                "{}/*/{}".format(self.context.work_dir, "pacemaker1.log"),
                "{}/*/{}".format(self.context.work_dir, "pacemaker2.log"),
                "{}/*/{}".format(self.context.work_dir, const.HALOG_F)
                ]
        mock_glob.side_effect = [
                ["workdir/node1/pacemaker1.log", "workdir/node2/pacemaker1.log"],
                ["workdir/node1/pacemaker2.log"],
                ["workdir/node1/{}".format(const.HALOG_F)]
                ]
        mock_filter_log.side_effect = ["data1\n", "data2\n", "data3\n", "data4\n"]

        res = core.check_logs(self.context)
        self.assertEqual(res, "\nLog patterns:\ndata1\ndata2\ndata3\ndata4\n")

        mock_basename.assert_has_calls([
            mock.call("/var/log/pacemaker1.log"),
            mock.call("/var/log/pacemaker2.log")
            ])
        mock_join.assert_has_calls([
            mock.call(self.context.work_dir, '*/{}'.format("pacemaker1.log")),
            mock.call(self.context.work_dir, '*/{}'.format("pacemaker2.log")),
            mock.call(self.context.work_dir, '*/{}'.format(const.HALOG_F))
            ])
        mock_glob.assert_has_calls([mock.call(m) for m in mock_join.side_effect])
        mock_filter_log.assert_has_calls([
            mock.call("workdir/node1/pacemaker1.log", "patt1|patt2"),
            mock.call("workdir/node2/pacemaker1.log", "patt1|patt2"),
            mock.call("workdir/node1/pacemaker2.log", "patt1|patt2"),
            mock.call("workdir/node1/{}".format(const.HALOG_F), "patt1|patt2"),
            ])

    @mock.patch('re.search')
    @mock.patch("builtins.open", new_callable=mock.mock_open, read_data="data1\ndata2")
    def test_filter_log(self, mock_open_file, mock_search):
        mock_search.side_effect = [True, False]

        res = core.filter_log("logfile", "pattstr")
        self.assertEqual(res, "data1\n")

        mock_open_file.assert_called_once_with("logfile", encoding='utf-8', errors='replace')
        mock_search.assert_has_calls([
            mock.call("pattstr", "data1"),
            mock.call("pattstr", "data2")
            ])

    @mock.patch('hb_report.core.diff_check')
    @mock.patch('os.path.join')
    def test_analyze_one(self, mock_join, mock_diff_check):
        self.context.nodes = ["node1", "node2", "node3"]
        mock_join.side_effect = [
                "{}/node1/file1".format(self.context.work_dir),
                "{}/node2/file1".format(self.context.work_dir),
                "{}/node3/file1".format(self.context.work_dir)
                ]
        mock_diff_check.side_effect = [(True, "Diff data1\n"), (True, "Diff data2\n")]

        rc, out = core.analyze_one(self.context, "file1")
        self.assertEqual((rc, out), (True, "Diff data1\nDiff data2\n"))

        mock_join.assert_has_calls([
            mock.call(self.context.work_dir, "node1", "file1"),
            mock.call(self.context.work_dir, "node2", "file1"),
            mock.call(self.context.work_dir, "node3", "file1")
            ])
        mock_diff_check.assert_has_calls([
            mock.call("{}/node1/file1".format(self.context.work_dir), "{}/node2/file1".format(self.context.work_dir)),
            mock.call("{}/node1/file1".format(self.context.work_dir), "{}/node3/file1".format(self.context.work_dir))
            ])

    @mock.patch('os.path.join')
    def test_consolidate_cib_return(self, mock_join):
        core.consolidate(self.context, const.CIB_F)
        mock_join.assert_not_called()

    @mock.patch('os.symlink')
    @mock.patch('shutil.move')
    @mock.patch('os.remove')
    @mock.patch('os.path.isfile')
    @mock.patch('os.path.join')
    def test_consolidate_cib(self, mock_join, mock_isfile, mock_remove, mock_move, mock_symlink):
        mock_join.side_effect = [
                "{}/node1/file1".format(self.context.work_dir),
                "{}/file1".format(self.context.work_dir),
                "{}/node2/file1".format(self.context.work_dir),
                "{}/file1".format(self.context.work_dir)
                ]
        mock_isfile.side_effect = [True, False]

        core.consolidate(self.context, "file1")

        mock_join.assert_has_calls([
            mock.call(self.context.work_dir, "node1", "file1"),
            mock.call(self.context.work_dir, "file1"),
            mock.call(self.context.work_dir, "node2", "file1"),
            mock.call(self.context.work_dir, "file1")
            ])
        mock_isfile.assert_has_calls([
            mock.call("{}/file1".format(self.context.work_dir)),
            mock.call("{}/file1".format(self.context.work_dir))
            ])
        mock_remove.assert_called_once_with("{}/node1/file1".format(self.context.work_dir))
        mock_move.assert_called_once_with("{}/node2/file1".format(self.context.work_dir), self.context.work_dir)
        mock_symlink.assert_has_calls([
            mock.call("../file1", "{}/node1/file1".format(self.context.work_dir)),
            mock.call("../file1", "{}/node2/file1".format(self.context.work_dir))
            ])

    @mock.patch('hb_report.core.crmutils.str2file')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.core.check_logs')
    @mock.patch('hb_report.core.check_cores')
    @mock.patch('hb_report.core.check_crmvfy')
    @mock.patch('hb_report.core.consolidate')
    @mock.patch('hb_report.core.analyze_one')
    @mock.patch('glob.glob')
    def test_analyze(self, mock_glob, mock_analyze_one, mock_consolidate, mock_crmvfy,
            mock_cores, mock_logs, mock_join, mock_str2file):
        mock_glob.side_effect = [
                ["{}/node1/{}".format(self.context.work_dir, const.MEMBERSHIP_F)],
                [],
                [],
                [
                    "{}/node1/{}".format(self.context.work_dir, const.SYSINFO_F),
                    "{}/node2/{}".format(self.context.work_dir, const.SYSINFO_F)
                    ],
                [
                    "{}/node1/{}".format(self.context.work_dir, const.CIB_F),
                    "{}/node2/{}".format(self.context.work_dir, const.CIB_F)
                    ]
                ]
        mock_analyze_one.side_effect = [(True, ""), (False, "Diff data")]
        mock_crmvfy.return_value = "crmvfy data"
        mock_cores.return_value = "cores data"
        mock_logs.return_value = "logs data"
        mock_join.return_value = "{}/{}".format(self.context.work_dir, const.ANALYSIS_F)

        core.analyze(self.context)

        mock_glob.assert_has_calls([
            mock.call("{}/*/{}".format(self.context.work_dir, const.MEMBERSHIP_F)),
            mock.call("{}/*/{}".format(self.context.work_dir, const.CRM_MON_F)),
            mock.call("{}/*/{}".format(self.context.work_dir, const.B_CONF)),
            mock.call("{}/*/{}".format(self.context.work_dir, const.SYSINFO_F)),
            mock.call("{}/*/{}".format(self.context.work_dir, const.CIB_F))
            ])
        mock_analyze_one.assert_has_calls([
            mock.call(self.context, const.SYSINFO_F),
            mock.call(self.context, const.CIB_F)
            ])
        mock_consolidate.assert_called_once_with(self.context, const.SYSINFO_F)
        mock_crmvfy.assert_called_once_with(self.context)
        mock_cores.assert_called_once_with(self.context)
        mock_logs.assert_called_once_with(self.context)
        mock_join.assert_called_once_with(self.context.work_dir, const.ANALYSIS_F)
        mock_str2file.assert_called_once_with('Diff members.txt...Only one /tmp/node1/members.txt, skip\nDiff crm_mon.txt...Not found /tmp/*/crm_mon.txt\nDiff corosync.conf...Not found /tmp/*/corosync.conf\nDiff sysinfo.txt...OK\n\nDiff cib.xml...\nDiff data\n\ncrmvfy datacores datalogs data', mock_join.return_value)

    @mock.patch('argparse.HelpFormatter')
    @mock.patch('argparse.ArgumentParser')
    def test_parse_argument_help(self, mock_parser, mock_formatter):
        mock_parser_inst = mock.Mock()
        mock_parser.return_value = mock_parser_inst
        mock_args_inst = mock.Mock(help=True)
        mock_parser_inst.parse_args.return_value = mock_args_inst

        with self.assertRaises(SystemExit):
            core.parse_argument(self.context)

        mock_parser_inst.print_help.assert_called_once_with()

    @mock.patch('hb_report.core.check_exclusive_options')
    @mock.patch('hb_report.core.crmutils.check_space_option_value')
    @mock.patch('hb_report.core.process_some_arguments')
    @mock.patch('argparse.HelpFormatter')
    @mock.patch('argparse.ArgumentParser')
    def test_parse_argument(self, mock_parser, mock_formatter, mock_process, mock_space, mock_exclusive):
        mock_parser_inst = mock.Mock()
        mock_parser.return_value = mock_parser_inst
        mock_args_inst = mock.Mock(help=False)
        mock_parser_inst.parse_args.return_value = mock_args_inst

        core.parse_argument(self.context)

        mock_exclusive.assert_called_once_with(mock_args_inst)
        mock_space.assert_called_once_with(mock_args_inst)
        mock_process.assert_called_once_with(self.context)

    @mock.patch('hb_report.core.check_exclusive_options')
    @mock.patch('hb_report.utils.log_fatal')
    @mock.patch('hb_report.core.crmutils.check_space_option_value')
    @mock.patch('hb_report.core.process_some_arguments')
    @mock.patch('argparse.HelpFormatter')
    @mock.patch('argparse.ArgumentParser')
    def test_parse_argument_space(self, mock_parser, mock_formatter, mock_process,
            mock_space, mock_fatal, mock_exclusive):
        mock_parser_inst = mock.Mock()
        mock_parser.return_value = mock_parser_inst
        mock_args_inst = mock.Mock(help=False)
        mock_parser_inst.parse_args.return_value = mock_args_inst
        mock_space.side_effect = ValueError("error data")
        mock_fatal.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            core.parse_argument(self.context)

        mock_exclusive.assert_called_once_with(mock_args_inst)
        mock_space.assert_called_once_with(mock_args_inst)
        mock_process.assert_not_called()
        mock_fatal.assert_called_once_with(mock_space.side_effect)

    @mock.patch('hb_report.utils.log_fatal')
    def test_check_exclusive_options_f_b(self, mock_fatal):
        mock_args = mock.Mock(from_time=True, before_time=True, to_time=False, nodes=False,
                extra_logs=False, speed_up=False)
        core.check_exclusive_options(mock_args)
        mock_fatal.assert_called_once_with("-f and -b options are exclusive")

    @mock.patch('hb_report.utils.log_fatal')
    def test_check_exclusive_options_t_b(self, mock_fatal):
        mock_args = mock.Mock(to_time=True, before_time=True, from_time=False, nodes=False,
                extra_logs=False, speed_up=False)
        core.check_exclusive_options(mock_args)
        mock_fatal.assert_called_once_with("-t and -b options are exclusive")

    @mock.patch('hb_report.utils.log_fatal')
    def test_check_exclusive_options_n_S(self, mock_fatal):
        mock_args = mock.Mock(nodes=True, single=True, from_time=False, to_time=False,
                extra_logs=False, speed_up=False)
        core.check_exclusive_options(mock_args)
        mock_fatal.assert_called_once_with("-n and -S options are exclusive")

    @mock.patch('hb_report.utils.log_fatal')
    def test_check_exclusive_options_E_M(self, mock_fatal):
        mock_args = mock.Mock(extra_logs=True, no_extra=True, from_time=False,
                to_time=False, nodes=False, speed_up=False)
        core.check_exclusive_options(mock_args)
        mock_fatal.assert_called_once_with("-E and -M options are exclusive")

    @mock.patch('hb_report.utils.log_fatal')
    def test_check_exclusive_options_s_Q(self, mock_fatal):
        mock_args = mock.Mock(speed_up=True, sanitize=True, from_time=False,
                to_time=False, nodes=False, extra_logs=False)
        core.check_exclusive_options(mock_args)
        mock_fatal.assert_called_once_with("-s and -Q options are exclusive")
