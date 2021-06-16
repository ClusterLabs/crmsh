import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

try:
    from unittest import mock, TestCase
except ImportError:
    import mock
import logging

from crmsh.crash_test import utils, main, config


class TestMyLoggingFormatter(TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """
        self.fence_info_inst = utils.FenceInfo()

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """


class TestFenceInfo(TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """
        self.fence_info_inst = utils.FenceInfo()

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('crmsh.crash_test.utils.get_property')
    def test_fence_enabled_false(self, mock_get_property):
        mock_get_property.return_value = None
        res = self.fence_info_inst.fence_enabled
        self.assertEqual(res, False)
        mock_get_property.assert_called_once_with("stonith-enabled")

    @mock.patch('crmsh.crash_test.utils.get_property')
    def test_fence_enabled_true(self, mock_get_property):
        mock_get_property.return_value = "True"
        res = self.fence_info_inst.fence_enabled
        self.assertEqual(res, True)
        mock_get_property.assert_called_once_with("stonith-enabled")

    @mock.patch('crmsh.crash_test.utils.msg_error')
    @mock.patch('crmsh.crash_test.utils.get_property')
    def test_fence_action_none(self, mock_get_property, mock_error):
        mock_get_property.return_value = None
        res = self.fence_info_inst.fence_action
        self.assertEqual(res, None)
        mock_get_property.assert_called_once_with("stonith-action")
        mock_error.assert_called_once_with('Cluster property "stonith-action" should be reboot|off|poweroff')

    @mock.patch('crmsh.crash_test.utils.get_property')
    def test_fence_action(self, mock_get_property):
        mock_get_property.return_value = "reboot"
        res = self.fence_info_inst.fence_action
        self.assertEqual(res, "reboot")
        mock_get_property.assert_called_once_with("stonith-action")

    @mock.patch('crmsh.crash_test.utils.get_property')
    def test_fence_timeout(self, mock_get_property):
        mock_get_property.return_value = "60s"
        res = self.fence_info_inst.fence_timeout
        self.assertEqual(res, "60")
        mock_get_property.assert_called_once_with("stonith-timeout")

    @mock.patch('crmsh.crash_test.utils.get_property')
    def test_fence_timeout_default(self, mock_get_property):
        mock_get_property.return_value = None
        res = self.fence_info_inst.fence_timeout
        self.assertEqual(res, config.FENCE_TIMEOUT)
        mock_get_property.assert_called_once_with("stonith-timeout")


class TestUtils(TestCase):
    '''
    Unitary tests for crash_test/utils.py
    '''

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

    @mock.patch('crmsh.crash_test.utils.datetime')
    def test_now(self, mock_datetime):
        mock_now = mock.Mock()
        mock_datetime.now.return_value = mock_now
        mock_now.strftime.return_value = "2019/07/05 14:44:55"

        result = utils.now()

        self.assertEqual(result, "2019/07/05 14:44:55")
        mock_datetime.now.assert_called_once_with()
        mock_now.strftime.assert_called_once_with("%Y/%m/%d %H:%M:%S")

    @mock.patch('crmsh.crash_test.utils.get_handler')
    def test_manage_handler(self, mock_get_handler):
        mock_get_handler.return_value = "handler"
        utils.logger = mock.Mock()
        utils.logger.removeHandler = mock.Mock()
        utils.logger.addHandler = mock.Mock()

        with utils.manage_handler("type1", keep=False):
            pass

        mock_get_handler.assert_called_once_with(utils.logger, "type1")
        utils.logger.removeHandler.assert_called_once_with("handler")
        utils.logger.addHandler.assert_called_once_with("handler")

    @mock.patch('crmsh.crash_test.utils.manage_handler')
    def test_msg_raw(self, mock_handler):
        utils.logger = mock.Mock()
        utils.logger.log = mock.Mock()
        utils.msg_raw("level1", "msg1")
        mock_handler.assert_called_once_with("stream", True)
        utils.logger.log.assert_called_once_with("level1", "msg1")

    @mock.patch('crmsh.crash_test.utils.msg_raw')
    def test_msg_info(self, mock_raw):
        utils.msg_info("msg1")
        mock_raw.assert_called_once_with(logging.INFO, "msg1", True)

    @mock.patch('crmsh.crash_test.utils.msg_raw')
    def test_msg_warn(self, mock_raw):
        utils.msg_warn("msg1")
        mock_raw.assert_called_once_with(logging.WARNING, "msg1", True)

    @mock.patch('crmsh.crash_test.utils.msg_raw')
    def test_msg_error(self, mock_raw):
        utils.msg_error("msg1")
        mock_raw.assert_called_once_with(logging.ERROR, "msg1", True)

    @mock.patch('os.fsync')
    @mock.patch('json.dumps')
    @mock.patch('builtins.open', create=True)
    def test_json_dumps(self, mock_open_file, mock_dumps, mock_fsync):
        main.ctx = mock.Mock(jsonfile="file1", task_list={"process_name": "xin", "age": 38})
        mock_open_write = mock.mock_open()
        file_handle = mock_open_write.return_value.__enter__.return_value
        mock_open_file.return_value = mock_open_write.return_value
        mock_dumps.return_value = "data"

        utils.json_dumps()

        mock_open_file.assert_called_once_with("file1", "w")
        mock_dumps.assert_called_once_with(main.ctx.task_list, indent=2)
        file_handle.write.assert_called_once_with("data")
        file_handle.flush.assert_called_once_with()
        mock_fsync.assert_called_once_with(file_handle)

    @mock.patch('crmsh.crash_test.utils.crmshutils.this_node')
    @mock.patch('crmsh.crash_test.utils.msg_error')
    @mock.patch('crmsh.crash_test.utils.crmshutils.get_stdout_stderr')
    def test_this_node_false(self, mock_run, mock_error, mock_this_node):
        mock_run.return_value = (1, None, "error data")
        mock_this_node.return_value = "node1"

        res = utils.this_node()
        self.assertEqual(res, "node1")

        mock_run.assert_called_once_with("crm_node --name")
        mock_error.assert_called_once_with("error data")
        mock_this_node.assert_called_once_with()
    
    @mock.patch('crmsh.crash_test.utils.crmshutils.get_stdout_stderr')
    def test_this_node(self, mock_run):
        mock_run.return_value = (0, "data", None)
        res = utils.this_node()
        self.assertEqual(res, "data")
        mock_run.assert_called_once_with("crm_node --name")

    @mock.patch('crmsh.crash_test.utils.datetime')
    def test_str_to_datetime(self, mock_datetime):
        utils.str_to_datetime("Mon Nov  2 15:37:11 2020", "%a %b %d %H:%M:%S %Y")
        mock_datetime.strptime.assert_called_once_with("Mon Nov  2 15:37:11 2020", "%a %b %d %H:%M:%S %Y")

    @mock.patch('crmsh.crash_test.utils.crmshutils.get_stdout_stderr')
    def test_corosync_port_list(self, mock_run):
        output = """
totem.interface.0.bindnetaddr (str) = 10.10.10.121
totem.interface.0.mcastaddr (str) = 239.101.40.63
totem.interface.0.mcastport (u16) = 5405
totem.interface.0.ttl (u8) = 1
totem.interface.1.bindnetaddr (str) = 20.20.20.121
totem.interface.1.mcastaddr (str) = 239.6.213.31
totem.interface.1.mcastport (u16) = 5407
totem.interface.1.ttl (u8) = 1
        """
        mock_run.return_value = (0, output, None)
        result = utils.corosync_port_list()
        expected = ['5405', '5407']
        self.assertListEqual(result, expected)
        mock_run.assert_called_once_with("corosync-cmapctl totem.interface")

    def test_get_handler(self):
        mock_handler1 = mock.Mock(_name="test1_handler")
        mock_handler2 = mock.Mock(_name="test2_handler")
        mock_logger = mock.Mock(handlers=[mock_handler1, mock_handler2])
        res = utils.get_handler(mock_logger, "test1_handler")
        self.assertEqual(res, mock_handler1)

    @mock.patch('os.getuid')
    def test_is_root(self, mock_getuid):
        mock_getuid.return_value = 0
        self.assertEqual(utils.is_root(), True)
        mock_getuid.assert_called_once_with()

    @mock.patch('crmsh.crash_test.utils.crmshutils.to_ascii')
    @mock.patch('os.path.basename')
    @mock.patch('builtins.open')
    @mock.patch('os.path.join')
    @mock.patch('os.listdir')
    def test_get_process_status_false(self, mock_listdir, mock_join, mock_open_file, mock_basename, mock_to_ascii):
        mock_listdir.return_value = ['1', '2', 'none']
        mock_join.side_effect = ['/proc/1/cmdline', '/proc/2/cmdline']
        mock_open_read_1 = mock.mock_open(read_data=b'/usr/sbin/cmd1\x00--user\x00')
        mock_open_read_2 = mock.mock_open(read_data=b'/usr/sbin/cmd2\x00')
        mock_open_file.side_effect = [
            mock_open_read_1.return_value,
            mock_open_read_2.return_value
        ]
        mock_to_ascii.side_effect = [
            "/usr/sbin/cmd1\x00--user\x00",
            "/usr/sbin/cmd2\x00"
        ]
        mock_basename.side_effect = ["cmd1", "cmd2"]

        rc, pid = utils.get_process_status("sbd")
        self.assertEqual(rc, False)
        self.assertEqual(pid, -1)

        mock_listdir.assert_called_once_with('/proc')
        mock_join.assert_has_calls([
            mock.call('/proc', '1', 'cmdline'),
            mock.call('/proc', '2', 'cmdline')
            ])
        mock_open_file.assert_has_calls([
            mock.call('/proc/1/cmdline', 'rb'),
            mock.call('/proc/2/cmdline', 'rb')
            ])
        mock_to_ascii.assert_has_calls([
            mock.call(b'/usr/sbin/cmd1\x00--user\x00'),
            mock.call(b'/usr/sbin/cmd2\x00')
            ])

    @mock.patch('crmsh.crash_test.utils.crmshutils.to_ascii')
    @mock.patch('os.path.basename')
    @mock.patch('builtins.open')
    @mock.patch('os.path.join')
    @mock.patch('os.listdir')
    def test_get_process_status(self, mock_listdir, mock_join, mock_open_file, mock_basename, mock_to_ascii):
        mock_listdir.return_value = ['1', '2', 'none']
        mock_join.side_effect = ['/proc/1/cmdline', '/proc/2/cmdline']
        mock_open_read_1 = mock.mock_open(read_data=b'/usr/sbin/cmd1\x00--user\x00')
        mock_open_read_2 = mock.mock_open(read_data=b'/usr/sbin/sbd\x00')
        mock_open_file.side_effect = [
            mock_open_read_1.return_value,
            mock_open_read_2.return_value
        ]
        mock_to_ascii.side_effect = [
            "/usr/sbin/cmd1\x00--user\x00",
            "/usr/sbin/sbd\x00"
        ]
        mock_basename.side_effect = ["cmd1", "sbd"]

        rc, pid = utils.get_process_status("sbd")
        self.assertEqual(rc, True)
        self.assertEqual(pid, 2)

        mock_listdir.assert_called_once_with('/proc')
        mock_join.assert_has_calls([
            mock.call('/proc', '1', 'cmdline'),
            mock.call('/proc', '2', 'cmdline')
            ])
        mock_open_file.assert_has_calls([
            mock.call('/proc/1/cmdline', 'rb'),
            mock.call('/proc/2/cmdline', 'rb')
            ])
        mock_to_ascii.assert_has_calls([
            mock.call(b'/usr/sbin/cmd1\x00--user\x00'),
            mock.call(b'/usr/sbin/sbd\x00')
            ])

    @mock.patch('crmsh.crash_test.utils.msg_error')
    @mock.patch('crmsh.crash_test.utils.crmshutils.get_stdout_stderr')
    def test_check_node_status_error_cmd(self, mock_run, mock_error):
        mock_run.return_value = (1, None, "error")
        res = utils.check_node_status("node1", "member")
        self.assertEqual(res, False)
        mock_run.assert_called_once_with("crm_node -l")
        mock_error.assert_called_once_with("error")

    @mock.patch('crmsh.crash_test.utils.msg_error')
    @mock.patch('crmsh.crash_test.utils.crmshutils.get_stdout_stderr')
    def test_check_node_status(self, mock_run, mock_error):
        output = """
1084783297 15sp2-1 member
1084783193 15sp2-2 lost
        """
        mock_run.return_value = (0, output, None)

        res = utils.check_node_status("15sp2-2", "member")
        self.assertEqual(res, False)
        res = utils.check_node_status("15sp2-1", "member")
        self.assertEqual(res, True)

        mock_run.assert_has_calls([
            mock.call("crm_node -l"),
            mock.call("crm_node -l")
            ])
        mock_error.assert_not_called()

    @mock.patch('crmsh.crash_test.utils.crmshutils.get_stdout_stderr')
    def test_online_nodes_empty(self, mock_run):
        mock_run.return_value = (0, "data", None)
        res = utils.online_nodes()
        self.assertEqual(res, [])
        mock_run.assert_called_once_with("crm_mon -1")

    @mock.patch('crmsh.crash_test.utils.crmshutils.get_stdout_stderr')
    def test_online_nodes(self, mock_run):
        output = """
Node List:
  * Online: [ 15sp2-1 15sp2-2 ]
        """
        mock_run.return_value = (0, output, None)
        res = utils.online_nodes()
        self.assertEqual(res, ["15sp2-1", "15sp2-2"])
        mock_run.assert_called_once_with("crm_mon -1")

    @mock.patch('crmsh.crash_test.utils.crmshutils.get_stdout_stderr')
    def test_get_property_none(self, mock_run):
        mock_run.return_value = (1, None, "error")
        res = utils.get_property("test")
        self.assertEqual(res, None)
        mock_run.assert_called_once_with("crm configure get_property test")

    @mock.patch('crmsh.crash_test.utils.crmshutils.get_stdout_stderr')
    def test_get_property(self, mock_run):
        mock_run.return_value = (0, "data", None)
        res = utils.get_property("test")
        self.assertEqual(res, "data")
        mock_run.assert_called_once_with("crm configure get_property test")

    @mock.patch('crmsh.crash_test.utils.online_nodes')
    def test_peer_node_list_empty(self, mock_online):
        mock_online.return_value = None
        res = utils.peer_node_list()
        self.assertEqual(res, [])
        mock_online.assert_called_once_with()

    @mock.patch('crmsh.crash_test.utils.this_node')
    @mock.patch('crmsh.crash_test.utils.online_nodes')
    def test_peer_node_list(self, mock_online, mock_this_node):
        mock_online.return_value = ["node1", "node2"]
        mock_this_node.return_value = "node1"
        res = utils.peer_node_list()
        self.assertEqual(res, ["node2"])
        mock_online.assert_called_once_with()

    # Test is_valid_sbd():
    @classmethod
    @mock.patch('os.path.exists')
    def test_is_valid_sbd_not_exist(cls, mock_os_path_exists):
        """
        Test device not exist
        """
        dev = "/dev/disk/by-id/scsi-device1"
        mock_os_path_exists.return_value = False

        res = utils.is_valid_sbd(dev)
        assert res is False

    @classmethod
    @mock.patch('crmsh.crash_test.utils.msg_error')
    @mock.patch('crmsh.utils.get_stdout_stderr')
    @mock.patch('os.path.exists')
    def test_is_valid_sbd_cmd_error(cls, mock_os_path_exists,
                                    mock_sbd_check_header, mock_msg_err):
        """
        Test device is not valid sbd
        """
        dev = "/dev/disk/by-id/scsi-device1"
        mock_os_path_exists.return_value = True
        mock_sbd_check_header.return_value = (-1, None, "Unknown error!")
        mock_msg_err.return_value = ""

        res = utils.is_valid_sbd(dev)
        mock_msg_err.assert_called_once_with("Unknown error!")
        assert res is False

    @classmethod
    @mock.patch('crmsh.crash_test.utils.msg_error')
    @mock.patch('crmsh.utils.get_stdout_stderr')
    @mock.patch('os.path.exists')
    def test_is_valid_sbd_not_sbd(cls, mock_os_path_exists,
                                  mock_sbd_check_header, mock_msg_err):
        """
        Test device is not SBD device
        """
        dev = "/dev/disk/by-id/scsi-device1"
        err_output = """
==Dumping header on disk {}
==Header on disk {} NOT dumped
sbd failed; please check the logs.
""".format(dev, dev)
        mock_os_path_exists.return_value = True
        mock_sbd_check_header.return_value = (1, "==Dumping header on disk {}".format(dev),
                                              err_output)

        res = utils.is_valid_sbd(dev)
        assert res is False
        mock_msg_err.assert_called_once_with(err_output)

    @classmethod
    @mock.patch('crmsh.utils.get_stdout_stderr')
    @mock.patch('os.path.exists')
    def test_is_valid_sbd_is_sbd(cls, mock_os_path_exists,
                                 mock_sbd_check_header):
        """
        Test device is not SBD device
        """
        dev = "/dev/disk/by-id/scsi-device1"
        std_output = """
==Dumping header on disk {}
Header version     : 2.1
UUID               : f4c99362-6522-46fc-8ce4-7db60aff19bb
Number of slots    : 255
Sector size        : 512
Timeout (watchdog) : 5
Timeout (allocate) : 2
Timeout (loop)     : 1
Timeout (msgwait)  : 10
==Header on disk {} is dumped
""".format(dev, dev)
        mock_os_path_exists.return_value = True
        mock_sbd_check_header.return_value = (0, std_output, None)

        res = utils.is_valid_sbd(dev)
        assert res is True

    # Test find_candidate_sbd() and _find_match_count()
    @classmethod
    @mock.patch('glob.glob')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.dirname')
    def test_find_candidate_no_dev(cls, mock_os_path_dname, mock_os_path_bname,
                                   mock_glob):
        """
        Test no suitable device
        """
        mock_os_path_dname.return_value = "/dev/disk/by-id"
        mock_os_path_bname.return_value = "scsi-label_CN_devA"
        mock_glob.return_value = []

        res = utils.find_candidate_sbd("/not-exist-folder/not-exist-dev")
        assert res == ""

    @classmethod
    @mock.patch('crmsh.crash_test.utils.is_valid_sbd')
    @mock.patch('glob.glob')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.dirname')
    def test_find_candidate_no_can(cls, mock_os_path_dname, mock_os_path_bname,
                                   mock_glob, mock_is_valid_sbd):
        """
        Test no valid candidate device
        """
        mock_os_path_dname.return_value = "/dev/disk/by-id"
        mock_os_path_bname.return_value = "scsi-label_CN_devA"
        mock_glob.return_value = ["/dev/disk/by-id/scsi-label_DE_devA",
                                  "/dev/disk/by-id/scsi-label_DE_devB",
                                  "/dev/disk/by-id/scsi-label_DE_devC",
                                  "/dev/disk/by-id/scsi-label_DE_devD"]
        mock_is_valid_sbd.side_effect = [False, False, False, False]

        res = utils.find_candidate_sbd("/dev/disk/by-id/scsi-label_CN_devA")
        assert res == ""

    @classmethod
    @mock.patch('crmsh.crash_test.utils.is_valid_sbd')
    @mock.patch('glob.glob')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.dirname')
    def test_find_candidate_has_multi(cls, mock_os_path_dname, mock_os_path_bname,
                                      mock_glob, mock_is_valid_sbd):
        """
        Test has multiple valid candidate devices
        """
        mock_os_path_dname.return_value = "/dev/disk/by-id"
        mock_os_path_bname.return_value = "scsi-label_CN_devA"
        mock_glob.return_value = ["/dev/disk/by-id/scsi-label_DE_devA",
                                  "/dev/disk/by-id/scsi-label_DE_devB",
                                  "/dev/disk/by-id/scsi-label_CN_devC",
                                  "/dev/disk/by-id/scsi-label_CN_devD",
                                  "/dev/disk/by-id/scsi-mp_China_devE",
                                  "/dev/disk/by-id/scsi-mp_China_devF"]
        mock_is_valid_sbd.side_effect = [True, False, False, True, True, False]

        res = utils.find_candidate_sbd("/dev/disk/by-id/scsi-label_CN_devA")
        assert res == "/dev/disk/by-id/scsi-label_CN_devD"
