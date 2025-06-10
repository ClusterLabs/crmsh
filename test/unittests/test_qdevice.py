import os
import unittest
import socket

try:
    from unittest import mock
except ImportError:
    import mock

from crmsh import bootstrap
from crmsh import sbd
from crmsh import qdevice, lock


F2 = open(os.path.join(os.path.dirname(__file__), 'corosync.conf.2')).read()
F4 = open(os.path.join(os.path.dirname(__file__), 'corosync.conf.3')).read()


@mock.patch('crmsh.utils.calculate_quorate_status')
@mock.patch('crmsh.utils.get_quorum_votes_dict')
def test_evaluate_qdevice_quorum_effect_restart(mock_get_dict, mock_quorate):
    mock_get_dict.return_value = {'Expected': '1', 'Total': '1'}
    mock_quorate.return_value = False
    res = qdevice.evaluate_qdevice_quorum_effect(qdevice.QDEVICE_ADD, False, False)
    assert res == qdevice.QdevicePolicy.QDEVICE_RESTART
    mock_get_dict.assert_called_once_with()
    mock_quorate.assert_called_once_with(2, 1)


@mock.patch('crmsh.utils.calculate_quorate_status')
@mock.patch('crmsh.utils.get_quorum_votes_dict')
def test_evaluate_qdevice_quorum_effect_reload(mock_get_dict, mock_quorate):
    mock_get_dict.return_value = {'Expected': '2', 'Total': '2'}
    mock_quorate.return_value = True
    res = qdevice.evaluate_qdevice_quorum_effect(qdevice.QDEVICE_ADD)
    assert res == qdevice.QdevicePolicy.QDEVICE_RELOAD
    mock_get_dict.assert_called_once_with()
    mock_quorate.assert_called_once_with(3, 2)


@mock.patch('crmsh.xmlutil.CrmMonXmlParser')
@mock.patch('crmsh.utils.calculate_quorate_status')
@mock.patch('crmsh.utils.get_quorum_votes_dict')
def test_evaluate_qdevice_quorum_effect_later(mock_get_dict, mock_quorate, mock_parser):
    mock_get_dict.return_value = {'Expected': '2', 'Total': '2'}
    mock_quorate.return_value = False
    mock_parser().is_any_resource_running.return_value = True
    res = qdevice.evaluate_qdevice_quorum_effect(qdevice.QDEVICE_REMOVE)
    assert res == qdevice.QdevicePolicy.QDEVICE_RESTART_LATER
    mock_get_dict.assert_called_once_with()
    mock_quorate.assert_called_once_with(2, 1)


@mock.patch('crmsh.xmlutil.CrmMonXmlParser')
@mock.patch('crmsh.utils.calculate_quorate_status')
@mock.patch('crmsh.utils.get_quorum_votes_dict')
def test_evaluate_qdevice_quorum_effect(mock_get_dict, mock_quorate, mock_parser):
    mock_get_dict.return_value = {'Expected': '2', 'Total': '2'}
    mock_quorate.return_value = False
    mock_parser().is_any_resource_running.return_value = False
    res = qdevice.evaluate_qdevice_quorum_effect(qdevice.QDEVICE_REMOVE)
    assert res == qdevice.QdevicePolicy.QDEVICE_RESTART
    mock_get_dict.assert_called_once_with()
    mock_quorate.assert_called_once_with(2, 1)


@mock.patch('crmsh.lock.RemoteLock')
def test_qnetd_lock_for_same_cluster_name(mock_remote_lock):
    _context = mock.Mock(qnetd_addr="qnetd-node", cluster_name="cluster1")
    remote_lock_inst = mock.Mock()
    mock_remote_lock.return_value = remote_lock_inst
    remote_lock_inst.lock.return_value.__enter__ = mock.Mock()
    remote_lock_inst.lock.return_value.__exit__ = mock.Mock()
    @qdevice.qnetd_lock_for_same_cluster_name
    def decorated(ctx):
        return
    decorated(_context)
    mock_remote_lock.assert_called_once_with("qnetd-node", for_join=False,
            lock_dir="/run/.crmsh_qdevice_lock_for_cluster1", wait=False)


@mock.patch('crmsh.utils.fatal')
@mock.patch('crmsh.lock.RemoteLock')
def test_qnetd_lock_for_same_cluster_name_claim_error(mock_remote_lock, mock_fatal):
    _context = mock.Mock(qnetd_addr="qnetd-node", cluster_name="cluster1")
    remote_lock_inst = mock.Mock()
    mock_remote_lock.return_value = remote_lock_inst
    remote_lock_inst.lock.side_effect = lock.ClaimLockError
    @qdevice.qnetd_lock_for_same_cluster_name
    def decorated(ctx):
        return
    decorated(_context)
    mock_fatal.assert_called_once_with("Duplicated cluster name \"cluster1\"!")
    mock_remote_lock.assert_called_once_with("qnetd-node", for_join=False,
            lock_dir="/run/.crmsh_qdevice_lock_for_cluster1", wait=False)


@mock.patch('crmsh.utils.fatal')
@mock.patch('crmsh.lock.RemoteLock')
def test_qnetd_lock_for_same_cluster_name_ssh_error(mock_remote_lock, mock_fatal):
    _context = mock.Mock(qnetd_addr="qnetd-node", cluster_name="cluster1")
    remote_lock_inst = mock.Mock()
    mock_remote_lock.return_value = remote_lock_inst
    remote_lock_inst.lock.side_effect = lock.SSHError("ssh error!")
    @qdevice.qnetd_lock_for_same_cluster_name
    def decorated(ctx):
        return
    decorated(_context)
    mock_remote_lock.assert_called_once_with("qnetd-node", for_join=False,
            lock_dir="/run/.crmsh_qdevice_lock_for_cluster1", wait=False) 


@mock.patch('crmsh.lock.RemoteLock')
def test_qnetd_lock_for_multi_cluster(mock_remote_lock):
    _context = mock.Mock(qnetd_addr="qnetd-node")
    remote_lock_inst = mock.Mock()
    mock_remote_lock.return_value = remote_lock_inst
    remote_lock_inst.lock.return_value.__enter__ = mock.Mock()
    remote_lock_inst.lock.return_value.__exit__ = mock.Mock()
    @qdevice.qnetd_lock_for_multi_cluster
    def decorated(ctx):
        return
    decorated(_context)
    mock_remote_lock.assert_called_once_with("qnetd-node", for_join=False, no_warn=True)


@mock.patch('crmsh.utils.fatal')
@mock.patch('crmsh.lock.RemoteLock')
def test_qnetd_lock_for_multi_cluster_error(mock_remote_lock, mock_fatal):
    _context = mock.Mock(qnetd_addr="qnetd-node")
    remote_lock_inst = mock.Mock()
    mock_remote_lock.return_value = remote_lock_inst
    remote_lock_inst.lock.side_effect = lock.SSHError("ssh error!")
    @qdevice.qnetd_lock_for_multi_cluster
    def decorated(ctx):
        return
    decorated(_context)
    mock_remote_lock.assert_called_once_with("qnetd-node", for_join=False, no_warn=True)


class TestQDevice(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """
        # Use the setup to create a fresh instance for each test
        self.qdevice_with_ip = qdevice.QDevice("10.10.10.123")
        self.qdevice_with_hostname = qdevice.QDevice("node.qnetd")
        self.qdevice_with_invalid_port = qdevice.QDevice("10.10.10.123", port=100)
        self.qdevice_with_invalid_tie_breaker = qdevice.QDevice("10.10.10.123", tie_breaker="wrong")
        self.qdevice_with_ip_cluster_node = qdevice.QDevice("10.10.10.123", cluster_node="node1.com")
        self.qdevice_with_invalid_cmds_relative_path = qdevice.QDevice("10.10.10.123", cmds="ls")
        self.qdevice_with_invalid_cmds_not_exist = qdevice.QDevice("10.10.10.123", cmds="/not_exist")
        self.qdevice_with_cluster_name = qdevice.QDevice("10.10.10.123", cluster_name="hacluster1")
        self.qdevice_with_stage_cluster_name = qdevice.QDevice("10.10.10.123", is_stage=True, cluster_name="cluster1")

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    def test_qnetd_cacert_on_local(self):
        res = self.qdevice_with_ip.qnetd_cacert_on_local
        self.assertEqual(res, "/etc/corosync/qdevice/net/10.10.10.123/qnetd-cacert.crt")

    def test_qnetd_cacert_on_cluster(self):
        res = self.qdevice_with_ip_cluster_node.qnetd_cacert_on_cluster
        self.assertEqual(res, "/etc/corosync/qdevice/net/node1.com/qnetd-cacert.crt")

    def test_qdevice_crq_on_qnetd(self):
        res = self.qdevice_with_cluster_name.qdevice_crq_on_qnetd
        self.assertEqual(res, "/etc/corosync/qnetd/nssdb/qdevice-net-node.crq.hacluster1")

    def test_qdevice_crq_on_local(self):
        res = self.qdevice_with_ip.qdevice_crq_on_local
        self.assertEqual(res, "/etc/corosync/qdevice/net/nssdb/qdevice-net-node.crq")

    def test_qnetd_cluster_crt_on_qnetd(self):
        res = self.qdevice_with_ip.qnetd_cluster_crt_on_qnetd
        self.assertEqual(res, "/etc/corosync/qnetd/nssdb/cluster-None.crt")

    @mock.patch('os.path.basename')
    @mock.patch("crmsh.qdevice.QDevice.qnetd_cluster_crt_on_qnetd", new_callable=mock.PropertyMock)
    def test_qnetd_cluster_crt_on_local(self, mock_qnetd_crt, mock_basename):
        mock_qnetd_crt.return_value = "crt_file"
        mock_basename.return_value = "crt_file"
        res = self.qdevice_with_ip.qnetd_cluster_crt_on_local
        self.assertEqual(res, "/etc/corosync/qdevice/net/10.10.10.123/crt_file")

    def test_qdevice_p12_on_local(self):
        res = self.qdevice_with_ip.qdevice_p12_on_local
        self.assertEqual(res, "/etc/corosync/qdevice/net/nssdb/qdevice-net-node.p12")

    def test_qdevice_p12_on_cluster(self):
        res = self.qdevice_with_ip_cluster_node.qdevice_p12_on_cluster
        self.assertEqual(res, "/etc/corosync/qdevice/net/node1.com/qdevice-net-node.p12")

    @mock.patch('crmsh.utils.InterfacesInfo.ip_in_local')
    @mock.patch('crmsh.utils.node_reachable_check')
    @mock.patch('socket.getaddrinfo')
    def test_check_qnetd_addr_local(self, mock_getaddrinfo, mock_reachable, mock_in_local):
        mock_getaddrinfo.return_value = [(None, ("10.10.10.123",)),]
        mock_in_local.return_value = True
        with self.assertRaises(ValueError) as err:
            qdevice.QDevice.check_qnetd_addr("qnetd-node")
        excepted_err_string = "host for qnetd must be a remote one"
        self.assertEqual(excepted_err_string, str(err.exception))

    @mock.patch('socket.getaddrinfo')
    def test_check_qnetd_addr(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.error
        with self.assertRaises(ValueError) as err:
            qdevice.QDevice.check_qnetd_addr("qnetd-node")
        excepted_err_string = "host \"qnetd-node\" is unreachable"
        self.assertEqual(excepted_err_string, str(err.exception))

    @mock.patch('crmsh.utils.valid_port')
    def test_check_qdevice_port(self, mock_port):
        mock_port.return_value = False
        with self.assertRaises(ValueError) as err:
            qdevice.QDevice.check_qdevice_port("1")
        excepted_err_string = "invalid qdevice port range(1024 - 65535)"
        self.assertEqual(excepted_err_string, str(err.exception))

    def test_check_qdevice_algo(self):
        with self.assertRaises(ValueError) as err:
            qdevice.QDevice.check_qdevice_algo("1")
        excepted_err_string = "invalid ALGORITHM choice: '1' (choose from 'ffsplit', 'lms')"
        self.assertEqual(excepted_err_string, str(err.exception))

    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    def test_check_qdevice_tie_breaker(self, mock_is_active):
        mock_is_active.return_value = False
        with self.assertRaises(ValueError) as err:
            qdevice.QDevice.check_qdevice_tie_breaker("1")
        excepted_err_string = "invalid qdevice tie_breaker(lowest/highest/valid_node_id)"
        self.assertEqual(excepted_err_string, str(err.exception))

    def test_check_qdevice_tls(self):
        with self.assertRaises(ValueError) as err:
            qdevice.QDevice.check_qdevice_tls("1")
        excepted_err_string = "invalid TLS choice: '1' (choose from 'on', 'off', 'required')"
        self.assertEqual(excepted_err_string, str(err.exception))

    def test_check_qdevice_hm(self):
        with self.assertRaises(ValueError) as err:
            qdevice.QDevice.check_qdevice_heuristics_mode("1")
        excepted_err_string = "invalid MODE choice: '1' (choose from 'on', 'sync', 'off')"
        self.assertEqual(excepted_err_string, str(err.exception))

    def test_check_qdevice_he_path_error(self):
        with self.assertRaises(ValueError) as err:
            qdevice.QDevice.check_qdevice_heuristics("command1")
        excepted_err_string = "commands for heuristics should be absolute path"
        self.assertEqual(excepted_err_string, str(err.exception))

    @mock.patch('os.path.exists')
    def test_check_qdevice_he_not_exist_erro(self, mock_exists):
        mock_exists.return_value = False
        with self.assertRaises(ValueError) as err:
            qdevice.QDevice.check_qdevice_heuristics("/usr/bin/testst")
        excepted_err_string = "command /usr/bin/testst not exist"
        self.assertEqual(excepted_err_string, str(err.exception))
    
    @mock.patch('crmsh.utils.package_is_installed')
    def test_check_package_installed(self, mock_installed):
        mock_installed.return_value = False
        with self.assertRaises(ValueError) as err:
            qdevice.QDevice.check_package_installed("corosync-qdevice")
        excepted_err_string = "Package \"corosync-qdevice\" not installed on this node"
        self.assertEqual(excepted_err_string, str(err.exception))

    @mock.patch('crmsh.qdevice.QDevice.check_qdevice_heuristics_mode')
    @mock.patch('crmsh.qdevice.QDevice.check_qdevice_heuristics')
    @mock.patch('crmsh.qdevice.QDevice.check_qdevice_tls')
    @mock.patch('crmsh.qdevice.QDevice.check_qdevice_tie_breaker')
    @mock.patch('crmsh.qdevice.QDevice.check_qdevice_algo')
    @mock.patch('crmsh.qdevice.QDevice.check_qdevice_port')
    @mock.patch('crmsh.qdevice.QDevice.check_qnetd_addr')
    @mock.patch('crmsh.qdevice.QDevice.check_package_installed')
    def test_valid_qdevice_options(self, mock_installed, mock_check_qnetd, mock_check_port,
            mock_check_algo, mock_check_tie, mock_check_tls, mock_check_h, mock_check_hm):
        self.qdevice_with_ip.valid_qdevice_options()
        mock_installed.assert_called_once_with("corosync-qdevice")
        mock_check_qnetd.assert_called_once_with("10.10.10.123")

    @mock.patch("crmsh.utils.package_is_installed")
    def test_valid_qnetd_not_installed(self, mock_installed):
        self.qdevice_with_ip.qnetd_ip = "10.10.10.123"
        mock_installed.return_value = False
        excepted_err_string = 'Package "corosync-qnetd" not installed on 10.10.10.123!\nCluster service already successfully started on this node except qdevice service.\nIf you still want to use qdevice, install "corosync-qnetd" on 10.10.10.123.\nThen run command "crm cluster init" with "qdevice" stage, like:\n  crm cluster init qdevice qdevice_related_options\nThat command will setup qdevice separately.'
        self.maxDiff = None

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_ip.valid_qnetd()
        self.assertEqual(excepted_err_string, str(err.exception))

        mock_installed.assert_called_once_with("corosync-qnetd", remote_addr="10.10.10.123")

    @mock.patch("crmsh.sh.ClusterShell.get_stdout_or_raise_error")
    @mock.patch("crmsh.qdevice.QDevice.start_qnetd")
    @mock.patch("crmsh.qdevice.QDevice.init_tls_certs_on_qnetd")
    @mock.patch("crmsh.utils.package_is_installed")
    def test_valid_qnetd_duplicated_cluster_name(
            self,
            mock_installed,
            mock_init_tls_certs_on_qnetd,
            mock_start_qnetd,
            mock_run,
    ):
        mock_installed.return_value = True
        mock_run.return_value = "data"
        excepted_err_string = "This cluster's name \"cluster1\" already exists on qnetd server!\nPlease consider to use the different cluster-name property."
        self.maxDiff = None

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_stage_cluster_name.valid_qnetd()
        self.assertEqual(excepted_err_string, str(err.exception))

        mock_installed.assert_called_once_with("corosync-qnetd", remote_addr="10.10.10.123")
        mock_init_tls_certs_on_qnetd.assert_called_once()
        mock_run.assert_called_once_with("corosync-qnetd-tool -l -c cluster1", "10.10.10.123")

    @mock.patch("crmsh.service_manager.ServiceManager.enable_service")
    def test_enable_qnetd(self, mock_enable):
        self.qdevice_with_ip.enable_qnetd()
        mock_enable.assert_called_once_with("corosync-qnetd.service", remote_addr="10.10.10.123")

    @mock.patch("crmsh.service_manager.ServiceManager.disable_service")
    def test_disable_qnetd(self, mock_disable):
        self.qdevice_with_ip.disable_qnetd()
        mock_disable.assert_called_once_with("corosync-qnetd.service", remote_addr="10.10.10.123")

    @mock.patch("crmsh.service_manager.ServiceManager.start_service")
    def test_start_qnetd(self, mock_start):
        self.qdevice_with_ip.start_qnetd()
        mock_start.assert_called_once_with("corosync-qnetd.service", remote_addr="10.10.10.123")

    @mock.patch("crmsh.service_manager.ServiceManager.stop_service")
    def test_stop_qnetd(self, mock_stop):
        self.qdevice_with_ip.stop_qnetd()
        mock_stop.assert_called_once_with("corosync-qnetd.service", remote_addr="10.10.10.123")

    @mock.patch("crmsh.parallax.parallax_call")
    @mock.patch("crmsh.qdevice.QDevice.qnetd_cacert_on_qnetd", new_callable=mock.PropertyMock)
    def test_init_tls_certs_on_qnetd_already_exists(self, mock_qnetd_cacert, mock_call):
        mock_call.return_value = [("10.10.10.123", (0, None, None))]
        mock_qnetd_cacert.return_value = "/etc/corosync/qnetd/nssdb/qnetd-cacert.crt"
        self.qdevice_with_ip.init_tls_certs_on_qnetd.__wrapped__(self.qdevice_with_ip)
        mock_call.assert_called_once_with(["10.10.10.123"],
                                          "test -f {}".format(mock_qnetd_cacert.return_value))
        mock_qnetd_cacert.assert_called_once_with()

    @mock.patch("crmsh.qdevice.logger")
    @mock.patch("crmsh.parallax.parallax_call")
    @mock.patch("crmsh.qdevice.QDevice.qnetd_cacert_on_qnetd", new_callable=mock.PropertyMock)
    def test_init_tls_certs_on_qnetd(self, mock_qnetd_cacert, mock_call, mock_logger):
        mock_call.side_effect = [ValueError(mock.Mock(), "Failed on 10.10.10.123: error happen"),
                                 [("10.10.10.123", (0, None, None))]]
        mock_qnetd_cacert.return_value = "/etc/corosync/qnetd/nssdb/qnetd-cacert.crt"

        self.qdevice_with_ip.init_tls_certs_on_qnetd.__wrapped__(self.qdevice_with_ip)

        mock_call.assert_has_calls([
            mock.call(["10.10.10.123"], "test -f {}".format(mock_qnetd_cacert.return_value)),
            mock.call(["10.10.10.123"], "corosync-qnetd-certutil -i")
        ])
        mock_qnetd_cacert.assert_called_once_with()
        mock_logger.info.assert_called_once_with('Generating QNetd CA and server certificates on %s', '10.10.10.123')

    @mock.patch("os.path.exists")
    @mock.patch("crmsh.parallax.parallax_slurp")
    @mock.patch("crmsh.qdevice.QDevice.qnetd_cacert_on_local", new_callable=mock.PropertyMock)
    def test_fetch_qnetd_crt_from_qnetd_exist(self, mock_qnetd_cacert_local,
                                              mock_parallax_slurp, mock_exists):
        mock_qnetd_cacert_local.return_value = "/etc/corosync/qdevice/net/10.10.10.123/qnetd-cacert.crt"
        mock_exists.return_value = True

        mock_log = mock.MagicMock()
        self.qdevice_with_ip.fetch_qnetd_crt_from_qnetd(mock_log)

        mock_exists.assert_called_once_with(mock_qnetd_cacert_local.return_value)
        mock_qnetd_cacert_local.assert_called_once_with()
        mock_parallax_slurp.assert_not_called()
        mock_log.assert_not_called()

    @mock.patch("os.path.exists")
    @mock.patch("crmsh.parallax.parallax_slurp")
    @mock.patch("crmsh.qdevice.QDevice.qnetd_cacert_on_local", new_callable=mock.PropertyMock)
    def test_fetch_qnetd_crt_from_qnetd(self, mock_qnetd_cacert_local,
                                        mock_parallax_slurp, mock_exists):
        mock_qnetd_cacert_local.return_value = "/etc/corosync/qdevice/net/10.10.10.123/qnetd-cacert.crt"
        mock_exists.return_value = False

        mock_log = mock.MagicMock()
        self.qdevice_with_ip.fetch_qnetd_crt_from_qnetd(mock_log)

        mock_exists.assert_called_once_with(mock_qnetd_cacert_local.return_value)
        mock_qnetd_cacert_local.assert_called_once_with()
        mock_log.assert_called_once_with("Fetch qnetd-cacert.crt from 10.10.10.123")
        mock_parallax_slurp.assert_called_once_with(["10.10.10.123"], "/etc/corosync/qdevice/net", "/etc/corosync/qnetd/nssdb/qnetd-cacert.crt")

    @mock.patch("crmsh.utils.list_cluster_nodes")
    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.parallax.parallax_copy")
    def test_copy_qnetd_crt_to_cluster_one_node(self, mock_copy, mock_this_node, mock_list_nodes):
        mock_this_node.return_value = "node1.com"
        mock_list_nodes.return_value = ["node1.com"]

        mock_log = mock.MagicMock()
        self.qdevice_with_ip.copy_qnetd_crt_to_cluster(mock_log)

        mock_this_node.assert_called_once_with()
        mock_list_nodes.assert_called_once_with()
        mock_copy.assert_not_called()
        mock_log.assert_not_called()

    @mock.patch("crmsh.utils.list_cluster_nodes")
    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.parallax.parallax_copy")
    @mock.patch("crmsh.qdevice.QDevice.qnetd_cacert_on_local", new_callable=mock.PropertyMock)
    @mock.patch("os.path.dirname")
    def test_copy_qnetd_crt_to_cluster(self, mock_dirname, mock_qnetd_cacert_local,
                                       mock_copy, mock_this_node, mock_list_nodes):
        mock_qnetd_cacert_local.return_value = "/etc/corosync/qdevice/net/10.10.10.123/qnetd-cacert.crt"
        mock_dirname.return_value = "/etc/corosync/qdevice/net/10.10.10.123"
        mock_this_node.return_value = "node1.com"
        mock_list_nodes.return_value = ["node1.com", "node2.com"]

        mock_log = mock.MagicMock()
        self.qdevice_with_ip.copy_qnetd_crt_to_cluster(mock_log)

        mock_this_node.assert_called_once_with()
        mock_list_nodes.assert_called_once_with()
        mock_log.assert_called_once_with("Copy exported qnetd-cacert.crt to ['node2.com']")
        mock_copy.assert_called_once_with(["node2.com"], mock_dirname.return_value,
                                          "/etc/corosync/qdevice/net", True)

    @mock.patch("crmsh.parallax.parallax_call")
    @mock.patch("crmsh.qdevice.QDevice.qnetd_cacert_on_local", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.utils.list_cluster_nodes")
    def test_init_db_on_cluster(self, mock_list_nodes, mock_qnetd_cacert_local, mock_call):
        mock_list_nodes.return_value = ["node1", "node2"]
        mock_qnetd_cacert_local.return_value = "/etc/corosync/qdevice/net/10.10.10.123/qnetd-cacert.crt"
        mock_call.return_value = [("node1", (0, None, None)), ("node2", (0, None, None))]

        mock_log = mock.MagicMock()
        self.qdevice_with_ip.init_db_on_cluster(mock_log)

        mock_list_nodes.assert_called_once_with()
        mock_qnetd_cacert_local.assert_called_once_with()
        mock_log.assert_called_once_with("Initialize database on ['node1', 'node2']",
                'corosync-qdevice-net-certutil -i -c /etc/corosync/qdevice/net/10.10.10.123/qnetd-cacert.crt')
        mock_call.assert_called_once_with(mock_list_nodes.return_value,
                                          "corosync-qdevice-net-certutil -i -c {}".format(mock_qnetd_cacert_local.return_value))

    @mock.patch("crmsh.sh.ClusterShell.get_stdout_or_raise_error")
    def test_create_ca_request(self, mock_stdout_stderr):
        mock_stdout_stderr.return_value = (0, None, None)

        mock_log = mock.MagicMock()
        self.qdevice_with_cluster_name.create_ca_request(mock_log)

        mock_log.assert_called_once_with("Generate certificate request qdevice-net-node.crq",
                'corosync-qdevice-net-certutil -r -n hacluster1')
        mock_stdout_stderr.assert_called_once_with("corosync-qdevice-net-certutil -r -n hacluster1")

    @mock.patch("crmsh.qdevice.QDevice.qdevice_crq_on_qnetd", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.qdevice.QDevice.qdevice_crq_on_local", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.parallax.parallax_copy")
    def test_copy_crq_to_qnetd(self, mock_copy, mock_qdevice_crq_local,
                               mock_qdevice_crq_qnetd):
        mock_qdevice_crq_local.return_value = "/etc/corosync/qdevice/net/nssdb/qdevice-net-node.crq"
        mock_qdevice_crq_qnetd.return_value = "/etc/corosync/qnetd/nssdb/qdevice-net-node.crq"

        mock_log = mock.MagicMock()
        self.qdevice_with_ip.copy_crq_to_qnetd(mock_log)

        mock_log.assert_called_once_with("Copy qdevice-net-node.crq to 10.10.10.123")
        mock_copy.assert_called_once_with(["10.10.10.123"], mock_qdevice_crq_local.return_value,
                                          mock_qdevice_crq_qnetd.return_value, False)
        mock_qdevice_crq_local.assert_called_once_with()
        mock_qdevice_crq_qnetd.assert_called_once_with()

    @mock.patch("crmsh.parallax.parallax_call")
    @mock.patch("crmsh.qdevice.QDevice.qdevice_crq_on_qnetd", new_callable=mock.PropertyMock)
    def test_sign_crq_on_qnetd(self, mock_qdevice_crq_qnetd, mock_call):
        mock_qdevice_crq_qnetd.return_value = "/etc/corosync/qnetd/nssdb/qdevice-net-node.crq"
        mock_call.return_value = ["10.10.10.123", (0, None, None)]

        mock_log = mock.MagicMock()
        self.qdevice_with_ip.cluster_name = "hacluster"
        self.qdevice_with_ip.sign_crq_on_qnetd(mock_log)

        mock_log.assert_called_once_with("Sign and export cluster certificate on 10.10.10.123",
                'corosync-qnetd-certutil -s -c /etc/corosync/qnetd/nssdb/qdevice-net-node.crq -n hacluster')
        mock_qdevice_crq_qnetd.assert_called_once_with()
        mock_call.assert_called_once_with(["10.10.10.123"],
                                          "corosync-qnetd-certutil -s -c {} -n hacluster".format(mock_qdevice_crq_qnetd.return_value))

    @mock.patch("crmsh.qdevice.QDevice.qnetd_cluster_crt_on_qnetd", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.parallax.parallax_slurp")
    def test_fetch_cluster_crt_from_qnetd(self, mock_parallax_slurp, mock_crt_on_qnetd):
        mock_crt_on_qnetd.return_value = "/etc/corosync/qnetd/nssdb/cluster-hacluster.crt"

        self.qdevice_with_ip.cluster_name = "hacluster"
        mock_log = mock.MagicMock()
        self.qdevice_with_ip.fetch_cluster_crt_from_qnetd(mock_log)

        mock_log.assert_called_once_with("Fetch cluster-hacluster.crt from 10.10.10.123")
        mock_crt_on_qnetd.assert_has_calls([mock.call(), mock.call()])
        mock_parallax_slurp.assert_called_once_with(["10.10.10.123"], "/etc/corosync/qdevice/net", mock_crt_on_qnetd.return_value)

    @mock.patch("crmsh.sh.ClusterShell.get_stdout_or_raise_error")
    @mock.patch("crmsh.qdevice.QDevice.qnetd_cluster_crt_on_local", new_callable=mock.PropertyMock)
    def test_import_cluster_crt(self, mock_crt_on_local, mock_stdout_stderr):
        mock_crt_on_local.return_value = "/etc/corosync/qdevice/net/10.10.10.123/cluster-hacluster.crt"

        mock_log = mock.MagicMock()
        self.qdevice_with_ip.import_cluster_crt(mock_log)

        mock_log.assert_called_once_with("Import certificate file cluster-hacluster.crt on local",
                'corosync-qdevice-net-certutil -M -c /etc/corosync/qdevice/net/10.10.10.123/cluster-hacluster.crt')
        mock_crt_on_local.assert_has_calls([mock.call(), mock.call()])
        mock_stdout_stderr.assert_called_once_with("corosync-qdevice-net-certutil -M -c {}".format(mock_crt_on_local.return_value))

    @mock.patch("crmsh.utils.list_cluster_nodes")
    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.parallax.parallax_copy")
    def test_copy_p12_to_cluster_one_node(self, mock_copy, mock_this_node, mock_list_nodes):
        mock_this_node.return_value = "node1.com"
        mock_list_nodes.return_value = ["node1.com"]

        mock_log = mock.MagicMock()
        self.qdevice_with_ip.copy_p12_to_cluster(mock_log)

        mock_log.assert_not_called()
        mock_this_node.assert_called_once_with()
        mock_list_nodes.assert_called_once_with()
        mock_copy.assert_not_called()

    @mock.patch("crmsh.utils.list_cluster_nodes")
    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.parallax.parallax_copy")
    @mock.patch("crmsh.qdevice.QDevice.qdevice_p12_on_local", new_callable=mock.PropertyMock)
    def test_copy_p12_to_cluster(self, mock_p12_on_local,
                                       mock_copy, mock_this_node, mock_list_nodes):
        mock_this_node.return_value = "node1.com"
        mock_list_nodes.return_value = ["node1.com", "node2.com"]
        mock_p12_on_local.return_value = "/etc/corosync/qdevice/net/nssdb/qdevice-net-node.p12"

        mock_log = mock.MagicMock()
        self.qdevice_with_ip.copy_p12_to_cluster(mock_log)

        mock_log.assert_called_once_with("Copy qdevice-net-node.p12 to ['node2.com']")
        mock_this_node.assert_called_once_with()
        mock_list_nodes.assert_called_once_with()
        mock_copy.assert_called_once_with(["node2.com"], mock_p12_on_local.return_value,
                                          mock_p12_on_local.return_value, False)
        mock_p12_on_local.assert_has_calls([mock.call(), mock.call()])

    @mock.patch("crmsh.parallax.parallax_call")
    @mock.patch("crmsh.utils.list_cluster_nodes_except_me")
    def test_import_p12_on_cluster_one_node(self, mock_list_nodes, mock_call):
        mock_list_nodes.return_value = []

        mock_log = mock.MagicMock()
        self.qdevice_with_ip.import_p12_on_cluster(mock_log)

        mock_log.assert_not_called()
        mock_list_nodes.assert_called_once_with()
        mock_call.assert_not_called()

    @mock.patch("crmsh.parallax.parallax_call")
    @mock.patch("crmsh.qdevice.QDevice.qdevice_p12_on_local", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.utils.list_cluster_nodes_except_me")
    def test_import_p12_on_cluster(self, mock_list_nodes, mock_p12_on_local, mock_call):
        mock_list_nodes.return_value = ["node2", "node3"]
        mock_p12_on_local.return_value = "/etc/corosync/qdevice/net/nssdb/qdevice-net-node.p12"
        mock_call.return_value = [("node2", (0, None, None)), ("node3", (0, None, None))]

        mock_log = mock.MagicMock()
        self.qdevice_with_ip.import_p12_on_cluster(mock_log)

        mock_log.assert_called_once_with("Import qdevice-net-node.p12 on ['node2', 'node3']",
                'corosync-qdevice-net-certutil -m -c /etc/corosync/qdevice/net/nssdb/qdevice-net-node.p12')
        mock_list_nodes.assert_called_once_with()
        mock_call.assert_called_once_with(
                ["node2", "node3"],
                "corosync-qdevice-net-certutil -m -c {}".format(mock_p12_on_local.return_value))
        mock_p12_on_local.assert_called_once_with()

    @mock.patch("crmsh.qdevice.QDevice.import_p12_on_cluster")
    @mock.patch("crmsh.qdevice.QDevice.copy_p12_to_cluster")
    @mock.patch("crmsh.qdevice.QDevice.import_cluster_crt")
    @mock.patch("crmsh.qdevice.QDevice.fetch_cluster_crt_from_qnetd")
    @mock.patch("crmsh.qdevice.QDevice.sign_crq_on_qnetd")
    @mock.patch("crmsh.qdevice.QDevice.copy_crq_to_qnetd")
    @mock.patch("crmsh.qdevice.QDevice.create_ca_request")
    @mock.patch("crmsh.qdevice.QDevice.init_db_on_cluster")
    @mock.patch("crmsh.qdevice.QDevice.copy_qnetd_crt_to_cluster")
    @mock.patch("crmsh.qdevice.QDevice.fetch_qnetd_crt_from_qnetd")
    def test_certificate_process_on_init(self, mock_fetch_qnetd_crt_from_qnetd,
            mock_copy_qnetd_crt_to_cluster, mock_init_db_on_cluster, mock_create_ca_request,
            mock_copy_crq_to_qnetd, mock_sign_crq_on_qnetd, mock_fetch_cluster_crt_from_qnetd,
            mock_import_cluster_crt, mock_copy_p12_to_cluster, mock_import_p12_on_cluster):

        self.qdevice_with_ip.certificate_process_on_init()
        mock_fetch_qnetd_crt_from_qnetd.assert_called_once()
        mock_copy_qnetd_crt_to_cluster.assert_called_once()
        mock_init_db_on_cluster.assert_called_once()
        mock_create_ca_request.assert_called_once()
        mock_copy_crq_to_qnetd.assert_called_once()
        mock_sign_crq_on_qnetd.assert_called_once()
        mock_fetch_cluster_crt_from_qnetd.assert_called_once()
        mock_import_cluster_crt.assert_called_once()
        mock_copy_p12_to_cluster.assert_called_once()
        mock_import_p12_on_cluster.assert_called_once()

    @mock.patch("crmsh.qdevice.QDevice.log_only_to_file")
    @mock.patch("os.path.exists")
    @mock.patch("crmsh.qdevice.QDevice.qnetd_cacert_on_cluster", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.qdevice.QDevice.qnetd_cacert_on_local", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.parallax.parallax_slurp")
    def test_fetch_qnetd_crt_from_cluster_exist(self, mock_parallax_slurp, mock_qnetd_cacert_local,
                                                mock_qnetd_cacert_cluster, mock_exists, mock_log):
        mock_exists.return_value = True
        mock_qnetd_cacert_cluster.return_value = "/etc/corosync/qdevice/net/node1.com/qnetd-cacert.crt"

        self.qdevice_with_ip_cluster_node.fetch_qnetd_crt_from_cluster()

        mock_log.assert_not_called()
        mock_exists.assert_called_once_with(mock_qnetd_cacert_cluster.return_value)
        mock_qnetd_cacert_cluster.assert_called_once_with()
        mock_qnetd_cacert_local.assert_not_called()
        mock_parallax_slurp.assert_not_called()

    @mock.patch("crmsh.qdevice.QDevice.log_only_to_file")
    @mock.patch("os.path.exists")
    @mock.patch("crmsh.qdevice.QDevice.qnetd_cacert_on_cluster", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.qdevice.QDevice.qnetd_cacert_on_local", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.parallax.parallax_slurp")
    def test_fetch_qnetd_crt_from_cluster(self, mock_parallax_slurp, mock_qnetd_cacert_local,
                                          mock_qnetd_cacert_cluster, mock_exists, mock_log):
        mock_exists.return_value = False
        mock_qnetd_cacert_cluster.return_value = "/etc/corosync/qdevice/net/node1.com/qnetd-cacert.crt"
        mock_qnetd_cacert_local.return_value = "/etc/corosync/qdevice/net/10.10.10.123/qnetd-cacert.crt"

        self.qdevice_with_ip_cluster_node.fetch_qnetd_crt_from_cluster()

        mock_log.assert_called_once_with("Step 1: Fetch qnetd-cacert.crt from node1.com")
        mock_exists.assert_called_once_with(mock_qnetd_cacert_cluster.return_value)
        mock_qnetd_cacert_cluster.assert_called_once_with()
        mock_qnetd_cacert_local.assert_called_once_with()
        mock_parallax_slurp.assert_called_once_with(["node1.com"], "/etc/corosync/qdevice/net", mock_qnetd_cacert_local.return_value)

    @mock.patch("crmsh.qdevice.QDevice.log_only_to_file")
    @mock.patch("crmsh.sh.ClusterShell.get_stdout_or_raise_error")
    @mock.patch("crmsh.qdevice.QDevice.qnetd_cacert_on_cluster", new_callable=mock.PropertyMock)
    def test_init_db_on_local(self, mock_qnetd_cacert_cluster, mock_stdout_stderr, mock_log):
        mock_qnetd_cacert_cluster.return_value = "/etc/corosync/qdevice/net/node1.com/qnetd-cacert.crt"
        mock_stdout_stderr.return_value = (0, None, None)

        self.qdevice_with_ip_cluster_node.init_db_on_local()

        mock_log.assert_called_once_with("Step 2: Initialize database on local",
                'corosync-qdevice-net-certutil -i -c /etc/corosync/qdevice/net/node1.com/qnetd-cacert.crt')
        mock_qnetd_cacert_cluster.assert_called_once_with()
        mock_stdout_stderr.assert_called_once_with("corosync-qdevice-net-certutil -i -c {}".format(mock_qnetd_cacert_cluster.return_value))

    @mock.patch("crmsh.qdevice.QDevice.log_only_to_file")
    @mock.patch("os.path.exists")
    @mock.patch("crmsh.qdevice.QDevice.qdevice_p12_on_cluster", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.qdevice.QDevice.qdevice_p12_on_local", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.parallax.parallax_slurp")
    def test_fetch_p12_from_cluster_exist(self, mock_parallax_slurp, mock_p12_on_local,
                                          mock_p12_on_cluster, mock_exists, mock_log):
        mock_exists.return_value = True
        mock_p12_on_cluster.return_value = "/etc/corosync/qdevice/net/node1.com/qdevice-net-node.p12"

        self.qdevice_with_ip_cluster_node.fetch_p12_from_cluster()

        mock_log.assert_not_called()
        mock_exists.assert_called_once_with(mock_p12_on_cluster.return_value)
        mock_p12_on_cluster.assert_called_once_with()
        mock_p12_on_local.assert_not_called()
        mock_parallax_slurp.assert_not_called()

    @mock.patch("crmsh.qdevice.QDevice.log_only_to_file")
    @mock.patch("os.path.exists")
    @mock.patch("crmsh.qdevice.QDevice.qdevice_p12_on_cluster", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.qdevice.QDevice.qdevice_p12_on_local", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.parallax.parallax_slurp")
    def test_fetch_p12_from_cluster(self, mock_parallax_slurp, mock_p12_on_local,
                                    mock_p12_on_cluster, mock_exists, mock_log):
        mock_exists.return_value = False
        mock_p12_on_cluster.return_value = "/etc/corosync/qdevice/net/node1.com/qdevice-net-node.p12"
        mock_p12_on_local.return_value = "/etc/corosync/qdevice/net/nssdb/qdevice-net-node.p12"

        self.qdevice_with_ip_cluster_node.fetch_p12_from_cluster()

        mock_log.assert_called_once_with("Step 3: Fetch qdevice-net-node.p12 from node1.com")
        mock_exists.assert_called_once_with(mock_p12_on_cluster.return_value)
        mock_p12_on_cluster.assert_called_once_with()
        mock_p12_on_local.assert_called_once_with()
        mock_parallax_slurp.assert_called_once_with(["node1.com"], '/etc/corosync/qdevice/net', mock_p12_on_local.return_value)

    @mock.patch("crmsh.qdevice.QDevice.log_only_to_file")
    @mock.patch("crmsh.sh.ClusterShell.get_stdout_or_raise_error")
    @mock.patch("crmsh.qdevice.QDevice.qdevice_p12_on_cluster", new_callable=mock.PropertyMock)
    def test_import_p12_on_local(self, mock_p12_on_cluster, mock_stdout_stderr, mock_log):
        mock_p12_on_cluster.return_value = "/etc/corosync/qdevice/net/node1.com/qdevice-net-node.p12"

        self.qdevice_with_ip_cluster_node.import_p12_on_local()

        mock_log.assert_called_once_with("Step 4: Import cluster certificate and key",
                'corosync-qdevice-net-certutil -m -c /etc/corosync/qdevice/net/node1.com/qdevice-net-node.p12')
        mock_p12_on_cluster.assert_called_once_with()
        mock_stdout_stderr.assert_called_once_with("corosync-qdevice-net-certutil -m -c {}".format(mock_p12_on_cluster.return_value))

    @mock.patch("crmsh.qdevice.QDevice.import_p12_on_local")
    @mock.patch("crmsh.qdevice.QDevice.fetch_p12_from_cluster")
    @mock.patch("crmsh.qdevice.QDevice.init_db_on_local")
    @mock.patch("crmsh.qdevice.QDevice.fetch_qnetd_crt_from_cluster")
    def test_certificate_process_on_join(self, mock_fetch_qnetd_crt_from_cluster, mock_init_db_on_local,
            mock_fetch_p12_from_cluster, mock_import_p12_on_local):
        self.qdevice_with_ip.certificate_process_on_join()
        mock_fetch_qnetd_crt_from_cluster.assert_called_once_with()
        mock_init_db_on_local.assert_called_once_with()
        mock_fetch_p12_from_cluster.assert_called_once_with()
        mock_import_p12_on_local.assert_called_once_with()

    @mock.patch("crmsh.utils.str2file")
    @mock.patch("crmsh.corosync.make_section")
    @mock.patch("crmsh.corosync.Parser")
    @mock.patch("crmsh.corosync.conf")
    @mock.patch("crmsh.utils.read_from_file")
    def test_write_qdevice_config(self, mock_read_file, mock_conf, mock_parser, mock_mksection, mock_str2file):
        mock_mksection.side_effect = [
            ["device {", "}"],
            ["net {", "}"]
        ]
        mock_read_file.return_value = "data"
        mock_conf.side_effect = ["corosync.conf", "corosync.conf"]
        mock_instance = mock.Mock()
        mock_parser.return_value = mock_instance
        mock_instance.to_string.return_value = "string data"

        self.qdevice_with_ip.write_qdevice_config()

        mock_conf.assert_has_calls([mock.call(), mock.call()])
        mock_parser.assert_called_once_with("data")
        mock_instance.remove.assert_called_once_with("quorum.device")
        mock_instance.add.assert_has_calls([
            mock.call('quorum', ["device {", "}"]),
            mock.call('quorum.device', ["net {", "}"])
        ])
        mock_instance.set.assert_has_calls([
            mock.call('quorum.device.votes', '1'),
            mock.call('quorum.device.model', 'net'),
            mock.call('quorum.device.net.tls', 'on'),
            mock.call('quorum.device.net.host', '10.10.10.123'),
            mock.call('quorum.device.net.port', 5403),
            mock.call('quorum.device.net.algorithm', 'ffsplit'),
            mock.call('quorum.device.net.tie_breaker', 'lowest')
        ])
        mock_instance.to_string.assert_called_once_with()
        mock_mksection.assert_has_calls([
            mock.call('quorum.device', []),
            mock.call('quorum.device.net', [])
        ])
        mock_str2file.assert_called_once_with("string data", "corosync.conf")

    @mock.patch("crmsh.utils.str2file")
    @mock.patch("crmsh.corosync.Parser")
    @mock.patch("crmsh.corosync.conf")
    @mock.patch("crmsh.utils.read_from_file")
    def test_remove_qdevice_config(self, mock_read_file, mock_conf, mock_parser, mock_str2file):
        mock_conf.side_effect = ["corosync.conf", "corosync.conf"]
        mock_read_file.return_value = "data"
        mock_instance = mock.Mock()
        mock_parser.return_value = mock_instance
        mock_instance.to_string.return_value = "string data"

        self.qdevice_with_ip.remove_qdevice_config()

        mock_conf.assert_has_calls([mock.call(), mock.call()])
        mock_parser.assert_called_once_with("data")
        mock_instance.remove.assert_called_once_with("quorum.device")
        mock_instance.to_string.assert_called_once_with()
        mock_str2file.assert_called_once_with("string data", "corosync.conf")

    @mock.patch("crmsh.parallax.parallax_call")
    @mock.patch('crmsh.utils.list_cluster_nodes')
    @mock.patch('os.path.exists')
    def test_remove_qdevice_db_not_exist(self, mock_exists, mock_list_nodes, mock_call):
        mock_exists.return_value = False

        self.qdevice_with_ip.remove_qdevice_db()

        mock_exists.assert_called_once_with('/etc/corosync/qdevice/net/nssdb')
        mock_list_nodes.assert_not_called()
        mock_call.assert_not_called()

    @mock.patch("crmsh.parallax.parallax_call")
    @mock.patch('crmsh.utils.list_cluster_nodes')
    @mock.patch('os.path.exists')
    def test_remove_qdevice_db(self, mock_exists, mock_list_nodes, mock_call):
        mock_exists.return_value = True
        mock_list_nodes.return_value = ["node1.com", "node2.com"]
        mock_call.return_value = [("node1.com", (0, None, None)), ("node2.com", (0, None, None))]

        self.qdevice_with_ip.remove_qdevice_db()

        mock_exists.assert_called_once_with('/etc/corosync/qdevice/net/nssdb')
        mock_list_nodes.assert_called_once_with()
        mock_call.assert_called_once_with(mock_list_nodes.return_value,
                                          'rm -rf /etc/corosync/qdevice/net/*'.format())

    @mock.patch('logging.Logger.warning')
    @mock.patch('crmsh.corosync.get_value')
    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    def test_check_qdevice_vote(self, mock_run, mock_get_value, mock_warning):
        data = """
Membership information
----------------------
    Nodeid      Votes    Qdevice Name
         1          1    A,V,NMW 192.168.122.221 (local)
         0          0            Qdevice
        """
        mock_run.return_value = data
        mock_get_value.return_value = "qnetd-node"
        qdevice.QDevice.check_qdevice_vote()
        mock_run.assert_called_once_with("corosync-quorumtool -s", success_exit_status={0, 2})
        mock_get_value.assert_called_once_with("quorum.device.net.host")
        mock_warning.assert_called_once_with("Qdevice's vote is 0, which simply means Qdevice can't talk to Qnetd(qnetd-node) for various reasons.")

    @mock.patch('crmsh.qdevice.evaluate_qdevice_quorum_effect')
    @mock.patch('crmsh.log.LoggerUtils.status_long')
    @mock.patch('crmsh.qdevice.QDevice.remove_qdevice_db')
    def test_config_and_start_qdevice(self, mock_rm_db, mock_status_long, mock_evaluate):
        mock_status_long.return_value.__enter__ = mock.Mock()
        mock_status_long.return_value.__exit__ = mock.Mock()
        self.qdevice_with_ip.certificate_process_on_init = mock.Mock()
        self.qdevice_with_ip.adjust_sbd_watchdog_timeout_with_qdevice = mock.Mock()
        self.qdevice_with_ip.config_qdevice = mock.Mock()
        self.qdevice_with_ip.start_qdevice_service = mock.Mock()

        self.qdevice_with_ip.config_and_start_qdevice.__wrapped__(self.qdevice_with_ip)

        mock_rm_db.assert_called_once_with()
        mock_status_long.assert_called_once_with("Qdevice certification process")
        self.qdevice_with_ip.certificate_process_on_init.assert_called_once_with()
        self.qdevice_with_ip.adjust_sbd_watchdog_timeout_with_qdevice.assert_called_once_with()
        self.qdevice_with_ip.config_qdevice.assert_called_once_with()
        self.qdevice_with_ip.start_qdevice_service.assert_called_once_with()

    @mock.patch('crmsh.utils.set_property')
    @mock.patch('crmsh.sbd.SBDTimeout.get_stonith_timeout')
    @mock.patch('crmsh.sbd.SBDManager.update_configuration')
    @mock.patch('crmsh.sbd.SBDManager.get_sbd_value_from_config')
    @mock.patch('crmsh.sbd.SBDManager.is_using_diskless_sbd')
    def test_adjust_sbd_watchdog_timeout_with_qdevice(self, mock_using_diskless_sbd, mock_get_sbd_value, mock_update_config, mock_get_timeout, mock_set_property):
        mock_using_diskless_sbd.return_value = True
        mock_get_sbd_value.return_value = ""
        mock_get_timeout.return_value = 100

        self.qdevice_with_stage_cluster_name.adjust_sbd_watchdog_timeout_with_qdevice()

        mock_using_diskless_sbd.assert_called_once_with()
        mock_get_sbd_value.assert_called_once_with("SBD_WATCHDOG_TIMEOUT")
        mock_update_config.assert_called_once_with({"SBD_WATCHDOG_TIMEOUT": str(sbd.SBDTimeout.SBD_WATCHDOG_TIMEOUT_DEFAULT_WITH_QDEVICE)})
        mock_set_property.assert_called_once_with("stonith-timeout", 100)

    @mock.patch('crmsh.qdevice.QDevice.start_qnetd')
    @mock.patch('crmsh.qdevice.QDevice.enable_qnetd')
    @mock.patch('crmsh.utils.cluster_run_cmd')
    @mock.patch('logging.Logger.info')
    def test_start_qdevice_service_reload(self, mock_status, mock_cluster_run, mock_enable_qnetd, mock_start_qnetd):
        self.qdevice_with_ip.qdevice_reload_policy = qdevice.QdevicePolicy.QDEVICE_RELOAD

        self.qdevice_with_ip.start_qdevice_service()

        mock_status.assert_has_calls([
            mock.call("Enable corosync-qdevice.service in cluster"),
            mock.call("Starting corosync-qdevice.service in cluster"),
            mock.call("Enable corosync-qnetd.service on 10.10.10.123"),
            mock.call("Starting corosync-qnetd.service on 10.10.10.123")
            ])
        mock_cluster_run.assert_has_calls([
            mock.call("systemctl enable corosync-qdevice"),
            mock.call("systemctl restart corosync-qdevice")
            ])
        mock_enable_qnetd.assert_called_once_with()
        mock_start_qnetd.assert_called_once_with()

    @mock.patch('crmsh.qdevice.QDevice.start_qnetd')
    @mock.patch('crmsh.qdevice.QDevice.enable_qnetd')
    @mock.patch('crmsh.bootstrap.wait_for_cluster')
    @mock.patch('crmsh.utils.cluster_run_cmd')
    @mock.patch('logging.Logger.info')
    def test_start_qdevice_service_restart(self, mock_status, mock_cluster_run, mock_wait, mock_enable_qnetd, mock_start_qnetd):
        self.qdevice_with_ip.qdevice_reload_policy = qdevice.QdevicePolicy.QDEVICE_RESTART

        self.qdevice_with_ip.start_qdevice_service()

        mock_status.assert_has_calls([
            mock.call("Enable corosync-qdevice.service in cluster"),
            mock.call("Restarting cluster service"),
            mock.call("Enable corosync-qnetd.service on 10.10.10.123"),
            mock.call("Starting corosync-qnetd.service on 10.10.10.123")
            ])
        mock_wait.assert_called_once_with()
        mock_cluster_run.assert_has_calls([
            mock.call("systemctl enable corosync-qdevice"),
            mock.call("crm cluster restart")
            ])
        mock_enable_qnetd.assert_called_once_with()
        mock_start_qnetd.assert_called_once_with()

    @mock.patch('crmsh.qdevice.QDevice.start_qnetd')
    @mock.patch('crmsh.qdevice.QDevice.enable_qnetd')
    @mock.patch('logging.Logger.warning')
    @mock.patch('crmsh.utils.cluster_run_cmd')
    @mock.patch('logging.Logger.info')
    def test_start_qdevice_service_warn(self, mock_status, mock_cluster_run, mock_warn, mock_enable_qnetd, mock_start_qnetd):
        self.qdevice_with_ip.qdevice_reload_policy = qdevice.QdevicePolicy.QDEVICE_RESTART_LATER

        self.qdevice_with_ip.start_qdevice_service()

        mock_status.assert_has_calls([
            mock.call("Enable corosync-qdevice.service in cluster"),
            mock.call("Enable corosync-qnetd.service on 10.10.10.123"),
            mock.call("Starting corosync-qnetd.service on 10.10.10.123")
            ])
        mock_cluster_run.assert_has_calls([
            mock.call("systemctl enable corosync-qdevice"),
            ])
        mock_warn.assert_called_once_with("To use qdevice service, need to restart cluster service manually on each node")
        mock_enable_qnetd.assert_called_once_with()
        mock_start_qnetd.assert_called_once_with()

    @mock.patch('crmsh.utils.cluster_run_cmd')
    @mock.patch('crmsh.bootstrap.update_expected_votes')
    @mock.patch('crmsh.log.LoggerUtils.status_long')
    @mock.patch('crmsh.corosync.add_nodelist_from_cmaptool')
    @mock.patch('crmsh.corosync.is_unicast')
    @mock.patch('crmsh.qdevice.QDevice.write_qdevice_config')
    def test_config_qdevice(self, mock_write, mock_is_unicast, mock_add_nodelist, mock_status_long,
            mock_update_votes, mock_run):
        mock_is_unicast.return_value = False
        mock_status_long.return_value.__enter__ = mock.Mock()
        mock_status_long.return_value.__exit__ = mock.Mock()
        self.qdevice_with_ip.qdevice_reload_policy = qdevice.QdevicePolicy.QDEVICE_RELOAD

        self.qdevice_with_ip.config_qdevice()

        mock_write.assert_called_once_with()
        mock_is_unicast.assert_called_once_with()
        mock_add_nodelist.assert_called_once_with()
        mock_status_long.assert_called_once_with("Update configuration")
        mock_update_votes.assert_called_once_with()
        mock_run.assert_called_once_with("crm corosync reload")

    @mock.patch('crmsh.utils.is_qdevice_configured')
    def test_remove_certification_files_on_qnetd_return(self, mock_configured):
        mock_configured.return_value = False
        qdevice.QDevice.remove_certification_files_on_qnetd()
        mock_configured.assert_called_once_with()

    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    @mock.patch('crmsh.corosync.get_value')
    @mock.patch('crmsh.utils.is_qdevice_configured')
    def test_remove_certification_files_on_qnetd(self, mock_configured, mock_get_value, mock_run):
        mock_configured.return_value = True
        mock_get_value.side_effect = ["qnetd-node", "cluster1"]
        qdevice.QDevice.remove_certification_files_on_qnetd()
        mock_configured.assert_called_once_with()
        mock_get_value.assert_has_calls([
            mock.call("quorum.device.net.host"),
            mock.call("totem.cluster_name")])
        crt_file = "/etc/corosync/qnetd/nssdb/cluster-cluster1.crt"
        crt_cmd = "test -f {crt_file} && rm -f {crt_file}".format(crt_file=crt_file)
        crq_file = "/etc/corosync/qnetd/nssdb/qdevice-net-node.crq.cluster1"
        crq_cmd = "test -f {crq_file} && rm -f {crq_file}".format(crq_file=crq_file)
        mock_run.assert_has_calls([
            mock.call(crt_cmd, "qnetd-node"),
            mock.call(crq_cmd, "qnetd-node")])
