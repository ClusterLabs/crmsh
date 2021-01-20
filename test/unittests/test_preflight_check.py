import os
import sys

try:
    from unittest import mock, TestCase
except ImportError:
    import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from preflight_check import check, config


class TestCheck(TestCase):

    @mock.patch('preflight_check.check.check_cluster')
    def test_check(self, mock_cluster_check):
        ctx = mock.Mock(cluster_check=True)
        check.check(ctx)
        mock_cluster_check.assert_called_once_with()

    @mock.patch('preflight_check.check.check_firewall')
    @mock.patch('preflight_check.check.check_time_service')
    @mock.patch('preflight_check.check.check_my_hostname_resolves')
    def test_check_environment(self, mock_hostname, mock_time, mock_firewall):
        check.check_environment()
        mock_hostname.assert_called_once_with()
        mock_time.assert_called_once_with()
        mock_firewall.assert_called_once_with()

    @mock.patch('preflight_check.utils.this_node')
    @mock.patch('preflight_check.check.crmshboot.my_hostname_resolves')
    @mock.patch('preflight_check.task.TaskCheck')
    def test_check_my_hostname_resolves(self, mock_task_check, mock_hostname, mock_this_node):
        mock_task_inst = mock.Mock()
        mock_task_check.return_value = mock_task_inst
        mock_task_inst.run.return_value.__enter__ = mock.Mock()
        mock_task_inst.run.return_value.__exit__ = mock.Mock()
        mock_hostname.return_value = False
        mock_this_node.return_value = "node1"

        check.check_my_hostname_resolves()

        mock_task_check.assert_called_once_with("Checking hostname resolvable")
        mock_hostname.assert_called_once_with()
        mock_task_inst.error.assert_called_once_with('Hostname "node1" is unresolvable.\n  Please add an entry to /etc/hosts or configure DNS.')

    @mock.patch('preflight_check.check.crmshutils.service_is_active')
    @mock.patch('preflight_check.check.crmshutils.service_is_enabled')
    @mock.patch('preflight_check.check.crmshutils.service_is_available')
    @mock.patch('preflight_check.task.TaskCheck')
    def test_check_time_service_none(self, mock_task, mock_service_available, mock_service_enabled, mock_service_active):
        mock_task_inst = mock.Mock()
        mock_task.return_value = mock_task_inst
        mock_task_inst.run.return_value.__enter__ = mock.Mock()
        mock_task_inst.run.return_value.__exit__ = mock.Mock()
        mock_service_available.side_effect = [False, False, False]

        check.check_time_service()

        mock_task.assert_called_once_with("Checking time service")
        mock_service_available.assert_has_calls([
            mock.call('chronyd.service'),
            mock.call('ntp.service'),
            mock.call('ntpd.service')
            ])
        mock_task_inst.warn.assert_called_once_with("No NTP service found.")

    @mock.patch('preflight_check.check.crmshutils.service_is_active')
    @mock.patch('preflight_check.check.crmshutils.service_is_enabled')
    @mock.patch('preflight_check.check.crmshutils.service_is_available')
    @mock.patch('preflight_check.task.TaskCheck')
    def test_check_time_service_warn(self, mock_task, mock_service_available, mock_service_enabled, mock_service_active):
        mock_task_inst = mock.Mock()
        mock_task.return_value = mock_task_inst
        mock_task_inst.run.return_value.__enter__ = mock.Mock()
        mock_task_inst.run.return_value.__exit__ = mock.Mock()
        mock_service_available.return_value = True
        mock_service_enabled.return_value = False
        mock_service_active.return_value = False

        check.check_time_service()

        mock_task.assert_called_once_with("Checking time service")
        mock_service_available.assert_called_once_with("chronyd.service")
        mock_task_inst.info.assert_called_once_with("chronyd.service is available")
        mock_task_inst.warn.assert_has_calls([
            mock.call("chronyd.service is disabled"),
            mock.call("chronyd.service is not active"),
            ])

    @mock.patch('preflight_check.check.crmshutils.service_is_active')
    @mock.patch('preflight_check.check.crmshutils.service_is_enabled')
    @mock.patch('preflight_check.check.crmshutils.service_is_available')
    @mock.patch('preflight_check.task.TaskCheck')
    def test_check_time_service(self, mock_task, mock_service_available, mock_service_enabled, mock_service_active):
        mock_task_inst = mock.Mock()
        mock_task.return_value = mock_task_inst
        mock_task_inst.run.return_value.__enter__ = mock.Mock()
        mock_task_inst.run.return_value.__exit__ = mock.Mock()
        mock_service_available.return_value = True
        mock_service_enabled.return_value = True
        mock_service_active.return_value = True

        check.check_time_service()

        mock_task.assert_called_once_with("Checking time service")
        mock_service_available.assert_called_once_with("chronyd.service")
        mock_task_inst.info.assert_has_calls([
            mock.call("chronyd.service is available"),
            mock.call("chronyd.service is enabled"),
            mock.call("chronyd.service is active")
            ])

    @mock.patch('preflight_check.check.crmshutils.get_stdout_stderr')
    @mock.patch('preflight_check.utils.corosync_port_list')
    def test_check_port_open_return(self, mock_corosync_port, mock_run):
        mock_corosync_port.return_value = ["1234", "5678"]
        mock_run.return_value = (1, None, "error")
        task_inst = mock.Mock()

        check.check_port_open(task_inst, "firewalld")

        mock_corosync_port.assert_called_once_with()
        task_inst.error.assert_called_once_with("error")
        mock_run.assert_called_once_with("firewall-cmd --list-port")

    @mock.patch('preflight_check.utils.corosync_port_list')
    def test_check_port_open_fail_to_get_port(self, mock_corosync_port):
        mock_corosync_port.return_value = []
        task_inst = mock.Mock()

        check.check_port_open(task_inst, "firewalld")

        mock_corosync_port.assert_called_once_with()
        task_inst.error.assert_called_once_with("Can not get corosync's port")

    @mock.patch('preflight_check.check.crmshutils.get_stdout_stderr')
    @mock.patch('preflight_check.utils.corosync_port_list')
    def test_check_port_open(self, mock_corosync_port, mock_run):
        mock_corosync_port.return_value = ["1234", "5678"]
        output_cmd = """
 1234/udp
 4444/tcp
        """
        mock_run.return_value = (0, output_cmd, None)
        task_inst = mock.Mock()

        check.check_port_open(task_inst, "firewalld")

        mock_corosync_port.assert_called_once_with()
        task_inst.error.assert_called_once_with("UDP port 5678 should open in firewalld")
        mock_run.assert_called_once_with("firewall-cmd --list-port")
        task_inst.info.assert_called_once_with("UDP port 1234 is opened in firewalld")

    @mock.patch('preflight_check.check.crmshutils.package_is_installed')
    @mock.patch('preflight_check.task.TaskCheck')
    def test_check_firewall_not_intalled(self, mock_task, mock_installed):
        mock_task_inst = mock.Mock()
        mock_task.return_value = mock_task_inst
        mock_task_inst.run.return_value.__enter__ = mock.Mock()
        mock_task_inst.run.return_value.__exit__ = mock.Mock()
        mock_installed.side_effect = [False, False]

        check.check_firewall()

        mock_task.assert_called_once_with("Checking firewall")
        mock_installed.assert_has_calls([
            mock.call("firewalld"),
            mock.call("SuSEfirewall2")
            ])
        mock_task_inst.warn.assert_called_once_with("Failed to detect firewall")

    @mock.patch('preflight_check.check.crmshutils.service_is_active')
    @mock.patch('preflight_check.check.crmshutils.package_is_installed')
    @mock.patch('preflight_check.task.TaskCheck')
    def test_check_firewall_warn(self, mock_task, mock_installed, mock_active):
        mock_task_inst = mock.Mock()
        mock_task.return_value = mock_task_inst
        mock_task_inst.run.return_value.__enter__ = mock.Mock()
        mock_task_inst.run.return_value.__exit__ = mock.Mock()
        mock_installed.return_value = True
        mock_active.return_value = False

        check.check_firewall()

        mock_task.assert_called_once_with("Checking firewall")
        mock_installed.assert_called_once_with("firewalld")
        mock_task_inst.info.assert_called_once_with("firewalld.service is available")
        mock_task_inst.warn.assert_called_once_with("firewalld.service is not active")

    @mock.patch('preflight_check.check.check_port_open')
    @mock.patch('preflight_check.check.crmshutils.service_is_active')
    @mock.patch('preflight_check.check.crmshutils.package_is_installed')
    @mock.patch('preflight_check.task.TaskCheck')
    def test_check_firewall(self, mock_task, mock_installed, mock_active, mock_check_port):
        mock_task_inst = mock.Mock()
        mock_task.return_value = mock_task_inst
        mock_task_inst.run.return_value.__enter__ = mock.Mock()
        mock_task_inst.run.return_value.__exit__ = mock.Mock()
        mock_installed.return_value = True
        mock_active.return_value = True

        check.check_firewall()

        mock_task.assert_called_once_with("Checking firewall")
        mock_installed.assert_called_once_with("firewalld")
        mock_task_inst.info.assert_has_calls([
            mock.call("firewalld.service is available"),
            mock.call("firewalld.service is active")
            ])
        mock_active.assert_called_once_with("firewalld")
        mock_check_port.assert_called_once_with(mock_task_inst, "firewalld")

    @mock.patch('preflight_check.check.check_cluster_service')
    def test_check_cluster_return(self, mock_check_cluster):
        mock_check_cluster.return_value = False
        check.check_cluster()
        mock_check_cluster.assert_called_once_with()

    @mock.patch('preflight_check.check.check_resources')
    @mock.patch('preflight_check.check.check_nodes')
    @mock.patch('preflight_check.check.check_fencing')
    @mock.patch('preflight_check.check.check_cluster_service')
    def test_check_cluster(self, mock_check_cluster, mock_check_fencing, mock_check_nodes, mock_check_resources):
        mock_check_cluster.return_value = True
        check.check_cluster()
        mock_check_cluster.assert_called_once_with()
        mock_check_fencing.assert_called_once_with()
        mock_check_nodes.assert_called_once_with()
        mock_check_resources.assert_called_once_with()

    @mock.patch('preflight_check.check.crmshutils.service_is_active')
    @mock.patch('preflight_check.check.crmshutils.service_is_enabled')
    @mock.patch('preflight_check.task.TaskCheck')
    def test_check_cluster_service_pacemaker_disable(self, mock_task, mock_enabled, mock_active):
        mock_task_inst = mock.Mock(passed=False)
        mock_task.return_value = mock_task_inst
        mock_task_inst.run.return_value.__enter__ = mock.Mock()
        mock_task_inst.run.return_value.__exit__ = mock.Mock()
        mock_enabled.side_effect = [False, True]
        mock_active.side_effect = [True, False]

        res = check.check_cluster_service()
        self.assertEqual(res, False)

        mock_task.assert_called_once_with("Checking cluster service", quiet=False)
        mock_enabled.assert_has_calls([
            mock.call("pacemaker"),
            mock.call("corosync")
            ])
        mock_task_inst.warn.assert_has_calls([
            mock.call("pacemaker.service is disabled"),
            mock.call("corosync.service is enabled")
            ])
        mock_active.assert_has_calls([
            mock.call("corosync"),
            mock.call("pacemaker")
            ])
        mock_task_inst.info.assert_called_once_with("corosync.service is running")
        mock_task_inst.error.assert_called_once_with("pacemaker.service is not running!")

    @mock.patch('preflight_check.check.crmshutils.service_is_active')
    @mock.patch('preflight_check.check.crmshutils.service_is_enabled')
    @mock.patch('preflight_check.task.TaskCheck')
    def test_check_cluster_service(self, mock_task, mock_enabled, mock_active):
        mock_task_inst = mock.Mock(passed=True)
        mock_task.return_value = mock_task_inst
        mock_task_inst.run.return_value.__enter__ = mock.Mock()
        mock_task_inst.run.return_value.__exit__ = mock.Mock()
        mock_enabled.side_effect = [True, True]
        mock_active.side_effect = [True, True]

        res = check.check_cluster_service()
        self.assertEqual(res, True)

        mock_task.assert_called_once_with("Checking cluster service", quiet=False)
        mock_enabled.assert_has_calls([
            mock.call("pacemaker"),
            mock.call("corosync")
            ])
        mock_active.assert_has_calls([
            mock.call("corosync"),
            mock.call("pacemaker")
            ])
        mock_task_inst.info.assert_has_calls([
            mock.call("pacemaker.service is enabled"),
            mock.call("corosync.service is running"),
            mock.call("pacemaker.service is running")
            ])
        mock_task_inst.warn.assert_called_once_with("corosync.service is enabled")

    @mock.patch('preflight_check.utils.FenceInfo')
    @mock.patch('preflight_check.task.TaskCheck')
    def test_check_fencing_no_stonith(self, mock_task, mock_fence_info):
        mock_task_inst = mock.Mock()
        mock_task.return_value = mock_task_inst
        mock_task_inst.run.return_value.__enter__ = mock.Mock()
        mock_task_inst.run.return_value.__exit__ = mock.Mock()
        mock_fence_info_inst = mock.Mock(fence_enabled=False)
        mock_fence_info.return_value = mock_fence_info_inst

        check.check_fencing()

        mock_task.assert_called_once_with("Checking STONITH/Fence")
        mock_fence_info.assert_called_once_with()
        mock_task_inst.warn.assert_called_once_with("stonith is disabled")

    @mock.patch('preflight_check.check.crmshutils.get_stdout_stderr')
    @mock.patch('preflight_check.utils.FenceInfo')
    @mock.patch('preflight_check.task.TaskCheck')
    def test_check_fencing_no_resources(self, mock_task, mock_fence_info, mock_run):
        mock_task_inst = mock.Mock()
        mock_task.return_value = mock_task_inst
        mock_task_inst.run.return_value.__enter__ = mock.Mock()
        mock_task_inst.run.return_value.__exit__ = mock.Mock()
        mock_fence_info_inst = mock.Mock(fence_enabled=True)
        mock_fence_info.return_value = mock_fence_info_inst
        mock_run.return_value = (1, None, None)

        check.check_fencing()

        mock_task.assert_called_once_with("Checking STONITH/Fence")
        mock_fence_info.assert_called_once_with()
        mock_run.assert_called_once_with("crm_mon -r1 | grep '(stonith:.*):'")
        mock_task_inst.info.assert_called_once_with("stonith is enabled")
        mock_task_inst.warn.assert_called_once_with("No stonith resource configured!")

    @mock.patch('preflight_check.check.crmshutils.service_is_active')
    @mock.patch('preflight_check.check.crmshutils.get_stdout_stderr')
    @mock.patch('preflight_check.utils.FenceInfo')
    @mock.patch('preflight_check.task.TaskCheck')
    def test_check_fencing_has_warn(self, mock_task, mock_fence_info, mock_run, mock_active):
        mock_task_inst = mock.Mock()
        mock_task.return_value = mock_task_inst
        mock_task_inst.run.return_value.__enter__ = mock.Mock()
        mock_task_inst.run.return_value.__exit__ = mock.Mock()
        mock_fence_info_inst = mock.Mock(fence_enabled=True)
        mock_fence_info.return_value = mock_fence_info_inst
        mock_run.return_value = (0, "* stonith-sbd  (stonith:external/sbd):  Stopped (disabled)", None)
        mock_active.return_value = False

        check.check_fencing()

        mock_task.assert_called_once_with("Checking STONITH/Fence")
        mock_fence_info.assert_called_once_with()
        mock_run.assert_called_once_with("crm_mon -r1 | grep '(stonith:.*):'")
        mock_task_inst.info.assert_has_calls([
            mock.call("stonith is enabled"),
            mock.call("stonith resource stonith-sbd(external/sbd) is configured")
            ])
        mock_task_inst.warn.assert_has_calls([
            mock.call("stonith resource stonith-sbd(external/sbd) is Stopped"),
            mock.call("sbd service is not running!")
            ])

    @mock.patch('preflight_check.check.crmshutils.service_is_active')
    @mock.patch('preflight_check.check.crmshutils.get_stdout_stderr')
    @mock.patch('preflight_check.utils.FenceInfo')
    @mock.patch('preflight_check.task.TaskCheck')
    def test_check_fencing(self, mock_task, mock_fence_info, mock_run, mock_active):
        mock_task_inst = mock.Mock()
        mock_task.return_value = mock_task_inst
        mock_task_inst.run.return_value.__enter__ = mock.Mock()
        mock_task_inst.run.return_value.__exit__ = mock.Mock()
        mock_fence_info_inst = mock.Mock(fence_enabled=True)
        mock_fence_info.return_value = mock_fence_info_inst
        mock_run.return_value = (0, "* stonith-sbd  (stonith:external/sbd):  Started node2", None)
        mock_active.return_value = True

        check.check_fencing()

        mock_task.assert_called_once_with("Checking STONITH/Fence")
        mock_fence_info.assert_called_once_with()
        mock_run.assert_called_once_with("crm_mon -r1 | grep '(stonith:.*):'")
        mock_task_inst.info.assert_has_calls([
            mock.call("stonith is enabled"),
            mock.call("stonith resource stonith-sbd(external/sbd) is configured"),
            mock.call("stonith resource stonith-sbd(external/sbd) is Started"),
            mock.call("sbd service is running")
            ])
        mock_active.assert_called_once_with("sbd")

    @mock.patch('preflight_check.check.crmshutils.get_stdout_stderr')
    @mock.patch('preflight_check.task.TaskCheck')
    def test_check_nodes_error(self, mock_task, mock_run):
        mock_task_inst = mock.Mock()
        mock_task.return_value = mock_task_inst
        mock_task_inst.run.return_value.__enter__ = mock.Mock()
        mock_task_inst.run.return_value.__exit__ = mock.Mock()
        mock_run.return_value = (1, None, "error data")

        check.check_nodes()

        mock_task.assert_called_once_with("Checking nodes")
        mock_run.assert_called_once_with("crm_mon -1")
        mock_task_inst.error.assert_called_once_with("run \"crm_mon -1\" error: error data")

    @mock.patch('preflight_check.check.crmshutils.get_stdout_stderr')
    @mock.patch('preflight_check.task.TaskCheck')
    def test_check_nodes(self, mock_task, mock_run):
        mock_task_inst = mock.Mock()
        mock_task.return_value = mock_task_inst
        mock_task_inst.run.return_value.__enter__ = mock.Mock()
        mock_task_inst.run.return_value.__exit__ = mock.Mock()
        output = """
Cluster Summary:
  * Stack: corosync
  * Current DC: 15sp2-1 (version 2.0.3+20200511.2b248d828-1.10-2.0.3+20200511.2b248d828) - partition with quorum
  * Last updated: Tue Nov  3 14:09:29 2020
  * Last change:  Tue Nov  3 13:47:29 2020 by root via cibadmin on 15sp2-1
  * 2 nodes configured
  * 1 resource instance configured (1 DISABLED)

Node List:
  * Online: [ 15sp2-1 ]
  * OFFLINE: [ 15sp2-2 ]
        """
        mock_run.return_value = (0, output, None)

        check.check_nodes()

        mock_task.assert_called_once_with("Checking nodes")
        mock_run.assert_called_once_with("crm_mon -1")
        mock_task_inst.info.assert_has_calls([
            mock.call("DC node: 15sp2-1"),
            mock.call("Cluster have quorum"),
            mock.call("Online nodes: [ 15sp2-1 ]")
            ])
        mock_task_inst.warn.assert_called_once_with("OFFLINE nodes: [ 15sp2-2 ]")

    @mock.patch('preflight_check.check.crmshutils.get_stdout_stderr')
    @mock.patch('preflight_check.task.TaskCheck')
    def test_check_nodes_warn(self, mock_task, mock_run):
        mock_task_inst = mock.Mock()
        mock_task.return_value = mock_task_inst
        mock_task_inst.run.return_value.__enter__ = mock.Mock()
        mock_task_inst.run.return_value.__exit__ = mock.Mock()
        output = """
Cluster Summary:
  * Stack: corosync
  * Current DC: NONE
  * Last updated: Tue Nov  3 14:16:49 2020
  * Last change:  Tue Nov  3 14:09:29 2020 by root via cibadmin on 15sp2-1
  * 2 nodes configured
  * 1 resource instance configured (1 DISABLED)

Node List:
  * Node 15sp2-1: UNCLEAN (offline)
  * Node 15sp2-2: UNCLEAN (offline)

Active Resources:
  * No active resources
        """
        mock_run.return_value = (0, output, None)

        check.check_nodes()

        mock_task.assert_called_once_with("Checking nodes")
        mock_run.assert_called_once_with("crm_mon -1")
        mock_task_inst.warn.assert_has_calls([
            mock.call("Cluster lost quorum!"),
            mock.call("Node 15sp2-1 is UNCLEAN!"),
            mock.call("Node 15sp2-2 is UNCLEAN!")
            ])

    @mock.patch('preflight_check.check.completers.resources_stopped')
    @mock.patch('preflight_check.check.completers.resources_started')
    @mock.patch('preflight_check.task.TaskCheck')
    def test_check_resources(self, mock_task, mock_started, mock_stopped):
        mock_task_inst = mock.Mock()
        mock_task.return_value = mock_task_inst
        mock_task_inst.run.return_value.__enter__ = mock.Mock()
        mock_task_inst.run.return_value.__exit__ = mock.Mock()
        mock_started.return_value = ["r1", "r2"]
        mock_stopped.return_value = ["r3", "r4"]

        check.check_resources()

        mock_task.assert_called_once_with("Checking resources")
        mock_task_inst.info.assert_has_calls([
            mock.call("Started resources: r1,r2"),
            mock.call("Stopped resources: r3,r4")
            ])
