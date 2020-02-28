import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
import re
import unittest
from hb_report import collect, const


try:
    from unittest import mock
except ImportError:
    import mock

class TestCollect(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """
        self.context = mock.Mock(work_dir="/tmp",
                dest_path="/opt",
                cib_dir="/var/lib/pacemaker/cib",
                pe_dir="/var/lib/pacemaker/pengine",
                cores_dirs="/var/lib/pacemaker/cores",
                pcmk_lib="/var/lib/pacemaker")

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('hb_report.utils.which')
    @mock.patch('hb_report.collect.crmutils.get_stdout')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('os.path.exists')
    def test_distro_os_release(self, mock_exists, mock_debug2, mock_get_stdout, mock_which):
        mock_exists.return_value = True
        mock_get_stdout.return_value = (0, "SUSE")

        res = collect.distro()
        self.assertEqual(res, "SUSE")

        mock_exists.assert_called_once_with(const.OSRELEASE)
        mock_debug2.assert_called_once_with("Using {} for distribution info".format(const.OSRELEASE))
        mock_get_stdout.assert_called_once_with("cat {}|awk -F'=' '/PRETTY_NAME/{{print $2}}'".format(const.OSRELEASE))
        mock_which.assert_not_called()

    @mock.patch('hb_report.utils.which')
    @mock.patch('hb_report.collect.crmutils.get_stdout')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('os.path.exists')
    def test_distro_lsb(self, mock_exists, mock_debug2, mock_get_stdout, mock_which):
        mock_exists.return_value = False
        mock_which.return_value = True
        mock_get_stdout.return_value = (0, "SUSE")

        res = collect.distro()
        self.assertEqual(res, "SUSE")

        mock_exists.assert_called_once_with(const.OSRELEASE)
        mock_which.assert_called_once_with("lsb_release")
        mock_debug2.assert_called_once_with("Using lsb_release for distribution info")
        mock_get_stdout.assert_called_once_with("lsb_release -d|awk -F: '{print $2}'")

    @mock.patch('hb_report.utils.which')
    @mock.patch('hb_report.collect.crmutils.get_stdout')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('os.path.exists')
    def test_distro_unknown(self, mock_exists, mock_debug2, mock_get_stdout, mock_which):
        mock_exists.return_value = False
        mock_which.return_value = False

        res = collect.distro()
        self.assertEqual(res, "Unknown")

        mock_exists.assert_called_once_with(const.OSRELEASE)
        mock_which.assert_called_once_with("lsb_release")
        mock_debug2.assert_not_called()
        mock_get_stdout.assert_not_called()

    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.collect.crmutils.str2file')
    @mock.patch('hb_report.collect.distro')
    @mock.patch('os.uname')
    @mock.patch('hb_report.utils.Package')
    def test_sys_info_speed_up(self, mock_package, mock_uname, mock_distro, 
            mock_str2file, mock_join, mock_debug1):
        const.PACKAGES = "packages"
        const.SYSINFO_F = "sysinfo.txt"
        self.context.speed_up = True
        mock_pkg_instance = mock.Mock()
        mock_package.return_value = mock_pkg_instance
        mock_pkg_instance.version.return_value = "version0.1"
        mock_uname.return_value = ("Linux", "node1", "1", "0.1", "x86")
        mock_distro.return_value = "SUSE"
        mock_join.return_value = "/tmp/sysinfo.txt"

        collect.sys_info(self.context)

        mock_package.assert_called_once_with("packages")
        mock_pkg_instance.version.assert_called_once_with()
        mock_pkg_instance.verify.assert_not_called()
        mock_uname.assert_called_once_with()
        mock_distro.assert_called_once_with()
        mock_join.assert_called_once_with("/tmp", "sysinfo.txt")
        mock_str2file.assert_called_once_with("===== Cluster Stack Packages Version =====\nversion0.1\n===== System Info =====\nPlatform: Linux\nKernel release: 1\nArchitecture: x86\nDistribution: SUSE\n", mock_join.return_value)
        mock_debug1.assert_has_calls([
            mock.call("Skip verify cluster stack packages"),
            mock.call("Dump packages version and system info into /opt/sysinfo.txt")
            ])

    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.collect.crmutils.str2file')
    @mock.patch('hb_report.collect.distro')
    @mock.patch('os.uname')
    @mock.patch('hb_report.utils.Package')
    def test_sys_info(self, mock_package, mock_uname, mock_distro, 
            mock_str2file, mock_join, mock_debug1):
        const.PACKAGES = "packages"
        const.SYSINFO_F = "sysinfo.txt"
        self.context.speed_up = False
        mock_pkg_instance = mock.Mock()
        mock_package.return_value = mock_pkg_instance
        mock_pkg_instance.version.return_value = "version0.1"
        mock_pkg_instance.verify.return_value = "OK"
        mock_uname.return_value = ("Linux", "node1", "1", "0.1", "x86")
        mock_distro.return_value = "SUSE"
        mock_join.return_value = "/tmp/sysinfo.txt"

        collect.sys_info(self.context)

        mock_package.assert_called_once_with("packages")
        mock_pkg_instance.version.assert_called_once_with()
        mock_pkg_instance.verify.assert_called_once_with()
        mock_uname.assert_called_once_with()
        mock_distro.assert_called_once_with()
        mock_join.assert_called_once_with("/tmp", "sysinfo.txt")
        mock_str2file.assert_called_once_with("===== Cluster Stack Packages Version =====\nversion0.1\n===== Cluster Stack Packages Verify =====\nOK\n===== System Info =====\nPlatform: Linux\nKernel release: 1\nArchitecture: x86\nDistribution: SUSE\n", mock_join.return_value)
        mock_debug1.assert_called_once_with("Dump packages version and system info into /opt/sysinfo.txt")

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('os.path.exists')
    def test_sbd_info_no_sbd_conf(self, mock_exists, mock_debug2):
        mock_exists.return_value = False

        collect.sbd_info(self.context)

        mock_exists.assert_called_once_with(const.SBDCONF)
        mock_debug2.assert_called_once_with("SBD config file {} not exist".format(const.SBDCONF))

    @mock.patch('os.path.basename')
    @mock.patch('hb_report.utils.which')
    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('shutil.copy2')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('os.path.exists')
    def test_sbd_info_no_sbd_cmd(self, mock_exists, mock_debug2, mock_copy2, 
            mock_debug1, mock_which, mock_basename):
        const.SBDCONF = "/etc/sbd.conf"
        mock_exists.return_value = True
        mock_which.return_value = False
        mock_basename.return_value = "sbd.conf"

        collect.sbd_info(self.context)

        mock_exists.assert_called_once_with(const.SBDCONF)
        mock_copy2.assert_called_once_with(const.SBDCONF, self.context.work_dir)
        mock_debug1.assert_called_once_with("Dump SBD config into {}/{}".format(self.context.dest_path, mock_basename.return_value))
        mock_debug2.assert_called_once_with("Command \"sbd\" not exist")
        mock_basename.assert_called_once_with(const.SBDCONF)

    @mock.patch('hb_report.utils.me')
    @mock.patch('hb_report.collect.crmutils.get_stdout_stderr')
    @mock.patch('os.path.join')
    @mock.patch("builtins.open", new_callable=mock.mock_open, create=True)
    @mock.patch('os.path.basename')
    @mock.patch('hb_report.utils.which')
    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('shutil.copy2')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('os.path.exists')
    def test_sbd_info(self, mock_exists, mock_debug2, mock_copy2, mock_debug1,
            mock_which, mock_basename, mock_open_file, mock_join, mock_run, mock_me):
        const.SBDCONF = "/etc/sbd.conf"
        cmd = ". {};export SBD_DEVICE;{};{}".format(const.SBDCONF, "sbd dump", "sbd list")
        mock_exists.return_value = True
        mock_basename.return_value = "sbd.conf"
        mock_which.return_value = True
        mock_join.return_value = "/tmp/{}".format(const.SBD_F)
        mock_run.return_value = (0, "SBD data", None)
        mock_me.return_value = "node1"

        collect.sbd_info(self.context)

        mock_exists.assert_called_once_with(const.SBDCONF)
        mock_debug2.assert_not_called()
        mock_copy2.assert_called_once_with(const.SBDCONF, self.context.work_dir)
        mock_debug1.assert_has_calls([
            mock.call("Dump SBD config into {}/{}".format(self.context.dest_path, mock_basename.return_value)),
            mock.call("Dump SBD info into {}/{}".format(self.context.dest_path, const.SBD_F))
            ])
        mock_which.assert_called_once_with("sbd")
        mock_run.assert_called_once_with(cmd)
        mock_me.assert_called_once_with()
        mock_open_file.assert_called_once_with(mock_join.return_value, "w")
        mock_open_file().write.assert_has_calls([
            mock.call("===== Run \"{}\" on {} =====\n".format(cmd, mock_me.return_value)),
            mock.call("SBD data")
            ])

    @mock.patch('os.path.join')
    @mock.patch('hb_report.utils.me')
    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('hb_report.collect.crmutils.str2file')
    @mock.patch('hb_report.collect.crmutils.get_stdout_stderr')
    @mock.patch('hb_report.utils.get_stdout_stderr_timeout')
    @mock.patch('hb_report.utils.which')
    def test_sys_stats(self, mock_which, mock_run_timeout, mock_run, mock_str2file,
            mock_debug1, mock_me, mock_join):
        mock_which.side_effect = [False] + [True for x in range(15)]
        mock_run_timeout.return_value = (0, "df data", None)
        mock_run.side_effect = [(0, "data", None) for x in range(14)]
        mock_me.side_effect = ["node1" for x in range(15)]
        mock_join.return_value = "{}/{}".format(self.context.work_dir, const.SYSSTATS_F)

        collect.sys_stats(self.context)

        cmd_list = ["uname -n", "uptime", "ps axf", "ps auxw", "top -b -n 1",
                "ip addr", "ip -s link", "ip n show", "ip -o route show", "netstat -i",
                "arp -an", "lsscsi", "lspci", "mount", "cat /proc/cpuinfo", "df"]
        mock_which.assert_has_calls([mock.call(cmd.split()[0]) for cmd in cmd_list])
        mock_run_timeout.assert_called_once_with("df")
        mock_run.assert_has_calls([mock.call(cmd) for cmd in cmd_list[1:] if cmd != "df"])
        mock_join.assert_called_once_with(self.context.work_dir, const.SYSSTATS_F)
        mock_str2file.assert_called_once_with('===== Run "uptime" on node1 =====\ndata\n\n===== Run "ps axf" on node1 =====\ndata\n\n===== Run "ps auxw" on node1 =====\ndata\n\n===== Run "top -b -n 1" on node1 =====\ndata\n\n===== Run "ip addr" on node1 =====\ndata\n\n===== Run "ip -s link" on node1 =====\ndata\n\n===== Run "ip n show" on node1 =====\ndata\n\n===== Run "ip -o route show" on node1 =====\ndata\n\n===== Run "netstat -i" on node1 =====\ndata\n\n===== Run "arp -an" on node1 =====\ndata\n\n===== Run "lsscsi" on node1 =====\ndata\n\n===== Run "lspci" on node1 =====\ndata\n\n===== Run "mount" on node1 =====\ndata\n\n===== Run "cat /proc/cpuinfo" on node1 =====\ndata\n\n===== Run "df" on node1 =====\ndf data\n\n', mock_join.return_value)
        mock_debug1.assert_called_once_with("Dump system stats into {}/{}".format(self.context.dest_path, const.SYSSTATS_F))

    @mock.patch('os.path.join')
    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('hb_report.collect.crmutils.str2file')
    @mock.patch('hb_report.collect.crmutils.get_stdout_stderr')
    def test_dump_state(self, mock_run, mock_str2file, mock_debug1, mock_join):
        meta_data = [
                ("crm_mon -1", const.CRM_MON_F, "crm_mon output"),
                ("cibadmin -Ql", const.CIB_F, "cib xml"),
                ("crm_node -p", const.MEMBERSHIP_F, "members of this partition")
                ]
        cmd_list = [item[0] for item in meta_data]
        outf_list = [item[1] for item in meta_data]

        mock_run.side_effect = [(0, "data", None) for x in range(len(meta_data))]
        mock_join.side_effect = ["{}/{}".format(self.context.work_dir, outf) for outf in outf_list]

        collect.dump_state(self.context)

        mock_run.assert_has_calls([mock.call(cmd) for cmd in cmd_list])
        mock_str2file.assert_has_calls([mock.call("data", item) for item in mock_join.side_effect])
        mock_debug1.assert_has_calls([mock.call("Dump {} into {}/{}".format(item[2], self.context.dest_path, item[1])) for item in meta_data])


    @mock.patch('os.path.basename')
    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('shutil.copy2')
    @mock.patch('os.path.isfile')
    def test_get_corosync_conf(self, mock_isfile, mock_copy2, mock_debug1, mock_basename):
        mock_isfile.return_value = True
        mock_basename.return_value = "corosync.conf"

        collect.get_corosync_conf(self.context)

        mock_isfile.assert_called_once_with(const.CONF)
        mock_copy2(const.CONF, self.context.work_dir)
        mock_debug1("Dump corosync config into {}/{}".format(self.context.dest_path, mock_basename.return_value))
        mock_basename.assert_called_once_with(const.CONF)

    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.utils.touch_file')
    @mock.patch('hb_report.collect.dump_state')
    @mock.patch('hb_report.collect.bootstrap.service_is_active')
    def test_dump_cluster_status_running(self, mock_active, mock_dump_state, mock_touch,
            mock_join, mock_debug1):
        mock_active.return_value = True
        mock_join.return_value = "{}/RUNNING".format(self.context.work_dir)

        collect.dump_cluster_status(self.context)

        mock_active.assert_called_once_with("pacemaker.service")
        mock_dump_state.assert_called_once_with(self.context)
        mock_join.assert_called_once_with(self.context.work_dir, "RUNNING")
        mock_touch.assert_called_once_with(mock_join.return_value)
        mock_debug1.assert_called_once_with('Cluster service is running, touch "RUNNING" file at {}'.format(self.context.dest_path))

    @mock.patch('hb_report.utils.touch_file')
    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('shutil.copy2')
    @mock.patch('os.path.exists')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.collect.bootstrap.service_is_active')
    def test_dump_cluster_status_stopped(self, mock_active, mock_join, mock_exists,
            mock_copy2, mock_debug1, mock_touch):
        mock_active.return_value = False
        mock_join.side_effect = [
                "{}/{}".format(self.context.cib_dir, const.CIB_F),
                "{}/STOPPED".format(self.context.work_dir)
                ]
        mock_exists.return_value = True

        collect.dump_cluster_status(self.context)

        mock_active.assert_called_once_with("pacemaker.service")
        mock_join.assert_has_calls([
            mock.call(self.context.cib_dir, const.CIB_F),
            mock.call(self.context.work_dir, "STOPPED")
            ])
        mock_exists.assert_called_once_with("{}/{}".format(self.context.cib_dir, const.CIB_F))
        mock_copy2("{}/{}".format(self.context.cib_dir, const.CIB_F), self.context.work_dir)
        mock_debug1.assert_has_calls([
            mock.call("Dump cib xml into {}/{}".format(self.context.dest_path, const.CIB_F)),
            mock.call('Cluster service is stopped, touch "STOPPED" file at {}'.format(self.context.dest_path))
            ])
        mock_touch.assert_called_once_with("{}/STOPPED".format(self.context.work_dir))

    @mock.patch('hb_report.collect.dump_crm_verify')
    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('hb_report.collect.crmutils.str2file')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.collect.crmutils.get_stdout_stderr')
    @mock.patch('os.path.isfile')
    def test_get_crm_configure(self, mock_isfile, mock_run, mock_join, mock_str2file,
            mock_debug1, mock_verify):
        mock_isfile.return_value = True
        mock_run.return_value = (0, "data", None)
        mock_join.side_effect = [
                "{}/{}".format(self.context.work_dir, const.CIB_F),
                "{}/{}".format(self.context.work_dir, const.CIB_TXT_F)
                ]

        collect.get_crm_configure(self.context)

        mock_isfile.assert_called_once_with("{}/{}".format(self.context.work_dir, const.CIB_F))
        mock_run.assert_called_once_with("CIB_file={}/{} crm configure show".format(self.context.work_dir, const.CIB_F))
        mock_join.assert_has_calls([
            mock.call(self.context.work_dir, const.CIB_F),
            mock.call(self.context.work_dir, const.CIB_TXT_F)
            ])
        mock_str2file.assert_called_once_with("data", "{}/{}".format(self.context.work_dir, const.CIB_TXT_F))
        mock_debug1.assert_called_once_with("Dump cib config into {}/{}".format(self.context.dest_path, const.CIB_TXT_F))
        mock_verify(self.context)

    @mock.patch('hb_report.utils.log_error')
    @mock.patch('hb_report.collect.crmutils.str2file')
    @mock.patch('hb_report.collect.crmutils.get_stdout_stderr')
    @mock.patch('os.path.join')
    def test_dump_crm_verify_true(self, mock_join, mock_run, mock_str2file, mock_log_err):
        mock_join.return_value = "{}/{}".format(self.context.work_dir, const.CIB_F)
        mock_run.return_value = (0, None, None)

        collect.dump_crm_verify(self.context)

        mock_join.assert_called_once_with(self.context.work_dir, const.CIB_F)
        mock_run.assert_called_once_with("crm_verify -V -x {}".format(mock_join.return_value))
        mock_str2file.assert_not_called()
        mock_log_err.assert_not_called()

    @mock.patch('hb_report.utils.log_error')
    @mock.patch('hb_report.collect.crmutils.str2file')
    @mock.patch('hb_report.collect.crmutils.get_stdout_stderr')
    @mock.patch('os.path.join')
    def test_dump_crm_verify_false(self, mock_join, mock_run, mock_str2file, mock_log_err):
        mock_join.side_effect = [
                "{}/{}".format(self.context.work_dir, const.CIB_F),
                "{}/{}".format(self.context.work_dir, const.CRM_VERIFY_F)
                ]
        mock_run.return_value = (1, None, "error data")

        collect.dump_crm_verify(self.context)

        mock_join.assert_has_calls([
            mock.call(self.context.work_dir, const.CIB_F),
            mock.call(self.context.work_dir, const.CRM_VERIFY_F)
            ])
        mock_run.assert_called_once_with("crm_verify -V -x {}".format("{}/{}".format(self.context.work_dir, const.CIB_F)))
        mock_str2file.assert_called_once_with("error data", "{}/{}".format(self.context.work_dir, const.CRM_VERIFY_F))
        mock_log_err.assert_called_once_with("Create {} because crm_verify failed".format(const.CRM_VERIFY_F))

    @mock.patch('hb_report.collect.get_crm_configure')
    @mock.patch('hb_report.collect.dump_cluster_status')
    @mock.patch('hb_report.collect.get_corosync_conf')
    def test_get_config(self, mock_corosync_conf, mock_dump_state, mock_crm_configure):
        collect.get_config(self.context)
        mock_corosync_conf.assert_called_once_with(self.context)
        mock_dump_state.assert_called_once_with(self.context)
        mock_crm_configure.assert_called_once_with(self.context)

    @mock.patch('hb_report.collect.convert_pe_dot_files')
    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('os.symlink')
    @mock.patch('hb_report.utils._mkdir')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.collect.find_pe_files')
    def test_get_pe_inputs(self, mock_find_pe, mock_join, mock_basename, mock_mkdir,
            mock_symlink, mock_debug2, mock_debug1, mock_convert):
        mock_find_pe.return_value = [
                "/var/lib/pacemaker/pengine/pe1.tar.gz", 
                "/var/lib/pacemaker/pengine/pe2.tar.gz"]
        mock_basename.side_effect = ["pengine", "pe1.tar.gz", "pe2.tar.gz", "pengine"]
        mock_join.side_effect = [
                "{}/{}".format(self.context.work_dir, "pengine"),
                "{}/{}/{}".format(self.context.work_dir, "pengine", "pe1.tar.gz"),
                "{}/{}/{}".format(self.context.work_dir, "pengine", "pe2.tar.gz"),
                ]

        collect.get_pe_inputs(self.context)

        mock_find_pe.assert_called_once_with(self.context)
        mock_basename.assert_has_calls([
            mock.call(self.context.pe_dir),
            mock.call("/var/lib/pacemaker/pengine/pe1.tar.gz"),
            mock.call("/var/lib/pacemaker/pengine/pe2.tar.gz"),
            mock.call(self.context.pe_dir)
            ])
        mock_join.assert_has_calls([
            mock.call(self.context.work_dir, "pengine"),
            mock.call("{}/{}".format(self.context.work_dir, "pengine"), "pe1.tar.gz"),
            mock.call("{}/{}".format(self.context.work_dir, "pengine"), "pe2.tar.gz")
            ])
        mock_mkdir.assert_called_once_with("{}/{}".format(self.context.work_dir, "pengine"))
        mock_symlink.assert_has_calls([
            mock.call("/var/lib/pacemaker/pengine/pe1.tar.gz", "{}/{}/{}".format(self.context.work_dir, "pengine", "pe1.tar.gz")),
            mock.call("/var/lib/pacemaker/pengine/pe2.tar.gz", "{}/{}/{}".format(self.context.work_dir, "pengine", "pe2.tar.gz"))
            ])
        mock_debug2.assert_called_once_with("Found {} pengine input files in {}".format(len(mock_find_pe.return_value), self.context.pe_dir))
        mock_debug1.assert_called_once_with("Dump {} pengine input files into {}/{}".format(len(mock_find_pe.return_value), self.context.dest_path, "pengine"))

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.collect.find_pe_files')
    def test_get_pe_inputs_no_pe(self, mock_find_pe, mock_debug2):
        mock_find_pe.return_value = []

        collect.get_pe_inputs(self.context)

        mock_find_pe.assert_called_once_with(self.context)
        mock_debug2.assert_called_once_with("Nothing found for the giving time")

    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.collect.pe_to_dot')
    @mock.patch('hb_report.utils.log_debug2')
    def test_convert_pe_dot_files_speed_up_true(self, mock_debug2, mock_to_dot,
            mock_join, mock_basename, mock_debug1):
        self.context.speed_up = True

        collect.convert_pe_dot_files(self.context, ["/var/lib/pe/pe1", "/var/lib/pe2"], "/opt/pe")

        mock_debug1.assert_called_once_with("Skip convert PE inputs to dot files")
        mock_debug2.assert_not_called()
        mock_to_dot.assert_not_called()
        mock_join.assert_not_called()
        mock_basename.assert_not_called()

    @mock.patch('os.path.basename')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.collect.pe_to_dot')
    @mock.patch('hb_report.utils.log_debug2')
    def test_convert_pe_dot_files_gt_20(self, mock_debug2, mock_to_dot,
            mock_join, mock_basename):
        self.context.speed_up = False

        collect.convert_pe_dot_files(self.context,
                ["/var/lib/pe/pe{}".format(x) for x in range(30)],
                "/opt/pe")

        mock_debug2.assert_called_once_with("Too many PE inputs to create dot files")
        mock_to_dot.assert_not_called()
        mock_join.assert_not_called()
        mock_basename.assert_not_called()

    @mock.patch('os.path.basename')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.collect.pe_to_dot')
    @mock.patch('hb_report.utils.log_debug2')
    def test_convert_pe_dot(self, mock_debug2, mock_to_dot,
            mock_join, mock_basename):
        self.context.speed_up = False
        mock_basename.side_effect = ["pe1", "pe2"]
        mock_join.side_effect = ["/opt/pe/pe1", "/opt/pe/pe2"]

        collect.convert_pe_dot_files(self.context, ["/var/lib/pe/pe1", "/var/lib/pe/pe2"], "/opt/pe")

        mock_debug2.assert_not_called()
        mock_basename.assert_has_calls([
            mock.call("/var/lib/pe/pe1"),
            mock.call("/var/lib/pe/pe2")
            ])
        mock_join.assert_has_calls([
            mock.call("/opt/pe", "pe1"),
            mock.call("/opt/pe", "pe2")
            ])
        mock_to_dot.assert_has_calls([
            mock.call("/opt/pe/pe1"),
            mock.call("/opt/pe/pe2")
            ])

    @mock.patch('re.search')
    @mock.patch('hb_report.collect.find_files')
    @mock.patch('hb_report.utils.log_debug2')
    def test_find_pe_files(self, mock_debug2, mock_find_files, mock_search):
        mock_find_files.return_value = [
                "/var/lib/pacemaker/pengine/pe1",
                "/var/lib/pacemaker/pengine/pe2",
                "/var/lib/pacemaker/pengine/pe.last"
                ]
        mock_search.side_effect = [False, False, True]

        res = collect.find_pe_files(self.context)
        self.assertEqual(res, ["/var/lib/pacemaker/pengine/pe1", "/var/lib/pacemaker/pengine/pe2"])

        mock_debug2.assert_called_once_with("Looking for PE files in {}".format(self.context.pe_dir))
        mock_find_files.assert_called_once_with(self.context, self.context.pe_dir)
        mock_search.assert_has_calls([
            mock.call("[.]last$", "/var/lib/pacemaker/pengine/pe1"),
            mock.call("[.]last$", "/var/lib/pacemaker/pengine/pe2"),
            mock.call("[.]last$", "/var/lib/pacemaker/pengine/pe.last")
            ])

    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.collect.crmutils.get_stdout')
    def test_pe_to_dot_failed(self, mock_run, mock_warn):
        pe_file = "/var/lib/pacemaker/pengine/pe1.gz"
        mock_run.return_value = (1, None)

        collect.pe_to_dot(pe_file)

        dotf = '.'.join(pe_file.split('.')[:-1]) + '.dot'
        cmd = "%s -D %s -x %s" % (const.PTEST, dotf, pe_file)
        mock_run.assert_called_once_with(cmd)
        mock_warn.assert_called_once_with("pe_to_dot: %s -> %s failed" % (pe_file, dotf))

    @mock.patch('hb_report.utils.log_warning')
    @mock.patch('hb_report.collect.crmutils.get_stdout')
    def test_pe_to_dot(self, mock_run, mock_warn):
        pe_file = "/var/lib/pacemaker/pengine/pe1.gz"
        mock_run.return_value = (0, None)

        collect.pe_to_dot(pe_file)

        dotf = '.'.join(pe_file.split('.')[:-1]) + '.dot'
        cmd = "%s -D %s -x %s" % (const.PTEST, dotf, pe_file)
        mock_run.assert_called_once_with(cmd)
        mock_warn.assert_not_called()

    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('hb_report.utils.touch_file')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.utils.me')
    @mock.patch('hb_report.collect.crmutils.get_dc')
    def test_touch_dc(self, mock_dc, mock_me, mock_join,
            mock_touch, mock_debug):
        mock_dc.return_value = "node1"
        mock_me.return_value = "node1"
        mock_join.return_value = "{}/DC".format(self.context.work_dir)

        collect.touch_dc(self.context)

        mock_dc.assert_called_once_with()
        mock_me.assert_called_once_with()
        mock_join.assert_called_once_with(self.context.work_dir, "DC")
        mock_touch.assert_called_once_with(mock_join.return_value)
        mock_debug.assert_called_once_with('Node node1 is DC, touch "DC" file at {}'.format(self.context.dest_path))

    @mock.patch('shutil.copy2')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('os.path.basename')
    @mock.patch('hb_report.collect.find_files')
    def test_get_core_files(self, mock_find_files, mock_basename, mock_debug2,
            mock_debug1, mock_join, mock_copy2):
        mock_find_files.return_value = [
                '/var/lib/pacemaker/cores/core1',
                '/var/lib/pacemaker/cores/core2'
                ]
        mock_basename.side_effect = ["core1", "core2", "cores"]
        mock_join.return_value = "{}/cores".format(self.context.work_dir)

        collect.get_core_files(self.context)

        mock_find_files.assert_called_once_with(self.context, self.context.cores_dirs)
        mock_basename.assert_has_calls([
            mock.call('/var/lib/pacemaker/cores/core1'),
            mock.call('/var/lib/pacemaker/cores/core2'),
            mock.call('/var/lib/pacemaker/cores')
            ])
        mock_debug2.assert_called_once_with("Found core files: /var/lib/pacemaker/cores/core1 /var/lib/pacemaker/cores/core2")
        mock_debug1.assert_called_once_with("Dump 2 core files into {}/cores".format(self.context.dest_path))
        mock_copy2.assert_has_calls([
            mock.call("/var/lib/pacemaker/cores/core1", mock_join.return_value),
            mock.call("/var/lib/pacemaker/cores/core2", mock_join.return_value)
            ])

    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.join')
    @mock.patch('shutil.copytree')
    @mock.patch('os.path.isdir')
    @mock.patch('shutil.copy2')
    @mock.patch('os.path.isfile')
    def test_get_other_confs(self, mock_isfile, mock_copy2, mock_isdir, mock_copytree,
            mock_join, mock_basename, mock_debug1):
        mock_isfile.side_effect = [True, False, True]
        mock_isdir.return_value = True
        mock_basename.return_value = "drbd.d"
        mock_join.return_value = "{}/drbd.d".format(self.context.work_dir)

        collect.get_other_confs(self.context)

        mock_isfile.assert_has_calls([
            mock.call("/etc/drbd.conf"),
            mock.call("/etc/drbd.d"),
            mock.call("/etc/booth/booth.conf")
            ])
        mock_copy2.assert_has_calls([
            mock.call("/etc/drbd.conf", self.context.work_dir),
            mock.call("/etc/booth/booth.conf", self.context.work_dir)
            ])
        mock_isdir.assert_called_once_with("/etc/drbd.d")
        mock_basename.assert_called_once_with("/etc/drbd.d")
        mock_join.assert_called_once_with(self.context.work_dir, "drbd.d")
        mock_copytree.assert_called_once_with("/etc/drbd.d", mock_join.return_value)
        mock_debug1.assert_has_calls([
            mock.call("Dump /etc/drbd.conf into {}".format(self.context.dest_path)),
            mock.call("Dump /etc/drbd.d into {}".format(self.context.dest_path)),
            mock.call("Dump /etc/booth/booth.conf into {}".format(self.context.dest_path))
            ])

    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('hb_report.collect.crmutils.str2file')
    @mock.patch('os.path.join')
    @mock.patch('os.path.isdir')
    @mock.patch('os.path.exists')
    @mock.patch('hb_report.utils.me')
    def test_check_perms_not_exist(self, mock_me, mock_exists, mock_isdir, mock_join, mock_str2file, mock_debug1):
        mock_me.side_effect = ["node1", "node1", "node1"]
        mock_exists.side_effect = [False, False, False]
        mock_join.return_value = "{}/{}".format(self.context.work_dir, const.PERMISSIONS_F)

        collect.check_perms(self.context)

        mock_me.assert_has_calls([mock.call(), mock.call(), mock.call()])
        mock_exists.assert_has_calls([
            mock.call(self.context.pcmk_lib),
            mock.call(self.context.pe_dir),
            mock.call(self.context.cib_dir)
            ])
        mock_isdir.assert_not_called()
        mock_join.assert_called_once_with(self.context.work_dir, const.PERMISSIONS_F)
        mock_str2file.assert_called_once_with("===== Check permissions for /var/lib/pacemaker on node1 ===== \n/var/lib/pacemaker not exist\n===== Check permissions for /var/lib/pacemaker/pengine on node1 ===== \n/var/lib/pacemaker/pengine not exist\n===== Check permissions for /var/lib/pacemaker/cib on node1 ===== \n/var/lib/pacemaker/cib not exist\n", mock_join.return_value)
        mock_debug1.assert_called_once_with("Dump permissions info into {}".format(self.context.dest_path))


    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('hb_report.collect.crmutils.str2file')
    @mock.patch('os.path.join')
    @mock.patch('os.stat')
    @mock.patch('os.path.isdir')
    @mock.patch('os.path.exists')
    @mock.patch('hb_report.utils.me')
    def test_check_perms_wrong_type(self, mock_me, mock_exists, mock_isdir, mock_stat,
            mock_join, mock_str2file, mock_debug1):
        mock_me.side_effect = ["node1", "node1", "node1"]
        mock_exists.side_effect = [True, True, True]
        mock_isdir.side_effect = [False, False, False]
        mock_join.return_value = "{}/{}".format(self.context.work_dir, const.PERMISSIONS_F)

        collect.check_perms(self.context)

        mock_me.assert_has_calls([mock.call(), mock.call(), mock.call()])
        mock_exists.assert_has_calls([
            mock.call(self.context.pcmk_lib),
            mock.call(self.context.pe_dir),
            mock.call(self.context.cib_dir)
            ])
        mock_isdir.assert_has_calls([
            mock.call(self.context.pcmk_lib),
            mock.call(self.context.pe_dir),
            mock.call(self.context.cib_dir)
            ])
        mock_stat.assert_not_called()
        mock_join.assert_called_once_with(self.context.work_dir, const.PERMISSIONS_F)
        mock_str2file.assert_called_once_with("===== Check permissions for /var/lib/pacemaker on node1 ===== \n/var/lib/pacemaker is not directory\n===== Check permissions for /var/lib/pacemaker/pengine on node1 ===== \n/var/lib/pacemaker/pengine is not directory\n===== Check permissions for /var/lib/pacemaker/cib on node1 ===== \n/var/lib/pacemaker/cib is not directory\n", mock_join.return_value)
        mock_debug1.assert_called_once_with("Dump permissions info into {}".format(self.context.dest_path))

    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('hb_report.collect.crmutils.str2file')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.collect.crmutils.get_stdout')
    @mock.patch('pwd.getpwnam')
    @mock.patch('os.stat')
    @mock.patch('os.path.isdir')
    @mock.patch('os.path.exists')
    @mock.patch('hb_report.utils.me')
    def test_check_perms_wrong_id(self, mock_me, mock_exists, mock_isdir, mock_stat,
            mock_getpwnam, mock_run, mock_join, mock_str2file, mock_debug1):
        mock_me.side_effect = ["node1", "node1", "node1"]
        mock_exists.side_effect = [True, True, True]
        mock_isdir.side_effect = [True, True, True]
        mock_stat.side_effect = [
                mock.Mock(st_uid=1, st_gid=1, st_mode=11111),
                mock.Mock(st_uid=1, st_gid=1, st_mode=11111),
                mock.Mock(st_uid=1, st_gid=1, st_mode=11111)
                ]
        mock_getpwnam.side_effect = [
                (None, None, 0, 0, None),
                (None, None, 0, 0, None),
                (None, None, 0, 0, None)
                ]
        mock_run.side_effect = [(0, "data"),(0, "data"), (0, "data")]
        mock_join.return_value = "{}/{}".format(self.context.work_dir, const.PERMISSIONS_F)

        collect.check_perms(self.context)

        mock_me.assert_has_calls([mock.call(), mock.call(), mock.call()])
        mock_exists.assert_has_calls([
            mock.call(self.context.pcmk_lib),
            mock.call(self.context.pe_dir),
            mock.call(self.context.cib_dir)
            ])
        mock_isdir.assert_has_calls([
            mock.call(self.context.pcmk_lib),
            mock.call(self.context.pe_dir),
            mock.call(self.context.cib_dir)
            ])
        mock_stat.assert_has_calls([
            mock.call(self.context.pcmk_lib),
            mock.call(self.context.pe_dir),
            mock.call(self.context.cib_dir)
            ])
        mock_getpwnam.assert_has_calls([
            mock.call("hacluster"),
            mock.call("hacluster"),
            mock.call("hacluster")
            ])
        mock_run.assert_has_calls([
            mock.call("ls -ld {}".format(self.context.pcmk_lib)),
            mock.call("ls -ld {}".format(self.context.pe_dir)),
            mock.call("ls -ld {}".format(self.context.cib_dir))
            ])
        mock_join.assert_called_once_with(self.context.work_dir, const.PERMISSIONS_F)
        mock_str2file.assert_called_once_with("===== Check permissions for /var/lib/pacemaker on node1 ===== \nWrong permissions or ownership for /var/lib/pacemaker: data\n===== Check permissions for /var/lib/pacemaker/pengine on node1 ===== \nWrong permissions or ownership for /var/lib/pacemaker/pengine: data\n===== Check permissions for /var/lib/pacemaker/cib on node1 ===== \nWrong permissions or ownership for /var/lib/pacemaker/cib: data\n", mock_join.return_value)
        mock_debug1.assert_called_once_with("Dump permissions info into {}".format(self.context.dest_path))

    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('hb_report.collect.crmutils.str2file')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.collect.crmutils.get_stdout')
    @mock.patch('pwd.getpwnam')
    @mock.patch('os.stat')
    @mock.patch('os.path.isdir')
    @mock.patch('os.path.exists')
    @mock.patch('hb_report.utils.me')
    def test_check_perms(self, mock_me, mock_exists, mock_isdir, mock_stat, mock_getpwnam,
            mock_run, mock_join, mock_str2file, mock_debug1):
        mock_me.side_effect = ["node1", "node1", "node1"]
        mock_exists.side_effect = [True, True, True]
        mock_isdir.side_effect = [True, True, True]
        mock_stat.side_effect = [
                mock.Mock(st_uid=90, st_gid=90, st_mode=16872),
                mock.Mock(st_uid=90, st_gid=90, st_mode=16872),
                mock.Mock(st_uid=90, st_gid=90, st_mode=16872)
                ]
        mock_getpwnam.side_effect = [
                (None, None, 90, 90, None),
                (None, None, 90, 90, None),
                (None, None, 90, 90, None)
                ]
        mock_run.side_effect = [(0, "data"),(0, "data"), (0, "data")]
        mock_join.return_value = "{}/{}".format(self.context.work_dir, const.PERMISSIONS_F)

        collect.check_perms(self.context)

        mock_me.assert_has_calls([mock.call(), mock.call(), mock.call()])
        mock_exists.assert_has_calls([
            mock.call(self.context.pcmk_lib),
            mock.call(self.context.pe_dir),
            mock.call(self.context.cib_dir)
            ])
        mock_isdir.assert_has_calls([
            mock.call(self.context.pcmk_lib),
            mock.call(self.context.pe_dir),
            mock.call(self.context.cib_dir)
            ])
        mock_stat.assert_has_calls([
            mock.call(self.context.pcmk_lib),
            mock.call(self.context.pe_dir),
            mock.call(self.context.cib_dir)
            ])
        mock_getpwnam.assert_has_calls([
            mock.call("hacluster"),
            mock.call("hacluster"),
            mock.call("hacluster")
            ])
        mock_run.assert_not_called()
        mock_join.assert_called_once_with(self.context.work_dir, const.PERMISSIONS_F)
        mock_str2file.assert_called_once_with("===== Check permissions for /var/lib/pacemaker on node1 ===== \nOK\n===== Check permissions for /var/lib/pacemaker/pengine on node1 ===== \nOK\n===== Check permissions for /var/lib/pacemaker/cib on node1 ===== \nOK\n", mock_join.return_value)
        mock_debug1.assert_called_once_with("Dump permissions info into {}".format(self.context.dest_path))

    @mock.patch('re.findall')
    @mock.patch('hb_report.utils.log_error')
    @mock.patch('hb_report.collect.crmutils.get_stdout_stderr')
    def test_dlm_lockspace_dump_error(self, mock_run, mock_log_error, mock_findall):
        mock_run.return_value = (1, None, "error")

        res = collect.dlm_lockspace_dump()
        assert res is None

        mock_run.assert_called_once_with("dlm_tool ls")
        mock_log_error.assert_called_once_with('Error running "dlm_tool ls": error')
        mock_findall.assert_not_called()

    @mock.patch('re.findall')
    @mock.patch('hb_report.utils.log_error')
    @mock.patch('hb_report.collect.crmutils.get_stdout_stderr')
    def test_dlm_lockspace_dump_debug_error(self, mock_run, mock_log_error, mock_findall):
        mock_run.side_effect = [(0, "name test1\nname test2", None), (1, None, "error")]
        mock_findall.return_value = ["name test1", "name test2"]

        res = collect.dlm_lockspace_dump()
        assert res is None

        mock_run.assert_has_calls([
                mock.call("dlm_tool ls"),
                mock.call("dlm_tool lockdebug test1")
                ])
        mock_log_error.assert_called_once_with('Error running "dlm_tool lockdebug test1": error')
        mock_findall.assert_called_once_with("^name", "name test1\nname test2", re.M)

    @mock.patch('re.findall')
    @mock.patch('hb_report.utils.log_error')
    @mock.patch('hb_report.collect.crmutils.get_stdout_stderr')
    def test_dlm_lockspace_dump(self, mock_run, mock_log_error, mock_findall):
        mock_run.side_effect = [
                (0, "name test1\nname test2", None),
                (0, "data test1", None),
                (0, "data test2", None),
                ]
        mock_findall.return_value = ["name test1", "name test2"]

        res = collect.dlm_lockspace_dump()
        assert res == "===== DLM lockspace overview =====\nname test1\nname test2\n-- DLM lockspace test1 --\ndata test1\n-- DLM lockspace test2 --\ndata test2\n"

        mock_run.assert_has_calls([
                mock.call("dlm_tool ls"),
                mock.call("dlm_tool lockdebug test1"),
                mock.call("dlm_tool lockdebug test2")
                ])
        mock_findall.assert_called_once_with("^name", "name test1\nname test2", re.M)
        mock_log_error.assert_not_called()

    @mock.patch('hb_report.utils.log_error')
    @mock.patch('hb_report.collect.crmutils.get_stdout_stderr')
    def test_dlm_lockspace_history_error(self, mock_run, mock_log_error):
        mock_run.return_value = (1, None, "error")

        res = collect.dlm_lockspace_history()
        assert res is None

        mock_run.assert_called_once_with("dlm_tool dump")
        mock_log_error.assert_called_once_with('Error running "dlm_tool dump": error')

    @mock.patch('hb_report.utils.log_error')
    @mock.patch('hb_report.collect.crmutils.get_stdout_stderr')
    def test_dlm_lockspace_history(self, mock_run, mock_log_error):
        mock_run.return_value = (0, "data", None)

        res = collect.dlm_lockspace_history()
        assert res == "===== DLM lockspace history =====\ndata\n"

        mock_run.assert_called_once_with("dlm_tool dump")
        mock_log_error.assert_not_called()

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.utils.which')
    def test_dlm_dump_no_cmd(self, mock_which, mock_debug2):
        mock_which.return_value = False

        collect.dlm_dump(self.context)

        mock_which.assert_called_once_with("dlm_tool")
        mock_debug2.assert_called_once_with("Command dlm_tool not exist")

    @mock.patch('hb_report.collect.dlm_lockspace_history')
    @mock.patch('hb_report.collect.dlm_lockspace_dump')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.utils.which')
    def test_dlm_dump_return1(self, mock_which, mock_debug2, mock_dump, mock_history):
        mock_which.return_value = True
        mock_dump.return_value = None

        collect.dlm_dump(self.context)

        mock_which.assert_called_once_with("dlm_tool")
        mock_debug2.assert_not_called()
        mock_dump.assert_called_once_with()
        mock_history.assert_not_called()

    @mock.patch('os.path.join')
    @mock.patch('hb_report.collect.dlm_lockspace_history')
    @mock.patch('hb_report.collect.dlm_lockspace_dump')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.utils.which')
    def test_dlm_dump_return2(self, mock_which, mock_debug2, mock_dump, mock_history, mock_join):
        mock_which.return_value = True
        mock_dump.return_value = "dump data"
        mock_history.return_value = None

        collect.dlm_dump(self.context)

        mock_which.assert_called_once_with("dlm_tool")
        mock_debug2.assert_not_called()
        mock_dump.assert_called_once_with()
        mock_history.assert_called_once_with()
        mock_join.assert_not_called()

    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('hb_report.collect.crmutils.str2file')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.collect.dlm_lockspace_history')
    @mock.patch('hb_report.collect.dlm_lockspace_dump')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.utils.which')
    def test_dlm_dump(self, mock_which, mock_debug2, mock_dump, mock_history,
            mock_join, mock_str2file, mock_debug1):
        mock_which.return_value = True
        mock_dump.return_value = "dump data\n"
        mock_history.return_value = "history data"
        mock_join.return_value = "{}/{}".format(self.context.work_dir, const.DLM_DUMP_F)

        collect.dlm_dump(self.context)

        mock_which.assert_called_once_with("dlm_tool")
        mock_debug2.assert_not_called()
        mock_dump.assert_called_once_with()
        mock_history.assert_called_once_with()
        mock_join.assert_called_once_with(self.context.work_dir, const.DLM_DUMP_F)
        mock_str2file.assert_called_once_with("dump data\nhistory data", mock_join.return_value)
        mock_debug1.assert_called_once_with("Dump DLM info into {}/{}".format(self.context.dest_path, const.DLM_DUMP_F))

    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.collect.crmutils.str2file')
    @mock.patch('hb_report.collect.crmutils.get_stdout_stderr')
    @mock.patch('hb_report.utils.which')
    @mock.patch('hb_report.utils.now')
    def test_time_status(self, mock_now, mock_which, mock_run, mock_str2file, mock_join,
            mock_debug1):
        mock_now.return_value = "Mon Feb 10 21:23:32 2020"
        mock_which.return_value = True
        mock_run.return_value = (0, "data", None)
        mock_join.return_value = "{}/{}".format(self.context.work_dir, const.TIME_F)

        collect.time_status(self.context)

        mock_now.assert_called_once_with('%c')
        mock_which.assert_called_once_with('ntpdc')
        mock_run.assert_called_once_with("ntpdc -pn")
        mock_join.assert_called_once_with(self.context.work_dir, const.TIME_F)
        mock_str2file.assert_called_once_with("Current time: Mon Feb 10 21:23:32 2020\nntpdc: data\n", mock_join.return_value)
        mock_debug1.assert_called_once_with("Dump time info into {}/{}".format(self.context.dest_path, const.TIME_F))

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.utils.which')
    def test_corosync_blackbox_no_cmd(self, mock_which, mock_debug2):
        mock_which.side_effect = [True, False]

        collect.corosync_blackbox(self.context)

        mock_which.assert_has_calls([
            mock.call("corosync-blackbox"),
            mock.call("qb-blackbox")
            ])
        mock_debug2.assert_called_once_with("Command qb-blackbox not exist")

    @mock.patch('re.search')
    @mock.patch('hb_report.collect.find_files')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.utils.which')
    def test_corosync_blackbox_not_found(self, mock_which, mock_debug2, mock_find_files, mock_search):
        mock_which.side_effect = [True, True]
        mock_find_files.return_value = []

        collect.corosync_blackbox(self.context)

        mock_which.assert_has_calls([
            mock.call("corosync-blackbox"),
            mock.call("qb-blackbox")
            ])
        mock_debug2.assert_not_called()
        mock_find_files.assert_called_once_with(self.context, const.COROSYNC_LIB)
        mock_search.assert_not_called()

    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.collect.crmutils.str2file')
    @mock.patch('hb_report.collect.crmutils.get_stdout_stderr')
    @mock.patch('re.search')
    @mock.patch('hb_report.collect.find_files')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('hb_report.utils.which')
    def test_corosync_blackbox(self, mock_which, mock_debug2, mock_find_files, mock_search,
            mock_run, mock_str2file, mock_join, mock_debug1):
        mock_which.side_effect = [True, True]
        mock_find_files.return_value = [
                "/var/lib/corosync/fdata1",
                "/var/lib/corosync/fdata2"
                ]
        mock_search.side_effect = [mock.Mock(), mock.Mock()]
        mock_run.return_value = (0, "data", None)
        mock_join.return_value = "{}/{}".format(self.context.work_dir, const.COROSYNC_RECORDER_F)

        collect.corosync_blackbox(self.context)

        mock_which.assert_has_calls([
            mock.call("corosync-blackbox"),
            mock.call("qb-blackbox")
            ])
        mock_debug2.assert_not_called()
        mock_find_files.assert_called_once_with(self.context, const.COROSYNC_LIB)
        mock_search.assert_has_calls([
            mock.call("fdata", "/var/lib/corosync/fdata1"),
            mock.call("fdata", "/var/lib/corosync/fdata2")
            ])
        mock_run.assert_called_once_with("corosync-blackbox")
        mock_join.assert_called_once_with(self.context.work_dir, const.COROSYNC_RECORDER_F)
        mock_str2file.assert_called_once_with("data", mock_join.return_value)
        mock_debug1.assert_called_once_with("Dump corosync flight data info {}/{}".format(self.context.dest_path, const.COROSYNC_RECORDER_F))

    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('os.path.exists')
    @mock.patch('os.path.join')
    def test_get_ratraces_not_exist(self, mock_join, mock_exists, mock_debug2):
        self.context.ha_varlib = "/var/lib/heartbeat"
        mock_join.return_value = "{}/trace_ra".format(self.context.ha_varlib)
        mock_exists.return_value = False

        collect.get_ratraces(self.context)

        mock_join.assert_called_once_with(self.context.ha_varlib, "trace_ra")
        mock_exists.assert_called_once_with(mock_join.return_value)

    @mock.patch('hb_report.collect.find_files')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('os.path.exists')
    @mock.patch('os.path.join')
    def test_get_ratraces_not_found(self, mock_join, mock_exists, mock_debug2, mock_find):
        self.context.ha_varlib = "/var/lib/heartbeat"
        mock_join.return_value = "{}/trace_ra".format(self.context.ha_varlib)
        mock_exists.return_value = True
        mock_find.return_value = []

        collect.get_ratraces(self.context)

        mock_join.assert_called_once_with(self.context.ha_varlib, "trace_ra")
        mock_exists.assert_called_once_with(mock_join.return_value)
        mock_debug2.assert_called_once_with("Looking for RA trace files in {}".format(mock_join.return_value))
        mock_find.assert_called_once_with(self.context, mock_join.return_value)

    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('hb_report.collect.crmutils.get_stdout_stderr')
    @mock.patch('os.path.dirname')
    @mock.patch('hb_report.collect.find_files')
    @mock.patch('hb_report.utils.log_debug2')
    @mock.patch('os.path.exists')
    @mock.patch('os.path.join')
    def test_get_ratraces(self, mock_join, mock_exists, mock_debug2, mock_find,
            mock_dirname, mock_run, mock_debug1):
        self.context.ha_varlib = "/var/lib/heartbeat"
        mock_join.side_effect = [
                "{}/trace_ra".format(self.context.ha_varlib),
                "trace_ra/trace_ra/ip.monitor.2020-02-10.10:55:08",
                "trace_ra/trace_ra/ip.monitor.2020-02-10.10:56:38"
                ]
        mock_exists.return_value = True
        mock_find.return_value = [
                "/var/lib/heartbeat/trace_ra/ip.monitor.2020-02-10.10:55:08",
                "/var/lib/heartbeat/trace_ra/ip.monitor.2020-02-10.10:56:38"
                ]
        mock_dirname.return_value = "/var/lib"

        collect.get_ratraces(self.context)

        mock_join.assert_has_calls([
            mock.call(self.context.ha_varlib, "trace_ra"),
            mock.call("trace_ra", "trace_ra/ip.monitor.2020-02-10.10:55:08"),
            mock.call("trace_ra", "trace_ra/ip.monitor.2020-02-10.10:56:38")
            ])
        trace_dir = "{}/trace_ra".format(self.context.ha_varlib)
        mock_exists.assert_called_once_with(trace_dir)
        mock_debug2.assert_called_once_with("Looking for RA trace files in {}".format(trace_dir))
        mock_find.assert_called_once_with(self.context, trace_dir)
        mock_dirname.assert_called_once_with(trace_dir)
        cmd = "tar -cf - -C {} {} | tar -xf - -C {}".format(mock_dirname.return_value, "trace_ra/trace_ra/ip.monitor.2020-02-10.10:55:08 trace_ra/trace_ra/ip.monitor.2020-02-10.10:56:38", self.context.work_dir)
        mock_run.assert_called_once_with(cmd)
        mock_debug1.assert_called_once_with("Dump RA trace files at {}".format(self.context.dest_path))

    @mock.patch('hb_report.collect.crmutils.get_stdout_stderr')
    def test_dump_D_process_None(self, mock_get_stdout_stderr):
        mock_get_stdout_stderr.return_value = (0, None, None)
        assert collect.dump_D_process() == "Dump D-state process stack: 0\n"
        mock_get_stdout_stderr.assert_called_once_with("ps aux|awk '$8 ~ /^D/{print $2}'")

    @mock.patch('hb_report.collect.crmutils.get_stdout_stderr')
    def test_dump_D_process(self, mock_get_stdout_stderr):
        mock_get_stdout_stderr.side_effect = [
                (0, "10001\n10002", None),
                (0, "comm_out for 10001", None),
                (0, "stack_out for 10001", None),
                (0, "comm_out for 10002", None),
                (0, "stack_out for 10002", None)
                ]

        out_string = "Dump D-state process stack: 2\npid: 10001     comm: comm_out for 10001\nstack_out for 10001\n\npid: 10002     comm: comm_out for 10002\nstack_out for 10002\n\n"
        assert collect.dump_D_process() == out_string

        mock_get_stdout_stderr.assert_has_calls([
            mock.call("ps aux|awk '$8 ~ /^D/{print $2}'"),
            mock.call("cat /proc/10001/comm"),
            mock.call("cat /proc/10001/stack"),
            mock.call("cat /proc/10002/comm"),
            mock.call("cat /proc/10002/stack")
            ])

    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('hb_report.collect.crmutils.str2file')
    @mock.patch('os.path.join')
    @mock.patch('hb_report.collect.crmutils.get_stdout')
    @mock.patch('os.path.exists')
    @mock.patch('hb_report.utils.which')
    @mock.patch('hb_report.collect.dump_D_process')
    def test_dump_ocfs2(self, mock_dumpD, mock_which, mock_exists, mock_run, mock_join,
            mock_str2file, mock_debug1):
        cmds = ["dmesg",  "ps -efL", "lsof",
            "lsblk -o 'NAME,KNAME,MAJ:MIN,FSTYPE,LABEL,RO,RM,MODEL,SIZE,OWNER,GROUP,MODE,ALIGNMENT,MIN-IO,OPT-IO,PHY-SEC,LOG-SEC,ROTA,SCHED,MOUNTPOINT'",
            "mounted.ocfs2 -f", "findmnt", "mount", "cat /sys/fs/ocfs2/cluster_stack"]
        mock_dumpD.return_value = "dump data"
        mock_which.side_effect = [True for x in cmds]
        mock_exists.return_value = False
        mock_run.side_effect = [(0, "data") for cmd in cmds[:-1]]
        mock_join.return_value = "{}/{}".format(self.context.work_dir, const.OCFS2_F)

        collect.dump_ocfs2(self.context)

        mock_dumpD.assert_called_once_with()
        mock_which.assert_has_calls([mock.call(cmd.split()[0]) for cmd in cmds])
        mock_exists.assert_called_once_with("/sys/fs/ocfs2/cluster_stack")
        mock_run.assert_has_calls([mock.call(cmd) for cmd in cmds[:-1]])
        mock_join.assert_called_once_with(self.context.work_dir, const.OCFS2_F)
        mock_str2file.assert_called_once_with("dump data\n\n#=====[ Command ] ==========================#\n# dmesg\ndata\n\n#=====[ Command ] ==========================#\n# ps -efL\ndata\n\n#=====[ Command ] ==========================#\n# lsof\ndata\n\n#=====[ Command ] ==========================#\n# lsblk -o 'NAME,KNAME,MAJ:MIN,FSTYPE,LABEL,RO,RM,MODEL,SIZE,OWNER,GROUP,MODE,ALIGNMENT,MIN-IO,OPT-IO,PHY-SEC,LOG-SEC,ROTA,SCHED,MOUNTPOINT'\ndata\n\n#=====[ Command ] ==========================#\n# mounted.ocfs2 -f\ndata\n\n#=====[ Command ] ==========================#\n# findmnt\ndata\n\n#=====[ Command ] ==========================#\n# mount\ndata", mock_join.return_value)
        mock_debug1.assert_called_once_with("Dump OCFS2 info into {}/{}".format(self.context.dest_path, const.OCFS2_F))

    @mock.patch('hb_report.core.crmutils.get_stdout_stderr')
    def test_find_files(self, mock_run):
        self.context.from_time_file = "file1"
        self.context.to_time_file = "file2"
        mock_run.return_value = (0, "data1\ndata2", None)
        res = collect.find_files(self.context, "dir")
        self.assertEqual(res, ["data1", "data2"])
        mock_run.assert_called_once_with("find dir -type f -newer file1 ! -newer file2")

    @mock.patch('hb_report.collect.crmutils.str2file')
    @mock.patch('os.path.join')
    def test_dump_context(self, mock_join, mock_str2file):
        self.context.dumps.return_value = "dumps data"
        mock_join.return_value = "{}/{}".format(self.context.work_dir, const.CTX_F)

        collect.dump_context(self.context)

        mock_join.assert_called_once_with(self.context.work_dir, const.CTX_F)
        self.context.dumps.assert_called_once_with()
        mock_str2file.assert_called_once_with("dumps data", mock_join.return_value)

    @mock.patch('hb_report.core.dump_logset')
    @mock.patch('os.path.isfile')
    def test_get_extra_logs(self, mock_isfile, mock_dump):
        self.context.no_extra = False
        self.context.extra_logs = ["file1", "file2"]
        mock_isfile.side_effect = [True, False]

        collect.get_extra_logs(self.context)

        mock_isfile.assert_has_calls([
            mock.call("file1"),
            mock.call("file2")
            ])
        mock_dump.assert_called_once_with(self.context, "file1")

    @mock.patch('hb_report.utils.log_debug1')
    def test_get_extra_logs_skip(self, mock_debug1):
        self.context.no_extra = True
        collect.get_extra_logs(self.context)
        mock_debug1.assert_called_once_with("Skip collect extra logs")

    @mock.patch('hb_report.collect.corosync.get_value')
    @mock.patch('os.path.isfile')
    def test_dump_corosync_log_no_config(self, mock_isfile, mock_get_value):
        mock_isfile.return_value = False
        collect.dump_corosync_log(self.context)
        mock_isfile.assert_called_once_with(const.CONF)
        mock_get_value.assert_not_called()

    @mock.patch('hb_report.core.dump_logset')
    @mock.patch('hb_report.collect.corosync.get_value')
    @mock.patch('os.path.isfile')
    def test_dump_corosync_log_no_exist(self, mock_isfile, mock_get_value, mock_dump):
        mock_isfile.side_effect = [True, False]
        mock_get_value.return_value = "logfile"
        collect.dump_corosync_log(self.context)
        mock_isfile.assert_has_calls([mock.call(const.CONF), mock.call("logfile")])
        mock_get_value.assert_called_once_with("logging.logfile")
        mock_dump.assert_not_called()

    @mock.patch('hb_report.core.dump_logset')
    @mock.patch('hb_report.collect.corosync.get_value')
    @mock.patch('os.path.isfile')
    def test_dump_corosync_log(self, mock_isfile, mock_get_value, mock_dump):
        mock_isfile.side_effect = [True, True]
        mock_get_value.return_value = "logfile"
        collect.dump_corosync_log(self.context)
        mock_isfile.assert_has_calls([mock.call(const.CONF), mock.call("logfile")])
        mock_get_value.assert_called_once_with("logging.logfile")
        mock_dump.assert_called_once_with(self.context, "logfile")

    @mock.patch("builtins.open", new_callable=mock.mock_open)
    @mock.patch('os.path.isfile')
    def test_get_pcmk_log_no_exist(self, mock_isfile, mock_open_file):
        mock_isfile.return_value = False
        collect.get_pcmk_log()
        mock_isfile.assert_called_once_with("/etc/sysconfig/pacemaker")
        mock_open_file.assert_not_called()

    @mock.patch('re.search')
    @mock.patch("builtins.open", new_callable=mock.mock_open, read_data="")
    @mock.patch('os.path.isfile')
    def test_get_pcmk_log_no_data(self, mock_isfile, mock_open_file, mock_search):
        mock_isfile.return_value = True
        collect.get_pcmk_log()
        mock_isfile.assert_called_once_with("/etc/sysconfig/pacemaker")
        mock_open_file.assert_called_once_with("/etc/sysconfig/pacemaker")
        mock_search.assert_not_called()

    @mock.patch('re.search')
    @mock.patch("builtins.open", new_callable=mock.mock_open, read_data="data")
    @mock.patch('os.path.isfile')
    def test_get_pcmk_log(self, mock_isfile, mock_open_file, mock_search):
        mock_isfile.return_value = True
        mock_search_inst = mock.Mock()
        mock_search.return_value = mock_search_inst
        mock_search_inst.group.return_value = "return data"
        res = collect.get_pcmk_log()
        self.assertEqual(res, "return data")
        mock_isfile.assert_called_once_with("/etc/sysconfig/pacemaker")
        mock_open_file.assert_called_once_with("/etc/sysconfig/pacemaker")
        mock_search.assert_called_once_with('^ *PCMK_logfile *= *(.*)', "data", re.M)
        mock_search_inst.group.assert_called_once_with(1)

    @mock.patch('hb_report.utils.is_log_empty')
    @mock.patch('os.path.isfile')
    @mock.patch('os.path.join')
    def test_events_not_exist(self, mock_join, mock_isfile, mock_empty):
        mock_join.return_value = "{}/{}".format(self.context.work_dir, const.HALOG_F)
        mock_isfile.return_value = False
        collect.events(self.context)
        mock_join.assert_called_once_with(self.context.work_dir, const.HALOG_F)
        mock_isfile.assert_called_once_with(mock_join.return_value)
        mock_empty.assert_not_called()

    @mock.patch('hb_report.utils.is_log_empty')
    @mock.patch('os.path.isfile')
    @mock.patch('os.path.join')
    def test_events_empty(self, mock_join, mock_isfile, mock_empty):
        mock_join.return_value = "{}/{}".format(self.context.work_dir, const.HALOG_F)
        mock_isfile.return_value = True
        mock_empty.return_value = True
        collect.events(self.context)
        mock_join.assert_called_once_with(self.context.work_dir, const.HALOG_F)
        mock_isfile.assert_called_once_with(mock_join.return_value)
        mock_empty.assert_called_once_with(mock_join.return_value)

    @mock.patch('hb_report.utils.log_debug1')
    @mock.patch('hb_report.collect.crmutils.str2file')
    @mock.patch('re.search')
    @mock.patch("builtins.open", new_callable=mock.mock_open, read_data="data1\ndata2")
    @mock.patch('hb_report.utils.is_log_empty')
    @mock.patch('os.path.isfile')
    @mock.patch('os.path.join')
    def test_events(self, mock_join, mock_isfile, mock_empty, mock_open_file, mock_search,
            mock_str2file, mock_debug1):
        mock_join.side_effect = ["{}/{}".format(self.context.work_dir, const.HALOG_F),
                "{}/{}".format(self.context.work_dir, const.EVENTS_F)]
        mock_isfile.return_value = True
        mock_empty.return_value = False
        const.EVENT_PATTERNS = "patt1\npatt2"
        mock_search.side_effect = [True, False]

        collect.events(self.context)

        mock_open_file.assert_called_once_with("{}/{}".format(self.context.work_dir, const.HALOG_F), encoding='utf-8', errors='replace')
        mock_search.assert_has_calls([
            mock.call("patt1|patt2", "data1"),
            mock.call("patt1|patt2", "data2")
            ])
        mock_join.assert_has_calls([
            mock.call(self.context.work_dir, const.HALOG_F),
            mock.call(self.context.work_dir, const.EVENTS_F)
            ])
        mock_str2file.assert_called_once_with("data1\n", "{}/{}".format(self.context.work_dir, const.EVENTS_F))
        mock_isfile.assert_called_once_with("{}/{}".format(self.context.work_dir, const.HALOG_F))
        mock_empty.assert_called_once_with("{}/{}".format(self.context.work_dir, const.HALOG_F))

    @mock.patch('hb_report.core.dump_logset')
    @mock.patch('os.path.isfile')
    @mock.patch('hb_report.collect.get_pcmk_log')
    def test_dump_pcmk_log(self, mock_get_pcmk_log, mock_isfile, mock_dump):
        mock_get_pcmk_log.return_value = "file"
        mock_isfile.return_value = True
        collect.dump_pcmk_log(self.context)
        mock_get_pcmk_log.assert_called_once_with()
        mock_isfile.assert_called_once_with("file")
        mock_dump.assert_called_once_with(self.context, "file")
