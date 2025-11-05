from subprocess import TimeoutExpired
from crmsh.report import collect, constants
import crmsh.log

import unittest
from unittest import mock


class TestCollect(unittest.TestCase):

    @mock.patch('logging.Logger.warning')
    @mock.patch('os.path.isfile')
    def test_get_pcmk_log_no_config(self, mock_isfile, mock_warning):
        mock_isfile.side_effect = [False, False, False]
        res = collect.get_pcmk_log()
        self.assertIsNone(res)
        mock_isfile.assert_has_calls([
            mock.call(constants.PCMKCONF),
            mock.call("/var/log/pacemaker/pacemaker.log"),
            mock.call("/var/log/pacemaker.log")
            ])
        mock_warning.assert_called_once_with("No valid pacemaker log file found")

    @mock.patch('logging.Logger.warning')
    @mock.patch('crmsh.utils.read_from_file')
    @mock.patch('os.path.isfile')
    def test_get_pcmk_log(self, mock_isfile, mock_read, mock_warning):
        mock_isfile.return_value = True
        mock_read.return_value = """
# has been enabled, those as well). This log is of more use to developers and
# advanced system administrators, and when reporting problems.
PCMK_logfile=/var/log/pacemaker/pacemaker.log

# Set the permissions on the above log file to owner/group read/write
        """
        res = collect.get_pcmk_log()
        self.assertEqual(res, "/var/log/pacemaker/pacemaker.log")
        mock_isfile.assert_has_calls([
            mock.call(constants.PCMKCONF),
            mock.call("/var/log/pacemaker/pacemaker.log")
            ])
        mock_read.assert_called_once_with(constants.PCMKCONF)

    @mock.patch('crmsh.report.utils.mark_duplicate_basenames')
    @mock.patch('crmsh.report.utils.dump_logset')
    @mock.patch('os.path.isfile')
    @mock.patch('crmsh.report.collect.get_pcmk_log')
    @mock.patch('crmsh.report.collect.get_corosync_log')
    def test_collect_ha_logs(self, mock_corosync_log, mock_get_log, mock_isfile, mock_dump, mock_mark):
        mock_corosync_log.return_value = "/var/log/cluster/corosync.log"
        mock_get_log.return_value = "/var/pacemaker.log"
        mock_mark.return_value = [
            (mock_get_log.return_value, False),
            (mock_corosync_log.return_value, False)
        ]
        mock_isfile.side_effect = [True, True]
        mock_ctx_inst = mock.Mock(extra_log_list=[])

        collect.collect_ha_logs(mock_ctx_inst)

        mock_get_log.assert_called_once_with()
        mock_isfile.assert_has_calls([
            mock.call(mock_get_log.return_value),
            mock.call(mock_corosync_log.return_value)
            ])
        mock_dump.assert_has_calls([
            mock.call(mock_ctx_inst, mock_get_log.return_value, create_dir=False),
            mock.call(mock_ctx_inst, mock_corosync_log.return_value, create_dir=False)
            ])

    @mock.patch('logging.Logger.warning')
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.corosync.conf')
    def test_get_corosync_log_not_exist(self, mock_conf, mock_exists, mock_warning):
        mock_conf.return_value = "/etc/corosync/corosync.conf"
        mock_exists.return_value = False
        self.assertIsNone(collect.get_corosync_log())

    @mock.patch('crmsh.corosync.get_value')
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.corosync.conf')
    def test_get_corosync_log(self, mock_conf, mock_exists, mock_get_value):
        mock_conf.return_value = "/etc/corosync/corosync.conf"
        mock_get_value.return_value = "/var/log/cluster/corosync.log"
        mock_exists.return_value = True
        self.assertEqual(collect.get_corosync_log(), mock_get_value.return_value)

    @mock.patch('crmsh.report.utils.real_path')
    @mock.patch('crmsh.report.collect.logger', spec=crmsh.log.DEBUG2Logger)
    @mock.patch('crmsh.utils.str2file')
    @mock.patch('crmsh.report.utils.get_cmd_output')
    @mock.patch('crmsh.report.utils.ts_to_str')
    def test_collect_journal_logs(self, mock_ts_to_str, mock_get_cmd_output,
                                  mock_str2file, mock_logger, mock_real_path):
        mock_real_path.side_effect = [
                constants.JOURNAL_F,
                constants.JOURNAL_PCMK_F,
                constants.JOURNAL_COROSYNC_F,
                constants.JOURNAL_SBD_F
        ]
        mock_ctx_inst = mock.Mock(from_time=1234, to_time=5678, work_dir="/opt/work")
        mock_ts_to_str.side_effect = ["10.10", "10.12"]
        mock_get_cmd_output.side_effect = ["data_default", "data_pacemaker", "data_corosync", "data_sbd"]
        collect.collect_journal_logs(mock_ctx_inst)
        mock_ts_to_str.assert_has_calls([
            mock.call(mock_ctx_inst.from_time),
            mock.call(mock_ctx_inst.to_time)
            ])
        cmd_list = [
                'journalctl -o short-iso-precise --since "10.10" --until "10.12" --no-pager | tail -n +2',
                'journalctl -u pacemaker -o short-iso-precise --since "10.10" --until "10.12" --no-pager | tail -n +2',
                'journalctl -u corosync -o short-iso-precise --since "10.10" --until "10.12" --no-pager | tail -n +2',
                'journalctl -u sbd -o short-iso-precise --since "10.10" --until "10.12" --no-pager | tail -n +2'
                ]
        mock_get_cmd_output.assert_has_calls([
            mock.call(cmd_list[0]),
            mock.call(cmd_list[1]),
            mock.call(cmd_list[2]),
            mock.call(cmd_list[3]),
            ])
        mock_logger.debug2.assert_has_calls([
            mock.call("Collect journal logs since: 10.10 until: 10.12"),
            mock.call(f"Running command: {cmd_list[0]}"),
            mock.call(f"Running command: {cmd_list[1]}"),
            mock.call(f"Running command: {cmd_list[2]}"),
            mock.call(f"Running command: {cmd_list[3]}"),
            ])
        mock_logger.debug.assert_has_calls([
            mock.call(f"Dump jounal log for default into {constants.JOURNAL_F}"),
            mock.call(f"Dump jounal log for pacemaker into {constants.JOURNAL_PCMK_F}"),
            mock.call(f"Dump jounal log for corosync into {constants.JOURNAL_COROSYNC_F}"),
            mock.call(f"Dump jounal log for sbd into {constants.JOURNAL_SBD_F}")
            ])

    @mock.patch('logging.Logger.debug')
    @mock.patch('os.path.exists')
    def test_collect_sbd_info_no_config(self, mock_exists, mock_debug):
        mock_exists.return_value = False
        mock_ctx_inst = mock.Mock()
        collect.collect_sbd_info(mock_ctx_inst)
        mock_exists.assert_called_once_with(constants.SBDCONF)
        mock_debug.assert_called_once_with(f"SBD config file {constants.SBDCONF} does not exist")

    @mock.patch('shutil.which')
    @mock.patch('shutil.copy2')
    @mock.patch('os.path.exists')
    def test_collect_sbd_info_no_cmd(self, mock_exists, mock_copy, mock_which):
        mock_exists.return_value = True
        mock_which.return_value = False
        mock_ctx_inst = mock.Mock(work_dir="/opt")
        collect.collect_sbd_info(mock_ctx_inst)
        mock_exists.assert_called_once_with(constants.SBDCONF)
        mock_copy.assert_called_once_with(constants.SBDCONF, mock_ctx_inst.work_dir)
        mock_which.assert_called_once_with("sbd")

    @mock.patch('crmsh.report.utils.real_path')
    @mock.patch('builtins.open', create=True)
    @mock.patch('logging.Logger.debug')
    @mock.patch('crmsh.report.utils.get_cmd_output')
    @mock.patch('shutil.which')
    @mock.patch('shutil.copy2')
    @mock.patch('os.path.exists')
    def test_collect_sbd_info(self, mock_exists, mock_copy, mock_which, mock_run, mock_debug, mock_open_file, mock_real_path):
        mock_real_path.return_value = constants.SBD_F
        mock_exists.return_value = True
        mock_which.return_value = True
        mock_open_write = mock.mock_open()
        file_handle = mock_open_write.return_value.__enter__.return_value
        mock_open_file.return_value = mock_open_write.return_value
        mock_run.side_effect = ["data", "data", "data"]
        mock_ctx_inst = mock.Mock(work_dir="/opt")

        collect.collect_sbd_info(mock_ctx_inst)

        mock_exists.assert_called_once_with(constants.SBDCONF)
        mock_copy.assert_called_once_with(constants.SBDCONF, mock_ctx_inst.work_dir)
        mock_which.assert_called_once_with("sbd")
        mock_open_file.assert_called_once_with(f"{mock_ctx_inst.work_dir}/{constants.SBD_F}", "w")
        file_handle.write.assert_has_calls([
            mock.call(f"\n\n{collect.DIVIDER}\n"),
            mock.call("# . /etc/sysconfig/sbd;export SBD_DEVICE;sbd dump;sbd list\n"),
            mock.call("data"),
            mock.call(f"\n\n{collect.DIVIDER}\n"),
            mock.call("# crm sbd configure show\n"),
            mock.call("data"),
            mock.call(f"\n\n{collect.DIVIDER}\n"),
            mock.call("# crm sbd status\n"),
            mock.call("data")
            ])
        mock_debug.assert_called_once_with(f"Dump SBD config file into {constants.SBD_F}")

    @mock.patch('logging.Logger.warning')
    @mock.patch('crmsh.report.collect.ShellUtils')
    def test_pe_to_dot(self, mock_run, mock_warning):
        mock_run_inst = mock.Mock()
        mock_run.return_value = mock_run_inst
        mock_run_inst.get_stdout_stderr.return_value = (1, None, None)
        collect.pe_to_dot("/opt/pe-input-0.bz2")
        mock_run_inst.get_stdout_stderr.assert_called_once_with("crm_simulate -D /opt/pe-input-0.dot -x /opt/pe-input-0.bz2")
        mock_warning.assert_called_once_with('pe_to_dot: %s -> %s failed', '/opt/pe-input-0.bz2', '/opt/pe-input-0.dot')

    @mock.patch('crmsh.report.utils.find_files_in_timespan')
    @mock.patch('crmsh.report.collect.logger', spec=crmsh.log.DEBUG2Logger)
    def test_collect_pe_inputs_no_found(self, mock_logger, mock_find_files):
        mock_ctx_inst = mock.Mock(pe_dir="/opt/pe_dir")
        mock_find_files.return_value = []
        collect.collect_pe_inputs(mock_ctx_inst)
        mock_find_files.assert_called_once_with(mock_ctx_inst, [mock_ctx_inst.pe_dir])
        mock_logger.debug2.assert_has_calls([
            mock.call(f"Looking for PE files in {mock_ctx_inst.pe_dir}"),
            mock.call("No PE file found for the giving time")
            ])

    @mock.patch('crmsh.report.utils.real_path')
    @mock.patch('crmsh.report.collect.pe_to_dot')
    @mock.patch('os.symlink')
    @mock.patch('crmsh.utils.mkdirp')
    @mock.patch('crmsh.report.utils.find_files_in_timespan')
    @mock.patch('crmsh.report.collect.logger', spec=crmsh.log.DEBUG2Logger)
    def test_collect_pe_inputs(self, mock_logger, mock_find_files, mock_mkdir, mock_symlink, mock_to_dot, mock_real_path):
        mock_real_path.return_value = "pe_dir"
        mock_ctx_inst = mock.Mock(pe_dir="/opt/pe_dir", work_dir="/opt/work_dir", speed_up=False)
        mock_find_files.return_value = ["/opt/pe_dir/pe_input1", "/opt/pe_dir/pe_input2"]

        collect.collect_pe_inputs(mock_ctx_inst)

        mock_find_files.assert_called_once_with(mock_ctx_inst, [mock_ctx_inst.pe_dir])
        mock_logger.debug2.assert_has_calls([
            mock.call(f"Looking for PE files in {mock_ctx_inst.pe_dir}"),
            mock.call(f"Found 2 PE files in {mock_ctx_inst.pe_dir}"),
            ])
        mock_logger.debug.assert_called_once_with(f"Dump PE files into pe_dir")

    @mock.patch('crmsh.report.utils.real_path')
    @mock.patch('crmsh.report.collect.logger', spec=crmsh.log.DEBUG2Logger)
    @mock.patch('crmsh.utils.str2file')
    @mock.patch('crmsh.report.utils.get_cmd_output')
    def test_collect_sys_stats(self, mock_run, mock_str2file, mock_logger, mock_real_path):
        mock_real_path.return_value = constants.SYSSTATS_F
        mock_run.side_effect = [
                "data_hostname", "data_uptime", "data_ps_axf", "data_ps_auxw",
                "data_top", "data_ip_addr", "data_ip_link", "data_ip_show", "data_iscsi",
                "data_lspci", "data_mount", "data_cpuinfo", TimeoutExpired("df", 5)
                ]
        mock_ctx_inst = mock.Mock(work_dir="/opt")
        collect.collect_sys_stats(mock_ctx_inst)
        mock_logger.warning.assert_called_once_with(f"Timeout while running command: df")
        mock_run.assert_has_calls([
            mock.call("hostname", timeout=5),
            mock.call("uptime", timeout=5),
            mock.call("ps axf", timeout=5),
            mock.call("ps auxw", timeout=5),
            mock.call("top -b -n 1", timeout=5),
            mock.call("ip addr", timeout=5),
            mock.call("ip -s link", timeout=5),
            mock.call("ip n show", timeout=5),
            mock.call("lsscsi", timeout=5),
            mock.call("lspci", timeout=5),
            mock.call("mount", timeout=5),
            mock.call("cat /proc/cpuinfo", timeout=5),
            mock.call("df", timeout=5)
            ])

    @mock.patch('crmsh.report.utils.real_path')
    @mock.patch('logging.Logger.debug')
    @mock.patch('crmsh.report.utils.get_distro_info')
    @mock.patch('crmsh.utils.str2file')
    @mock.patch('os.uname')
    @mock.patch('crmsh.report.utils.Package')
    def test_collect_sys_info(self, mock_package, mock_uname, mock_str2file, mock_get_distro, mock_debug, mock_real_path):
        mock_real_path.return_value = constants.SYSINFO_F
        mock_package_inst = mock.Mock()
        mock_package.return_value = mock_package_inst
        mock_package_inst.version = mock.Mock(return_value="version_data\n")
        mock_package_inst.verify = mock.Mock(return_value="verify_data\n")
        mock_ctx_inst = mock.Mock(speed_up=False, work_dir="/opt/work")
        mock_uname.return_value = ("Linux", None, "4.5", None, "x86_64")
        mock_get_distro.return_value = "suse"

        collect.collect_sys_info(mock_ctx_inst)

        mock_package.assert_called_once_with(' '.join(constants.PACKAGE_LIST))
        mock_str2file.assert_called_once_with('##### System info #####\nPlatform: Linux\nKernel release: 4.5\nArchitecture: x86_64\nDistribution: suse\n\n##### Installed cluster related packages #####\nversion_data\n\n\n##### Verification output of packages #####\nverify_data\n', '/opt/work/sysinfo.txt')
        mock_debug.assert_called_once_with(f"Dump packages and platform info into {constants.SYSINFO_F}")

    @mock.patch('crmsh.report.utils.real_path')
    @mock.patch('crmsh.report.collect.dump_configurations')
    @mock.patch('crmsh.report.collect.consume_cib_in_workdir')
    @mock.patch('crmsh.report.collect.logger', spec=crmsh.log.DEBUG2Logger)
    @mock.patch('crmsh.utils.str2file')
    @mock.patch('crmsh.report.collect.dump_runtime_state')
    @mock.patch('crmsh.report.collect.ServiceManager')
    def test_collect_config_running(self, mock_service, mock_dump_state, mock_write, mock_debug2, mock_cib, mock_dump_config, mock_real_path):
        mock_real_path.return_value = "workdir"
        mock_service_inst = mock.Mock()
        mock_service.return_value = mock_service_inst
        mock_service_inst.service_is_active.return_value = True
        mock_ctx_inst = mock.Mock(work_dir="/opt/workdir")
        collect.collect_config(mock_ctx_inst)

    @mock.patch('crmsh.report.utils.real_path')
    @mock.patch('crmsh.report.collect.dump_configurations')
    @mock.patch('crmsh.report.collect.consume_cib_in_workdir')
    @mock.patch('crmsh.report.collect.logger', spec=crmsh.log.DEBUG2Logger)
    @mock.patch('crmsh.utils.str2file')
    @mock.patch('shutil.copy2')
    @mock.patch('crmsh.report.collect.ServiceManager')
    def test_collect_config_stopped(self, mock_service, mock_copy2, mock_write, mock_debug2, mock_cib, mock_dump_config, mock_real_path):
        mock_real_path.return_value = "workdir"
        mock_service_inst = mock.Mock()
        mock_service.return_value = mock_service_inst
        mock_service_inst.service_is_active.return_value = False
        mock_ctx_inst = mock.Mock(work_dir="/opt/workdir", cib_dir="/var/log/pacemaker/cib")
        collect.collect_config(mock_ctx_inst)

    @mock.patch('crmsh.utils.str2file')
    @mock.patch('crmsh.report.collect.sh.cluster_shell')
    @mock.patch('os.path.isfile')
    def test_consume_cib_in_workdir(self, mock_isfile, mock_run, mock_str2file):
        mock_isfile.return_value = True
        mock_run_inst = mock.Mock()
        mock_run.return_value = mock_run_inst
        mock_run_inst.get_stdout_or_raise_error.return_value = "data1"
        mock_run_inst.get_rc_stdout_stderr_without_input.return_value = (0, "data2", "error")
        collect.consume_cib_in_workdir("/workdir")
        mock_isfile.assert_called_once_with(f"/workdir/{constants.CIB_F}")
        cmd1 = "CIB_file=/workdir/cib.xml crm configure show"
        mock_run_inst.get_stdout_or_raise_error.assert_called_once_with(cmd1)
        cmd2 = f"crm_verify -V -x /workdir/cib.xml"
        mock_run_inst.get_rc_stdout_stderr_without_input.assert_called_once_with(None, cmd2)
        mock_str2file.assert_has_calls([
            mock.call("data1", f"/workdir/{constants.CONFIGURE_SHOW_F}"),
            mock.call("error", f"/workdir/{constants.CRM_VERIFY_F}")
        ])

    @mock.patch('crmsh.report.utils.real_path')
    @mock.patch('crmsh.report.collect.logger', spec=crmsh.log.DEBUG2Logger)
    @mock.patch('shutil.copy2')
    @mock.patch('crmsh.utils.mkdirp')
    @mock.patch('crmsh.report.utils.find_files_in_timespan')
    def test_collect_ratraces(self, mock_find, mock_mkdirp, mock_copy, mock_logger, mock_real_path):
        mock_real_path.return_value = "/var/log"
        data = "INFO: Trace for .* is written to /var/log/cluster/pacemaker.log"
        mock_ctx_inst = mock.Mock(
            work_dir="/opt/work",
            trace_dir_list="/var/lib/heartbeat/trace_ra",
        )
        mock_find.return_value = [
            "/var/lib/heartbeat/trace_ra/IPaddr2/admin-ip.monitor.2024-02-26.15:21:39",
            "/var/lib/heartbeat/trace_ra/IPaddr2/admin-ip.start.2024-02-26.15:21:39",
            "/var/lib/heartbeat/trace_ra/IPaddr2/admin-ip.stop.2024-02-26.15:21:46",
        ]

        collect.collect_ratraces(mock_ctx_inst)

        mock_mkdirp.assert_called_with('/opt/work/trace_ra/IPaddr2')
        mock_copy.assert_has_calls([
            mock.call("/var/lib/heartbeat/trace_ra/IPaddr2/admin-ip.monitor.2024-02-26.15:21:39", '/opt/work/trace_ra/IPaddr2'),
            mock.call("/var/lib/heartbeat/trace_ra/IPaddr2/admin-ip.start.2024-02-26.15:21:39", '/opt/work/trace_ra/IPaddr2'),
            mock.call("/var/lib/heartbeat/trace_ra/IPaddr2/admin-ip.stop.2024-02-26.15:21:46", '/opt/work/trace_ra/IPaddr2'),
        ])
        mock_logger.debug.assert_called_with(f'Dump RA trace files into {mock_real_path.return_value}')

    @mock.patch('crmsh.report.utils.real_path')
    @mock.patch('logging.Logger.debug')
    @mock.patch('crmsh.utils.str2file')
    @mock.patch('crmsh.report.utils.get_cmd_output')
    @mock.patch('shutil.which')
    def test_collect_dlm_info(self, mock_which, mock_get_output, mock_str2file, mock_debug, mock_real_path):
        mock_real_path.return_value = constants.DLM_DUMP_F
        mock_which.return_value = True
        ls_data = """
dlm lockspaces
name          08BB5A6A38EE491DBF63627EEB57E558
id            0x19041a12
        """
        mock_get_output.side_effect = [ls_data, "lockdebug data", "dump data"]
        mock_ctx_inst = mock.Mock(work_dir="/opt/work_dir")
        collect.collect_dlm_info(mock_ctx_inst)
        mock_debug.assert_called_once_with(f"Dump DLM information into {constants.DLM_DUMP_F}")

    @mock.patch('crmsh.report.collect.dump_core_info')
    @mock.patch('logging.Logger.warning')
    @mock.patch('os.path.basename')
    @mock.patch('crmsh.report.utils.find_files_in_timespan')
    def test_collect_coredump_info(self, mock_find, mock_basename, mock_warning, mock_dump):
        mock_ctx_inst = mock.Mock(cores_dir_list=['/var/lib/pacemaker/cores'], work_dir="/opt/work_dir")
        mock_find.return_value = ["/var/lib/pacemaker/cores/core.1"]
        mock_basename.return_value = "core.1"
        collect.collect_coredump_info(mock_ctx_inst)
        mock_dump.assert_called_once_with("/opt/work_dir", mock_find.return_value)
        mock_warning.assert_called_once_with(f"Found coredump file: {mock_find.return_value}")

    @mock.patch('crmsh.report.collect.ShellUtils')
    def test_find_binary_path_for_core_not_found(self, mock_run):
        mock_run().get_stdout_stderr.return_value = (0, "Core not found", None)
        res = collect.find_binary_path_for_core("core.1")
        self.assertEqual("Cannot find the program path for core core.1", res)

    @mock.patch('crmsh.report.collect.ShellUtils')
    def test_find_binary_path_for_core(self, mock_run):
        mock_run_inst = mock.Mock()
        mock_run.return_value = mock_run_inst
        mock_run_inst.get_stdout_stderr.return_value = (0, "Core was generated by `/usr/sbin/crm_mon'", None)
        res = collect.find_binary_path_for_core("core.1")
        self.assertEqual("Core core.1 was generated by /usr/sbin/crm_mon", res)

    @mock.patch('crmsh.report.utils.real_path')
    @mock.patch('crmsh.report.collect.logger', spec=crmsh.log.DEBUG2Logger)
    @mock.patch('crmsh.utils.str2file')
    @mock.patch('shutil.which')
    def test_dump_core_info_no_gdb(self, mock_which, mock_str2file, mock_logger, mock_real_path):
        mock_real_path.return_value = constants.COREDUMP_F
        mock_which.return_value = False
        collect.dump_core_info("/opt/workdir", ["core.1"])
        mock_logger.warning.assert_called_once_with("Please install gdb to get more info for coredump files")

    @mock.patch('crmsh.report.utils.real_path')
    @mock.patch('crmsh.report.collect.logger', spec=crmsh.log.DEBUG2Logger)
    @mock.patch('crmsh.utils.str2file')
    @mock.patch('crmsh.report.collect.find_binary_path_for_core')
    @mock.patch('shutil.which')
    def test_dump_core_info(self, mock_which, mock_find_binary, mock_str2file, mock_debug2, mock_real_path):
        mock_real_path.return_value = constants.COREDUMP_F
        mock_which.return_value = True
        mock_find_binary.return_value = "data"
        collect.dump_core_info("/opt/workdir", ["core.1"])
        mock_str2file.assert_called_once_with("data\n\nPlease utilize the gdb and debuginfo packages to obtain more detailed information locally", f"/opt/workdir/{constants.COREDUMP_F}")
        mock_debug2(f"Dump coredump info into {constants.COREDUMP_F}")

    @mock.patch('crmsh.utils.str2file')
    @mock.patch('pwd.getpwnam')
    @mock.patch('os.stat')
    @mock.patch('os.path.isdir')
    def test_collect_perms_state(self, mock_isdir, mock_stat, mock_getpwnam, mock_str2file):
        mock_ctx_inst = mock.Mock(
            pcmk_lib_dir="/var/lib/pacemaker",
            pe_dir="/var/lib/pacemaker/pe",
            cib_dir="/var/lib/pacemaker/cib",
            work_dir="/opt/work_dir"
        )
        mock_isdir.side_effect = [False, True, True]
        mock_stat_inst_pe = mock.Mock(st_uid=1000, st_gid=1000, st_mode=0o750)
        mock_stat_inst_cib = mock.Mock(st_uid=1000, st_gid=1000, st_mode=0o750)
        mock_stat.side_effect = [mock_stat_inst_pe, mock_stat_inst_cib]
        mock_getpwnam_inst_pe = mock.Mock(pw_uid=1000, pw_gid=1000)
        mock_getpwnam_inst_cib = mock.Mock(pw_uid=1001, pw_gid=1000)
        mock_getpwnam.side_effect = [mock_getpwnam_inst_pe, mock_getpwnam_inst_cib]

        collect.collect_perms_state(mock_ctx_inst)

        data = "##### Check perms for /var/lib/pacemaker: /var/lib/pacemaker is not a directory or does not exist\n##### Check perms for /var/lib/pacemaker/pe: OK\n##### Check perms for /var/lib/pacemaker/cib: Permissions or ownership for /var/lib/pacemaker/cib are incorrect\n"
        mock_str2file.assert_called_once_with(data, f"/opt/work_dir/{constants.PERMISSIONS_F}")

    @mock.patch('crmsh.report.utils.real_path')
    @mock.patch('crmsh.utils.this_node')
    @mock.patch('crmsh.utils.get_dc')
    @mock.patch('logging.Logger.debug')
    @mock.patch('crmsh.utils.str2file')
    @mock.patch('crmsh.report.collect.sh.cluster_shell')
    def test_dump_runtime_state(self, mock_run, mock_str2file, mock_debug, mock_get_dc, mock_this_node, mock_real_path):
        mock_real_path.side_effect = [
            constants.CRM_MON_F,
            constants.CIB_F,
            constants.MEMBERSHIP_F,
            "workdir"
        ]
        mock_run_inst = mock.Mock()
        mock_run.return_value = mock_run_inst
        mock_run_inst.get_stdout_or_raise_error.side_effect = [
                "crm_mon_data_r1",
                "crm_mon_data_n1",
                "crm_mon_data_rf1",
                "crm_mon_data_rnt1",
                "cib_data",
                "crm_node_data"
                ]
        mock_get_dc.return_value = "node1"
        mock_this_node.return_value = "node1"
        collect.dump_runtime_state("/opt/workdir")
        mock_debug.assert_has_calls([
            mock.call(f"Dump crm_mon state into {constants.CRM_MON_F}"),
            mock.call(f"Dump CIB contents into {constants.CIB_F}"),
            mock.call(f"Dump members of this partition into {constants.MEMBERSHIP_F}"),
            mock.call(f"Current DC is node1; Touch file 'DC' in workdir")
        ])

    @mock.patch('shutil.copytree')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.isdir')
    @mock.patch('shutil.copy2')
    @mock.patch('os.path.isfile')
    @mock.patch('crmsh.corosync.conf')
    def test_dump_configurations(self, mock_corosync_conf, mock_isfile, mock_copy2, mock_isdir, mock_basename, mock_copytree):
        mock_corosync_conf.return_value = "/etc/corosync/corosync.conf"
        mock_isfile.side_effect = [True, True, False, True]
        mock_isdir.return_value = True
        mock_basename.return_value = "drbd.d"
        collect.dump_configurations("/opt/workdir")

    @mock.patch('crmsh.report.utils.real_path')
    @mock.patch('logging.Logger.debug')
    @mock.patch('crmsh.utils.str2file')
    @mock.patch('crmsh.report.utils.get_cmd_output')
    @mock.patch('crmsh.report.utils.find_files_in_timespan')
    def test_collect_corosync_blackbox(self, mock_find_files, mock_get_cmd_output, mock_str2file, mock_debug, mock_real_path):
        mock_real_path.return_value = constants.COROSYNC_RECORDER_F
        mock_ctx_inst = mock.Mock(work_dir="/opt/workdir")
        mock_find_files.return_value = ["/var/lib/corosync/fdata.1"]
        mock_get_cmd_output.return_value = "data"
        collect.collect_corosync_blackbox(mock_ctx_inst)
        mock_debug.assert_called_once_with(f"Dump corosync blackbox info into {constants.COROSYNC_RECORDER_F}")

    @mock.patch('crmsh.corosync.query_quorum_status')
    @mock.patch('crmsh.report.collect.ServiceManager')
    def test_collect_qdevice_info_return(self, mock_service, mock_quorum):
        mock_ctx_inst = mock.Mock(work_dir="/opt/workdir")
        mock_service_inst = mock.Mock()
        mock_service.return_value = mock_service_inst
        mock_service_inst.service_is_active.return_value = False
        collect.collect_qdevice_info(mock_ctx_inst)
        mock_quorum.assert_not_called()

    @mock.patch('logging.Logger.debug')
    @mock.patch('crmsh.report.utils.real_path')
    @mock.patch('crmsh.utils.str2file')
    @mock.patch('os.path.join')
    @mock.patch('crmsh.corosync.query_qnetd_status')
    @mock.patch('crmsh.corosync.query_qdevice_status')
    @mock.patch('crmsh.corosync.query_quorum_status')
    @mock.patch('crmsh.report.collect.ServiceManager')
    def test_collect_qdevice_info(self, mock_service, mock_quorum, mock_qdevice, mock_qnetd, mock_join, mock_str2file, mock_real_path, mock_debug):
        mock_ctx_inst = mock.Mock(work_dir="/opt/workdir")
        mock_service_inst = mock.Mock()
        mock_service.return_value = mock_service_inst
        mock_service_inst.service_is_active.side_effect = [True, True]
        mock_qdevice.return_value = "qdevice_data"
        mock_qnetd.return_value = "qnetd_data"
        mock_quorum.return_value = "quorum_data"
        mock_join.return_value = "/opt/workdir/qdevice.txt"
        mock_real_path.return_value = "/opt/workdir/qdevice.txt"
        collect.collect_qdevice_info(mock_ctx_inst)
        mock_debug.assert_called_once_with('Dump quorum/qdevice/qnetd information into /opt/workdir/qdevice.txt')

    @mock.patch('crmsh.report.collect.ServiceManager')
    def test_collect_corosync_status_return(self, mock_service):
        mock_service_inst = mock.Mock()
        mock_service.return_value = mock_service_inst
        mock_service_inst.service_is_active.return_value = False
        collect.collect_corosync_status(mock.Mock())
        mock_service_inst.service_is_active.assert_called_once_with("corosync.service")

    @mock.patch('crmsh.report.utils.real_path')
    @mock.patch('logging.Logger.debug')
    @mock.patch('crmsh.report.utils.get_cmd_output')
    @mock.patch('builtins.open', create=True)
    @mock.patch('os.path.join')
    @mock.patch('crmsh.report.collect.ServiceManager')
    def test_collect_corosync_status(self, mock_service, mock_join, mock_open_file, mock_get_cmd_output, mock_debug, mock_real_path):
        mock_ctx_inst = mock.Mock(work_dir="/opt/workdir")
        mock_service_inst = mock.Mock()
        mock_service.return_value = mock_service_inst
        mock_service_inst.service_is_active.return_value = True
        mock_join.return_value = f"/opt/workdir/{constants.COROSYNC_STATUS_F}"
        mock_real_path.return_value = f"/opt/workdir/{constants.COROSYNC_STATUS_F}"
        mock_open_write = mock.mock_open()
        file_handle = mock_open_write.return_value.__enter__.return_value
        mock_open_file.return_value = mock_open_write.return_value
        mock_get_cmd_output.side_effect = ["data1", "data2", "data3", "data4"]

        collect.collect_corosync_status(mock_ctx_inst)

        mock_open_file.assert_called_once_with(f"{mock_join.return_value}", "w")
        file_handle.write.assert_has_calls([
            mock.call(f"\n\n{collect.DIVIDER}\n"),
            mock.call("# crm corosync status\n"),
            mock.call("data1"),
            mock.call(f"\n\n{collect.DIVIDER}\n"),
            mock.call("# crm corosync link show\n"),
            mock.call("data2"),
            mock.call(f"\n\n{collect.DIVIDER}\n"),
            mock.call("# crm corosync status cpg\n"),
            mock.call("data3"),
            mock.call(f"\n\n{collect.DIVIDER}\n"),
            mock.call("# corosync-cmapctl\n"),
            mock.call("data4")
        ])
        mock_debug.assert_called_once_with(f"Dump corosync status info into {mock_real_path.return_value}")

    @mock.patch("logging.Logger.error")
    @mock.patch('crmsh.utils.str2file')
    @mock.patch("crmsh.report.utils.real_path")
    @mock.patch("logging.Logger.debug")
    @mock.patch("crmsh.report.collect.cluster_fs_commands_output")
    @mock.patch("crmsh.report.collect.lsof_cluster_fs_device")
    @mock.patch("crmsh.report.collect.dump_D_process")
    @mock.patch("crmsh.report.collect.ShellUtils")
    @mock.patch("shutil.which")
    def test_collect_cluster_fs_info(self, mock_which, mock_run, mock_dump, mock_lsof, mock_cluster, mock_debug, mock_real_path, mock_str2file, mock_error):
        mock_which.return_value = True
        mock_run_inst = mock.Mock()
        mock_run.return_value = mock_run_inst
        mock_run_inst.get_stdout_stderr.side_effect = [
            (1, None, "error"),
            (0, "data", None)
        ]
        mock_dump.return_value = "dump_data\n"
        mock_lsof.return_value = "lsof_data\n"
        mock_cluster.return_value = "cluster_data"
        mock_ctx_inst = mock.Mock(work_dir="/opt/work")
        mock_real_path.side_effect = ["/path/ocfs2.txt", "/path/gfs2.txt"]

        collect.collect_cluster_fs_info(mock_ctx_inst)

        mock_debug.assert_has_calls([
            mock.call('Dump %s information into %s', 'OCFS2', '/path/ocfs2.txt'),
            mock.call('Dump %s information into %s', 'GFS2', '/path/gfs2.txt')
        ])
        mock_str2file.assert_has_calls([
            mock.call('Failed to run "mounted.ocfs2 -d": error', '/opt/work/ocfs2.txt'),
            mock.call('dump_data\nlsof_data\ncluster_data', '/opt/work/gfs2.txt')
        ])

    @mock.patch('crmsh.report.collect.ShellUtils')
    def test_dump_D_process_empty(self, mock_run):
        mock_run_inst = mock.Mock()
        mock_run.return_value = mock_run_inst
        mock_run_inst.get_stdout_stderr.return_value = (0, None, None)
        res = collect.dump_D_process()
        self.assertEqual(res, "Dump D-state process stack: 0\n")

    @mock.patch('crmsh.report.collect.ShellUtils')
    def test_dump_D_process(self, mock_run):
        mock_run_inst = mock.Mock()
        mock_run.return_value = mock_run_inst
        mock_run_inst.get_stdout_stderr.side_effect = [
            (0, "1000", None),
            (0, "data1", None),
            (0, "data2", None)
        ]
        res = collect.dump_D_process()
        self.assertEqual(res, "Dump D-state process stack: 1\npid: 1000     comm: data1\ndata2\n\n")
        mock_run_inst.get_stdout_stderr.assert_has_calls([
            mock.call("ps aux|awk '$8 ~ /^D/{print $2}'"),
            mock.call('cat /proc/1000/comm'),
            mock.call('cat /proc/1000/stack')
            ])

    @mock.patch('crmsh.report.collect.ShellUtils')
    def test_lsof_cluster_fs_device(self, mock_run):
        mock_run_inst = mock.Mock()
        mock_run.return_value = mock_run_inst
        mount_data = """
/dev/vda3 on /home type xfs (rw,relatime,attr2,inode64,logbufs=8,logbsize=32k,noquota)
tmpfs on /run/user/0 type tmpfs (rw,nosuid,nodev,relatime,size=169544k,nr_inodes=42386,mode=700,inode64)
/dev/sda7 on /srv/clusterfs type ocfs2 (rw,relatime,heartbeat=non
        """
        mock_run_inst.get_stdout_stderr.side_effect = [(0, mount_data, None), (0, "data", None)]
        res = collect.lsof_cluster_fs_device("OCFS2")
        self.assertEqual(res, f"\n\n{collect.DIVIDER}\n# lsof /dev/sda7\ndata")
        mock_run_inst.get_stdout_stderr.assert_has_calls([
            mock.call("mount"),
            mock.call("lsof /dev/sda7")
        ])

    @mock.patch('crmsh.report.utils.get_cmd_output')
    @mock.patch('os.path.exists')
    @mock.patch('shutil.which')
    def test_cluster_fs_commands_output(self, mock_which, mock_exists, mock_run):
        mock_which.side_effect = [False for i in range(5)] + [True, True]
        mock_exists.return_value = False
        mock_run.return_value = "data"
        res = collect.cluster_fs_commands_output("OCFS2")
        self.assertEqual(res, f"\n\n{collect.DIVIDER}\n# mounted.ocfs2 -f\ndata")
