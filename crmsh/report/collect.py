"""
Define functions to collect log and info
Function starts with "collect_" will be called in parallel
"""
import sys
import os
import shutil
import re
import stat
import pwd
import datetime
from subprocess import TimeoutExpired
from typing import List, Optional

import crmsh.user_of_host
from crmsh import log, sh, corosync
from crmsh import utils as crmutils
from crmsh.report import constants, utils, core
from crmsh.sh import ShellUtils
from crmsh.service_manager import ServiceManager


logger = log.setup_report_logger(__name__)


def get_corosync_log() -> Optional[str]:
    """
    Get the path of the corosync log file
    """
    corosync_log = None
    corosync_conf_path = corosync.conf()
    if os.path.exists(corosync_conf_path):
        corosync_log = corosync.get_value("logging.logfile")
    else:
        logger.warning(f"File {corosync_conf_path} does not exist")
    return corosync_log


def get_pcmk_log() -> Optional[str]:
    """
    Get the path of the pacemaker log file
    """
    pcmk_log_candidates = [
        "/var/log/pacemaker/pacemaker.log",
        "/var/log/pacemaker.log"
    ]

    if os.path.isfile(constants.PCMKCONF):
        data = crmutils.read_from_file(constants.PCMKCONF)
        if data:
            res = re.search(r'^ *PCMK_logfile *= *(.*)', data, re.M)
            if res:
                pcmk_log_candidates.insert(0, res.group(1))

    for log in pcmk_log_candidates:
        if os.path.isfile(log):
            return log

    logger.warning("No valid pacemaker log file found")
    return None


def collect_ha_logs(context: core.Context) -> None:
    """
    Collect pacemaker, corosync and extra logs
    """
    log_list = [get_pcmk_log(), get_corosync_log()] + context.extra_log_list
    log_list = [os.path.expanduser(log) for log in log_list if log is not None]
    log_list_marked_same_basename = utils.mark_duplicate_basenames(log_list)
    for log, same_basename in log_list_marked_same_basename:
        if os.path.isfile(log):
            utils.dump_logset(context, log, create_dir=same_basename)


def collect_journal_logs(context: core.Context) -> None:
    """
    Collect journal logs from a specific time range
    """
    from_time_str = utils.ts_to_str(context.from_time)
    to_time_str = utils.ts_to_str(context.to_time)
    logger.debug2(f"Collect journal logs since: {from_time_str} until: {to_time_str}")

    journal_target_dict = {
        "default": constants.JOURNAL_F,
        "pacemaker": constants.JOURNAL_PCMK_F,
        "corosync": constants.JOURNAL_COROSYNC_F,
        "sbd": constants.JOURNAL_SBD_F
    }
    for item, outf in journal_target_dict.items():
        journalctl_unit = "" if item == "default" else f" -u {item}"
        cmd = f'journalctl{journalctl_unit} -o short-iso-precise --since "{from_time_str}" --until "{to_time_str}" --no-pager | tail -n +2'
        output = utils.get_cmd_output(cmd)
        logger.debug2(f"Running command: {cmd}")
        _file = os.path.join(context.work_dir, outf)
        crmutils.str2file(output, _file)
        logger.debug(f"Dump jounal log for {item} into {utils.real_path(_file)}")


def dump_D_process() -> str:
    """
    Dump D-state process stack
    """
    out_string = ""

    sh_utils_inst = ShellUtils()
    _, out, _ = sh_utils_inst.get_stdout_stderr("ps aux|awk '$8 ~ /^D/{print $2}'")
    len_D_process = len(out.split('\n')) if out else 0
    out_string += f"Dump D-state process stack: {len_D_process}\n"
    if len_D_process == 0:
        return out_string

    for pid in out.split('\n'):
        _, cmd_out, _ = sh_utils_inst.get_stdout_stderr(f"cat /proc/{pid}/comm")
        out_string += f"pid: {pid}     comm: {cmd_out}\n"
        _, stack_out, _ = sh_utils_inst.get_stdout_stderr(f"cat /proc/{pid}/stack")
        out_string += stack_out + "\n\n"

    return out_string


def lsof_cluster_fs_device(fs_type: str) -> str:
    """
    List open files for OCFS2/GFS2 device
    """
    out_string = ""

    sh_utils_inst = ShellUtils()
    _, out, _ = sh_utils_inst.get_stdout_stderr("mount")
    dev_list = re.findall(f"^(.*) on .* type {fs_type.lower()} ", out, re.M)
    for dev in dev_list:
        cmd = f"lsof {dev}"
        out_string += "\n\n#=====[ Command ] ==========================#\n"
        out_string += f"# {cmd}\n"
        _, cmd_out, _ = sh_utils_inst.get_stdout_stderr(cmd)
        if cmd_out:
            out_string += cmd_out

    return out_string


def cluster_fs_commands_output(fs_type: str) -> str:
    """
    Run OCFS2/GFS2 related commands, return outputs
    """
    out_string = ""

    cmds = [
        "dmesg",
        "ps -efL",
        "lsblk -o 'NAME,KNAME,MAJ:MIN,FSTYPE,LABEL,RO,RM,MODEL,SIZE,OWNER,GROUP,MODE,ALIGNMENT,MIN-IO,OPT-IO,PHY-SEC,LOG-SEC,ROTA,SCHED,MOUNTPOINT'",
        "findmnt",
        "mount"
    ]

    if fs_type.lower() == "ocfs2":
        cmds.extend([
            "mounted.ocfs2 -f",
            "cat /sys/fs/ocfs2/cluster_stack"
        ])

    for cmd in cmds:
        cmd_name = cmd.split()[0]
        if not shutil.which(cmd_name):
            continue
        if cmd_name == "cat" and not os.path.exists(cmd.split()[1]):
            continue
        out_string += "\n\n#===== [ Command ] ==========================#\n"
        out_string += f"# {cmd}\n"
        out_string += utils.get_cmd_output(cmd)

    return out_string


def collect_cluster_fs_info(context: core.Context) -> None:
    """
    Collects OCFS2 and GFS2 information
    """
    def collect_info(cmd: str, fs_type: str, output_file: str) -> None:
        out_string = ""
        no_partition_msg = f"No {fs_type} partitions found"

        rc, out, err = ShellUtils().get_stdout_stderr(cmd)
        if rc != 0:
            if fs_type == "OCFS2":
                error_msg = f"Failed to run \"{cmd}\": {err}"
                out_string += error_msg
                logger.error(error_msg)
            elif fs_type == "GFS2":
                out_string += no_partition_msg
        elif fs_type == "OCFS2" and len(out.split('\n')) == 1:
            out_string += no_partition_msg
        else:
            out_string += dump_D_process()
            out_string += lsof_cluster_fs_device(fs_type)
            out_string += cluster_fs_commands_output(fs_type)

        target_f = os.path.join(context.work_dir, output_file)
        logger.debug("Dump %s information into %s", fs_type, utils.real_path(target_f))
        crmutils.str2file(out_string, target_f)

    # Collect OCFS2 information
    if shutil.which("mounted.ocfs2"):
        collect_info("mounted.ocfs2 -d", "OCFS2", constants.OCFS2_F)

    # Collect GFS2 information
    collect_info('mount|grep "type gfs2"', "GFS2", constants.GFS2_F)


def collect_ratraces(context: core.Context) -> None:
    """
    Collect ra trace file from default /var/lib/heartbeat/trace_ra and custom one
    """
    trace_dir_str = ' '.join(context.trace_dir_list)
    if not trace_dir_str:
        return

    logger.debug2("Looking for RA trace files in \"%s\"", trace_dir_str)
    for f in utils.find_files_in_timespan(context, trace_dir_str.split()):
        dest_dir = os.path.join(context.work_dir, '/'.join(f.split('/')[-3:-1]))
        crmutils.mkdirp(dest_dir)
        shutil.copy2(f, dest_dir)
        logger.debug(f"Dump RA trace files into {utils.real_path(dest_dir)}")


def collect_corosync_blackbox(context: core.Context) -> None:
    fdata_list = []
    for f in utils.find_files_in_timespan(context, ["/var/lib/corosync"]):
        if re.search("fdata", f):
            fdata_list.append(f)
    if fdata_list:
        blackbox_f = os.path.join(context.work_dir, constants.COROSYNC_RECORDER_F)
        out_string = utils.get_cmd_output("corosync-blackbox")
        crmutils.str2file(out_string, blackbox_f)
        logger.debug(f"Dump corosync blackbox info into {utils.real_path(blackbox_f)}")


def collect_dlm_info(context: core.Context) -> None:
    """
    Get DLM information
    """
    if shutil.which("dlm_tool"):
        name_list = []
        out_string = "##### NOTICE - Lockspace overview:\n"
        out_string += utils.get_cmd_output("dlm_tool ls")
        name_list = re.findall(r"^name\s*(.*)$", out_string, re.MULTILINE)

        for name in name_list:
            out_string += f"\n\n## NOTICE - Lockspace {name}\n"
            lockdebug_cmd = f"dlm_tool lockdebug {name}"
            out_string += utils.get_cmd_output(lockdebug_cmd)

        out_string += "\n\n##### NOTICE - Lockspace history:\n"
        out_string += utils.get_cmd_output("dlm_tool dump")

        dlm_f = os.path.join(context.work_dir, constants.DLM_DUMP_F)
        crmutils.str2file(out_string, dlm_f)
        logger.debug(f"Dump DLM information into {utils.real_path(dlm_f)}")


def collect_perms_state(context: core.Context) -> None:
    """
    Check and collect permissions and ownership information for specific directories
    """
    results = []

    for check_dir in [context.pcmk_lib_dir, context.pe_dir, context.cib_dir]:
        if not os.path.isdir(check_dir):
            result = f"{check_dir} is not a directory or does not exist"
        else:
            stat_info = os.stat(check_dir)
            pwd_inst = pwd.getpwnam('hacluster')
            expected_uid = pwd_inst.pw_uid
            expected_gid = pwd_inst.pw_gid
            expected_mode = 0o750

            uid_match = stat_info.st_uid == expected_uid
            gid_match = stat_info.st_gid == expected_gid
            mode_match = stat_info.st_mode & 0o7777 == expected_mode

            if uid_match and gid_match and mode_match:
                result = "OK"
            else:
                result = f"Permissions or ownership for {check_dir} are incorrect"
        results.append(f"##### Check perms for {check_dir}: {result}\n")

    perms_f = os.path.join(context.work_dir, constants.PERMISSIONS_F)
    crmutils.str2file(''.join(results), perms_f)


def dump_configurations(workdir: str) -> None:
    config_list = constants.CONFIGURATIONS
    config_list.append(corosync.conf())

    for conf in config_list:
        if os.path.isfile(conf):
            shutil.copy2(conf, workdir)
        elif os.path.isdir(conf):
            shutil.copytree(conf, os.path.join(workdir, os.path.basename(conf)))


def find_binary_path_for_core(core_file: str) -> str:
    """
    Find the binary that generated the given core file
    """
    path_str = ""
    cmd = f"gdb --batch cat {core_file}"
    _, out, _ = ShellUtils().get_stdout_stderr(cmd)
    if out:
        res = re.search("Core was generated by `(.*)'", out, re.M)
        path_str = res.group(1) if res else ""

    if path_str:
        return f"Core {core_file} was generated by {path_str}"
    else:
        return f"Cannot find the program path for core {core_file}"


def dump_core_info(workdir: str, core_file_list: List[str]) -> None:
    """
    Dump coredump files information into file
    """
    out_string = ""
    if shutil.which("gdb"):
        for core_file in core_file_list:
            out_string += find_binary_path_for_core(core_file) + "\n"
        out_string += "\nPlease utilize the gdb and debuginfo packages to obtain more detailed information locally"
    else:
        msg = "Please install gdb to get more info for coredump files"
        out_string += msg
        logger.warning(msg)

    core_f = os.path.join(workdir, constants.COREDUMP_F)
    crmutils.str2file(out_string, core_f)
    logger.debug(f"Dump coredump info into {utils.real_path(core_f)}")


def collect_coredump_info(context: core.Context) -> None:
    """
    Collects coredump files information from the library path of Pacemaker and Corosync
    """
    cores = utils.find_files_in_timespan(context, context.cores_dir_list)
    flist = [f for f in cores if "core" in os.path.basename(f)]
    if flist:
        logger.warning(f"Found coredump file: {flist}")
        dump_core_info(context.work_dir, flist)


def dump_runtime_state(workdir: str) -> None:
    """
    Dump runtime state files
    """
    cluster_shell_inst = sh.cluster_shell()

    # Dump the output of 'crm_mon' command with multiple options
    out = ""
    for option, desc in [
        ("-r1", "inactive resources"),
        ("-n1", "resources grouped by node"),
        ("-rf1", "resource fail counts"),
        ("-rnt1", "resource operation history with timing details"),
        ("--output-as=xml", "XML format")
    ]:
        cmd = f"crm_mon {option}"
        out += f"\n#### Display cluster state with {desc}: {cmd} ####\n"
        out += cluster_shell_inst.get_stdout_or_raise_error(cmd)
        out += "\n\n"

    target_f = os.path.join(workdir, constants.CRM_MON_F)
    crmutils.str2file(out, target_f)
    logger.debug(f"Dump crm_mon state into {utils.real_path(target_f)}")

    # Dump other runtime state files
    for cmd, f, desc in [
        ("cibadmin -Q", constants.CIB_F, "CIB contents"),
        ("crm_node -p", constants.MEMBERSHIP_F, "members of this partition")
    ]:
        out = cluster_shell_inst.get_stdout_or_raise_error(cmd)
        target_f = os.path.join(workdir, f)
        crmutils.str2file(out, target_f)
        logger.debug(f"Dump {desc} into {utils.real_path(target_f)}")

    node = crmutils.get_dc()
    if node and node == crmutils.this_node():
        crmutils.str2file("", os.path.join(workdir, "DC"))
        logger.debug(f"Current DC is {node}; Touch file 'DC' in {utils.real_path(workdir)}")


def consume_cib_in_workdir(workdir: str) -> None:
    """
    Generate 'crm configure show' and 'crm_verify' outputs based on the cib.xml file in the work directory
    """
    cib_in_workdir = os.path.join(workdir, constants.CIB_F)
    if os.path.isfile(cib_in_workdir):
        cluster_shell_inst = sh.cluster_shell()
        cmd = f"CIB_file={cib_in_workdir} crm configure show"
        out = cluster_shell_inst.get_stdout_or_raise_error(cmd)
        crmutils.str2file(out, os.path.join(workdir, constants.CONFIGURE_SHOW_F))

        cmd = f"crm_verify -V -x {cib_in_workdir}"
        _, _, err = cluster_shell_inst.get_rc_stdout_stderr_without_input(None, cmd)
        if err:
            crmutils.str2file(err, os.path.join(workdir, constants.CRM_VERIFY_F))


def collect_config(context: core.Context) -> None:
    """
    """
    workdir = context.work_dir

    if ServiceManager().service_is_active("pacemaker.service"):
        dump_runtime_state(workdir)
        crmutils.str2file("", os.path.join(workdir, "RUNNING"))
        logger.debug(f"Touch file 'RUNNING' in {utils.real_path(workdir)}")
    else:
        # TODO should determine offline node was ha node
        if not os.path.isfile(os.path.join(context.cib_dir, constants.CIB_F)):
            logger.warning(f"Cannot find cib.xml in {context.cib_dir}")
            return
        shutil.copy2(os.path.join(context.cib_dir, constants.CIB_F), workdir)
        crmutils.str2file("", os.path.join(workdir, "STOPPED"))
        logger.debug(f"Touch file 'STOPPED' in {utils.real_path(workdir)}")

    consume_cib_in_workdir(workdir)
    dump_configurations(workdir)


def pe_to_dot(pe_file: str) -> None:
    dotf = os.path.splitext(pe_file)[0] + '.dot'
    cmd = f"{constants.PTEST} -D {dotf} -x {pe_file}"
    code, _, _ = ShellUtils().get_stdout_stderr(cmd)
    if code != 0:
        logger.warning("pe_to_dot: %s -> %s failed", pe_file, dotf)


def collect_pe_inputs(context: core.Context) -> None:
    """
    Collects PE files in the specified directory and generates DOT files if needed
    """
    logger.debug2(f"Looking for PE files in {context.pe_dir}")

    _list = utils.find_files_in_timespan(context, [context.pe_dir])
    pe_file_list = [f for f in _list if not f.endswith(".last")]
    if pe_file_list:
        pe_flist_dir = os.path.join(context.work_dir, os.path.basename(context.pe_dir))
        crmutils.mkdirp(pe_flist_dir)

        gen_dot = len(pe_file_list) <= 20 and not context.speed_up
        for f in pe_file_list:
            pe_file_path_in_report = os.path.join(pe_flist_dir, os.path.basename(f))
            os.symlink(f, pe_file_path_in_report)
            if gen_dot:
                pe_to_dot(pe_file_path_in_report)
        logger.debug2(f"Found {len(pe_file_list)} PE files in {context.pe_dir}")
        dump_path = f"{context.work_dir}/{os.path.basename(context.pe_dir)}"
        logger.debug(f"Dump PE files into {utils.real_path(dump_path)}")
    else:
        logger.debug2("No PE file found for the giving time")


def collect_sbd_info(context: core.Context) -> None:
    """
    Collect SBD config file and information
    """
    if not os.path.exists(constants.SBDCONF):
        logger.debug(f"SBD config file {constants.SBDCONF} does not exist")
        return
    shutil.copy2(constants.SBDCONF, context.work_dir)
    if not shutil.which("sbd"):
        return

    sbd_f = os.path.join(context.work_dir, constants.SBD_F)
    cmd_list = [
        f". {constants.SBDCONF};export SBD_DEVICE;sbd dump;sbd list",
        "crm sbd configure show",
        "crm sbd status"
    ]
    with open(sbd_f, "w") as f:
        for cmd in cmd_list:
            f.write("\n\n#=====[ Command ] ==========================#\n")
            f.write(f"# {cmd}\n")
            f.write(utils.get_cmd_output(cmd))

    logger.debug(f"Dump SBD config file into {utils.real_path(sbd_f)}")


def collect_sys_stats(context: core.Context) -> None:
    """
    Collect system statistics
    """
    cmd_list = [
        "hostname", "uptime", "ps axf", "ps auxw", "top -b -n 1",
        "ip addr", "ip -s link", "ip n show", "lsscsi", "lspci",
        "mount", "cat /proc/cpuinfo", "df"
    ]

    out_string = ""
    for cmd in cmd_list:
        out_string += f"##### Run \"{cmd}\" #####\n"
        try:
            out_string += utils.get_cmd_output(cmd, timeout=5) + "\n"
        except TimeoutExpired:
            logger.warning(f"Timeout while running command: {cmd}")

    _file = os.path.join(context.work_dir, constants.SYSSTATS_F)
    crmutils.str2file(out_string, _file)
    logger.debug(f"Dump system statistics into {utils.real_path(_file)}")


def collect_sys_info(context: core.Context) -> None:
    """
    Collect the versions of cluster-related packages and platform information
    """
    pkg_inst = utils.Package(' '.join(constants.PACKAGE_LIST))
    version_info = pkg_inst.version()
    packages_info = "##### Installed cluster related packages #####\n"
    packages_info += version_info + '\n\n'
    if not context.speed_up:
        packages_info += "##### Verification output of packages #####\n"
        packages_info += pkg_inst.verify()

    platform, _, release, _, arch = os.uname()
    sys_info = (
            f"##### System info #####\n"
            f"Platform: {platform}\n"
            f"Kernel release: {release}\n"
            f"Architecture: {arch}\n"
            )
    if platform == "Linux":
        sys_info += f"Distribution: {utils.get_distro_info()}\n"
    out_string = f"{sys_info}\n{packages_info}"

    _file = os.path.join(context.work_dir, constants.SYSINFO_F)
    crmutils.str2file(out_string, _file)
    logger.debug(f"Dump packages and platform info into {utils.real_path(_file)}")


def collect_qdevice_info(context: core.Context) -> None:
    """
    Collect quorum/qdevice/qnetd information
    """
    service_manager = ServiceManager()
    if not service_manager.service_is_active("corosync.service"):
        return
    out_string = "##### Quorum status #####\n"
    out_string += corosync.query_quorum_status() + "\n"

    if service_manager.service_is_active("corosync-qdevice.service"):
        out_string += "\n##### Qdevice status #####\n"
        out_string += corosync.query_qdevice_status() + "\n"
        out_string += "\n##### Qnetd status #####\n"
        out_string += corosync.query_qnetd_status() + "\n"

    _file = os.path.join(context.work_dir, constants.QDEVICE_F)
    crmutils.str2file(out_string, _file)
    logger.debug(f"Dump quorum/qdevice/qnetd information into {utils.real_path(_file)}")
