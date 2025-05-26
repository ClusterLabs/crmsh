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

from crmsh import log
from crmsh import utils as crmutils
from crmsh.report import constants, utillib


logger = log.setup_report_logger(__name__)


def collect_ocfs2_info():
    ocfs2_f = os.path.join(constants.WORKDIR, constants.OCFS2_F)
    with open(ocfs2_f, "w") as f:
        rc, out, err = crmutils.get_stdout_stderr("mounted.ocfs2 -d")
        if rc != 0:
            f.write("Failed to run \"mounted.ocfs2 -d\": {}".format(err))
            return
        # No ocfs2 device, just header line printed
        elif len(out.split('\n')) == 1:
            f.write("No ocfs2 partitions found")
            return

        f.write(utillib.dump_D_process())
        f.write(utillib.lsof_ocfs2_device())

        cmds = [ "dmesg",  "ps -efL",
                "lsblk -o 'NAME,KNAME,MAJ:MIN,FSTYPE,LABEL,RO,RM,MODEL,SIZE,OWNER,GROUP,MODE,ALIGNMENT,MIN-IO,OPT-IO,PHY-SEC,LOG-SEC,ROTA,SCHED,MOUNTPOINT'",
                "mounted.ocfs2 -f", "findmnt", "mount",
                "cat /sys/fs/ocfs2/cluster_stack"
                ]
        for cmd in cmds:
            cmd_name = cmd.split()[0]
            if not utillib.which(cmd_name) or \
               cmd_name == "cat" and not os.path.exists(cmd.split()[1]):
                continue
            _, out = crmutils.get_stdout(cmd)
            f.write("\n\n#=====[ Command ] ==========================#\n")
            f.write("# %s\n"%(cmd))
            f.write(out)


def collect_ratraces():
    """
    Collect ra trace file from default /var/lib/heartbeat/trace_ra and custom one
    """
    # since the "trace_dir" attribute been removed from cib after untrace
    # need to parse crmsh log file to extract custom trace ra log directory on each node
    log_contents = ""
    cmd = "grep 'INFO: Trace for .* is written to ' {}*|grep -v 'collect'".format(log.CRMSH_LOG_FILE)

    if utillib.local_mode():
        log_contents = crmutils.get_stdout_or_raise_error(cmd, no_raise=True) + "\n"
    else:
        for node in crmutils.list_cluster_nodes():
            log_contents += crmutils.get_stdout_or_raise_error(cmd, remote=node, no_raise=True) + "\n"

    trace_dir_str = ' '.join(list(set(re.findall("written to (.*)/.*", log_contents))))
    if not trace_dir_str:
        return

    logger.debug("Looking for RA trace files in \"%s\"", trace_dir_str)
    for f in utillib.find_files(trace_dir_str, constants.FROM_TIME, constants.TO_TIME):
        dest_dir = os.path.join(constants.WORKDIR, '/'.join(f.split('/')[-3:-1]))
        crmutils.mkdirp(dest_dir)
        shutil.copy2(f, dest_dir)


def collect_corosync_blackbox():
    fdata_list = []
    for f in utillib.find_files("/var/lib/corosync", constants.FROM_TIME, constants.TO_TIME):
        if re.search("fdata", f):
            fdata_list.append(f)
    if fdata_list:
        blackbox_f = os.path.join(constants.WORKDIR, constants.COROSYNC_RECORDER_F)
        crmutils.str2file(utillib.get_command_info("corosync-blackbox")[1], blackbox_f)


def collect_time_status():
    out_string = "Time: "
    out_string += datetime.datetime.now().strftime('%c') + '\n'
    out_string += "ntpdc: "
    out_string += utillib.get_command_info("ntpdc -pn")[1] + '\n'

    time_f = os.path.join(constants.WORKDIR, constants.TIME_F)
    crmutils.str2file(out_string, time_f)


def collect_dlm_info():
    """
    get dlm info
    """
    if utillib.which("dlm_tool"):
        out_string = "##### NOTICE - Lockspace overview:\n"
        out_string += utillib.get_command_info("dlm_tool ls")[1] + '\n'
        for item in utillib.grep("^name", incmd="dlm_tool ls"):
            lock_name = item.split()[1]
            out_string += "## NOTICE - Lockspace {}\n".format(lock_name)
            out_string += utillib.get_command_info("dlm_tool lockdebug {}".format(lock_name))[1] + '\n'
        out_string += "##### NOTICE - Lockspace history:\n"
        out_string += utillib.get_command_info("dlm_tool dump")[1] + '\n'

        dlm_f = os.path.join(constants.WORKDIR, constants.DLM_DUMP_F)
        crmutils.str2file(out_string, dlm_f)


def collect_perms_state():
    out_string = ""

    for check_dir in [constants.PCMK_LIB, constants.PE_STATE_DIR, constants.CIB_DIR]:
        flag = 0
        out_string += "##### Check perms for %s: " % check_dir
        stat_info = os.stat(check_dir)
        if not stat.S_ISDIR(stat_info.st_mode):
            flag = 1
            out_string += "\n%s wrong type or doesn't exist\n" % check_dir
            continue
        if stat_info.st_uid != pwd.getpwnam('hacluster')[2] or\
           stat_info.st_gid != pwd.getpwnam('hacluster')[3] or\
           "%04o" % (stat_info.st_mode & 0o7777) != "0750":
            flag = 1
            out_string += "\nwrong permissions or ownership for %s: " % check_dir
            out_string += utillib.get_command_info("ls -ld %s" % check_dir)[1] + '\n'
        if flag == 0:
            out_string += "OK\n"

    perms_f = os.path.join(constants.WORKDIR, constants.PERMISSIONS_F)
    crmutils.str2file(out_string, perms_f)


def collect_configurations():
    workdir = constants.WORKDIR
    for conf in constants.CONFIGURATIONS:
        if os.path.isfile(conf):
            shutil.copy2(conf, workdir)
        elif os.path.isdir(conf):
            shutil.copytree(conf, os.path.join(workdir, os.path.basename(conf)))


def collect_backtraces():
    """
    Check CORES_DIRS for core dumps within the report timeframe and
    use gdb to get the backtraces
    """
    cores = utillib.find_files(constants.CORES_DIRS, constants.FROM_TIME, constants.TO_TIME)
    flist = [f for f in cores if "core" in os.path.basename(f)]
    if flist:
        utillib.print_core_backtraces(flist)
        logger.debug("found backtraces: %s", ' '.join(flist))


def collect_config():
    workdir = constants.WORKDIR
    if os.path.isfile(constants.CONF):
        shutil.copy2(constants.CONF, workdir)
    if crmutils.is_process("pacemaker-controld") or crmutils.is_process("crmd"):
        utillib.dump_state(workdir)
        open(os.path.join(workdir, "RUNNING"), 'w')
    else:
        shutil.copy2(os.path.join(constants.CIB_DIR, constants.CIB_F), workdir)
        open(os.path.join(workdir, "STOPPED"), 'w')
    if os.path.isfile(os.path.join(workdir, constants.CIB_F)):
        cmd = "crm_verify -V -x %s" % os.path.join(workdir, constants.CIB_F)
        crmutils.str2file(utillib.get_command_info(cmd)[1], os.path.join(workdir, constants.CRM_VERIFY_F))
        cmd = r"CIB_file=%s/%s crm configure show" % (workdir, constants.CIB_F)
        crmutils.str2file(utillib.get_command_info(cmd)[1], os.path.join(workdir, constants.CIB_TXT_F))


def collect_dc_file():
    if constants.SKIP_LVL:
        return
    node = crmutils.get_dc()
    if node and node == constants.WE:
        open(os.path.join(constants.WORKDIR, "DC"), 'w')


def collect_pe_inputs():
    from_time = constants.FROM_TIME
    to_time = constants.TO_TIME
    work_dir = constants.WORKDIR
    pe_dir = constants.PE_STATE_DIR
    logger.debug("looking for PE files in %s in %s", pe_dir, constants.WE)

    flist = []
    for f in utillib.find_files(pe_dir, from_time, to_time):
        if re.search("[.]last$", f):
            continue
        flist.append(f)

    if flist:
        flist_dir = os.path.join(work_dir, os.path.basename(pe_dir))
        utillib._mkdir(flist_dir)
        for f in flist:
            os.symlink(f, os.path.join(flist_dir, os.path.basename(f)))
        logger.debug("found %d pengine input files in %s", len(flist), pe_dir)

        if len(flist) <= 20:
            if not constants.SKIP_LVL:
                for f in flist:
                    utillib.pe_to_dot(os.path.join(flist_dir, os.path.basename(f)))
        else:
            logger.debug("too many PE inputs to create dot files")
    else:
        logger.debug("Nothing found for the giving time")


def collect_sbd_info():
    """
    save sbd configuration file
    """
    if os.path.exists(constants.SBDCONF):
        shutil.copy2(constants.SBDCONF, constants.WORKDIR)

    if not utillib.which("sbd"):
        return
    sbd_f = os.path.join(constants.WORKDIR, constants.SBD_F)
    cmd = ". {};export SBD_DEVICE;{};{}".format(constants.SBDCONF, "sbd dump", "sbd list")
    with open(sbd_f, "w") as f:
        _, out = crmutils.get_stdout(cmd)
        f.write("\n\n#=====[ Command ] ==========================#\n")
        f.write("# %s\n"%(cmd))
        f.write(out)


def collect_sys_stats():
    out_string = ""
    cmd_list = ["hostname", "uptime", "ps axf", "ps auxw", "top -b -n 1",
                "ip addr", "ip -s link", "ip n show", "lsscsi", "lspci",
                "mount", "cat /proc/cpuinfo", "df"]
    for cmd in cmd_list:
        out_string += "##### run \"%s\" on %s\n" % (cmd, constants.WE)
        if cmd != "df":
            out_string += utillib.get_command_info(cmd)[1] + '\n'
        else:
            out_string += utillib.get_command_info_timeout(cmd) + '\n'

    sys_stats_f = os.path.join(constants.WORKDIR, constants.SYSSTATS_F)
    crmutils.str2file(out_string, sys_stats_f)


def collect_sys_info():
    """
    some basic system info and stats
    """
    out_string = "#####Cluster info:\n"
    out_string += utillib.cluster_info()
    out_string += utillib.ra_build_info()
    out_string += utillib.booth_info()
    out_string += "\n"
    out_string += "#####Cluster related packages:\n"
    out_string += utillib.pkg_versions(constants.PACKAGES)
    if not constants.SKIP_LVL:
        out_string += utillib.verify_packages(constants.PACKAGES)
    out_string += "\n"
    out_string += "#####System info:\n"
    out_string += "Platform: %s\n" % os.uname()[0]
    out_string += "Kernel release: %s\n" % os.uname()[2]
    out_string += "Architecture: %s\n" % os.uname()[-1]
    if os.uname()[0] == "Linux":
        out_string += "Distribution: %s\n" % utillib.get_distro_info()

    sys_info_f = os.path.join(constants.WORKDIR, constants.SYSINFO_F)
    crmutils.str2file(out_string, sys_info_f)
