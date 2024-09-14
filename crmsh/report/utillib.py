# Copyright (C) 2017 Xin Liang <XLiang@suse.com>
# See COPYING for license information.

import bz2
import lzma
import datetime
import glob
import gzip
import multiprocessing
import os
import random
import re
import shutil
import string
import subprocess
import sys
import atexit
import tempfile
import contextlib
from dateutil import tz
from threading import Timer
from inspect import getmembers, isfunction

import crmsh.config
from crmsh import utils as crmutils
from crmsh import corosync, log, userdir
from crmsh.report import constants, collect


logger = log.setup_report_logger(__name__)


class Tempfile(object):

    def __init__(self):
        self.file = create_tempfile()
        logger.debug("create tempfile \"%s\"", self.file)

    def add(self, filename):
        with open(self.file, 'a') as f:
            f.write(filename + '\n')
        logger.debug("add tempfile \"%s\" to \"%s\"", filename, self.file)

    def drop(self):
        with open(self.file, 'r') as f:
            for line in f.read().split('\n'):
                if os.path.isdir(line):
                    shutil.rmtree(line)
                if os.path.isfile(line):
                    os.remove(line)
        os.remove(self.file)
        logger.debug("remove tempfile \"%s\"", self.file)


def add_tempfiles(filename):
    t = Tempfile()
    t.add(filename)
    atexit.register(t.drop)


def _mkdir(directory):
    """
    from crmsh/tmpfiles.py
    """
    if not os.path.isdir(directory):
        try:
            os.makedirs(directory)
        except OSError as err:
            log_fatal("Failed to create directory: %s" % (err))


def arch_logs(logf, from_time, to_time):
    """
    go through archived logs (timewise backwards) and see if there
    are lines belonging to us
    (we rely on untouched log files, i.e. that modify time
    hasn't been changed)
    """
    ret = []
    files = [logf]
    files += glob.glob(logf+"*[0-9z]")
    # like ls -t, newest first
    for f in sorted(files, key=os.path.getmtime, reverse=True):
        # reset this var to check every file's format
        constants.GET_STAMP_FUNC = None
        res = is_our_log(f, from_time, to_time)
        if res == 0: # noop, continue
            continue
        elif res == 1: # include log and continue
            ret.append(f)
            logger.debug("found log %s", f)
        elif res == 2: # don't go through older logs!
            break
        elif res == 3: # include log and continue
            ret.append(f)
            logger.debug("found log %s", f)
            break
    return ret


def analyze():
    workdir = constants.WORKDIR
    out_string = ""
    tmp_string = ""
    flist = [constants.MEMBERSHIP_F, constants.CRM_MON_F,
             constants.B_CONF, constants.SYSINFO_F, constants.CIB_F]
    for f in flist:
        out_string += "Diff %s... " % f
        if not glob.glob("%s/*/%s" % (workdir, f)):
            out_string += "no %s/*/%s :/\n" % (workdir, f)
            continue
        code, tmp_string = analyze_one(workdir, f)
        if tmp_string:
            out_string += "\n" + tmp_string + "\n\n"
        else:
            out_string += "OK\n"
        if code == 0:
            if f != constants.CIB_F:
                consolidate(workdir, f)

    out_string += "\n"

    out_string += check_crmvfy(workdir)
    out_string += check_backtraces(workdir)
    out_string += check_permissions(workdir)
    out_string += check_logs(workdir)

    analyze_f = os.path.join(workdir, constants.ANALYSIS_F)
    crmutils.str2file(out_string, analyze_f)


def analyze_one(workdir, file_):
    out_string = ""
    tmp_string = ""
    tmp_rc = 0
    node0 = ""
    rc = 0
    for n in constants.NODES.split():
        if node0:
            tmp_rc, tmp_string = diff_check(os.path.join(workdir, node0, file_), os.path.join(workdir, n, file_))
            out_string += tmp_string
            rc += tmp_rc
        else:
            node0 = n
    return (rc, out_string)


def base_check():
    if not which("which"):
        log_fatal("please install the which(1) program")
    if not os.path.exists(constants.BIN_CRM):
        if os.path.exists("/usr/bin/crm"):
            constants.BIN_CRM = "/usr/bin/crm"
        else:
            log_fatal("Cannot find crm command!")


def booth_info():
    if not which("booth"):
        return ""
    return get_command_info("booth --version")[1]


def check_backtraces(workdir):
    out_string = ""
    pattern = "Core was generated|Program terminated"
    for n in constants.NODES.split():
        bt_f = os.path.join(workdir, n, constants.BT_F)
        if os.path.isfile(bt_f) and os.stat(bt_f).st_size != 0:
            out_string += "WARN: coredumps found at %s:\n" % n
            for line in grep(pattern, infile=bt_f):
                out_string += "    %s\n" % line
    return out_string


def check_crmvfy(workdir):
    """
    some basic analysis of the report
    """
    out_string = ""
    for n in constants.NODES.split():
        crm_verify_f = os.path.join(workdir, n, constants.CRM_VERIFY_F)
        if os.path.isfile(crm_verify_f) and os.stat(crm_verify_f).st_size != 0:
            out_string += "WARN: crm_verify reported warnings at %s:\n" % n
            out_string += open(crm_verify_f).read()
    return out_string


def check_env():
    set_env()
    base_check()
    get_ocf_dir()
    load_ocf_dirs()


def check_if_log_is_empty():
    for f in find_files_all(constants.HALOG_F, constants.WORKDIR):
        if os.stat(f).st_size == 0:
            logger.warning("Report contains no logs; did you get the right timeframe?")


def check_logs(workdir):
    out_string = ""
    log_list = []
    for l in constants.EXTRA_LOGS.split():
        log_list += find_files_all(os.path.basename(l), workdir)
    if not log_list:
        return out_string

    out_string += "\nLog patterns:\n"
    log_patterns = constants.LOG_PATTERNS.replace(' ', '|')
    for n in constants.NODES.split():
        for f in log_list:
            out_string += '\n'.join(grep(log_patterns, infile=f))
    return out_string


def check_permissions(workdir):
    out_string = ""
    for n in constants.NODES.split():
        permissions_f = os.path.join(workdir, n, constants.PERMISSIONS_F)
        if os.path.isfile(permissions_f) and os.stat(permissions_f).st_size != 0:
            out_string += "Checking problems with permissions/ownership at %s:\n" % n
            out_string += open(permissions_f).read()
    return out_string


def check_time(var, option):
    if not var:
        log_fatal("""bad time specification: %s
                        try these like: 2pm
                                        1:00
                                        "2007/9/5 12:30"
                                        "09-Sep-07 2:00"
                  """ % option)


def cib_diff(file1, file2):
    """
    check if files have same content in the cluster
    """
    code = 0
    out_string = ""
    tmp_string = ""
    d1 = os.path.dirname(file1)
    d2 = os.path.dirname(file2)
    if (os.path.isfile(os.path.join(d1, "RUNNING")) and
        os.path.isfile(os.path.join(d2, "RUNNING"))) or \
        (os.path.isfile(os.path.join(d1, "STOPPED")) and
         os.path.isfile(os.path.join(d2, "STOPPED"))):
        if which("crm_diff"):
            code, tmp_string = get_command_info("crm_diff -c -n %s -o %s" % (file1, file2))
            out_string += tmp_string
        else:
            code = 1
            logger.warning("crm_diff(8) not found, cannot diff CIBs")
    else:
        code = 1
        out_string += "can't compare cibs from running and stopped systems\n"
    return code, out_string


def cluster_info():
    return get_command_info("corosync -v")[1]


def generate_collect_functions():
    """
    Generate function list from collect.py
    """
    return [func for func, _ in getmembers(collect, isfunction) if func.startswith("collect_")]


def collect_info():
    """
    get all other info (config, stats, etc)
    """
    collect_func_list = generate_collect_functions()
    # Make sure not to occupy all CPUs
    pool = multiprocessing.Pool(round(0.8 * multiprocessing.cpu_count()))
    # result here to store AsyncResult object returned from apply_async
    # Then calling get() method will catch exceptions like NameError, AttributeError, etc.
    # Otherwise parent process will not know these exceptions raised
    # Calling get() right after apply_async will be blocked until child process finished, so
    # need to append to a list firstly
    result_list = []
    for cf in collect_func_list:
        result = pool.apply_async(getattr(collect, cf))
        result_list.append(result)
    pool.close()
    pool.join()

    for result in result_list:
        try:
            result.get()
        except Exception as err:
            logger.error(str(err))

    logfile_list = []
    corosync_log = corosync.get_value('logging.logfile')
    if corosync_log:
        logfile_list.append(corosync_log)
    logfile_list += constants.EXTRA_LOGS.split()

    for l in logfile_list:
        if not os.path.isfile(l):
            continue
        if l == constants.HA_LOG and l != constants.HALOG_F:
            os.symlink(constants.HALOG_F, os.path.join(constants.WORKDIR, os.path.basename(l)))
            continue
        if is_our_log(l, constants.FROM_TIME, constants.TO_TIME) == 4:
            logger.debug("found irregular log file %s", l)
            outf = os.path.join(constants.WORKDIR, os.path.basename(l))
            shutil.copy2(l, constants.WORKDIR)
            log_size(l, outf+'.info')
            continue
        getstampproc = find_getstampproc(l)
        if getstampproc:
            constants.GET_STAMP_FUNC = getstampproc
            outf = os.path.join(constants.WORKDIR, os.path.basename(l))
            if dump_logset(l, constants.FROM_TIME, constants.TO_TIME, outf):
                log_size(l, outf+'.info')
        else:
            logger.debug("could not figure out the log format of %s", l)


def collect_journal(from_t, to_t, outf):
    if not which("journalctl"):
        logger.warning("Command journalctl not found")
        return

    if crmutils.is_int(from_t) and from_t == 0:
        from_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    elif crmutils.is_int(from_t):
        from_time = ts_to_dt(from_t).strftime("%Y-%m-%d %H:%M")
    if crmutils.is_int(to_t) and to_t == 0:
        to_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    elif crmutils.is_int(to_t):
        to_time = ts_to_dt(to_t).strftime("%Y-%m-%d %H:%M")
    if os.path.isfile(outf):
        logger.warning("%s already exists", outf)

    logger.debug("journalctl from: '%d' until: '%d' from_time: '%s' to_time: '%s' > %s",
              from_t, to_t, from_time, to_time, outf)
    cmd = 'journalctl -o short-iso-precise --since "%s" --until "%s" --no-pager | tail -n +2' % \
          (from_time, to_time)
    crmutils.str2file(get_command_info(cmd)[1], outf)


def compatibility_pcmk():
    get_crm_daemon_dir()
    if not constants.CRM_DAEMON_DIR:
        log_fatal("cannot find pacemaker daemon directory!")
    get_pe_state_dir()
    if not constants.PE_STATE_DIR:
        log_fatal("cannot find pe daemon directory!")
    get_cib_dir()
    if not constants.CIB_DIR:
        log_fatal("cannot find cib daemon directory!")

    constants.PCMK_LIB = os.path.dirname(constants.CIB_DIR)
    logger.debug("setting PCMK_LIB to %s", constants.PCMK_LIB)
    constants.CORES_DIRS = os.path.join(constants.PCMK_LIB, "cores")
    constants.CONF = "/etc/corosync/corosync.conf"
    if os.path.isfile(constants.CONF):
        constants.CORES_DIRS += " /var/lib/corosync"
    constants.B_CONF = os.path.basename(constants.CONF)


def consolidate(workdir, f):
    """
    remove duplicates if files are same, make links instead
    """
    for n in constants.NODES.split():
        if os.path.isfile(os.path.join(workdir, f)):
            os.remove(os.path.join(workdir, n, f))
        else:
            shutil.move(os.path.join(workdir, n, f), workdir)
        os.symlink("../%s" % f, os.path.join(workdir, n, f))


def create_tempfile(time=None):
    random_str = random_string(4)
    try:
        filename = tempfile.mkstemp(suffix=random_str, prefix="tmp.")[1]
    except:
        log_fatal("Can't create file %s" % filename)
    if time:
        os.utime(filename, (time, time))
    return filename


def date():
    return datetime.datetime.now().strftime("%a %b %-d %H:%M:%S CST %Y")


def diff_check(file1, file2):
    out_string = ""
    for f in [file1, file2]:
        if not os.path.isfile(f):
            out_string += "%s does not exist\n" % f
            return (1, out_string)
    if os.path.basename(file1) == constants.CIB_F:
        return cib_diff(file1, file2)
    else:
        return (0, txt_diff(file1, file2))


def get_distro_info():
    """
    get distribution information
    """
    res = None
    if os.path.exists(constants.OSRELEASE):
        logger.debug("Using {} to get distribution info".format(constants.OSRELEASE))
        res = re.search("PRETTY_NAME=\"(.*)\"", read_from_file(constants.OSRELEASE))
    elif which("lsb_release"):
        logger.debug("Using lsb_release to get distribution info")
        out = crmutils.get_stdout_or_raise_error("lsb_release -d")
        res = re.search("Description:\s+(.*)", out)
    return res.group(1) if res else "Unknown"


def dump_log(logf, from_line, to_line):
    if not from_line:
        return
    return filter_lines(logf, from_line, to_line)


def dump_logset(logf, from_time, to_time, outf):
    """
    find log/set of logs which are interesting for us
    """
    if os.stat(logf).st_size == 0:
        return False
    logf_set = arch_logs(logf, from_time, to_time)
    if not logf_set:
        return False
    num_logs = len(logf_set)
    oldest = logf_set[-1]
    newest = logf_set[0]
    mid_logfiles = logf_set[1:-1]
    out_string = ""

    # the first logfile: from $from_time to $to_time (or end)
    # logfiles in the middle: all
    # the last logfile: from beginning to $to_time (or end)
    if num_logs == 1:
        out_string += print_logseg(newest, from_time, to_time)
    else:
        out_string += print_logseg(oldest, from_time, 0)
        for f in mid_logfiles:
            out_string += print_logseg(f, 0, 0)
            logger.debug("including complete %s logfile", f)
        out_string += print_logseg(newest, 0, to_time)

    crmutils.str2file(out_string, outf)
    return True


def dump_state(workdir):
    res = grep("^Last upd", incmd="crm_mon -1", flag="v")
    crmutils.str2file('\n'.join(res), os.path.join(workdir, constants.CRM_MON_F))
    cmd = "cibadmin -Ql"
    crmutils.str2file(get_command_info(cmd)[1], os.path.join(workdir, constants.CIB_F))
    cmd = "crm_node -p"
    crmutils.str2file(get_command_info(cmd)[1], os.path.join(workdir, constants.MEMBERSHIP_F))


def events(destdir):
    events_f = os.path.join(destdir, "events.txt")
    out_string = ""
    pattern = '|'.join(constants.EVENT_PATTERNS.split()[1::2])
    halog_f = os.path.join(destdir, constants.HALOG_F)
    if os.path.isfile(halog_f):
        out_string = '\n'.join(grep(pattern, infile=halog_f))
        crmutils.str2file(out_string, events_f)
        for n in constants.NODES.split():
            if os.path.isdir(os.path.join(destdir, n)):
                events_node_f = os.path.join(destdir, n, "events.txt")
                out_string = '\n'.join(grep(" %s " % n, infile=events_f))
                crmutils.str2file(out_string, events_node_f)
    else:
        for n in constants.NODES.split():
            halog_f = os.path.join(destdir, n, constants.HALOG_F)
            if not os.path.isfile(halog_f):
                continue
            out_string = '\n'.join(grep(pattern, infile=halog_f))
            crmutils.str2file(out_string, os.path.join(destdir, n, "events.text"))


def find_decompressor(log_file):
    decompressor = "cat"
    if re.search("bz2$", log_file):
        decompressor = "bzip2 -dc"
    elif re.search("gz$", log_file):
        decompressor = "gzip -dc"
    elif re.search("xz$", log_file):
        decompressor = "xz -dc"
    return decompressor


def find_files(dirs, from_time, to_time):
    res = []

    if (not crmutils.is_int(from_time)) or (from_time <= 0):
        logger.warning("sorry, can't find files based on time if you don't supply time")
        return

    file_with_stamp = create_tempfile(from_time)
    findexp = "-newer %s" % file_with_stamp

    if crmutils.is_int(to_time) and to_time > 0:
        file_with_stamp = create_tempfile(to_time)
        findexp += " ! -newer %s" % file_with_stamp

    cmd = r"find %s -type f %s" % (dirs, findexp)
    cmd_res = get_command_info(cmd)[1].strip()
    if cmd_res:
        res = cmd_res.split('\n')

    os.remove(file_with_stamp)
    return res


def find_files_all(name, path):
    result = []
    for root, dirs, files in os.walk(path):
        if name in files:
            result.append(os.path.join(root, name))
    return result


def find_first_ts(data):
    ts = None
    for line in data:
        ts = get_ts(line)
        if ts:
            break
    return ts


def filter_lines(data, from_line, to_line):
    out_string = ""
    count = 1
    for line in data.split('\n'):
        if count >= from_line and count <= to_line:
            out_string += line + '\n'
        if count > to_line:
            break
        count += 1
    return out_string


def finalword():
    if constants.COMPRESS == 1:
        logger.info("The report is saved in %s/%s.tar%s", constants.DESTDIR, constants.DEST, constants.COMPRESS_EXT)
    else:
        logger.info("The report is saved in %s/%s", constants.DESTDIR, constants.DEST)
    if constants.TO_TIME == 0:
        to_time = datetime.datetime.now().strftime("%x %X")
    else:
        to_time = ts_to_dt(constants.TO_TIME).strftime("%x %X")
    logger.info("Report timespan: %s - %s", ts_to_dt(constants.FROM_TIME).strftime("%x %X"), to_time)
    logger.info("Thank you for taking time to create this report.")


def find_getstampproc(log_file):
    func = None
    loop_cout = 10
    with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
        for line in f.readlines():
            if loop_cout == 0:
                break
            else:
                loop_cout -= 1
            with stdchannel_redirected(sys.stderr, os.devnull):
                func = find_getstampproc_raw(line.strip('\n'))
                if func:
                    break
    return func


def find_getstampproc_raw(line):
    func = None
    res = get_stamp_syslog(line)
    if res:
        func = "syslog"
        return func
    res = get_stamp_rfc5424(line)
    if res:
        func = "rfc5424"
        return func
    res = get_stamp_legacy(line)
    if res:
        func = "legacy"
        logger.debug("the log file is in the legacy format (please consider switching to syslog format)")
        return func
    return func


def find_log():
    """
    first try syslog files, if none found then use the
    logfile/debugfile settings
    """
    if constants.EXTRA_LOGS:
        for l in constants.EXTRA_LOGS.split():
            if os.path.isfile(l):
                return l

        tmp_f = os.path.join(constants.WORKDIR, constants.JOURNAL_F)
        if os.path.isfile(tmp_f):
            return tmp_f

        for l in constants.PCMK_LOG.split():
            if os.path.isfile(l):
                return l

    if constants.HA_DEBUGFILE:
        logger.debug("will try with %s", constants.HA_DEBUGFILE)
    return constants.HA_DEBUGFILE


def find_ssh_user():
    ssh_user = ""
    ssh_user_try_list = []
    if constants.SSH_USER:
        ssh_user_try_list.append(constants.SSH_USER)
    sudoer = userdir.get_sudoer()
    if sudoer:
        ssh_user_try_list.append(sudoer)
    current_user = userdir.getuser()
    ssh_user_try_list.append(current_user)

    for n in constants.NODES.split():
        if n == constants.WE:
            continue
        rc = False
        for u in ssh_user_try_list:
            ssh_s = f"{u}@{n}"
            if not crmutils.check_ssh_passwd_need(u, u, n):
                logger.debug("ssh %s OK", ssh_s)
                ssh_user = u
                rc = True
                break
            else:
                logger.debug("ssh %s failed", ssh_s)
        if not rc:
            constants.SSH_PASSWORD_NODES.append(n)

    if constants.SSH_PASSWORD_NODES:
        logger.warning("passwordless ssh to node(s) %s does not work", constants.SSH_PASSWORD_NODES)
    if ssh_user:
        constants.SUDO = "" if ssh_user in ["root", "hacluster"] else "sudo"
    constants.SSH_USER = ssh_user if ssh_user else ""


def findln_by_time(data, ts):
    '''
    Get line number of the specific time stamp
    '''
    data_list = data.split('\n')

    first= 1
    last= len(data_list)
    time_middle = None

    while first <= last:
        middle = (last + first) // 2
        trycnt = 10
        while trycnt > 0:
            res = line_time(data_list, middle)
            if res:
                time_middle = res
                break
            trycnt -= 1
            # shift the whole first-last segment
            prevmid = middle
            while prevmid == middle:
                first -= 1
                if first < 1:
                    first = 1
                last -= 1
                if last < first:
                    last = first
                prevmid = middle
                middle = (last + first) // 2
                if first == last:
                    break
        if not time_middle:
            return None
        if time_middle > ts:
            last = middle - 1
        elif time_middle < ts:
            first = middle + 1
        else:
            break
    return middle


def find_binary_for_core(corefile):
    """
    Given a core file, try to find the
    binary that generated it
    Returns a path or None
    """
    def findbin(fname):
        def isexec(filename):
            return os.path.isfile(filename) and os.access(filename, os.X_OK)
        bindirs = [constants.HA_BIN, constants.CRM_DAEMON_DIR]
        if which(fname):
            return fname
        else:
            for d in bindirs:
                if d is None:
                    continue
                testpath = os.path.join(d, fname)
                if isexec(testpath):
                    return testpath
        return None
    if which("cat"):
        random_binary = "cat"
    lines = [l for l in get_command_info_timeout(["gdb", random_binary, corefile]).splitlines() if "Core was generated by" in l]
    binname = None
    if len(lines) > 0:
        m = re.search(r"generated by .([^']+)", )
        if m:
            fname = m.group(1)
            binname = findbin(fname)
    if binname is not None:
        logger.debug("found the program at %s for core %s", testpath, corefile)
    else:
        logger.warning("Could not find the program path for core %s", corefile)
    return binname


def print_core_backtraces(flist):
    """
    Use gdb to get backtrace from core files.
    flist: names of core files to check
    """
    if not which("gdb"):
        logger.warning("Please install gdb to get backtraces")
        return
    for corefile in flist:
        absbinpath = find_binary_for_core(corefile)
        if absbinpath is None:
            continue
        get_debuginfo(absbinpath, corefile)
        bt_opts = os.environ.get("BT_OPTS", "thread apply all bt full")
        print("====================== start backtrace ======================")
        print(get_command_info_timeout(["ls", "-l", corefile]))
        print(get_command_info_timeout(["gdb", "-batch", "-n", "-quiet",
                                        "-ex", bt_opts, "-ex", "quit",
                                        absbinpath, corefile]))
        print("======================= end backtrace =======================")


def get_cib_dir():
    try:
        constants.CIB_DIR = crmsh.config.path.crm_config
    except:
        return
    if not os.path.isdir(constants.CIB_DIR):
        constants.CIB_DIR = None


def get_command_info(cmd):
    code, out, err = crmutils.get_stdout_stderr(cmd)
    if out:
        return (code, out + '\n')
    else:
        return (code, "")


def get_command_info_timeout(cmd, timeout=5):
    # Python 101: How to timeout a subprocess
    def kill(process):
        process.kill()
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=os.environ,  # bsc#1205925
    )
    my_timer = Timer(timeout, kill, [proc])
    try:
        my_timer.start()
        stdout, stderr = proc.communicate()
    finally:
        my_timer.cancel()

    if stdout and proc.returncode == 0:
        return crmutils.to_ascii(stdout)
    else:
        return ""


def get_conf_var(option, default=None):
    ret = default
    if os.path.isfile(constants.CONF):
        data = read_from_file(constants.CONF)
        for line in data.split('\n'):
            if re.match("^\s*%s\s*:" % option, line):
                ret = line.split(':')[1].lstrip()
    return ret


def get_crm_daemon_dir():
    try:
        constants.CRM_DAEMON_DIR = crmsh.config.path.crm_daemon_dir
    except:
        return
    if not os.path.isdir(constants.CRM_DAEMON_DIR) or \
       not any(is_exec(os.path.join(constants.CRM_DAEMON_DIR, cmd)) for cmd in ["crmd", "pacemaker-controld"]):
        constants.CRM_DAEMON_DIR = None


def get_dirname(path):
    tmp = os.path.dirname(path)
    if not tmp:
        tmp = "."
    return tmp


def get_local_ip():
    local_ip = []
    ip_pattern = "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
    for line in grep(ip_pattern, incmd="corosync-cfgtool -s"):
        local_ip.append(line.split()[2])
    return local_ip


def get_log_vars():
    if is_conf_set("debug"):
        constants.HA_LOGLEVEL = "debug"
    if is_conf_set("to_logfile"):
        constants.HA_LOGFILE = get_conf_var("logfile", default="syslog")
        constants.HA_DEBUGFILE = constants.HA_LOGFILE
    elif is_conf_set("to_syslog"):
        constants.HA_LOGFACILITY = get_conf_var("syslog_facility", default="daemon")

    logger.debug("log settings: facility=%s logfile=%s debugfile=%s",
              constants.HA_LOGFACILITY, constants.HA_LOGFILE, constants.HA_DEBUGFILE)


def get_nodes():
    """
    find nodes for this cluster
    """
    nodes = []
    # 1. set by user?
    if constants.USER_NODES:
        nodes = constants.USER_NODES.split()
    # 2. running crm
    elif crmutils.is_process("pacemaker-controld") or crmutils.is_process("crmd"):
        cmd = "crm node server"
        nodes = get_command_info(cmd)[1].strip().split('\n')
    # 3. if the cluster's stopped, try the CIB
    else:
        cmd = r"(CIB_file=%s/%s crm node server)" % (constants.CIB_DIR, constants.CIB_F)
        nodes = get_command_info(cmd)[1].strip().split('\n')

    return nodes


def get_peer_ip():
    local_ip = get_local_ip()
    peer_ip = []
    ip_pattern = "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
    for line in grep("runtime.*.srp.*.ip", incmd="corosync-cmapctl"):
        for ip in re.findall(ip_pattern, line):
            if ip not in local_ip:
                peer_ip.append(ip)
    return peer_ip


def get_ocf_dir():
    ocf_dir = None
    try:
        ocf_dir = crmsh.config.path.ocf_root
    except:
        log_fatal("Can not find OCF_ROOT_DIR!")
    if not os.path.isdir(ocf_dir):
        log_fatal("Directory %s is not OCF_ROOT_DIR!" % ocf_dir)
    constants.OCF_DIR = ocf_dir


def get_pe_state_dir():
    try:
        constants.PE_STATE_DIR = crmsh.config.path.pe_state_dir
    except:
        return
    if not os.path.isdir(constants.PE_STATE_DIR):
        constants.PE_STATE_DIR = None


def get_pkg_mgr():
    pkg_mgr = None

    if which("dpkg"):
        pkg_mgr = "deb"
    elif which("rpm"):
        pkg_mgr = "rpm"
    elif which("pkg_info"):
        pkg_mgr = "pkg_info"
    elif which("pkginfo"):
        pkg_mgr = "pkginfo"
    else:
        logger.warning("Unknown package manager!")

    return pkg_mgr


def get_stamp_legacy(line):
    try:
        res = crmutils.parse_time(line.split()[1], quiet=True)
    except:
        return None
    return res


def get_stamp_rfc5424(line):
    try:
        res = crmutils.parse_time(line.split()[0], quiet=True)
    except:
        return None
    return res


def get_stamp_syslog(line):
    try:
        res = crmutils.parse_time(' '.join(line.split()[0:3]), quiet=True)
    except:
        return None
    return res


def get_ts(line):
    ts = None
    with stdchannel_redirected(sys.stderr, os.devnull):
        if not constants.GET_STAMP_FUNC:
            func = find_getstampproc_raw(line)
        else:
            func = constants.GET_STAMP_FUNC
        if func:
            if func == "rfc5424":
                ts = crmutils.parse_to_timestamp(line.split()[0], quiet=True)
            if func == "syslog":
                ts = crmutils.parse_to_timestamp(' '.join(line.split()[0:3]), quiet=True)
            if func == "legacy":
                ts = crmutils.parse_to_timestamp(line.split()[1], quiet=True)
    return ts


def grep(pattern, infile=None, incmd=None, flag=None):
    res = []
    if not infile and not incmd:
        return res

    if infile:
        if os.path.isfile(infile):
            res = grep_file(pattern, infile, flag)
        elif os.path.isdir(infile):
            for root, dirs, files in os.walk(infile):
                for f in files:
                    res += grep_file(pattern, os.path.join(root, f), flag)
        else:
            for f in glob.glob(infile):
                res += grep_file(pattern, f, flag)
    elif incmd:
        res += grep_row(pattern, get_command_info(incmd)[1], flag)

    if flag and "q" in flag:
        return len(res) != 0
    return res


def grep_file(pattern, infile, flag):
    res = []
    with open(infile, 'r', encoding='utf-8', errors="replace") as fd:
        res = grep_row(pattern, fd.read(), flag)
        if res:
            if flag and "l" in flag:
                return [infile]
        return res


def grep_row(pattern, indata, flag):
    INVERT = False
    SHOWNUM = False
    reflag = 0
    if flag:
        if "v" in flag:
            INVERT = True
        if "i" in flag:
            reflag |= re.I
        if "w" in flag:
            pattern = r"\b%s\b" % pattern
        if "n" in flag:
            SHOWNUM = True

    res = []
    count = 0
    for line in indata.split('\n')[:-1]:
        count += 1
        if re.search(pattern, line, reflag):
            if not INVERT:
                if SHOWNUM:
                    res.append("%d:%s" % (count, line))
                else:
                    res.append(line)
        elif INVERT:
            if SHOWNUM:
                res.append("%d:%s" % (count, line))
            else:
                res.append(line)
    return res


def head(n, indata):
    return indata.split('\n')[:n]


def is_conf_set(option, subsys=None):
    subsys_start = 0
    if os.path.isfile(constants.CONF):
        data = read_from_file(constants.CONF)
        for line in data.split('\n'):
            if re.search("^\s*subsys\s*:\s*%s$" % subsys, line):
                subsys_start = 1
            if subsys_start == 1 and re.search("^\s*}", line):
                subsys_start = 0
            if re.match("^\s*%s\s*:\s*(on|yes)$" % option, line):
                if not subsys or subsys_start == 1:
                    return True
    return False


def is_exec(filename):
    return os.path.isfile(filename) and os.access(filename, os.X_OK)


def is_our_log(logf, from_time, to_time):
    """
    check if the log contains a piece of our segment
    """
    data = read_from_file(logf)
    if not data:
        logger.debug("Found empty file \"%s\"; exclude", logf)
        return 0
    first_time = find_first_ts(head(10, data))
    last_time = find_first_ts(tail(10, data))

    if (not first_time) or (not last_time):
        if os.stat(logf).st_size > 0:
            return 4 # irregular log, not empty
        return 0  # skip (empty log?)
    if from_time > last_time:
        # we shouldn't get here anyway if the logs are in order
        return 2  # we're past good logs; exit
    if from_time >= first_time:
        return 3  # this is the last good log
    if to_time == 0 or to_time >= first_time:
        return 1  # include this log
    else:
        return 0  # don't include this log



def line_time(data_list, line_num):
    '''
    Get time stamp of the specific line
    '''
    return get_ts(data_list[line_num-1])


def load_ocf_dirs():
    inf = "%s/lib/heartbeat/ocf-directories" % constants.OCF_DIR
    if not os.path.isfile(inf):
        log_fatal("file %s not exist" % inf)
    constants.HA_VARLIB = grep("HA_VARLIB:=", infile=inf)[0].split(':=')[1].strip('}')
    constants.HA_BIN = grep("HA_BIN:=", infile=inf)[0].split(':=')[1].strip('}')


def log_fatal(msg):
    logger.error(msg)
    sys.exit(1)


def log_size(logf, outf):
    l_size = os.stat(logf).st_size + 1
    out_string = "%s %d" % (logf, l_size)
    crmutils.str2file(out_string, outf)


def make_temp_dir():
    dir_path = r"/tmp/.crm_report.workdir.%s" % random_string(6)
    _mkdir(dir_path)
    return dir_path


def mktemplate(argv):
    """
    description template, editing, and other notes
    """
    workdir = constants.WORKDIR
    out_string = constants.EMAIL_TMPLATE.format("%s" % date(), ' '.join(argv[1:]))
    sysinfo_f = os.path.join(workdir, constants.SYSINFO_F)
    if os.path.isfile(sysinfo_f):
        out_string += "Common saystem info found:\n"
        with open(sysinfo_f, 'r') as f:
            out_string += f.read()
    else:
        for n in constants.NODES.split():
            sysinfo_node_f = os.path.join(workdir, n, constants.SYSINFO_F)
            if os.path.isfile(sysinfo_node_f):
                out_string += "System info %s:\n" % n
                out_string += sed_inplace(sysinfo_node_f, r'^', '    ')
                out_string += "\n"
    crmutils.str2file(out_string, os.path.join(workdir, constants.DESCRIPTION_F))


def pe_to_dot(pe_file):
    dotf = '.'.join(pe_file.split('.')[:-1]) + '.dot'
    cmd = "%s -D %s -x %s" % (constants.PTEST, dotf, pe_file)
    code, _ = crmutils.get_stdout(cmd)
    if code != 0:
        logger.warning("pe_to_dot: %s -> %s failed", pe_file, dotf)


def pick_compress():
    prog, ext = pick_first_compress()
    if prog:
        constants.COMPRESS_PROG, constants.COMPRESS_EXT = prog, ext
    else:
        logger.warning("the resulting tarball may be huge")
        constants.COMPRESS_PROG = "cat"


def pick_first_compress():
    compress_prog_suffix_dict = {
        "gzip": ".gz",
        "bzip2": ".bz2",
        "xz": ".xz"
    }
    for cmd, suffix in compress_prog_suffix_dict.items():
        if shutil.which(cmd):
            return cmd, suffix
    logger.warning("Could not find a compression program")
    return None, None


def pkg_ver_deb(packages):
    res = ""
    for pack in packages.split():
        code, out = get_command_info("dpkg-query -s %s" % pack)
        if code != 0:
            continue
        distro = "Unknown"
        for line in out.split('\n'):
            if re.match("^Package\s*:", line):
                name = line.split(':')[1].lstrip()
            elif re.match("^Version\s*:", line):
                version = line.split(':')[1].lstrip()
            elif re.match("^Architecture\s*:", line):
                arch = line.split(':')[1].lstrip()
        res += "%s %s - %s\n" % (name, version, arch)
    return res


def pkg_ver_pkg_info(packages):
    pass


def pkg_ver_pkginfo(packages):
    pass


def pkg_ver_rpm(packages):
    res = ""
    for pack in packages.split():
        code, out = get_command_info("rpm -qi %s" % pack)
        if code != 0:
            continue
        distro = "Unknown"
        for line in out.split('\n'):
            if re.match("^Name\s*:", line):
                name = line.split(':')[1].lstrip()
            elif re.match("^Version\s*:", line):
                version = line.split(':')[1].lstrip()
            elif re.match("^Release\s*:", line):
                release = line.split(':')[1].lstrip()
            elif re.match("^Distribution\s*:", line):
                distro = line.split(':')[1].lstrip()
            elif re.match("^Architecture\s*:", line):
                arch = line.split(':')[1].lstrip()
        res += "%s %s-%s - %s %s\n" % (name, version, release, distro, arch)
    return res


def pkg_versions(packages):
    pkg_mgr = get_pkg_mgr()
    if not pkg_mgr:
        return ""
    logger.debug("the package manager is %s", pkg_mgr)
    if pkg_mgr == "deb":
        return pkg_ver_deb(packages)
    if pkg_mgr == "rpm":
        return pkg_ver_rpm(packages)
    if pkg_mgr == "pkg_info":
        return pkg_ver_pkg_info(packages)
    if pkg_mgr == "pkginfo":
        return pkg_ver_pkginfo(packages)


def print_log(logf):
    """
    print part of the log
    """
    cat = find_decompressor(logf)
    cmd = "%s %s" % (cat, logf)
    out = crmutils.get_stdout(cmd)
    return out


def print_logseg(logf, from_time, to_time):
    data = read_from_file(logf)

    if from_time == 0:
        from_line = 1
    else:
        from_line = findln_by_time(data, from_time)
        if from_line is None:
            return ""

    if to_time == 0:
        to_line = len(data.split('\n'))
    else:
        to_line = findln_by_time(data, to_time)
        if to_line is None:
            return ""

    logger.debug("Including segment [%d-%d] from %s", from_line, to_line, logf)
    return filter_lines(data, from_line, to_line)


def ra_build_info():
    out = "UNKnown"
    inf = "%s/lib/heartbeat/ocf-shellfuncs" % constants.OCF_DIR
    res = grep("Build version:", infile=inf)
    if res and not re.search(r"\$Format:%H\$", res[0]):
        out = res[0]
    return "resource-agents: %s\n" % out


def random_string(num):
    tmp = []
    if crmutils.is_int(num) and num > 0:
        s = string.ascii_letters + string.digits
        tmp = random.sample(s, num)
    return ''.join(tmp)


def sanitize():
    """
    replace sensitive info with '****'
    """
    logger.debug("Check or replace sensitive info from cib, pe and log files")

    get_sensitive_key_value_list()

    work_dir = constants.WORKDIR
    file_list = []
    for (dirpath, dirnames, filenames) in os.walk(work_dir):
        for _file in filenames:
            file_list.append(os.path.join(dirpath, _file))

    for f in [item for item in file_list if os.path.isfile(item)]:
        rc = sanitize_one(f)
        if rc == 1:
            logger.warning("Some PE/CIB/log files contain possibly sensitive data")
            logger.warning("Using \"-s\" option can replace sensitive data")
            break


def sanitize_one(in_file):
    """
    Open the file, replace sensitive string and write back
    """
    data = read_from_file(in_file)
    if not data:
        return
    if not include_sensitive_data(data):
        return
    if not constants.DO_SANITIZE:
        return 1
    logger.debug("Replace sensitive info for %s", in_file)
    write_to_file(in_file, sub_sensitive_string(data))


def parse_sanitize_rule(rule_string):
    for rule in rule_string.split():
        if ':' in rule:
            key, value = rule.split(':')
            if value != "raw":
                log_fatal("For sanitize_pattern {}, option should be \"raw\"".format(key))
            constants.SANITIZE_RULE_DICT[key] = value
        else:
            constants.SANITIZE_RULE_DICT[rule] = None


def say_ssh_user():
    if not constants.SSH_USER:
        return "you user"
    else:
        return constants.SSH_USER


def sed_inplace(filename, pattern, repl):
    out_string = ""

    pattern_compiled = re.compile(pattern)
    with open(filename, 'r') as fd:
        for line in fd:
            out_string += pattern_compiled.sub(repl, line)

    return out_string


def set_env():
    os.environ["LC_ALL"] = "POSIX"


@contextlib.contextmanager
def stdchannel_redirected(stdchannel, dest_filename):
    """
    A context manager to temporarily redirect stdout or stderr
    e.g.:
    with stdchannel_redirected(sys.stderr, os.devnull):
        if compiler.has_function('clock_gettime', libraries=['rt']):
            libraries.append('rt')
    """

    try:
        oldstdchannel = os.dup(stdchannel.fileno())
        dest_file = open(dest_filename, 'w')
        os.dup2(dest_file.fileno(), stdchannel.fileno())
        yield

    finally:
        if oldstdchannel is not None:
            os.dup2(oldstdchannel, stdchannel.fileno())
        if dest_file is not None:
            dest_file.close()


def start_slave_collector(node, arg_str):
    cmd = "{} report __slave".format(constants.BIN_CRM)
    if node == constants.WE:
        for item in arg_str.split():
            cmd += " {}".format(str(item))
        _, out = crmutils.get_stdout(cmd)
    else:
        node = f"{constants.SSH_USER}@{node}" if constants.SSH_USER else node
        cmd = r'ssh {} {} "{} {}"'.format(constants.SSH_OPTS, node, constants.SUDO, cmd)
        for item in arg_str.split():
            cmd += " {}".format(str(item))
        if constants.SSH_USER and os.geteuid() == 0:
            code, out, err = crmutils.su_get_stdout_stderr(constants.SSH_USER, cmd)
        else:
            # a remote user is not specfied
            # or current user is not root, impossible to su
            code, out, err = crmutils.get_stdout_stderr(cmd)
        if code != 0:
            logger.warning(err)
            for ip in get_peer_ip():
                logger.info("Trying connect by %s", ip)
                cmd = cmd.replace(node, ip, 1)
                code, out, err = crmutils.get_stdout_stderr(cmd)
                if code != 0:
                    logger.warning(err)
                break
        if err:
            print(err, file=sys.stderr)

    if out == '': # if we couldn't get anything
        return

    compress_data = ""
    for data in out.split('\n'):
        if data.startswith(constants.COMPRESS_DATA_FLAG):
            # crm report data from collector
            compress_data = data.lstrip(constants.COMPRESS_DATA_FLAG)
        else:
            # log data from collector
            print(data)

    cmd = r"(cd {} && tar xf -)".format(constants.WORKDIR)
    crmutils.get_stdout(cmd, input_s=eval(compress_data))


def str_to_bool(v):
    return v.lower() in ["true"]


def tail(n, indata):
    return indata.split('\n')[-n:]


def dump_D_process():
    '''
    dump D-state process stack
    '''
    out_string = ""
    _, out, _ = crmutils.get_stdout_stderr("ps aux|awk '$8 ~ /^D/{print $2}'")
    len_D_process = len(out.split('\n')) if out else 0
    out_string += "Dump D-state process stack: {}\n".format(len_D_process)
    if len_D_process == 0:
        return out_string
    for pid in out.split('\n'):
        _, cmd_out, _ = crmutils.get_stdout_stderr("cat /proc/{}/comm".format(pid))
        out_string += "pid: {}     comm: {}\n".format(pid, cmd_out)
        _, stack_out, _ = crmutils.get_stdout_stderr("cat /proc/{}/stack".format(pid))
        out_string += stack_out + "\n\n"
    return out_string


def lsof_ocfs2_device():
    """
    List open files for OCFS2 device
    """
    out_string = ""
    _, out, _ = crmutils.get_stdout_stderr("mount")
    dev_list = re.findall("\n(.*) on .* type ocfs2 ", out)
    for dev in dev_list:
        cmd = "lsof {}".format(dev)
        out_string += "\n\n#=====[ Command ] ==========================#\n"
        out_string += "# {}\n".format(cmd)
        _, cmd_out, _ = crmutils.get_stdout_stderr(cmd)
        if cmd_out:
            out_string += cmd_out
    return out_string


def touch_r(src, dst):
    """
    like shell command "touch -r src dst"
    """
    if not os.path.exists(src):
        logger.warning("In touch_r function, %s not exists", src)
        return
    stat_info = os.stat(src)
    os.utime(dst, (stat_info.st_atime, stat_info.st_mtime))


def ts_to_dt(timestamp):
    """
    timestamp convert to datetime; consider local timezone
    """
    dt = crmutils.timestamp_to_datetime(timestamp)
    dt += tz.tzlocal().utcoffset(dt)
    return dt


def txt_diff(file1, file2):
    return get_command_info("diff -bBu %s %s" % (file1, file2))[1]


def verify_deb(packages):
    res = ""
    for pack in packages.split():
        cmd = r"dpkg --verify %s | grep -v 'not installed'" % pack
        code, out = crmutils.get_stdout(cmd)
        if code != 0 and out:
            res = "For package %s:\n" % pack
            res += out + "\n"
    return res


def verify_packages(packages):
    pkg_mgr = get_pkg_mgr()
    if not pkg_mgr:
        return ""
    if pkg_mgr == "deb":
        return verify_deb(packages)
    if pkg_mgr == "rpm":
        return verify_rpm(packages)
    if pkg_mgr == "pkg_info":
        return verify_pkg_info(packages)
    if pkg_mgr == "pkginfo":
        return verify_pkginfo(packages)


def verify_pkg_info(packages):
    pass


def verify_pkginfo(packages):
    pass


def verify_rpm(packages):
    res = ""
    for pack in packages.split():
        cmd = r"rpm --verify %s|grep -v 'not installed'" % pack
        code, out = crmutils.get_stdout(cmd)
        if code != 0 and out:
            res = "For package %s:\n" % pack
            res += out + "\n"
    return res


def which(prog):
    code, _ = get_command_info("which %s" % prog)
    if code == 0:
        return True
    else:
        return False


def get_open_method(infile):
    file_type_open_dict = {
            "gz": gzip.open,
            "bz2": bz2.open,
            "xz": lzma.open
            }
    try:
        _open = file_type_open_dict[infile.split('.')[-1]]
    except KeyError:
        _open = open
    return _open


def read_from_file(infile):
    data = None
    _open = get_open_method(infile)
    with _open(infile, 'rt', encoding='utf-8', errors='replace') as f:
        try:
            data = f.read()
        except Exception as err:
            logger.error("When reading file \"%s\": %s", infile, str(err))
            return None
    return crmutils.to_ascii(data)


def write_to_file(tofile, data):
    _open = get_open_method(tofile)
    with _open(tofile, 'w') as f:
        if _open == open:
            f.write(data)
        else:
            f.write(data.encode('utf-8'))


def get_sensitive_key_value_list():
    """
    For each defined sanitize rule, get the sensitive value or key list
    """
    for key, value in constants.SANITIZE_RULE_DICT.items():
        try:
            if value == "raw":
                constants.SANITIZE_VALUE_RAW += extract_sensitive_value_list(key)
            else:
                constants.SANITIZE_VALUE_CIB += extract_sensitive_value_list(key)
                constants.SANITIZE_KEY_CIB.append(key.strip('.*?')+'.*?')
        except (FileNotFoundError, EOFError) as e:
            logger.warning(e)


def extract_sensitive_value_list(rule):
    """
    Extract sensitive value from cib.xml
    """
    cib_file = os.path.join(constants.WORKDIR, constants.WE, constants.CIB_F)
    if not os.path.exists(cib_file):
        raise FileNotFoundError("File {} was not collected".format(constants.CIB_F))

    with open(cib_file) as fd:
        data = fd.read()
    if not data:
        raise EOFError("File {} is empty".format(cib_file))

    value_list = re.findall(r'name="({})" value="(.*?)"'.format(rule.strip('?')+'?'), data)
    return [value[1] for value in value_list]


def include_sensitive_data(data):
    """
    Check whether contain sensitive data
    """
    if constants.SANITIZE_VALUE_RAW or constants.SANITIZE_VALUE_CIB:
        return True
    return False


def sub_sensitive_string(data):
    """
    Do the replace job

    For the raw sanitize_pattern option, replace exactly the value
    For the key:value nvpair sanitize_pattern, replace the value in which line contain the key
    """
    result = data
    if constants.SANITIZE_VALUE_RAW:
        patt = '|'.join([re.escape(s) for s in constants.SANITIZE_VALUE_RAW])
        result = re.sub(r'\b({})\b'.format(patt), "******", data)
    if constants.SANITIZE_VALUE_CIB:
        patt = '|'.join([re.escape(s) for s in constants.SANITIZE_VALUE_CIB])
        result = re.sub('({})({})'.format('|'.join(constants.SANITIZE_KEY_CIB), patt), '\\1******', result)
    return result


def local_mode():
    """
    Check if -S option is set or if the node list is just the local node
    """
    return constants.NO_SSH or constants.NODES == constants.WE
# vim:ts=4:sw=4:et:
