# Copyright (C) 2017 Xin Liang <XLiang@suse.com>
# See COPYING for license information.

import datetime
import glob
import os
import re
import shutil
import sys
import traceback
from dateutil import tz
from enum import Enum
from typing import Optional, List, Tuple

from crmsh import utils as crmutils
from crmsh import corosync, log, userdir, tmpfiles, config, sh
from crmsh.report import constants, collect, core
from crmsh.sh import ShellUtils


logger = log.setup_report_logger(__name__)


class LogType(Enum):
    GOOD = 0             # good log; include
    IRREGULAR = 1        # irregular log; include
    EMPTY = 2            # empty log; exclude
    BEFORE_TIMESPAN = 3  # log before timespan; exclude
    AFTER_TIMESPAN = 4   # log after timespan; exclude


def convert_logtype_to_str(log_type: LogType) -> str:
    log_type_str = {
        LogType.GOOD: "in timespan",
        LogType.IRREGULAR: "irregular",
        LogType.EMPTY: "empty",
        LogType.BEFORE_TIMESPAN: "before timespan",
        LogType.AFTER_TIMESPAN: "after timespan"
    }
    return log_type_str[log_type]


class ReportGenericError(Exception):
    pass


def arch_logs(context: core.Context, logf: str) -> Tuple[List[str], LogType]:
    """
    Go through archived logs and return those in timespan and the LogType
    """
    return_list = []
    log_type = None

    file_list = [logf] + glob.glob(logf+"*[0-9z]")
    # like ls -t, newest first
    for f in sorted(file_list, key=os.path.getmtime, reverse=True):
        tmp = is_our_log(context, f)
        logger.debug2("File %s is %s", f, convert_logtype_to_str(tmp))
        if tmp not in (LogType.GOOD, LogType.IRREGULAR):
            continue
        log_type = tmp
        return_list.append(f)

    if return_list:
        logger.debug2(
            "Found %s logs: %s",
            convert_logtype_to_str(log_type),
            ', '.join(return_list)
        )
    return return_list, log_type


def analyze(context: core.Context) -> None:
    """
    """
    result_list = []

    result_list.append(compare_and_consolidate_files(context))
    result_list += check_collected_files(context)
    result_list += extract_critical_log(context)

    analyze_f = os.path.join(context.work_dir, constants.ANALYSIS_F)
    crmutils.str2file('\n'.join(result_list), analyze_f)


def compare_and_consolidate_files(context: core.Context) -> str:
    out_string: str = ""
    workdir = context.work_dir
    compare_file_list = [
        constants.MEMBERSHIP_F,
        constants.CRM_MON_F,
        constants.COROSYNC_F,
        constants.SYSINFO_F,
        constants.CIB_F
    ]

    for f in compare_file_list:
        out_string += f"Diff {f}... "
        if not glob.glob(f"{workdir}/*/{f}"):
            out_string += f"no {f} found in {workdir}\n"
            continue
        rc, out = do_compare(context, f)
        out_string += f"\n{out}\n" if out else "OK\n"
        if rc == 0 and f != constants.CIB_F:
            consolidate(context, f)

    return out_string + '\n'


def do_compare(context: core.Context, file: str) -> Tuple[int, str]:
    """
    Compare file content between cluster nodes
    """
    rc, out_string = 0, ""
    prev_file_path = None

    for n in context.node_list:
        current_file_path = os.path.join(context.work_dir, n, file)

        if prev_file_path:
            rc, out = diff_check(prev_file_path, current_file_path)
            out_string += f"{out}\n" if out else ""
            rc += rc
        else:
            prev_file_path = current_file_path

    return rc, out_string


def check_collected_files(context: core.Context) -> List[str]:
    """
    Check collected files for warnings and issues
    """
    results = []
    file_description_dict = {
        constants.COREDUMP_F: "WARN: Coredump found at",
        constants.CRM_VERIFY_F: "WARN: crm_verify reported warnings at",
        constants.PERMISSIONS_F: "Checking problems with permissions/ownership at"
    }

    for node in context.node_list:
        for f, desc in file_description_dict.items():
            f_in_work_dir = os.path.join(context.work_dir, node, f)
            if os.path.isfile(f_in_work_dir) and not crmutils.file_is_empty(f_in_work_dir):
                results.append(f"{desc} {node}:")
                results.append(crmutils.read_from_file(f_in_work_dir))

    return results


def extract_critical_log(context: core.Context) -> List[str]:
    """
    Extract warnings and errors from collected log files
    """
    result_list = []
    log_pattern_list = [f".*{p}.*" for p in constants.LOG_PATTERNS.split()]
    log_pattern_str = '|'.join(log_pattern_list)

    for f in glob.glob(f"{context.work_dir}/*/*.log"):
        _list = re.findall(log_pattern_str, crmutils.read_from_file(f))
        if _list:
            result_list.append(f"\nWARNINGS or ERRORS in {'/'.join(f.split('/')[3:])}:")
            result_list.extend(_list)

    return result_list


def cib_diff(file1: str, file2: str) -> Tuple[int, str]:
    """
    check if CIB files have same content in the cluster
    """
    node1_dir = os.path.dirname(file1)
    node2_dir = os.path.dirname(file2)

    if (os.path.isfile(os.path.join(node1_dir, "RUNNING")) and
        os.path.isfile(os.path.join(node2_dir, "RUNNING"))) or \
        (os.path.isfile(os.path.join(node1_dir, "STOPPED")) and
         os.path.isfile(os.path.join(node2_dir, "STOPPED"))):
        cmd = f"crm_diff -c -n {file1} -o {file2}"
        code, out_string, _ = ShellUtils().get_stdout_stderr(cmd)
    else:
        code, out_string = 1, "Can't compare cibs from running and stopped systems\n"
    return code, out_string


def consolidate(context: core.Context, target_file: str) -> None:
    """
    Remove duplicates if files are same, make links instead
    """
    workdir = context.work_dir
    for node in context.node_list:
        target_file_in_path = os.path.join(workdir, node, target_file)
        if os.path.isfile(os.path.join(workdir, target_file)):
            os.remove(target_file_in_path)
        else:
            shutil.move(target_file_in_path, workdir)
        os.symlink(f"../{target_file}", target_file_in_path)


def diff_check(file1: str, file2: str) -> Tuple[int, str]:
    """
    Check the differences between two files
    """
    for f in [file1, file2]:
        if not os.path.isfile(f):
            return (1, f"{f} does not exist\n")

    diff_func = cib_diff if os.path.basename(file1) == constants.CIB_F else txt_diff
    return diff_func(file1, file2)


def get_distro_info() -> str:
    """
    Get distribution information
    """
    res = None
    if os.path.exists(constants.OSRELEASE):
        logger.debug2(f"Using {constants.OSRELEASE} to get distribution info")
        res = re.search("PRETTY_NAME=\"(.*)\"", crmutils.read_from_file(constants.OSRELEASE))
    elif shutil.which("lsb_release"):
        logger.debug2("Using lsb_release to get distribution info")
        out = sh.LocalShell().get_stdout_or_raise_error("lsb_release -d")
        res = re.search("Description:\s+(.*)", out)
    return res.group(1) if res else "Unknown"


def dump_logset(context: core.Context, logf: str) -> None:
    """
    Dump the log set into the specified output file
    """
    logf_set, logf_type = arch_logs(context, logf)
    if not logf_set:
        logger.debug2(f"{logf} is not in timespan {get_timespan_str(context)}")
        return

    out_string = ""

    if logf_type == LogType.IRREGULAR:
        for f in logf_set:
            out_string += print_logseg(f, 0, 0)
    else:
        newest, oldest = logf_set[0], logf_set[-1]
        middle_set = logf_set[1:-1]

        if len(logf_set) == 1:
            out_string += print_logseg(newest, context.from_time, context.to_time)
        else:
            out_string += print_logseg(oldest, context.from_time, 0)
            for f in middle_set:
                out_string += print_logseg(f, 0, 0)
            out_string += print_logseg(newest, 0, context.to_time)

    if out_string:
        outf = os.path.join(context.work_dir, os.path.basename(logf))
        crmutils.str2file(out_string.strip('\n'), outf)
        logger.debug(f"Dump {logf} into {real_path(outf)}")


def find_files_in_timespan(context: core.Context, target_dir_list: List[str]) -> List[str]:
    """
    Get a list of files in the target directories with creation time in the timespan
    """
    file_list = []

    for target_dir in target_dir_list:
        if not os.path.isdir(target_dir):
            continue

        for root, dirs, files in os.walk(target_dir):
            for file in files:
                file_path = os.path.join(root, file)
                file_stat = os.stat(file_path)
                if context.from_time <= file_stat.st_ctime <= context.to_time:
                    file_list.append(file_path)

    return file_list


def find_first_timestamp(data: List[str], log_file: str) -> float:
    """
    Find the first timestamp in the given list of log line
    """
    for line in data:
        timestamp = get_timestamp(line, log_file)
        if timestamp:
            return timestamp
    return None


def filter_lines(data: str, from_line: int, to_line: int) -> str:
    """
    Filter lines from the given data based on the specified line range.
    """
    lines = data.split('\n')
    filtered_lines = [
        line + '\n' 
        for count, line in enumerate(lines, start=1) 
        if from_line <= count <= to_line
    ]
    return ''.join(filtered_lines)


def determin_log_format(data: str) -> str:
    """
    Determines the log format based on the given log line
    """
    for line in head(constants.CHECK_LOG_LINES, data):
        _list = line.split()
        if not _list:
            continue
        # syslog format:
        # Feb 12 18:30:08 15sp1-1 kernel: e820: BIOS-provided physical RAM map:
        if len(_list) >= 3 and crmutils.parse_time(' '.join(_list[0:3]), quiet=True):
            return "syslog"
        # rfc5424 format:
        # 2003-10-11T22:14:15.003Z mymachine.example.com su
        if crmutils.parse_time(_list[0], quiet=True):
            return "rfc5424"
        if len(_list) > 1 and crmutils.parse_time(_list[1], quiet=True):
            return "legacy"
    return None


def findln_by_timestamp(data: str, given_timestamp: float, log_file: str) -> int:
    """
    Get line number of the specific time stamp
    """
    data_list = data.split('\n')
    first, last = 1, len(data_list)

    while first <= last:
        middle = (last + first) // 2
        trycnt = 10
        while trycnt > 0:
            middle_timestamp = get_timestamp(data_list[middle - 1], log_file)
            if middle_timestamp:
                break
            # shift the whole first-last segment
            trycnt -= 1
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

        if not middle_timestamp:
            return None
        if middle_timestamp > given_timestamp:
            last = middle - 1
        elif middle_timestamp < given_timestamp:
            first = middle + 1
        else:
            break

    return middle


def get_pkg_mgr() -> str:
    """
    Get the package manager available in the system
    """
    pkg_mgr_candidates = {
        "rpm": "rpm",
        "dpkg": "deb"
    }
    for pkg_mgr, pkg_mgr_name in pkg_mgr_candidates.items():
        if shutil.which(pkg_mgr):
            return pkg_mgr_name

    logger.warning("Unknown package manager!")
    return ""


def get_timestamp_from_time_line(time_line: str, stamp_type: str, log_file: str):
    timestamp = crmutils.parse_to_timestamp(time_line, quiet=True)
    if timestamp and stamp_type == "syslog":
        now = datetime.datetime.now()
        # got a timestamp in the future
        if timestamp > now.timestamp():
            # syslog doesn't have year info, so we need to guess it
            mtime = os.path.getmtime(log_file)
            mtime = datetime.datetime.fromtimestamp(mtime)
            # assume the log is from last year
            if mtime.year == now.year:
                time_line += f" {mtime.year-1}"
            # assume the log is from that year
            elif mtime.year < now.year:
                time_line += f" {mtime.year}"
            # it's impossible that the log is from next year
            else:
                return None
        return crmutils.parse_to_timestamp(time_line, quiet=True)
    else:
        return timestamp


def get_timestamp(line: str, log_file: str) -> float:
    """
    Get timestamp for the given line
    """
    if not line or not constants.STAMP_TYPE:
        return None

    stamp_type = constants.STAMP_TYPE
    if stamp_type == "rfc5424":
        time_line = line.split()[0]
    elif stamp_type == "syslog":
        time_line = ' '.join(line.split()[0:3])
    elif stamp_type == "legacy":
        time_line = line.split()[1]

    return get_timestamp_from_time_line(time_line, stamp_type, log_file)



def head(n: int, indata: str) -> List[str]:
    return indata.split('\n')[:n]


def is_our_log(context: core.Context, logf: str) -> int:
    """
    Check if the log contains a piece of our segment

    Return log type LogType
    """
    data = crmutils.read_from_file(logf)
    if not data:
        return LogType.EMPTY
    stamp_type = determin_log_format(data)
    if not stamp_type:
        return LogType.IRREGULAR
    constants.STAMP_TYPE = stamp_type

    first_time = find_first_timestamp(head(constants.CHECK_LOG_LINES, data), logf)
    last_time = find_first_timestamp(tail(constants.CHECK_LOG_LINES, data), logf)
    from_time = context.from_time
    to_time = context.to_time

    if not first_time or not last_time:
        return LogType.IRREGULAR
    if from_time > last_time:
        return LogType.BEFORE_TIMESPAN
    if from_time >= first_time or to_time >= first_time:
        return LogType.GOOD
    return LogType.AFTER_TIMESPAN


def create_description_template(context: core.Context) -> None:
    """
    Create description template, editing, and other notes
    """
    out_string = constants.DECRIPTION_TMPLATE.format(now(), ' '.join(sys.argv[1:]))

    for n in context.node_list:
        sysinfo_node_f = os.path.join(context.work_dir, n, constants.SYSINFO_F)
        if os.path.isfile(sysinfo_node_f):
            out_string += f"[Info from node {n}]:\n"
            out_string += crmutils.read_from_file(sysinfo_node_f)
            out_string += "\n\n\n\n"

    description_f = os.path.join(context.work_dir, constants.DESCRIPTION_F)
    crmutils.str2file(out_string, description_f)


def print_logseg(log_file: str, from_time: float, to_time: float) -> str:
    """
    Print the log segment specified by the given timestamps
    """
    data = crmutils.read_from_file(log_file)
    if not data:
        return ""

    from_line = 1 if from_time == 0 else findln_by_timestamp(data, from_time, log_file)
    to_line = len(data.split('\n')) if to_time == 0 else findln_by_timestamp(data, to_time, log_file)

    if from_line is None or to_line is None:
        return ""

    logger.debug2("Including segment [%d-%d] from %s", from_line, to_line, log_file)
    return filter_lines(data, from_line, to_line)


def tail(n: int, indata: str) -> List[str]:
    return indata.split('\n')[-n:]


def txt_diff(file1: str, file2: str) -> Tuple[int, str]:
    cmd = f"diff -bBu {file1} {file2}"
    rc, out, _ = ShellUtils().get_stdout_stderr(cmd)
    return rc, out


class Sanitizer:
    """
    A class containing methods for sanitizing sensitive data in CIB and PE files
    """
    DEFAULT_RULE_LIST = ["passw.*"]

    def __init__(self, context: core.Context) -> None:
        self.file_list_in_workdir = []
        self.context = context
        self.cib_data = None
        self.sensitive_regex_set = set()
        self.sensitive_value_list_with_raw_option = []
        self.sensitive_value_list = []
        self.sensitive_key_list = []

    def prepare(self) -> None:
        """
        Prepare the data and files for the sanitization process
        """
        self.cib_data = self._load_cib_from_work_dir()
        if not self.cib_data:
            return False
        self._parse_sensitive_set()
        self._extract_sensitive_value_list()

        if self._include_sensitive_data():
            if not self.context.sanitize:
                logger.warning("Some PE/CIB/log files contain possibly sensitive data")
                logger.warning("Using \"-s\" option can replace sensitive data")
                return False
            self._get_file_list_in_work_dir()
        else:
            self.context.sanitize = False

        return True

    def _include_sensitive_data(self) -> List[str]:
        """
        Check whether contain sensitive data
        """
        return self.sensitive_value_list_with_raw_option or self.sensitive_value_list

    def _get_file_list_in_work_dir(self) -> List[str]:
        """
        Get all files in work directory
        """
        for dirpath, dirnames, filenames in os.walk(self.context.work_dir):
            for _file in filenames:
                self.file_list_in_workdir.append(os.path.join(dirpath, _file))

    def _load_cib_from_work_dir(self) -> None:
        """
        Load CIB data from the working directory
        """
        cib_file_list = glob.glob(f"{self.context.work_dir}/*/{constants.CIB_F}")
        if not cib_file_list:
            return None
        return crmutils.read_from_file(cib_file_list[0])

    def _parse_sensitive_set(self) -> None:
        """
        Parse sensitive regex from -E option and config.report.sanitize_rule
        """
        # from command line option -p
        patt_set = set(self.context.sensitive_regex_list)
        # from /etc/crm/crm.conf
        if config.report.sanitize_rule:
            patt_set |= set(re.split('\s*\|\s*|\s+', config.report.sanitize_rule.strip('|')))
        if patt_set:
            self.context.sanitize = True
        # Not set from -p option and crm.conf, use default
        else:
            patt_set = set(Sanitizer.DEFAULT_RULE_LIST)
        logger.debug2(f"Regex set to match sensitive data: {patt_set}")
        self.sensitive_regex_set = patt_set

    def _extract_sensitive_value_list(self) -> None:
        """
        Extract sensitive value list from cib data
        """
        for patt in self.sensitive_regex_set:
            if ':' in patt:
                rule, option = patt.split(':')
                if option == 'raw':
                    self.sensitive_value_list_with_raw_option += self._extract_from_cib(rule)
                else:
                    logger.warning(f"For sanitize pattern {patt}, option should be \"raw\"")
            else:
                self.sensitive_value_list += self._extract_from_cib(patt)
                self.sensitive_key_list.append(patt.strip('.*?')+'.*?')

    def _extract_from_cib(self, rule:str) -> List[str]:
        name_patt = rule.strip('?')+'?'
        value_list = re.findall(f'name="({name_patt})" value="(.*?)"', self.cib_data)
        return [value[1] for value in value_list]

    def _sub_sensitive_string(self, data: str) -> str:
        """
        Do the replacement job

        For the raw sanitize pattern, replace exactly the value
        For the key:value nvpair sanitize pattern, replace the value in which line contain the key
        """
        result = data
        replace_raw_n: int = 0
        replace_n: int = 0

        if self.sensitive_value_list_with_raw_option:
            patt_str = '|'.join([re.escape(patt) for patt in self.sensitive_value_list_with_raw_option])
            result, replace_raw_n = re.subn(r'\b({})\b'.format(patt_str), "******", data)
        if self.sensitive_value_list:
            key_str = '|'.join(self.sensitive_key_list)
            patt_str = '|'.join([re.escape(patt) for patt in self.sensitive_value_list])
            result, replace_n = re.subn(f'({key_str})({patt_str})', '\\1******', result)

        return "" if (replace_raw_n == 0 and replace_n == 0) else result


    def sanitize(self) -> None:
        """
        Replace and overwrite files containing sensitive data
        """
        if not self.context.sanitize:
            return
        for f in self.file_list_in_workdir:
            data = crmutils.read_from_file(f)
            if not data:
                continue
            replaced_str = self._sub_sensitive_string(data)
            if replaced_str:
                logger.debug("Replace sensitive info for %s", f)
                write_to_file(replaced_str, f)


def do_sanitize(context: core.Context) -> None:
    """
    Perform sanitization by replacing sensitive information in CIB/PE/other logs data with '*'
    """
    inst = Sanitizer(context)
    if inst.prepare():
        inst.sanitize()


class Package:
    """
    A class to retrieve package versions and verify packages
    on various distros
    """
    def __init__(self, packages: str) -> None:
        self.pkg_type = get_pkg_mgr()
        self.packages = packages

    def pkg_ver_deb(self) -> str:
        cmd = f"dpkg-query -W -f='${{Package}}    ${{Version}}.${{Architecture}}\n' {self.packages}"
        _, out, _ = ShellUtils().get_stdout_stderr(cmd)
        return '\n'.join([line for line in out.splitlines() if "no packages found" not in line])

    def pkg_ver_rpm(self) -> str:
        _, out, _ = ShellUtils().get_stdout_stderr(f"rpm -q {self.packages}")
        return '\n'.join([line for line in out.splitlines() if "not installed" not in line])

    def version(self) -> str:
        if not self.pkg_type:
            return ""
        return getattr(self, f"pkg_ver_{self.pkg_type}")()

    def verify_deb(self) -> str:
        cmd = f"dpkg --verify {self.packages}"
        _, out, _ = ShellUtils().get_stdout_stderr(cmd)
        return '\n'.join([line for line in out.splitlines() if "not installed" not in line])

    def verify_rpm(self) -> str:
        cmd = f"rpm --verify {self.packages}"
        _, out, _ = ShellUtils().get_stdout_stderr(cmd)
        return '\n'.join([line for line in out.splitlines() if "not installed" not in line])

    def verify(self) -> str:
        if not self.pkg_type:
            return ""
        return getattr(self, f"verify_{self.pkg_type}")()


def write_to_file(data: str, tofile: str) -> None:
    _open = crmutils.get_open_method(tofile)
    with _open(tofile, 'w') as f:
        if _open == open:
            f.write(data)
        else:
            f.write(data.encode('utf-8'))


def parse_to_timestamp(time: str) -> Optional[float]:
    """
    Parses the input time string and converts it to a timestamp
    """
    time_format_mapping = {
        'Y': 365,  # 1 year is approximately 365 days
        'm': 30,   # 1 month is approximately 30 days
        'd': 1,
        'H': 1 / 24,  # 1 hour is 1/24 of a day
        'M': 1 / 1440  # 1 minute is 1/1440 of a day
    }

    # Match the input time string to the format
    match = re.match(r'^-?([1-9][0-9]*)([YmdHM])$', time)

    if not match:
        res = crmutils.parse_to_timestamp(time, quiet=True)
        if res:
            return res
        logger.error(f"Invalid time string '{time}'")
        logger.error('Try these formats like: 2pm; "2019/9/5 12:30"; "09-Sep-07 2:00"; "[1-9][0-9]*[YmdHM]"')
        raise ReportGenericError

    number_str, flag = match.groups()
    number = int(number_str) * time_format_mapping[flag]
    timedelta = datetime.timedelta(days=number)

    # Calculate the timestamp
    timestamp = (datetime.datetime.now() - timedelta).timestamp()

    return timestamp


def ts_to_str(timestamp: float) -> str:
    """
    Convert timestamp to date string
    """
    return dt_to_str(ts_to_dt(timestamp))


def ts_to_dt(timestamp: float) -> datetime.datetime:
    """
    Convert timestamp to datetime.datetime object, consider utc offset
    """
    dt = crmutils.timestamp_to_datetime(timestamp)
    dt += tz.tzlocal().utcoffset(dt)
    return dt


def dt_to_str(dt: datetime.datetime, form: str = constants.TIME_FORMAT) -> str:
    return dt.strftime(form)


def now(form: str = constants.TIME_FORMAT) -> str:
    return dt_to_str(datetime.datetime.now(), form=form)


def get_cmd_output(cmd: str, timeout: int = None) -> str:
    """
    Get the output of a command, include stdout and stderr
    """
    out_str = ""
    _, out, err = ShellUtils().get_stdout_stderr(cmd, timeout=timeout)
    if out:
        out_str += f"{out}\n"
    if err:
        out_str += f"{err}\n"
    return out_str


def get_timespan_str(context: core.Context) -> str:
    from_time_str = ts_to_str(context.from_time)
    to_time_str = ts_to_str(context.to_time)
    return f"{from_time_str} - {to_time_str}"


def print_traceback():
    traceback.print_exc()
    sys.stdout.flush()


def real_path(target_file: str) -> str:
    return '/'.join(target_file.split('/')[3:])
# vim:ts=4:sw=4:et:
