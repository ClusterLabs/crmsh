import socket
import sys
import re
import datetime
import os
import subprocess
import gzip
import bz2
import lzma
from dateutil import tz

import crmsh.config
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from hb_report import const
from crmsh import msg as crmmsg
from crmsh import utils as crmutils


def log_info(msg):
    crmmsg.common_info("{}#{}: {}".format(me(), get_role(), msg))


def log_warning(msg):
    crmmsg.common_warn("{}#{}: {}".format(me(), get_role(), msg))


def log_error(msg):
    crmmsg.common_err("{}#{}: {}".format(me(), get_role(), msg))


def log_fatal(msg):
    crmmsg.common_err("{}#{}: {}".format(me(), get_role(), msg))
    sys.exit(1)


def get_role():
    from hb_report import core
    if core.is_collector():
        return "Collector"
    else:
        return "Master"


def log_debug1(msg):
    from hb_report import core
    if core.ctx.debug >= 1:
        crmsh.config.core.debug = "yes"
        crmmsg.common_debug("{}#{}: {}".format(me(), get_role(), msg))


def log_debug2(msg):
    from hb_report import core
    if core.ctx.debug > 1:
        crmsh.config.core.debug = "yes"
        crmmsg.common_debug("{}#{}: {}".format(me(), get_role(), msg))


def parse_time(line, quiet=False):
    try:
        res = crmutils.parse_time(line, quiet)
    except:
        return None
    return res


def is_rfc5424(line):
    return parse_time(line.split()[0], quiet=True)


def is_syslog(line):
    return parse_time(' '.join(line.split()[0:3]), quiet=True)


def find_stamp_type(line):
    if is_syslog(line):
        return "syslog"
    elif is_rfc5424(line):
        return "rfc5424"
    return None


def get_ts(line):
    from hb_report import core
    ts = None
    if not hasattr(core.ctx, "stamp_type") or not core.ctx.stamp_type:
        core.ctx.stamp_type = find_stamp_type(line)
    _type = core.ctx.stamp_type
    # rfc5424 format is like
    # 2003-10-11T22:14:15.003Z mymachine.example.com su
    if _type == "rfc5424":
        ts = crmutils.parse_to_timestamp(line.split()[0], quiet=True)
    # syslog format is like
    # Feb 12 18:30:08 15sp1-1 kernel: e820: BIOS-provided physical RAM map:
    if _type == "syslog":
        ts = crmutils.parse_to_timestamp(' '.join(line.split()[0:3]), quiet=True)
    return ts


def line_time(data_list, line_num):
    '''
    Get time stamp of the specific line
    '''
    return get_ts(data_list[line_num-1])


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


def find_first_ts(data):
    ts = None
    for line in data:
        if not line:
            continue
        ts = get_ts(line)
        if ts:
            break
    return ts


def head(n, indata):
    return indata.split('\n')[:n]


def tail(n, indata):
    return reversed(indata.split('\n')[-n:])


def parse_to_timestamp(time):
    res = re.match("^-?([1-9][0-9]*)([YmdHM])$", time)
    if res:
        number_str, flag = res.groups()
        number = int(number_str)
        if flag == 'Y':
            timedelta = datetime.timedelta(days = number * 365)
        if flag == 'm':
            timedelta = datetime.timedelta(days = number * 30)
        if flag == 'd':
            timedelta = datetime.timedelta(days = number)
        if flag == 'H':
            timedelta = datetime.timedelta(hours = number)
        if flag == 'M':
            timedelta = datetime.timedelta(minutes = number)
        time = (datetime.datetime.now() - timedelta).strftime("%Y-%m-%d %H:%M")

    res = crmutils.parse_to_timestamp(time)
    if res:
        return res
    else:
        log_fatal('Try these format like: 2pm; 1:00; "2019/9/5 12:30"; "09-Sep-07 2:00"'.format(time))


def me():
    return socket.gethostname()


class Package(object):
    def __init__(self, pkgs):
        self.for_rpm = True
        pkg_type = get_pkg_mgr()
        if pkg_type != "rpm":
            self.for_rpm = False
            log_warning("The package manager is {}, not support for now".format(pkg_type))
        else:
            self.pkgs = pkgs

    def version(self):
        if not self.for_rpm:
            return ""
        return pkg_ver_rpm(self.pkgs)

    def verify(self):
        if not self.for_rpm:
            return ""
        return verify_rpm(self.pkgs)


def get_pkg_mgr():
    for p in ["rpm", "dpkg", "pkg_info", "pkginfo"]:
        if which(p):
            return p
    log_warning("Unknown package manager!")
    return None


def pkg_ver_rpm(packages):
    res = "Name | Version-Release | Distribution | Arch\n-----\n"
    cmd = "rpm -q --qf '%{name} | %{version}-%{release} | %{distribution} | %{arch}\n'"

    rc, out = crmutils.get_stdout("{} {}".format(cmd, packages))
    if out:
        for line in out.split('\n'):
            if re.search('not installed', line):
                continue
            res += line + '\n'
    return res


def verify_rpm(packages):
    res = ""
    rc, out = crmutils.get_stdout("rpm --verify {}".format(packages))
    if out:
        for line in out.split('\n'):
            if re.search('not installed', line):
                continue
            res += line + '\n'
    if not res:
        res = "All packages verify successfully\n"
        log_debug2(res.strip('\n'))
    return res


def which(prog):
    rc, _, _ = crmutils.get_stdout_stderr("which {}".format(prog))
    return rc == 0


def _mkdir(directory):
    if not os.path.isdir(directory):
        try:
            os.makedirs(directory)
        except OSError as err:
            log_fatal("Failed to create directory: %s" % (err))


def dirname(path):
    tmp = os.path.dirname(path)
    return tmp if tmp else "."


def ts_to_dt(timestamp):
    """
    timestamp convert to datetime; consider local timezone
    """
    dt = crmutils.timestamp_to_datetime(timestamp)
    dt += tz.tzlocal().utcoffset(dt)
    return dt


def now(form="%Y-%m-%d %H:%M"):
    return dt_to_str(datetime.datetime.now(), form=form)


def dt_to_str(dt, form="%Y-%m-%d %H:%M"):
    if not isinstance(dt, datetime.datetime):
        raise TypeError("expected <class 'datetime.datetime'>")
    return dt.strftime(form)


def ts_to_str(ts):
    return dt_to_str(ts_to_dt(ts))


def get_stdout_stderr_timeout(cmd, input_s=None, shell=True, timeout=5):
    '''
    Run a cmd, return (rc, stdout, stderr)
    '''
    proc = subprocess.Popen(cmd,
                            shell=shell,
                            stdin=input_s and subprocess.PIPE or None,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    try:
        stdout_data, stderr_data = proc.communicate(input_s, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        log_error("Timeout running \"{}\"".format(cmd))
        return (-1, None, None)
    return (proc.returncode, crmutils.to_ascii(stdout_data), crmutils.to_ascii(stderr_data))


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
        data = f.read()
    return crmutils.to_ascii(data)


def write_to_file(tofile, data):
    _open = get_open_method(tofile)
    with _open(tofile, 'w') as f:
        if _open == open:
            f.write(data)
        else:
            f.write(data.encode('utf-8'))


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


def touch_file(filename):
    open(filename, 'w').close()


def unzip_list(_list):
    return [y for x in _list for y in x.split()]


def unique(sequence):
    seen = set()
    return [x for x in sequence if not (x in seen or seen.add(x))]


def is_log_empty(logf):
    return os.stat(logf).st_size == 0
