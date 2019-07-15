import socket
import sys
import re
import datetime
import string
import random
import os
import tempfile
import contextlib
import tarfile
from dateutil import tz

import crmsh.config
from crmsh import msg as crmmsg
from crmsh import utils as crmutils


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


def parse_time(timeline):
    with stdchannel_redirected(sys.stderr, os.devnull):
        try:
            res = crmutils.parse_time(timeline)
        except:
            return None
        return res


def log_info(msg):
    crmmsg.common_info("%s# %s" % (me(), msg))


def log_warning(msg):
    crmmsg.common_warn("%s# %s" % (me(), msg))


def log_fatal(msg):
    crmmsg.common_err("%s# %s" % (me(), msg))
    sys.exit(1)


def log_debug(msg):
    import core
    if core.ctx.debug:
        crmsh.config.core.debug = "yes"
        crmmsg.common_debug("%s# %s" % (me(), msg))


def get_stamp_legacy(line):
    return parse_time(line.split()[1])


def get_stamp_rfc5424(line):
    return parse_time(line.split()[0])


def get_stamp_syslog(line):
    return parse_time(' '.join(line.split()[0:3]))


def find_stamp_type(line):
    _type = None
    if get_stamp_syslog(line):
        _type = "syslog"
    elif get_stamp_rfc5424(line):
        _type = "rfc5424"
    elif get_stamp_legacy(line):
        _type = "legacy"
    log_msg = "the log file is in the {} format".format(_type)
    if _type == "legacy":
        log_msg += "(please consider switching to syslog format)"
    log_debug(log_msg)
    return _type


def get_ts(line):
    ts = None
    import core
    if not hasattr(core.ctx, "stamp_type"):
        core.ctx.stamp_type = find_stamp_type(line)
    _type = core.ctx.stamp_type
    if _type == "rfc5424":
        ts = crmutils.parse_to_timestamp(line.split()[0])
    if _type == "syslog":
        ts = crmutils.parse_to_timestamp(' '.join(line.split()[0:3]))
    if _type == "legacy":
        ts = crmutils.parse_to_timestamp(line.split()[1])
    return ts


def line_time(logf, line_num):
    ts = None
    with open(logf, 'r', encoding='utf-8', errors='replace') as fd:
        line_res = head(line_num, fd.read())
        if line_res:
            ts = get_ts(line_res[-1])
    return ts


def findln_by_time(logf, tm):
    tmid = None
    first = 1
    last = sum(1 for l in open(logf, 'r', encoding='utf-8', errors='replace'))

    while first <= last:
        mid = (last+first)//2
        trycnt = 10
        while trycnt > 0:
            res = line_time(logf, mid)
            if res:
                tmid = int(res)
                break
            log_debug("cannot extract time: %s:%d; will try the next one" % (logf, mid))
            trycnt -= 1
            # shift the whole first-last segment
            prevmid = mid
            while prevmid == mid:
                first -= 1
                if first < 1:
                    first = 1
                last -= 1
                if last < first:
                    last = first
                prevmid = mid
                mid = (last+first)//2
                if first == last:
                    break
        if not tmid:
            log_warning("giving up on log...")
            return None
        if int(tmid) > tm:
            last = mid - 1
        elif int(tmid) < tm:
            first = mid + 1
        else:
            break
    return mid


def find_first_ts(data):
    ts = None
    for line in data:
        ts = get_ts(line)
        if ts:
            break
    return ts


def head(n, indata):
    return indata.split('\n')[:n]


def tail(n, indata):
    return indata.split('\n')[-n:]


def is_2dlist(aList):
    return all([isinstance(sublist, list) for sublist in aList])


def parse_to_timestamp(time):
    if re.search("^-[1-9][0-9]*[YmdHM]$", time):
        number = int(re.findall("[1-9][0-9]*", time)[0])
        if re.search("^-[1-9][0-9]*Y$", time):
            timedelta = datetime.timedelta(days = number * 365)
        if re.search("^-[1-9][0-9]*m$", time):
            timedelta = datetime.timedelta(days = number * 30)
        if re.search("^-[1-9][0-9]*d$", time):
            timedelta = datetime.timedelta(days = number)
        if re.search("^-[1-9][0-9]*H$", time):
            timedelta = datetime.timedelta(hours = number)
        if re.search("^-[1-9][0-9]*M$", time):
            timedelta = datetime.timedelta(minutes = number)
        time = (datetime.datetime.now() - timedelta).strftime("%Y-%m-%d %H:%M")

    res = crmutils.parse_to_timestamp(time)
    if res:
        return res
    else:
        log_fatal('''bad time specification: {}
Try these like: 2pm
                1:00
                "2007/9/5 12:30"
                "09-Sep-07 2:00"
                -[1-9][0-9]*[YmdHM]'''.format(time))


def me():
    return socket.gethostname()


def zip_nested(nested):
    return [x for sublist in nested for x in sublist]


def which(prog):
    return crmutils.ext_cmd("which {} &> /dev/null".format(prog)) == 0


def random_string(num):
    if not isinstance(num, int):
        raise TypeError('expected int')
    if num <= 0:
        raise ValueError('expected positive int')
    s = string.ascii_letters + string.digits
    return ''.join(random.sample(s, num))


def _mkdir(directory):
    if not os.path.isdir(directory):
        try:
            os.makedirs(directory)
        except OSError as err:
            log_fatal("Failed to create directory: %s" % (err))


def make_temp_dir():
    import core
    dir_path = '/tmp/{}.{}'.format(core.WORKDIR_PREFIX, random_string(6))
    _mkdir(dir_path)
    return dir_path


def make_temp_file(time=None):
    random_str = random_string(4)
    try:
        filename = tempfile.mkstemp(suffix=random_str, prefix="tmp.")[1]
    except:
        log_fatal("Can't create file {}".format(filename))
    if time:
        os.utime(filename, (time, time))
    return filename


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


def get_command_info(cmd):
    rc, out, err = crmutils.get_stdout_stderr(cmd)
    if rc == 0:
        return out
    else:
        log_fatal("Error running \"{}\"({}): {}".format(cmd, rc, err))
        return None


def log_mark(msg):
    if not which("logger"):
        log_warning("Command logger not found")
        return

    crmutils.ext_cmd("logger -p {}".format(msg))
    log_debug("run: logger -p {}".format(msg))


def parallax_call(context):
    try:
        import parallax
    except ImportError:
        error("parallax python library is missing")

    options = parallax.Options()
    options.ssh_options = re.split("-o | -o ", context.ssh_opts)[1:]

    return parallax.call(hosts, cmd, opts)


def get_data_from_tarfile(logf):
    with tarfile.open(logf, 'r') as tar:
        for member in tar.getmembers():
            f = tar.extractfile(member)
            if f:
                return crmutils.to_ascii(f.read())
            else:
                return None


def filter_lines(logf, from_line, to_line):
    out_string = ""
    count = 1
    with open(logf, 'r', encoding='utf-8', errors='replace') as f:
        for line in f.readlines():
            if count >= from_line and count <= to_line:
                out_string += line
            if count > to_line:
                break
            count += 1
    return out_string
