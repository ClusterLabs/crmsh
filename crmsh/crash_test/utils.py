import os
import re
import glob
import json
import logging
from datetime import datetime
from contextlib import contextmanager
from crmsh import utils as crmshutils
from . import config
from crmsh import log
from crmsh.sh import ShellUtils


logger = log.setup_logger(__name__)


CRED = '\033[31m'
CYELLOW = '\033[33m'
CGREEN = '\033[32m'
CEND = '\033[0m'

LEVEL = {
    "info": logging.INFO,
    "warn": logging.WARNING,
    "error": logging.ERROR
}


class MyLoggingFormatter(logging.Formatter):
    """
    Class to change logging formatter
    """

    FORMAT_FLUSH = "[%(asctime)s]%(levelname)s: %(message)s"
    FORMAT_NOFLUSH = "%(timestamp)s%(levelname)s: %(message)s"

    COLORS = {
        'WARNING': CYELLOW,
        'INFO': CGREEN,
        'ERROR': CRED
    }

    def __init__(self, flush=True):
        fmt = self.FORMAT_FLUSH if flush else self.FORMAT_NOFLUSH
        logging.Formatter.__init__(self, fmt=fmt, datefmt='%Y/%m/%d %H:%M:%S')

    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            levelname_color = self.COLORS[levelname] + levelname + CEND
            record.levelname = levelname_color
        return logging.Formatter.format(self, record)


def now(form="%Y/%m/%d %H:%M:%S"):
    return datetime.now().strftime(form)


@contextmanager
def manage_handler(_type, keep=True):
    """
    Define a contextmanager to remove specific logging handler temporarily
    """
    try:
        handler = get_handler(logger, _type)
        if not keep:
            logger.removeHandler(handler)
        yield
    finally:
        if not keep:
            logger.addHandler(handler)


def msg_raw(level, msg, to_stdout=True):
    with manage_handler("console", to_stdout):
        logger.log(level, msg)


def msg_info(msg, to_stdout=True):
    msg_raw(logging.INFO, msg, to_stdout)


def msg_warn(msg, to_stdout=True):
    msg_raw(logging.WARNING, msg, to_stdout)


def msg_error(msg, to_stdout=True):
    msg_raw(logging.ERROR, msg, to_stdout)


def json_dumps():
    """
    Dump the json results to file
    """
    from . import main
    with open(main.ctx.jsonfile, 'w') as f:
        f.write(json.dumps(main.ctx.task_list, indent=2))
        f.flush()
        os.fsync(f)


class FenceInfo(object):
    """
    Class to collect fence info
    """
    @property
    def fence_enabled(self):
        enable_result = crmshutils.get_property("stonith-enabled")
        if not enable_result or enable_result.lower() != "true":
            return False
        return True

    @property
    def fence_configured(self):
        return crmshutils.has_stonith_running()

    @property
    def fence_action(self):
        action_result = crmshutils.get_property("stonith-action")
        if action_result is None or action_result not in ["off", "poweroff", "reboot"]:
            msg_error("Cluster property \"stonith-action\" should be reboot|off|poweroff")
            return None
        return action_result

    @property
    def fence_timeout(self):
        timeout_result = crmshutils.get_property("stonith-timeout")
        if timeout_result and re.match(r'[1-9][0-9]*(s|)$', timeout_result):
            return timeout_result.strip("s")
        return config.FENCE_TIMEOUT


def check_node_status(node, state):
    """
    Check whether the node has expected state
    """
    rc, stdout, stderr = ShellUtils().get_stdout_stderr('crm_node -l')
    if rc != 0:
        msg_error(stderr)
        return False
    pattern = re.compile(r'^.* {} {}'.format(node, state), re.MULTILINE)
    if not pattern.search(stdout):
        return False
    return True


def online_nodes():
    """
    Get online node list
    """
    rc, stdout, stderr = ShellUtils().get_stdout_stderr('crm_mon -1')
    if rc == 0 and stdout:
        res = re.search(r'Online:\s+\[\s(.*)\s\]', stdout)
        if res:
            return res.group(1).split()
    return []


def peer_node_list():
    """
    Get online node list except self
    """
    online_nodelist = online_nodes()
    if online_nodelist:
        online_nodelist.remove(this_node())
        return online_nodelist
    return []


def this_node():
    """
    Try to get the node name from crm_node command
    If failed, use its hostname
    """
    rc, stdout, stderr = ShellUtils().get_stdout_stderr("crm_node --name")
    if rc != 0:
        msg_error(stderr)
        return crmshutils.this_node()
    return stdout


def str_to_datetime(str_time, fmt):
    return datetime.strptime(str_time, fmt)


def corosync_port_list():
    """
    Get corosync ports using corosync-cmapctl
    """
    ports = []
    rc, out, _ = ShellUtils().get_stdout_stderr("corosync-cmapctl totem.interface")
    if rc == 0 and out:
        ports = re.findall(r'(?:mcastport.*) ([0-9]+)', out)
    return ports


def get_handler(logger, _type):
    """
    Get logger specific handler
    """
    for h in logger.handlers:
        if getattr(h, '_name') == _type:
            return h


def is_root():
    return os.getuid() == 0


def get_process_status(s):
    """
    Returns true if argument is the name of a running process.

    s: process name
    returns Boolean and pid
    """
    # find pids of running processes
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    for pid in pids:
        try:
            pid_file = os.path.join('/proc', pid, 'cmdline')
            with open(pid_file, 'rb') as f:
                data = f.read()
                procname = os.path.basename(crmshutils.to_ascii(data).replace('\x00', ' ').split(' ')[0])
                if procname == s or procname == s + ':':
                    return True, int(pid)
        except EnvironmentError:
            # a process may have died since we got the list of pids
            pass
    return False, -1


def _find_match_count(str1, str2):
    """
    Find the max match number of s1 and s2
    """
    leng = min(len(str1), len(str2))
    num = 0

    for i in range(leng):
        if str1[i] == str2[i]:
            num += 1
        else:
            break

    return num


def is_valid_sbd(dev):
    """
    Check whether the device is a initialized SBD device

    dev: dev path
    return 'True' if 'dev' is a initialized SBD device
    """
    if not os.path.exists(dev):
        return False

    rc, out, err = ShellUtils().get_stdout_stderr(config.SBD_CHECK_CMD.format(dev=dev))
    if rc != 0 and err:
        msg_error(err)
        return False

    return True


def find_candidate_sbd(dev):
    """
    Find the devices that already have SBD header

    return the path of candidate SBD device
    """
    ddir = os.path.dirname(dev)
    dname = os.path.basename(dev)

    dev_list = glob.glob(ddir + "/*")
    if len(dev_list) == 0:
        return ""

    can_filter = filter(is_valid_sbd, dev_list)
    candidates = list(can_filter)

    if len(candidates) == 0:
        return ""

    index = 0
    i = 0
    max_match = -1
    num_list = map(_find_match_count, [dev] * len(candidates), candidates)
    for num in num_list:
        if num > max_match:
            max_match = num
            index = i
        i += 1

    return candidates[index]


def warning_ask(warn_string):
    from . import main
    if main.ctx.force:
        return False
        
    try:
        ans = input(CYELLOW + warn_string + CEND)
    except EOFError:
        return False
    return True if ans == "Yes" else False
