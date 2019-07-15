import os
import sys
import argparse
import datetime
import atexit
import shutil
import time
import glob
import tarfile
import multiprocessing

import utils
from crmsh import utils as crmutils
from crmsh import corosync
from crmsh.config import report, path, core


NAME = 'hb_report'
CIB_F = "cib.xml"
HALOG_F = "ha-log.txt"
JOURNAL_F = "journal.log"
WORKDIR_PREFIX = ".hb_report.workdir"
PCMK_LOG = "/var/log/pacemaker/pacemaker.log /var/log/pacemaker.log"
UNIQUE_MSG= "Mark:HB_REPORT:{}".format(utils.now())
TRY_SSH = "root hacluster"
SSH_OPTS = "-o StrictHostKeyChecking=no -o EscapeChar=none -o ConnectTimeout=15"


def is_collector():
    """
    the instance where user runs hb_report is the master
    the others are slaves
    """
    return len(sys.argv) > 1 and sys.argv[1] == "__slave"


def include_me(context):
    return utils.me() in context.nodes


def get_nodes(context):
    """
    find nodes for this cluster
    """
    # 1. set by user
    if context.nodes:
        return

    # 2. running crm
    if crmutils.is_process("pacemaker-controld") or crmutils.is_process("crmd"):
        cmd = "crm node server"
    # 3. if the cluster's stopped, try the CIB
    else:
        cmd = r"(CIB_file=%s/%s crm node server)" % (context.cib_dir, CIB_F)

    info = utils.get_command_info(cmd)
    if info:
        context.nodes = info.split('\n')


class Context(object):

    def __init__(self):
        self.__dict__['from_time'] = utils.parse_to_timestamp(report.from_time)
        self.__dict__['no_compress'] = not report.compress
        self.__dict__['speed_up'] = report.speed_up
        self.__dict__['extra_logs'] = report.collect_extra_logs
        self.__dict__['rm_exist_dest'] = report.remove_exist_dest
        self.__dict__['single'] = report.single_node

        self.__dict__['to_time'] = 0
        self.__dict__['sensitive_regex'] = "passw.*"
        self.__dict__['regex'] = "CRIT: ERROR:"
        self.__dict__['dest'] = '{}-{}'.format(NAME, utils.now("%a-%d-%b-%Y"))
        self.__dict__['ssh_askpw_nodes'] = []

    def __str__(self):
        _str = ""
        for key, value in self.__dict__.items():
            _str += "{}=={}=={}\n".format(key, value, type(value))
        return _str

    def __setattr__(self, name, value):
        if name in ["from_time", "to_time"]:
            value = utils.parse_to_timestamp(value)
        elif isinstance(value, list) and utils.is_2dlist(value):
            value = utils.zip_nested(value)
        super().__setattr__(name, value)

    def __setitem__(self, key, value):
        self.__dict__[key] = value

    def create_tempfile(self):
        self.temp_file = utils.make_temp_file()
        utils.log_debug("create tempfile \"{}\"".format(self.temp_file))

    def add_tempfile(self, filename):
        with open(self.temp_file, 'a') as f:
            f.write(filename + '\n')
        utils.log_debug("add tempfile \"{}\" to \"{}\"".format(filename, self.temp_file))

    def drop_tempfile(self):
        with open(self.temp_file, 'r') as f:
            for line in f.read().split('\n'):
                if os.path.isdir(line):
                    shutil.rmtree(line)
                if os.path.isfile(line):
                    os.remove(line)
        os.remove(self.temp_file)
        utils.log_debug("remove tempfile \"{}\"".format(self.temp_file))


def print_extra_help():
    print('''
  . the multifile output is stored in a tarball {dest}.tar.bz2
  . the time specification is as in either Date::Parse or
    Date::Manip, whatever you have installed; Date::Parse is
    preferred
  . we try to figure where is the logfile; if we can't, please
    clue us in ('-l')
  . we collect only one logfile and /var/log/messages; if you
    have more than one logfile, then use '-E' option to supply
    as many as you want ('-M' empties the list)

  Examples

    report -f 2pm report_1
    report -f "2007/9/5 12:30" -t "2007/9/5 14:00" report_2
    report -f 1:00 -t 3:00 -l /var/log/cluster/ha-debug report_3
    report -f "09sep07 2:00" -u hbadmin report_4
    report -f 18:00 -p "usern.*" -p "admin.*" report_5
    report -f cts:133 ctstest_133

  . WARNING . WARNING . WARNING . WARNING . WARNING . WARNING .

    We won't sanitize the CIB and the peinputs files, because
    that would make them useless when trying to reproduce the
    PE behaviour. You may still choose to obliterate sensitive
    information if you use the -s and -p options, but in that
    case the support may be lacking as well. The logs and the
    crm_mon, ccm_tool, and crm_verify output are *not* sanitized.

    Additional system logs (/var/log/messages) are collected in
    order to have a more complete report. If you don't want that
    specify -M.

    IT IS YOUR RESPONSIBILITY TO PROTECT THE DATA FROM EXPOSURE!''')



def parse_argument(context):
    parser = argparse.ArgumentParser(description='{} - create report for HA cluster'.format(NAME),
                                     add_help=False)
    parser.add_argument('-h', '--help', dest='help', action='store_true',
                        help='show this help message and exit')
    parser.add_argument('-f', dest='from_time', metavar='time',
                        help='time to start from')
    parser.add_argument('-t', dest='to_time', metavar='time',
                        help='time to finish at (default: now)')
    parser.add_argument('-d', dest='no_compress', action='store_true',
                        help="don't compress, but leave result in a directory")
    parser.add_argument('-n', dest='nodes', metavar='node', nargs='*', action='append',
                        help='''node names for this cluster; this option is additive
                                (use either -n a b or -n a -n b)
                                if you run report on the loghost or use autojoin,
                                it is highly recommended to set this option''')
    parser.add_argument('-u', dest='ssh_user', metavar='user',
                        help='ssh user to access other nodes'),
    parser.add_argument('-X', dest='ssh_options', metavar='ssh-options',
                        help='extra ssh(1) options'),
    parser.add_argument('-l', dest='ha_log', metavar='file',
                        help='log file')
    parser.add_argument('-E', dest='extra_logs', metavar='file', nargs='*', action='append',
                        help='''extra logs to collect; this option is additive
                                (dflt: /var/log/messages)''')
    parser.add_argument('-s', dest='sanitize', action='store_true',
                        help='sanitize the PE and CIB files')
    parser.add_argument('-p', dest='sensitive_regex', metavar='patt', nargs='*', action='append',
                        help='''regular expression to match variables containing sensitive data;
                                this option is additive (dflt: "passw.*")''')
    parser.add_argument('-L', dest='regex', metavar='patt', nargs='*', action='append',
                        help='''regular expression to match in log files for analysis;
                                this option is additive (dflt: CRIT: ERROR:)''')
    parser.add_argument('-e', dest='editor', metavar='prog',
                        help='your favourite editor')
    parser.add_argument('-Q', dest='speed_up', action='store_true',
                        help="don't run resource intensive operations (speed up)")
    parser.add_argument('-M', dest='no_extra', action='store_true',
                        help="don't collect extra logs (/var/log/messages)")
    parser.add_argument('-D', dest='no_editor', action='store_true',
                        help="don't invoke editor to write description")
    parser.add_argument('-Z', dest='rm_exist_dest', action='store_true',
                        help='if destination directories exist, remove them instead of exiting')
    parser.add_argument('-S', dest='single', action='store_true',
                        help='''single node operation; don't try to start report
                                collectors on other nodes''')
    parser.add_argument('-v', dest='debug', action='store_true',
                        help='increase verbosity')
    parser.add_argument('-V', dest='version', action='store_true',
                        help='print version')
    parser.add_argument('dest', nargs='?',
                        help='report name (may include path where to store the report)')

    args = parser.parse_args()
    if args.help:
        parser.print_help()
        print_extra_help()
        sys.exit(0)

    for arg in vars(args):
        value = getattr(args, arg)
        if value or not hasattr(context, arg):
            setattr(context, arg, value)

    process_some_arguments(context)


def process_some_arguments(context):
    context.from_time_str = utils.dt_to_str(utils.ts_to_dt(context.from_time))
    if context.to_time == 0:
        context.to_time_str = utils.now()
    else:
        context.to_time_str = utils.dt_to_str(utils.ts_to_dt(context.to_time))

    if context.ha_log and \
       not os.path.isfile(context.ha_log) and \
       not is_collector():
        utils.log_warning("\"{}\" not found; we will try to find log ourselves".format(context.ha_log))


def load_from_config(context):
    context.cib_dir = getattr(path, 'crm_config', None)
    if not context.cib_dir or not os.path.isdir(context.cib_dir):
        utils.log_fatal("Cannot find cib files directory!")

    context.debug = getattr(context, 'debug', getattr(core, 'debug', False))

    # from corosync.conf
    context.to_logfile = crmutils.get_boolean(corosync.get_value('logging.to_logfile'))
    context.logfile = corosync.get_value('logging.logfile')
    context.log_facility = corosync.get_value('logging.syslog_facility')
    if not context.log_facility:
        context.log_facility = "daemon"


def is_our_log(context, logf):
    """
    check if the log contains a piece of our segment
    """
    if tarfile.is_tarfile(logf):
        data = utils.get_data_from_tarfile(logf)
        if data is None:
            return 0 # don't include this log
    else:
        with open(logf, 'r', encoding='utf-8', errors="replace") as fd:
            data = fd.read()

    # reset this var to check every file's format
    if hasattr(context, 'stamp_type'):
        delattr(context, "stamp_type")
    first_time = utils.find_first_ts(utils.head(10, data))
    last_time = utils.find_first_ts(utils.tail(10, data))
    from_time = context.from_time
    to_time = context.to_time

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


def arch_logs(context, logf):
    """
    go through archived logs (timewise backwards) and see if there
    are lines belonging to us
    (we rely on untouched log files, i.e. that modify time
    hasn't been changed)
    """
    ret = []
    # look for rotation files such as: ha-log-20090308 or
    # ha-log-20090308.gz (.bz2) or ha-log.0, etc
    files = [logf] + glob.glob(logf+"*[0-9z]")
    for f in sorted(files, key=os.path.getctime):
        res = is_our_log(context, f)
        if res == 0: # noop, continue
            continue
        elif res == 1: # include log and continue
            ret.append(f)
            utils.log_debug("found log %s" % f)
        elif res == 2: # don't go through older logs!
            break
        elif res == 3: # include log and continue
            ret.append(f)
            utils.log_debug("found log %s" % f)
            break
    return ret


def print_logseg(context, logf):
    if tarfile.is_tarfile(logf):
        data = utils.get_data_from_tarfile(logf)
        if data is None:
            return
    
    from_time = context.from_time
    to_time = context.to_time

    if not from_time or from_time == 0:
        from_line = 1
    else:
        from_line = utils.findln_by_time(logf, from_time)
    if from_line is None:
        utils.log_warning("couldn't find line for time {}; corrupt log file?".format(from_time))
        return

    if to_time != 0:
        to_line = findln_by_time(logf, to_time)
        if to_line is None:
            utils.log_warning("couldn't find line for time {}; corrupt log file?".format(to_time))
            return

    utils.log_debug("including segment [{}-{}] from {}".format(from_line, to_line, logf))  
    return utils.filter_lines(logf, from_line, to_line)    


def get_log(context):
    if context.extra_logs:
        collect_journal(context)

    if not context.ha_log:
        context.ha_log = find_log(context)
    if not context.ha_log or not os.path.isfile(context.ha_log):
        utils.log_warning("no log at {}".format(utils.me()))
        return
    utils.log_debug("find ha-log {}".format(context.ha_log))

    outf = os.path.join(context.work_dir, HALOG_F)
    dump_logset(context, context.ha_log, outf)


def find_log(context):
    #journalctl -u pacemaker -u corosync -u sbd
    if context.extra_logs:
        for f in context.extra_logs.split():
            if os.path.isfile(f) and f not in PCMK_LOG.split():
                return f

        f = os.path.join(context.work_dir, JOURNAL_F)
        if os.path.isfile(f):
            return f

        for f in PCMK_LOG.split():
            if os.path.isfile(f):
                return f
    else:
        utils.log_debug("will try with {}".format(context.logfile))
        return context.logfile


def dump_logset(context, logf, outf):
    '''
    find log/set of logs which are interesting for us
    '''
    logf_set = []
    logf_set = arch_logs(context, logf)
    if len(logf_set) == 0:
        return

    num_logs = len(logf_set)
    oldest = logf_set[-1]
    newest = logf_set[0]
    mid_logfiles = logf_set[1:-1]
    out_string = ""

    # the first logfile: from $from_time to $to_time (or end)
    # logfiles in the middle: all
    # the last logfile: from beginning to $to_time (or end)
    if num_logs == 1:
        out_string += print_logseg(newest, context)
    else:
        out_string += print_logseg(oldest, from_time, 0)
        for f in mid_logfiles:
            out_string += print_log(f)
            log_debug("including complete %s logfile" % f)
        out_string += print_logseg(newest, 0, to_time)

    crmutils.str2file(out_string, outf)


def valid_dest(context):
    dest_dir = utils.dirname(context.dest)
    if not os.path.isdir(dest_dir):
        utils.log_fatal('{} is invalid directory name'.format(dest_dir))

    dest_file = os.path.basename(context.dest)
    if not crmutils.is_filename_sane(dest_file):
        utils.log_fatal('{} is invalid file name'.format(dest_file))

    if context.no_compress and os.path.isdir(context.dest):
        if context.rm_exist_dest:
            shutil.rmtree(context.dest)
        else:
            utils.log_fatal('destination directory {} exists, \
                             please cleanup or use -Z option'.format(context.dest))
  

def setup_workdir(context):
    valid_dest(context)
    tmpdir = utils.make_temp_dir()
    context.add_tempfile(tmpdir)
    if not is_collector():
        context.work_dir = os.path.join(tmpdir, os.path.basename(context.dest))
    else:
        context.work_dir = os.path.join(tmpdir,
                                        os.path.basename(context.dest),
                                        utils.me())
    utils._mkdir(context.work_dir)
    utils.log_debug('set up work directory in {}'.format(context.work_dir))


def collect_journal(context):
    if not utils.which("journalctl"):
        utils.log_warning("Command journalctl not found")
        return

    outf = os.path.join(context.work_dir, JOURNAL_F)
    if os.path.isfile(outf):
        utils.log_warning("{} already exists".format(outf))

    utils.log_debug("journalctl from: '{}' until: '{}' from_time: '{}' to_time: '{}' > {}".\
                    format(context.from_time,
                           context.to_time,
                           context.from_time_str,
                           context.to_time_str,
                           outf))

    cmd = 'journalctl -o short-iso --since "{}" --until "{}" --no-pager | tail -n +2'.\
          format(context.from_time_str, context.to_time_str)
    utils.log_debug("running command: {}".format(cmd))
    info = utils.get_command_info(cmd)
    if info:
        crmutils.str2file(info, outf)


def test_ssh_conn(addr):
    cmd = r"ssh %s -T -o Batchmode=yes %s true" % (SSH_OPTS, addr)
    rc, _, _= crmutils.get_stdout_stderr(cmd)
    return rc == 0


def find_ssh_user(context):
    ssh_user = "__undef"

    if not context.ssh_user:
        try_user_list = "__default " + TRY_SSH
    else:
        try_user_list = context.ssh_user

    for n in context.nodes:
        rc = 1
        if n == utils.me():
            continue
        for u in try_user_list.split():
            if u != '__default':
                ssh_s = '@'.join((u, n))
            else:
                ssh_s = n

            if test_ssh_conn(ssh_s):
                utils.log_debug("ssh {} OK".format(ssh_s))
                ssh_user = u
                try_user_list = u
                rc = 0
                break
            else:
                utils.log_debug("ssh {} failed".format(ssh_s))
        if rc == 1:
            context.ssh_askpw_nodes.append(n)

    if context.ssh_askpw_nodes:
        utils.log_warning("passwordless ssh to node(s) {} does not work".format(context.ssh_askpw_nodes))
    if ssh_user == "__undef":
        return
    if ssh_user != "__default":
        context.ssh_user = ssh_user


def say_ssh_user(context):
    if context.ssh_user:
        return context.ssh_user
    else:
        return "your user"


def ssh_issue(context):
    if not context.single:
        find_ssh_user(context)

    ssh_opts = SSH_OPTS
    if context.ssh_user:
        ssh_opts += " -o User={}".format(context.ssh_user)
    context.ssh_opts = ssh_opts

    if (not context.ssh_user and os.getuid() != 0) or \
        context.ssh_user and context.ssh_user != "root":
        utils.log_debug("ssh user other than root, use sudo")
        context.sudo = "sudo -u root"

    if os.getuid() != 0:
        utils.log_debug("local user other than root, use sudo")
        context.local_sudo = "sudo -u root"


def collect_for_nodes(context):
    if not context.single:
        nodes = context.nodes
    elif include_me(context):
        nodes = [utils.me()]

    for node in nodes:
        if node in context.ssh_askpw_nodes:
            utils.log_info("Please provide password for {} at {}".\
                           format(say_ssh_user(context), node))
            utils.log_info("Note that collecting data will take a while.")
        else:
            p = multiprocessing.Process(target=start_slave_collector, args=(context, node))
            p.start()
            p.join()


def start_slave_collector(context, node):
    if node == utils.me():
        cmd = r"./{} __slave '{}'".format(context.name, context)
        #utils.log_debug("run: {}".format(cmd))
        crmutils.get_stdout(cmd)
    else:
        pass
        '''
        cmd = r'ssh {} {} "{} hb_report __slave"'.\
              format(constants.SSH_OPTS, node,
                     constants.SUDO, os.getcwd())
        for item in arg_str.split():
            cmd += " {}".format(str(item))
        code, out, err = crmutils.get_stdout_stderr(cmd)
        if code != 0:
            log_warning(err)
            for ip in get_peer_ip():
                log_info("Trying connect by %s" % ip)
                cmd = cmd.replace(node, ip, 1)
                code, out, err = crmutils.get_stdout_stderr(cmd)
                if code != 0:
                    log_warning(err)
                break
         '''


def type_convert(_type, value):
    def str_to_bool(v):
        return v.lower() in ["true"]

    if "str" in _type:
        return str(value)
    if "float" in _type:
        return float(value)
    if "bool" in _type:
        return str_to_bool(value)
    if "int" in _type:
        return int(value)
    if "list" in _type:
        return list(value)
    if "NoneType" in _type:
        return None


def load_context(context):
    for item in sys.argv[2].split('\n')[:-1]:
        key, value, _type = item.split('==')
        context[key] = type_convert(_type, value)


def run(context):
    if is_collector():
        load_context(context)
    else:
        parse_argument(context)
        load_from_config(context)

    context.create_tempfile()
    atexit.register(context.drop_tempfile)
    setup_workdir(context)

    if not is_collector():
        get_nodes(context)
        utils.log_debug("nodes: {}".format(context.nodes))
        if not include_me(context):
            utils.log_warning("this is not a node and you didn't specify a list of nodes using -n")

        ssh_issue(context)

    if is_collector():
        utils.log_mark("{}.info {}".format(context.log_facility, UNIQUE_MSG))

    if include_me(context):
        get_log(context)

    if not is_collector():
        collect_for_nodes(context)


ctx = Context()
