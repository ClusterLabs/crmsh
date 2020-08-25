import os
import sys
import argparse
import datetime
import shutil
import time
import glob
import re
import json
from multiprocessing import Process

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from hb_report import const, utils, collect
from crmsh import utils as crmutils
from crmsh import corosync, tmpfiles
from crmsh.config import report, path, core


def is_collector():
    '''
    collector is for collecting logs and data
    '''
    return len(sys.argv) > 2 and sys.argv[1] == "__slave"


def include_me(node_list):
    return utils.me() in node_list


def get_nodes(context):
    '''
    find nodes to collect
    '''
    # not set by using -n
    if not context.nodes:
        nodes = crmutils.list_cluster_nodes()
        if not nodes:
            utils.log_fatal("Could not figure out a list of nodes; is this a cluster node?")
        context.nodes = nodes
    if context.single and include_me(context.nodes):
        context.nodes = [utils.me()]

    utils.log_debug1("Nodes to collect: {}".format(context.nodes))


class Context(object):

    def __init__(self):
        self.__dict__['from_time'] = utils.parse_to_timestamp(report.from_time)
        self.__dict__['no_compress'] = not report.compress
        self.__dict__['speed_up'] = report.speed_up
        self.__dict__['extra_logs'] = report.collect_extra_logs.split()
        self.__dict__['rm_exist_dest'] = report.remove_exist_dest
        self.__dict__['single'] = report.single_node

        self.__dict__['to_time'] = utils.parse_to_timestamp(utils.now())
        self.__dict__['sensitive_regex'] = ["passw.*"]
        self.__dict__['regex'] = "CRIT: ERROR: error: warning: crit:".split()
        self.__dict__['ssh_askpw_nodes'] = []

    def __str__(self):
        return json.dumps(self.__dict__)

    def __setattr__(self, name, value):
        if name == "before_time" and value:
            if not re.match('^[1-9][0-9]*[YmdHM]$', value):
                utils.log_fatal("Wrong format of -b option ([1-9][0-9]*[YmdHM])")
        if name in ["from_time", "to_time"] and value:
            value = utils.parse_to_timestamp(value)
        if name == "ssh_options" and value:
            value = utils.unzip_list(value)
            for item in value:
                if not re.search('.*=.*', item):
                    utils.log_fatal("Wrong format of ssh option \"{}\"".format(item))
        if name == "nodes" and value:
            value = utils.unzip_list(value)
        if name in ["extra_logs", "regex", "sensitive_regex"] and value:
            value = utils.unzip_list(value) + self.__dict__[name]
        if isinstance(value, list):
            value = utils.unique(value)
        super().__setattr__(name, value)

    def __setitem__(self, key, value):
        self.__dict__[key] = value

    def dumps(self):
        return json.dumps(self.__dict__, indent=2)


def parse_argument(context):
    parser = argparse.ArgumentParser(
            usage="{} [options] [dest]".format(context.name),
            add_help=False,
            formatter_class=lambda prog: argparse.HelpFormatter(prog, width=80))
    parser.add_argument("-h", "--help", action="store_true", dest="help",
            help="Show this help message and exit")
    parser.add_argument('-f', dest='from_time', metavar='time',
            help='Time to start from (default: 12 hours before)')
    parser.add_argument('-t', dest='to_time', metavar='time',
            help='Time to finish at (default: now)')
    parser.add_argument('-b', dest='before_time', metavar='time',
            help='How long time in the past, before now ([1-9][0-9]*[YmdHM])')
    parser.add_argument('-d', dest='no_compress', action='store_true',
            help="Don't compress, but leave result in a directory")
    parser.add_argument('-n', dest='nodes', metavar='node', action="append", default=[],
            help='Node names for this cluster; this option is additive (use -n a -n b or -n "a b"); if you run report on the loghost or use autojoin, it is highly recommended to set this option''')
    parser.add_argument('-u', dest='ssh_user', metavar='user',
            help='SSH user to access other nodes'),
    parser.add_argument('-X', dest='ssh_options', metavar='ssh-options', action='append', default=[],
            help='Extra ssh(1) options (default: StrictHostKeyChecking=no EscapeChar=none ConnectTimeout=15); this option is additive (use -X opt1 -X opt2 or -X "opt1 opt2")'),
    parser.add_argument('-E', dest='extra_logs', metavar='file', action='append', default=[],
            help='Extra logs to collect (default: /var/log/messages, /var/log/ha-cluster-bootstrap.log); this option is additive (use -E file1 -E file2 or -E "file1 file2")')
    parser.add_argument('-s', dest='sanitize', action='store_true',
            help='Replace sensitive info in PE or CIB or pacemaker log files')
    parser.add_argument('-p', dest='sensitive_regex', metavar='patt', action='append', default=[],
            help='Regular expression to match variables containing sensitive data (default: passw.*); this option is additive (use -p patt1 -p patt2 or -p "patt1 patt2")')
    parser.add_argument('-L', dest='regex', metavar='patt', action='append', default=[],
            help='Regular expression to match in log files for analysis (default: CRIT:, ERROR:, error:, warning:, crit:); this option is additive (use -L patt1 -L patt2 or -L "patt1 patt2")')
    parser.add_argument('-Q', dest='speed_up', action='store_true',
            help="The quick mode, which skips producing dot files from PE inputs, verifying installed cluster stack rpms and sanitizing files for sensitive information")
    parser.add_argument('-M', dest='no_extra', action='store_true',
            help="Don't collect extra logs, opposite option of -E")
    parser.add_argument('-Z', dest='rm_exist_dest', action='store_true',
            help='If destination directories exist, remove them instead of exiting')
    parser.add_argument('-S', dest='single', action='store_true',
            help="Single node operation; don't try to start report collectors on other nodes")
    parser.add_argument('-v', dest='debug', action='count', default=0,
            help='Increase verbosity')
    parser.add_argument('dest', nargs='?',
            help='Report name (may include path where to store the report)')

    args = parser.parse_args()
    if args.help:
        parser.print_help()
        print(const.EXTRA_HELP)
        sys.exit(0)

    check_exclusive_options(args)
    try:
        crmutils.check_space_option_value(args)
    except ValueError as err:
        utils.log_fatal(err)

    for arg in vars(args):
        value = getattr(args, arg)
        if value or not hasattr(context, arg):
            setattr(context, arg, value)

    process_some_arguments(context)


def check_exclusive_options(args):
    if args.from_time and args.before_time:
        utils.log_fatal("-f and -b options are exclusive")
    if args.to_time and args.before_time:
        utils.log_fatal("-t and -b options are exclusive")
    if args.nodes and args.single:
        utils.log_fatal("-n and -S options are exclusive")
    if args.extra_logs and args.no_extra:
        utils.log_fatal("-E and -M options are exclusive")
    if args.speed_up and args.sanitize:
        utils.log_fatal("-s and -Q options are exclusive")


def process_some_arguments(context):
    if context.before_time:
        context.from_time = context.before_time

    if context.to_time <= context.from_time:
        utils.log_fatal("Start time must be before finish time")

    if not context.dest:
        context.dest = '{}-{}'.format(context.name, utils.now("%a-%d-%b-%Y"))

    context.from_time_str = utils.ts_to_str(context.from_time)
    context.to_time_str = utils.ts_to_str(context.to_time)
    _, context.from_time_file = tmpfiles.create(time=context.from_time)
    _, context.to_time_file = tmpfiles.create(time=context.to_time)


def get_ocf_root(context):
    context.ocf_root = getattr(path, 'ocf_root', None)
    if not context.ocf_root or not os.path.isdir(context.ocf_root):
        utils.log_fatal("Cannot find ocf root directory!")


def get_ha_varlib(context):
    ocf_lib_file = "{}/lib/heartbeat/ocf-directories".format(context.ocf_root)
    if not os.path.exists(ocf_lib_file):
        utils.log_fatal("File {} not exist".format(ocf_lib_file))
    with open(ocf_lib_file) as f:
        data = f.read()
    for line in data.split('\n'):
        res = re.search(r'HA_VARLIB:=(.*)}', line)
        if res:
            context.ha_varlib = res.group(1)


def get_pe_dir(context):
    context.pe_dir = getattr(path, 'pe_state_dir', None)
    if not context.pe_dir or not os.path.isdir(context.pe_dir):
        utils.log_fatal("Cannot find PE files directory!")


def get_cib_dir(context):
    context.cib_dir = getattr(path, 'crm_config', None)
    if not context.cib_dir or not os.path.isdir(context.cib_dir):
        utils.log_fatal("Cannot find CIB files directory!")


def get_cores_dir(context):
    context.pcmk_lib = os.path.dirname(context.cib_dir)
    utils.log_debug2("Setting PCMK_LIB to %s" % context.pcmk_lib)
    context.cores_dirs = os.path.join(context.pcmk_lib, "cores")
    if os.path.isdir(const.COROSYNC_LIB):
        context.cores_dirs += " {}".format(const.COROSYNC_LIB)


def load_from_corosync_conf(context):
    if not os.path.exists(corosync.conf()):
        return
    context.to_logfile = crmutils.get_boolean(corosync.get_value('logging.to_logfile'))
    context.logfile = corosync.get_value('logging.logfile')
    context.log_facility = corosync.get_value('logging.syslog_facility')
    if not context.log_facility:
        context.log_facility = "daemon"


def load_from_config(context):
    '''
    load context attributes from crmsh.config and corosync.conf
    '''
    get_ocf_root(context)
    get_ha_varlib(context)
    get_pe_dir(context)
    get_cib_dir(context)
    get_cores_dir(context)
    load_from_corosync_conf(context)


def is_our_log(context, logf):
    '''
    check if the log contains a piece of our segment

    return value
    0      good log;        include
    1      irregular log;   include
    2      empty log;       don't include
    3      before timespan; don't include
    4      after timespan;  don't include
    '''
    data = utils.read_from_file(logf)
    if not data:
        utils.log_debug2("Found empty file \"{}\"; exclude".format(logf))
        return 2

    # reset this attr to check file's format
    if hasattr(context, 'stamp_type'):
        delattr(context, "stamp_type")
    first_time = utils.find_first_ts(utils.head(10, data))
    last_time = utils.find_first_ts(utils.tail(10, data))
    from_time = context.from_time
    to_time = context.to_time

    if (not first_time) or (not last_time):
        utils.log_debug2("Found irregular file \"{}\"; include".format(logf))
        return 1
    if from_time > last_time:
        utils.log_debug2("Found before timespan file \"{}\"; exclude".format(logf))
        return 3
    if from_time >= first_time:
        utils.log_debug2("Found in timespan file \"{}\"; include".format(logf))
        return 0
    if to_time >= first_time:
        utils.log_debug2("Found in timespan file \"{}\"; include".format(logf))
        return 0
    else:
        utils.log_debug2("Found after timespan file \"{}\"; exclude".format(logf))
        return 4


def arch_logs(context, logf):
    '''
    go through archived logs (timewise backwards) and see if there
    are lines belonging to us
    (we rely on untouched log files, i.e. that modify time
    hasn't been changed)
    '''
    ret = []
    _type = -1
    # look for rotation files such as: ha-log-20090308 or
    # ha-log-20090308.gz (.bz2) or ha-log.0, etc
    files = [logf] + glob.glob(logf+"*[0-9z]")
    # like ls -t, newest first
    for f in sorted(files, key=os.path.getmtime, reverse=True):
        res = is_our_log(context, f)
        # empty or after timespan, continue
        if res in [2, 4]:
            continue
        # before timespan, no need go ahead
        if res == 3:
            break
        # good/irregular file, append
        if res in [0, 1]:
            _type = res
            ret.append(f)
    if ret:
        utils.log_debug2("Found logs {}".format(ret))
    return _type, ret


def print_logseg(logf, from_time, to_time):
    data = utils.read_from_file(logf)

    if from_time == 0:
        from_line = 1
    else:
        from_line = utils.findln_by_time(data, from_time)
        if from_line is None:
            utils.log_warning("Couldn't find line in {} for time {}".\
                    format(logf, utils.ts_to_str(from_time)))
            return ""

    if to_time == 0:
        to_line = len(data.split('\n'))
    else:
        to_line = utils.findln_by_time(data, to_time)
        if to_line is None:
            utils.log_warning("Couldn't find line in {} for time {}".\
                    format(logf, utils.ts_to_str(to_time)))
            return ""

    utils.log_debug2("Including segment [{}-{}] from {}".format(from_line, to_line, logf))  
    return utils.filter_lines(data, from_line, to_line) 


def dump_logset(context, logf):
    '''
    find log/set of logs which are interesting for us
    '''
    logf_type, logf_list = arch_logs(context, logf)
    if not logf_list:
        utils.log_debug2("No suitable log set found for log {}".format(logf))
        return

    out_string = ""
    # irregular file list
    if logf_type == 1:
        for f in logf_list:
            out_string += print_logseg(f, 0, 0)
            utils.log_debug2("Including complete {} logfile".format(f))
    else:
        num_logs = len(logf_list)
        if num_logs == 1:
            out_string += print_logseg(logf_list[0], context.from_time, context.to_time)
        else:
            newest, *middles, oldest = logf_list
            out_string += print_logseg(oldest, context.from_time, 0)
            for f in middles:
                out_string += print_logseg(f, 0, 0)
                utils.log_debug2("Including complete {} logfile".format(f))
            out_string += print_logseg(newest, 0, context.to_time)

    if out_string:
        outf = os.path.join(context.work_dir, os.path.basename(logf))
        crmutils.str2file(out_string.strip('\n'), outf)
        utils.log_debug1("Dump logset {} into {}/{}".\
                format(logf_list, context.dest_path, os.path.basename(logf)))


def valid_dest(context):
    dest_dir = utils.dirname(context.dest)
    if not os.path.isdir(dest_dir):
        utils.log_fatal('{} is invalid directory name'.format(dest_dir))
    context.dest_dir = dest_dir

    dest_file = os.path.basename(context.dest)
    if not crmutils.is_filename_sane(dest_file):
        utils.log_fatal('{} is invalid file name'.format(dest_file))

    if context.no_compress and os.path.isdir(context.dest):
        if context.rm_exist_dest:
            shutil.rmtree(context.dest)
        else:
            utils.log_fatal('Destination directory {} exists, please cleanup or use -Z option'.format(context.dest))

    context.dest = dest_file


def setup_workdir(context):
    '''
    setup work directory that we can put all logs into it
    '''
    valid_dest(context)
    tmpdir = tmpfiles.create_dir()
    if not is_collector():
        context.work_dir = os.path.join(tmpdir, os.path.basename(context.dest))
    else:
        context.work_dir = os.path.join(tmpdir,
                                        os.path.basename(context.dest),
                                        utils.me())
        context.dest_path = "{}/{}".format(context.dest, utils.me())
    utils._mkdir(context.work_dir)
    utils.log_debug2('Setup work directory in {}'.format(context.work_dir))


def collect_journal(context, cmd, outf):
    if not utils.which("journalctl"):
        utils.log_warning("Command journalctl not found")
        return

    utils.log_debug2("Running command: {}".format(' '.join(cmd.split())))
    rc, out, err = crmutils.get_stdout_stderr(cmd)
    if rc == 0 and out:
        utils.log_debug1("Dump {} into {}".format(os.path.basename(outf), context.dest_path))
        crmutils.str2file(out, outf)
    if rc != 0 and err:
        utils.log_error(err)


def collect_journal_ha(context):
    '''
    Using journalctl collect ha related log as ha-log.txt
    '''
    outf = os.path.join(context.work_dir, const.HALOG_F)
    cmd = 'journalctl -u pacemaker -u corosync -u sbd \
            --since "{}" --until "{}" \
            -o short-iso --no-pager | tail -n +2'.\
            format(context.from_time_str, context.to_time_str)
    collect_journal(context, cmd, outf)


def collect_journal_general(context):
    '''
    Using journalctl collect system log as journal.log
    '''
    outf = os.path.join(context.work_dir, const.JOURNAL_F)
    cmd = 'journalctl --since "{}" --until "{}" \
            -o short-iso --no-pager | tail -n +2'.\
            format(context.from_time_str, context.to_time_str)
    collect_journal(context, cmd, outf)


def collect_other_logs_and_info(context):
    #collect other configurations and information
    process_list = []
    for cf in const.COLLECT_FUNCTIONS:
        p = Process(target=getattr(collect, cf), args=(context,))
        p.start()
        process_list.append(p)
    for p in process_list:
        p.join()
    # replace sensitive content
    sanitize(context)


def find_ssh_user(context):
    ssh_user = "__undef"

    if not context.ssh_user:
        try_user_list = ["__default"] + const.TRY_SSH.split()
    else:
        try_user_list = [context.ssh_user]

    for n in context.nodes:
        rc = 1
        if n == utils.me():
            continue
        for u in try_user_list:
            if u != '__default':
                ssh_s = '@'.join((u, n))
            else:
                ssh_s = n

            if not crmutils.check_ssh_passwd_need([ssh_s]):
                utils.log_debug2("ssh {} OK".format(ssh_s))
                ssh_user = u
                try_user_list = [u] # we support just one user
                rc = 0
                break
            else:
                utils.log_debug2("ssh {} failed".format(ssh_s))
        if rc == 1:
            context.ssh_askpw_nodes.append(n)

    if context.ssh_askpw_nodes:
        utils.log_warning("Passwordless ssh to node(s) {} does not work".format(context.ssh_askpw_nodes))
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

    if context.ssh_options:
        ssh_opts = ' '.join(context.ssh_options)
    else:
        ssh_opts = const.SSH_OPTS
    if context.ssh_user:
        ssh_opts += " User={}".format(context.ssh_user)
    context.ssh_options = ssh_opts.split()

    context.sudo = ""
    if (not context.ssh_user and os.getuid() != 0) or \
        context.ssh_user and context.ssh_user != "root":
        utils.log_debug2("ssh user other than root, use sudo")
        context.sudo = "sudo -u root"

    context.local_sudo = ""
    if os.getuid() != 0:
        utils.log_debug2("Local user other than root, use sudo")
        context.local_sudo = "sudo -u root"


def collect_for_nodes(context):
    process_list = []
    for node in context.nodes:
        if node in context.ssh_askpw_nodes:
            continue
        p = Process(target=start_slave_collector, args=(context, node))
        p.start()
        process_list.append(p)
    for p in process_list:
        p.join()

    for node in context.ssh_askpw_nodes:
        utils.log_info("Please provide password for {} at {}".format(say_ssh_user(context), node))
        utils.log_info("Note that collecting data will take a while.")
        start_slave_collector(context, node)


def start_slave_collector(context, node):
    cmd_slave = r"{} __slave '{}'".format(context.name, context)
    if node == utils.me():
        cmd = r'{} {}'.format(context.local_sudo, cmd_slave)
    else:
        cmd = r'ssh -o {} {} "{} {}"'.format(' -o '.join(context.ssh_options), node, context.sudo, cmd_slave.replace('"', '\\"'))

    rc, out, err = crmutils.get_stdout_stderr(cmd)
    # maybe ssh error
    if rc != 0:
        context.nodes.remove(node)
        utils.log_error(err)
        return
    compress_data = ""
    for data in out.split('\n'):
        if data.startswith(const.COMPRESS_DATA_FLAG):
            # hb_report data from collector
            compress_data = data.lstrip(const.COMPRESS_DATA_FLAG)
        else:
            # log data from collector
            print(data)

    cmd = r"(cd {} && tar xf -)".format(context.work_dir)
    crmutils.get_stdout_stderr(cmd, input_s=eval(compress_data))


def load_context(context):
    '''
    Load context attributes from master process
    '''
    for key, value in json.loads(sys.argv[2]).items():
        context[key] = value


def sanitize(context):
    '''
    replace sensitive info with '****'
    '''
    if context.speed_up:
        utils.log_debug1("Skip check sensitive info")
        return

    utils.log_debug2("Check or replace sensitive info from cib, pe and log files")
    context.sanitize_pattern_string = '|'.join(context.sensitive_regex)

    pe_list = glob.glob(os.path.join(context.work_dir, "pengine", "*"))

    file_list = []
    for f in [const.CIB_F, const.PCMK_LOG_F, const.CIB_TXT_F]:
        file_list.append(os.path.join(context.work_dir, f))
    file_list += pe_list

    for f in [item for item in file_list if os.path.isfile(item)]:
        rc = sanitize_one(context, f)
        if rc == 1:
            utils.log_warning("Some PE/CIB/log files contain possibly sensitive data")
            utils.log_warning("Using \"-s\" option can replace sensitive data")
            break


def sanitize_one(context, in_file):
    data = utils.read_from_file(in_file)
    if not data:
        return
    if not include_sensitive_data(context, data):
        return
    if not context.sanitize:
        return 1
    utils.log_debug2("Replace sensitive info for {}".format(in_file))
    if os.path.basename(in_file) == const.CIB_TXT_F:
        _type = "txt"
    else:
        _type = "xml"
    utils.write_to_file(in_file, sub_sensitive_string(context, data, _type))


def sub_sensitive_string(context, data, _type):
    sub_pattern_dict = {"xml": ' value=".*" ', "txt": "({})=\w+".format(context.sanitize_pattern_string)}
    replace_string_dict= {"xml": ' value="******" ', "txt": r"\1=******"}
    res_string = ""
    for line in data.strip('\n').split('\n'):
        if include_sensitive_data(context, line):
            res_string += re.sub(sub_pattern_dict[_type], replace_string_dict[_type], line) + '\n'
        else:
            res_string += line + '\n'
    return res_string


def include_sensitive_data(context, data):
    # for cib.xml and pe file
    if re.search('name="{}"'.format(context.sanitize_pattern_string), data):
        return True
    # for cib.txt
    if re.search("({})=[^\"]".format(context.sanitize_pattern_string), data):
        return True
    return False


def pick_first(choice):
    for tmp in choice:
        if crmutils.is_program(tmp):
            return tmp
    return None


def pick_compress(context):
    compress_prog_ext_dict = {
        "bzip2": ".bz2",
        "gzip": ".gz",
        "xz":".xz"
    }
    context.compress_prog = pick_first(compress_prog_ext_dict.keys())
    if context.compress_prog:
        context.compress_ext = compress_prog_ext_dict[context.compress_prog]
    else:
        utils.log_warning("Could not find a compression program; the resulting tarball may be huge")
        context.compress_prog = "cat"


def consolidate(context, file_name):
    """
    Remove duplicates if files are same, make links instead
    """
    if file_name == const.CIB_F:
        return
    for n in context.nodes:
        orig_file = os.path.join(context.work_dir, n, file_name)
        if os.path.isfile(os.path.join(context.work_dir, file_name)):
            os.remove(orig_file)
        else:
            shutil.move(orig_file, context.work_dir)
        os.symlink("../{}".format(file_name), orig_file)


def cib_diff(cib1, cib2):
    """
    check if cib files have same content in the cluster
    """
    return_code = False
    out_string = ""

    if not utils.which("crm_diff"):
        utils.log_warning("crm_diff(8) not found, cannot diff CIBs")
        return return_code, out_string

    dir1 = os.path.dirname(cib1)
    dir2 = os.path.dirname(cib2)
    run1 = os.path.join(dir1, "RUNNING")
    run2 = os.path.join(dir2, "RUNNING")
    stop1 = os.path.join(dir1, "STOPPED")
    stop2 = os.path.join(dir2, "STOPPED")

    if os.path.isfile(run1) and os.path.isfile(run2) or \
            os.path.isfile(stop1) and os.path.isfile(stop2):
        rc, out, _ = crmutils.get_stdout_stderr("crm_diff -c -n {} -o {}".format(cib1, cib2))
        if out:
            out_string += "{}\n".format(out)
        return_code = not bool(rc)
    else:
        out_string += "Can't compare cibs from running and stopped systems\n"
    return return_code, out_string


def text_diff(file1, file2):
    out_string = ""
    rc, out, _ = crmutils.get_stdout_stderr("diff -bBu {} {}".format(file1, file2))
    return_code = not bool(rc)
    if out:
        out_string += "{}\n".format(out)
    return return_code, out_string


def diff_check(file1, file2):
    out_string = ""
    return_code = False
    for f in [file1, file2]:
        if not os.path.exists(f):
            out_string += "{} does not exist\n".format(f)
            return return_code, out_string
    if os.path.basename(file1) == const.CIB_F:
        return cib_diff(file1, file2)
    else:
        return text_diff(file1, file2)


def analyze_one(context, file_name):
    rc_list = []
    out_string = ""
    file1 = os.path.join(context.work_dir, context.nodes[0], file_name)
    for n in context.nodes[1:]:
        rc, out = diff_check(file1, os.path.join(context.work_dir, n, file_name))
        rc_list.append(rc)
        out_string += out
    return all(rc_list), out_string


def analyze(context):
    out_string = ""
    flist = [const.MEMBERSHIP_F, const.CRM_MON_F, const.B_CONF, const.SYSINFO_F, const.CIB_F]
    for f in flist:
        out_string += "Diff {}...".format(f)
        glob_res = glob.glob("{}/*/{}".format(context.work_dir, f))
        if len(glob_res) == 1:
            out_string += "Only one {}, skip\n".format(glob_res[0])
            continue
        if not glob_res:
            out_string += "Not found {}/*/{}\n".format(context.work_dir, f)
            continue
    
        rc, out = analyze_one(context, f)
        if rc:
            out_string += "OK\n\n"
            consolidate(context, f)
        else:
            out_string += "\n{}\n\n".format(out)

    out_string += check_crmvfy(context)
    out_string += check_cores(context)
    out_string += check_logs(context)
    crmutils.str2file(out_string, os.path.join(context.work_dir, const.ANALYSIS_F))


def check_crmvfy(context):
    out_string = ""
    for n in context.nodes:
        crm_verify_f = os.path.join(context.work_dir, n, const.CRM_VERIFY_F)
        if os.path.isfile(crm_verify_f):
            out_string += "WARN: crm_verify reported warnings at {}:\n".format(n)
            with open(crm_verify_f) as f:
                out_string += f.read()
    return out_string


def check_cores(context):
    out_string = ""
    flist = glob.glob(os.path.join(context.work_dir, "*/cores/*"))
    if flist:
        out_string += "WARN: coredupmps found at:\n"
        for f in flist:
            out_string += "  {}\n".format(f)
    return out_string


def filter_log(log, patt):
    out = ""
    with open(log, encoding='utf-8', errors='replace') as fd:
        data = fd.read()
    for line in data.split('\n'):
        if re.search(patt, line):
            out += '{}\n'.format(line)
    return out


def check_logs(context):
    out_string = ""
    logfile_list = []
    flist = [os.path.basename(f) for f in context.extra_logs] + [const.HALOG_F]
    for f in flist:
        logfile_list += glob.glob(os.path.join(context.work_dir, '*/{}'.format(f)))
    if not logfile_list:
        return out_string
    out_string += "\nLog patterns:\n"
    log_patterns = '|'.join(context.regex)
    for f in logfile_list:
        out_string += filter_log(f, log_patterns)
    return out_string


def process_results(context):
    analyze(context)

    if context.no_compress:
        shutil.move(context.work_dir, context.dest_dir)
    else:
        pick_compress(context)
        cmd_meta = {
            "w_dir": context.work_dir,
            "dest": context.dest,
            "d_dir": context.dest_dir,
            "comp_prog": context.compress_prog,
            "comp_ext": context.compress_ext
        }
        cmd = r"(cd {w_dir}/.. && tar cf - {dest})|{comp_prog} > {d_dir}/{dest}.tar{comp_ext}".format(**cmd_meta)
        utils.log_debug2("Running: {}".format(cmd))
        crmutils.get_stdout(cmd)

    finalword(context)


def finalword(context):
    if context.no_compress:
        dest_path = "{}/{}".format(context.dest_dir, context.dest)
    else:
        dest_path = "{}/{}.tar{}".format(context.dest_dir, context.dest, context.compress_ext)
    utils.log_info("The report is saved in {}".format(dest_path))
    utils.log_info("Report timespan: {} - {}".format(context.from_time_str, context.to_time_str))
    utils.log_info("Thank you for taking time to create this report.")


def push_data(context):
    utils.log_debug2("Pushing data from {}".format(context.work_dir))
    cmd = r'cd {}/.. && tar -h -cf - {}'.format(context.work_dir, utils.me())
    rc, out, err = crmutils.get_stdout_stderr(cmd, raw=True)
    if rc == 0 and out:
        print("{}{}".format(const.COMPRESS_DATA_FLAG, out))
        utils.log_debug1("="*45)
    if rc != 0 and err:
        utils.log_fatal(err)


def run(context):
    '''
    Major work flow
    '''
    if is_collector():
        load_context(context)
    else:
        parse_argument(context)
        load_from_config(context)

    setup_workdir(context)

    if is_collector():
        collect_journal_ha(context)
        collect_journal_general(context)
        collect_other_logs_and_info(context)
        push_data(context)
    else:
        get_nodes(context)
        ssh_issue(context)
        collect_for_nodes(context)
        process_results(context)
