#!/usr/bin/python3
# Copyright (C) 2017 Xin Liang <XLiang@suse.com>
# See COPYING for license information.

import getopt
import multiprocessing
import os
import re
import sys
import datetime
import shutil

from crmsh import utils as crmutils
from crmsh import config, log, userdir
from crmsh.report import constants, utillib


logger = log.setup_report_logger(__name__)


def collect_for_nodes(nodes, arg_str):
    """
    Start slave collectors
    """
    process_list = []
    for node in nodes.split():
        if utillib.node_needs_pwd(node):
            logger.info("Please provide password for %s at %s", utillib.say_ssh_user(), node)
            logger.info("Note that collecting data will take a while.")
            utillib.start_slave_collector(node, arg_str)
        else:
            p = multiprocessing.Process(target=utillib.start_slave_collector, args=(node, arg_str))
            p.start()
            process_list.append(p)
    for p in process_list:
            p.join()

def dump_env():
    """
    this is how we pass environment to other hosts
    """
    env_dict = {}
    env_dict["DEST"] = constants.DEST
    env_dict["FROM_TIME"] = constants.FROM_TIME
    env_dict["TO_TIME"] = constants.TO_TIME
    env_dict["USER_NODES"] = constants.USER_NODES
    env_dict["NODES"] = constants.NODES
    env_dict["HA_LOG"] = constants.HA_LOG
    # env_dict["UNIQUE_MSG"] = constants.UNIQUE_MSG
    env_dict["SANITIZE_RULE_DICT"] = constants.SANITIZE_RULE_DICT
    env_dict["DO_SANITIZE"] = constants.DO_SANITIZE
    env_dict["SKIP_LVL"] = constants.SKIP_LVL
    env_dict["EXTRA_LOGS"] = constants.EXTRA_LOGS
    env_dict["PCMK_LOG"] = constants.PCMK_LOG
    env_dict["VERBOSITY"] = int(config.report.verbosity) or (1 if config.core.debug else 0)

    res_str = ""
    for k, v in env_dict.items():
        res_str += " {}={}".format(k, v)
    return res_str

def get_log():
    """
    get the right part of the log
    """
    outf = os.path.join(constants.WORKDIR, constants.HALOG_F)

    # collect journal from systemd unless -M was passed
    if constants.EXTRA_LOGS:
        utillib.collect_journal(constants.FROM_TIME,
                                constants.TO_TIME,
                                os.path.join(constants.WORKDIR, constants.JOURNAL_F))

    if constants.HA_LOG and not os.path.isfile(constants.HA_LOG):
        if not is_collector(): # warning if not on slave
            logger.warning("%s not found; we will try to find log ourselves", constants.HA_LOG)
            constants.HA_LOG = ""
    if not constants.HA_LOG:
        constants.HA_LOG = utillib.find_log()
    if (not constants.HA_LOG) or (not os.path.isfile(constants.HA_LOG)):
        if constants.CTS:
            pass  # TODO
        else:
            logger.warning("not log at %s", constants.WE)
        return

    if constants.CTS:
        pass  # TODO
    else:
        try:
            getstampproc = utillib.find_getstampproc(constants.HA_LOG)
        except PermissionError:
            return
        if getstampproc:
            constants.GET_STAMP_FUNC = getstampproc
            if utillib.dump_logset(constants.HA_LOG, constants.FROM_TIME, constants.TO_TIME, outf):
                utillib.log_size(constants.HA_LOG, outf+'.info')
        else:
            logger.warning("could not figure out the log format of %s", constants.HA_LOG)


def is_collector():
    """
    the instance where user runs crm report is the master
    the others are slaves
    """
    if len(sys.argv) > 1 and sys.argv[1] == "__slave":
        return True
    return False


def load_env(env_str):
    list_ = []
    for tmp in env_str.split():
        if re.search('=', tmp):
            item = tmp
        else:
            list_.remove(item)
            item += " %s" % tmp
        list_.append(item)

    env_dict = {}
    env_dict = crmutils.nvpairs2dict(list_)
    constants.DEST = env_dict["DEST"]
    constants.FROM_TIME = float(env_dict["FROM_TIME"])
    constants.TO_TIME = float(env_dict["TO_TIME"])
    constants.USER_NODES = env_dict["USER_NODES"]
    constants.NODES = env_dict["NODES"]
    constants.HA_LOG = env_dict["HA_LOG"]
    # constants.UNIQUE_MSG = env_dict["UNIQUE_MSG"]
    constants.SANITIZE_RULE_DICT = env_dict["SANITIZE_RULE_DICT"]
    constants.DO_SANITIZE = env_dict["DO_SANITIZE"]
    constants.SKIP_LVL = utillib.str_to_bool(env_dict["SKIP_LVL"])
    constants.EXTRA_LOGS = env_dict["EXTRA_LOGS"]
    constants.PCMK_LOG = env_dict["PCMK_LOG"]
    config.report.verbosity = env_dict["VERBOSITY"]


def parse_argument(argv):
    try:
        opt, arg = getopt.getopt(argv[1:], constants.ARGOPTS_VALUE)
    except getopt.GetoptError:
        usage("short")

    if len(arg) == 0:
        constants.DESTDIR = "."
        constants.DEST = "crm_report-%s" % datetime.datetime.now().strftime('%a-%d-%b-%Y')
    elif len(arg) == 1:
        constants.TMP = arg[0]
    else:
        usage("short")

    verbosity = 0
    for args, option in opt:
        if args == '-h':
            usage()
        if args == "-V":
            version()
        if args == '-f':
            constants.FROM_TIME = crmutils.parse_to_timestamp(option)
            utillib.check_time(constants.FROM_TIME, option)
        if args == '-t':
            constants.TO_TIME = crmutils.parse_to_timestamp(option)
            utillib.check_time(constants.TO_TIME, option)
        if args == "-n":
            constants.USER_NODES += " %s" % option
        if args == "-u":
            constants.SSH_USER = option
        if args == "-X":
            constants.SSH_OPTS += " %s" % option
        if args == "-l":
            constants.HA_LOG = option
        if args == "-e":
            constants.EDITOR = option
        if args == "-p":
            constants.SANITIZE_RULE += " %s" % option
        if args == "-s":
            constants.DO_SANITIZE = True
        if args == "-Q":
            constants.SKIP_LVL = True
        if args == "-L":
            constants.LOG_PATTERNS += " %s" % option
        if args == "-S":
            constants.NO_SSH = True
        if args == "-D":
            constants.NO_DESCRIPTION = 1
        if args == "-Z":
            constants.FORCE_REMOVE_DEST = True
        if args == "-M":
            constants.EXTRA_LOGS = ""
        if args == "-E":
            constants.EXTRA_LOGS += " %s" % option
        if args == "-v":
            verbosity += 1
        if args == '-d':
            constants.COMPRESS = False

    config.report.verbosity = verbosity

    if config.report.sanitize_rule:
        constants.DO_SANITIZE = True
        temp_pattern_set = set()
        temp_pattern_set |= set(re.split('\s*\|\s*|\s+', config.report.sanitize_rule.strip('|')))
        constants.SANITIZE_RULE += " {}".format(' '.join(temp_pattern_set))
    utillib.parse_sanitize_rule(constants.SANITIZE_RULE)

    if not constants.FROM_TIME:
        from_time = config.report.from_time
        if re.search("^-[1-9][0-9]*[YmdHM]$", from_time):
            number = int(re.findall("[1-9][0-9]*", from_time)[0])
            if re.search("^-[1-9][0-9]*Y$", from_time):
                timedelta = datetime.timedelta(days = number * 365)
            if re.search("^-[1-9][0-9]*m$", from_time):
                timedelta = datetime.timedelta(days = number * 30)
            if re.search("^-[1-9][0-9]*d$", from_time):
                timedelta = datetime.timedelta(days = number)
            if re.search("^-[1-9][0-9]*H$", from_time):
                timedelta = datetime.timedelta(hours = number)
            if re.search("^-[1-9][0-9]*M$", from_time):
                timedelta = datetime.timedelta(minutes = number)
            from_time = (datetime.datetime.now() - timedelta).strftime("%Y-%m-%d %H:%M")
            constants.FROM_TIME = crmutils.parse_to_timestamp(from_time)
            utillib.check_time(constants.FROM_TIME, from_time)
        else:
            utillib.log_fatal("Wrong format for from_time in /etc/crm/crm.conf; (-[1-9][0-9]*[YmdHM])")


def run():

    utillib.check_env()
    tmpdir = utillib.make_temp_dir()
    utillib.add_tempfiles(tmpdir)

    #
    # get and check options; and the destination
    #
    if not is_collector():
        parse_argument(sys.argv)
        set_dest(constants.TMP)
        constants.WORKDIR = os.path.join(tmpdir, constants.DEST)
    else:
        constants.WORKDIR = os.path.join(tmpdir, constants.DEST, constants.WE)
    utillib._mkdir(constants.WORKDIR)

    if is_collector():
        load_env(' '.join(sys.argv[2:]))

    utillib.compatibility_pcmk()
    if constants.CTS == "" or is_collector():
        utillib.get_log_vars()

    if not is_collector():
        constants.NODES = ' '.join(utillib.get_nodes())
        logger.debug("nodes: %s", constants.NODES)
    if constants.NODES == "":
        utillib.log_fatal("could not figure out a list of nodes; is this a cluster node?")
    if constants.WE in constants.NODES.split():
        constants.THIS_IS_NODE = 1

    if not is_collector():
        if constants.THIS_IS_NODE != 1:
            logger.warning("this is not a node and you didn't specify a list of nodes using -n")
        #
        # ssh business
        #
        if not constants.NO_SSH:
            # if the ssh user was supplied, consider that it
            # works; helps reduce the number of ssh invocations
            utillib.find_ssh_user()
            if constants.SSH_USER:
                constants.SSH_OPTS += " -o User=%s" % constants.SSH_USER
        # assume that only root can collect data
        if ((not constants.SSH_USER) and (os.getuid() not in [0, 90])) or \
           constants.SSH_USER and constants.SSH_USER not in ["root", "hacluster"] or \
           userdir.get_sudoer():
            logger.debug("ssh user other than root, use sudo")
            constants.SUDO = "sudo"
        if os.getuid() != 0:
            logger.debug("local user other than root, use sudo")
            constants.LOCAL_SUDO = "sudo -u root"

    #
    # find the logs and cut out the segment for the period
    #
    if constants.THIS_IS_NODE == 1:
        get_log()

    if not is_collector():
        arg_str = dump_env()
        if not constants.NO_SSH:
            collect_for_nodes(constants.NODES, arg_str)
        elif constants.THIS_IS_NODE == 1:
            collect_for_nodes(constants.WE, arg_str)

    #
    # endgame:
    #     slaves tar their results to stdout, the master waits
    #     for them, analyses results, asks the user to edit the
    #     problem description template, and prints final notes
    #
    if is_collector():
        utillib.collect_info()
        cmd = r"cd %s/.. && tar -h -cf - %s" % (constants.WORKDIR, constants.WE)
        code, out, err = crmutils.get_stdout_stderr(cmd, raw=True)
        print("{}{}".format(constants.COMPRESS_DATA_FLAG, out))
    else:
        p_list = []
        p_list.append(multiprocessing.Process(target=utillib.analyze))
        p_list.append(multiprocessing.Process(target=utillib.events, args=(constants.WORKDIR,)))
        for p in p_list:
            p.start()

        utillib.check_if_log_is_empty()
        utillib.mktemplate(sys.argv)

        for p in p_list:
            p.join()

        if not constants.SKIP_LVL:
            utillib.sanitize()

        if constants.COMPRESS:
            utillib.pick_compress()
            cmd = r"(cd %s/.. && tar cf - %s)|%s > %s/%s.tar%s" % (
                constants.WORKDIR, constants.DEST, constants.COMPRESS_PROG,
                constants.DESTDIR, constants.DEST, constants.COMPRESS_EXT)
            crmutils.ext_cmd(cmd)
        else:
            shutil.move(constants.WORKDIR, constants.DESTDIR)
        utillib.finalword()


def set_dest(dest):
    """
    default DEST has already been set earlier (if the
    argument is missing)
    """
    if dest:
        constants.DESTDIR = utillib.get_dirname(dest)
        constants.DEST = os.path.basename(dest)
    if not os.path.isdir(constants.DESTDIR):
        utillib.log_fatal("%s is illegal directory name" % constants.DESTDIR)
    if not crmutils.is_filename_sane(constants.DEST):
        utillib.log_fatal("%s contains illegal characters" % constants.DEST)
    if not constants.COMPRESS and os.path.isdir(os.path.join(constants.DESTDIR, constants.DEST)):
        if constants.FORCE_REMOVE_DEST:
            shutil.rmtree(os.path.join(constants.DESTDIR, constants.DEST))
        else:
            utillib.log_fatal("destination directory DESTDIR/DEST exists, please cleanup or use -Z")


def usage(short_msg=''):
    print("""
usage: report -f {time} [-t time]
       [-u user] [-X ssh-options] [-l file] [-n nodes] [-E files]
       [-p patt] [-L patt] [-e prog] [-MSDZQVsvhd] [dest]

        -f time: time to start from
        -t time: time to finish at (dflt: now)
        -d     : don't compress, but leave result in a directory
        -n nodes: node names for this cluster; this option is additive
                 (use either -n "a b" or -n a -n b)
                 if you run report on the loghost or use autojoin,
                 it is highly recommended to set this option
        -u user: ssh user to access other nodes (dflt: empty, root, hacluster)
        -X ssh-options: extra ssh(1) options
        -l file: log file
        -E file: extra logs to collect; this option is additive
                 (dflt: /var/log/messages)
        -s     : sanitize the PE and CIB files
        -p patt: regular expression to match variables containing sensitive data;
                 this option is additive (dflt: "passw.*")
        -L patt: regular expression to match in log files for analysis;
                 this option is additive (dflt: CRIT: ERROR:)
        -e prog: your favourite editor
        -Q     : don't run resource intensive operations (speed up)
        -M     : don't collect extra logs (/var/log/messages)
        -D     : don't invoke editor to write description
        -Z     : if destination directories exist, remove them instead of exiting
                 (this is default for CTS)
        -S     : single node operation; don't try to start report
                 collectors on other nodes
        -v     : increase verbosity
        -V     : print version
        dest   : report name (may include path where to store the report)
    """)
    if short_msg != "short":
        print("""
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
          report -f "09-sep-07 2:00" -u hbadmin report_4
          report -f 18:00 -p "usern.*" -p "admin.*" report_5

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

          IT IS YOUR RESPONSIBILITY TO PROTECT THE DATA FROM EXPOSURE!
        """)
    sys.exit(1)


def version():
    print(utillib.crmsh_info().strip('\n'))
    sys.exit(0)


if __name__ == "__main__":
    try:
        run()
    except UnicodeDecodeError:
        import traceback
        traceback.print_exc()
        sys.stdout.flush()

# vim:ts=4:sw=4:et:
