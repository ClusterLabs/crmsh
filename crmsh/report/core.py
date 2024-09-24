#!/usr/bin/python3
# Copyright (C) 2017 Xin Liang <XLiang@suse.com>
# See COPYING for license information.

import argparse
import multiprocessing
import os
import re
import subprocess
import sys
import shutil
import json
import ast
import typing
from inspect import getmembers, isfunction
from io import StringIO
from typing import List

import crmsh.sh
import crmsh.report.sh
import crmsh.user_of_host
from crmsh import utils as crmutils, userdir
from crmsh import constants as crmconstants
from crmsh import config, log, tmpfiles, ui_cluster
from crmsh.sh import ShellUtils


logger = log.setup_report_logger(__name__)


class Context:
    """
    Class to set/get essential attributes during the whole crm report process
    """
    def load(self) -> None:
        """
        Load default values
        """
        self.name = "crm_report"
        self.from_time: float = config.report.from_time
        self.to_time: float = utils.now()
        self.no_compress: bool = not config.report.compress
        self.speed_up: bool = config.report.speed_up
        self.extra_log_list: List[str] = config.report.collect_extra_logs.split()
        self.rm_exist_dest: bool = config.report.remove_exist_dest
        self.single: bool= config.report.single_node
        self.sensitive_regex_list: List[str] = []
        self.regex_list: List[str] = "CRIT: ERROR: error: warning: crit:".split()
        self.passwordless_shell_for_nodes = dict()
        self.me = crmutils.this_node()
        self.pe_dir: str
        self.cib_dir: str
        self.pcmk_lib_dir: str
        self.pcmk_exec_dir: str
        self.cores_dir_list: List[str]
        self.trace_dir_list: List[str]
        self.dest: str
        self.dest_dir: str
        self.work_dir: str
        self.node_list: List[str]
        self.ssh_user: str
        self.ssh_option_list: List[str]
        self.no_log_list: List[str]
        self.sanitize: bool
        self.debug: int
        self.compress_prog: str
        self.compress_suffix: str
        self.main_node = self.me

    def __str__(self) -> str:
        return json.dumps({k: v for k, v in self.__dict__.items() if k != 'passwordless_shell_for_nodes'})

    def __setattr__(self, name: str, value) -> None:
        """
        Set the attribute value and perform validations
        """
        if name in ["from_time", "to_time"] and value:
            value = utils.parse_to_timestamp(value)
        if name == "extra_log_list" and value and hasattr(self, "extra_log_list"):
            value = list(set(self.extra_log_list) | set(value))
        super().__setattr__(name, value)

    def __setitem__(self, key: str, value) -> None:
        self.__dict__[key] = value


from crmsh.report import constants, utils, collect


class CapitalizedHelpFormatter(argparse.HelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        if prefix is None:
            prefix = 'Usage: '
        return super().add_usage(usage.capitalize(), actions, groups, prefix)

    def start_section(self, heading):
        return super().start_section(heading.capitalize())


def add_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
            usage=f"\n{constants.NAME} [options] [dest]",
            add_help=False,
            formatter_class=lambda prog: CapitalizedHelpFormatter(prog, width=80)
            )
    parser.add_argument("-h", "--help", action="store_true", dest="help",
                        help="Show this help message and exit")
    parser.add_argument('-f', dest='from_time', metavar='FROM_TIME',
                        help='Time to start from (default: 12 hours ago), can be specific time or delta time until now')
    parser.add_argument('-t', dest='to_time', metavar='TO_TIME',
                        help='Time to finish at (default: now); can be specific time or delta time until now')
    parser.add_argument('-d', dest='no_compress', action='store_true',
                        help="Don't compress, but leave result in a directory")
    parser.add_argument('-n', dest='node_list', metavar='NODE', action=ui_cluster.CustomAppendAction, default=[],
                        help='Node names for this cluster; this option is additive (use -n a -n b or -n "a b")')
    parser.add_argument('-u', dest='ssh_user', metavar='SSH_USER',
                        help='SSH user to access other nodes')
    parser.add_argument('-X', dest='ssh_option_list', metavar='SSH_OPTION', action=ui_cluster.CustomAppendAction, default=[],
                        help='Extra ssh(1) options; this option is additive')
    parser.add_argument('-E', dest='extra_log_list', metavar='FILE', action=ui_cluster.CustomAppendAction, default=[],
                        help='Extra logs to collect; this option is additive')
    parser.add_argument('-e', dest='no_log_list', metavar='FILE', action=ui_cluster.CustomAppendAction, default=[],
                        help='Don\'t collect these files; this option is additive')
    parser.add_argument('-s', dest='sanitize', action='store_true',
                        help='Replace sensitive info in PE or CIB or pacemaker log files')
    parser.add_argument('-p', dest='sensitive_regex_list', metavar='PATT', action=ui_cluster.CustomAppendAction, default=[],
                        help='Regular expression to match variables containing sensitive data (default: passw.*); this option is additive')
    parser.add_argument('-Q', dest='speed_up', action='store_true',
                        help="The quick mode, which skips producing dot files from PE inputs, verifying installed cluster stack rpms and sanitizing files for sensitive information")
    parser.add_argument('-Z', dest='rm_exist_dest', action='store_true',
                        help='If destination directories exist, remove them instead of exiting')
    parser.add_argument('-S', dest='single', action='store_true',
                        help="Single node operation; don't try to start report collectors on other nodes")
    parser.add_argument('-v', dest='debug', action='count', default=0,
                        help='Increase verbosity')
    parser.add_argument('dest', nargs='?',
                        help="Report name (which may include the path for storing the report), default format is 'crm_report-current_date,' such as 'crm_report-Mon-09-Oct-2023'")

    args = parser.parse_args()
    if args.help:
        print(constants.DESCRIPTION_HELP)
        parser.print_help()
        print(constants.EXTRA_HELP)
        sys.exit(0)

    return args


def push_data(context: Context) -> None:
    """
    Push data from this node
    """
    logger.debug2(f"Pushing data from {context.me}:{context.work_dir} to {context.main_node}")
    cmd = f'cd {context.work_dir}/.. && tar -h -c {context.me}'
    _, out, err = ShellUtils().get_stdout_stderr(cmd, raw=True)
    if out:
        print(f"{constants.COMPRESS_DATA_FLAG}{out}")
    if err:
        raise utils.ReportGenericError(crmutils.to_ascii(err))


def pick_compress_prog(context: Context) -> None:
    """
    Pick the appropriate compression program and its file suffix
    """
    context.compress_prog, context.compress_suffix = pick_first_compress()
    if not context.compress_prog:
        context.compress_prog, context.compress_suffix = "cat", ""


def pick_first_compress():
    compress_prog_suffix_dict = {
        "gzip": ".gz",
        "bzip2": ".bz2",
        "xz": ".xz"
    }
    default_prog = config.report.compress_prog
    default_suffix = compress_prog_suffix_dict.get(default_prog)
    if shutil.which(default_prog) and default_suffix:
        return default_prog, default_suffix
    for cmd, suffix in compress_prog_suffix_dict.items():
        if shutil.which(cmd):
            return cmd, suffix
    logger.warning("Could not find a compression program")
    return None, None


def finalword(context: Context) -> None:
    logger.info(f"The report is saved in {context.dest_path}")
    timespan_str = utils.get_timespan_str(context)
    logger.info(f"Report timespan: {timespan_str}")
    nodes_str = ' '.join(context.node_list)
    logger.info(f"Including nodes: {nodes_str}")
    logger.info("Thank you for taking time to create this report")


def process_results(context: Context) -> None:
    """
    Process report results
    """
    if not context.speed_up:
        utils.do_sanitize(context)
    utils.analyze(context)
    utils.create_description_template(context)

    if context.no_compress:
        shutil.move(context.work_dir, context.dest_dir)
    else:
        cmd_cd_tar = f"(cd {context.work_dir}/.. && tar cf - {context.dest})"
        cmd_compress = f"{context.compress_prog} > {context.dest_dir}/{context.dest}.tar{context.compress_suffix}"
        cmd = f"{cmd_cd_tar}|{cmd_compress}"
        logger.debug2(f"Running: {cmd}")
        crmsh.sh.cluster_shell().get_stdout_or_raise_error(cmd)

    finalword(context)


def collect_logs_and_info(context: Context) -> None:
    """
    Collect logs and information using multiprocessing
    """
	# Make sure not to occupy all CPUs
    pool = multiprocessing.Pool(round(0.8 * multiprocessing.cpu_count()))
    # result here to store AsyncResult object returned from apply_async
    # Then calling get() method will catch exceptions like NameError, AttributeError, etc.
    # Otherwise parent process will not know these exceptions raised
    # Calling get() right after apply_async will be blocked until child process finished, so
    # need to append to a list firstly
    result_list = []
    # Generate function list from collect.py
    for cf in [f for f, _ in getmembers(collect, isfunction) if f.startswith("collect_")]:
        result = pool.apply_async(getattr(collect, cf), (context,))
        result_list.append(result)
    pool.close()
    pool.join()

    for result in result_list:
        try:
            result.get()
        except:
            utils.print_traceback()


def collect_for_nodes(context: Context) -> None:
    """
    Start collectors on each node
    """
    process_list = []
    if len(context.passwordless_shell_for_nodes) == len(context.node_list):
        for node in context.node_list:
            p = multiprocessing.Process(target=start_collector, args=(node, context))
            p.start()
            process_list.append(p)
        for p in process_list:
            p.join()
    else:
        for node in context.node_list:
            start_collector(node, context)


def start_collector(node: str, context: Context) -> None:
    """
    Start collector at specific node
    """
    cmd = f"{constants.BIN_COLLECTOR} '{context}'"

    shell = context.passwordless_shell_for_nodes.get(node)
    if shell is not None:
        ret = shell.subprocess_run_without_input(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        # This is a last effort when passwordless ssh is not available
        cmd = cmd.replace('"', '\\"')
        ret = _interactive_ssh_run_as_root(node, context.ssh_user, cmd)
    if ret.returncode != 0:
        logger.warning(
            'Failed to run collector on %s: %s: %s',
            node, ret.returncode, crmsh.sh.Utils.decode_str(ret.stderr) if ret.stderr is not None else '',
        )
        return
    elif ret.stderr:
        print(crmsh.sh.Utils.decode_str(ret.stderr), file=sys.stderr)

    compress_data = ""
    for data in ret.stdout.decode('utf-8').split("\n"):
        if data.startswith(constants.COMPRESS_DATA_FLAG):
            # crm report data from collector
            compress_data = data.lstrip(constants.COMPRESS_DATA_FLAG)
        else:
            # INFO log data from collector
            print(data)

    try:
        # Safely evaluate the string representation of a tarball from push_data
        data_object = ast.literal_eval(compress_data)
    except (SyntaxError, ValueError) as e:
        logger.error(f"Error evaluating data: {e}")
        return

    # Extract the tarball in the specified working directory
    cmd = f"cd {context.work_dir} && tar x"
    ShellUtils().get_stdout(cmd, input_s=data_object)


def process_dest(context: Context) -> None:
    """
    Process destination path and file
    """
    if not context.dest:
        suffix = utils.now(constants.RESULT_TIME_SUFFIX)
        context.dest = f"{context.name}-{suffix}"

    dest_dir = os.path.dirname(context.dest) or "."
    if not os.path.isdir(dest_dir):
        raise utils.ReportGenericError(f"Directory {dest_dir} does not exist")
    context.dest_dir = dest_dir

    dest_file = os.path.basename(context.dest)
    if not crmutils.is_filename_sane(dest_file):
        raise utils.ReportGenericError(f"{dest_file} is invalid file name")

    if context.no_compress and os.path.isdir(context.dest):
        if context.rm_exist_dest:
            shutil.rmtree(context.dest)
        else:
            raise utils.ReportGenericError(f"Destination directory {context.dest} exists, please cleanup or use -Z option")

    context.dest = dest_file
    pick_compress_prog(context)
    if context.no_compress:
        context.dest_path = f"{context.dest_dir}/{context.dest}"
    else:
        context.dest_path = f"{context.dest_dir}/{context.dest}.tar{context.compress_suffix}"


def local_mode(context: Context) -> bool:
    return context.single or (len(context.node_list) == 1 and context.node_list[0] == context.me)


def process_node_list(context: Context) -> None:
    if not local_mode(context) and config.core.no_ssh:
        logger.error('%s', crmconstants.NO_SSH_ERROR_MSG)
        context.single = True
    if context.single:
        context.node_list = [context.me]
    elif not context.node_list:
        context.node_list = crmutils.list_cluster_nodes()
        if not context.node_list:
            raise utils.ReportGenericError("Could not figure out a list of nodes; is this a cluster node?")

    for node in context.node_list[:]:
        if node == context.me:
            continue
        try:
            crmutils.ping_node(node)
        except Exception as err:
            logger.error(str(err))
            context.node_list.remove(node)


def process_arguments(context: Context) -> None:
    if context.to_time <= context.from_time:
        raise ValueError("The start time must be before the finish time")
    process_node_list(context)
    process_dest(context)


def setup_workdir(context: Context) -> None:
    """
    Setup working directory where crm report can put all logs into it
    """
    tmpdir = tmpfiles.create_dir()
    if not is_collector():
        context.work_dir = os.path.join(tmpdir, os.path.basename(context.dest))
    else:
        context.work_dir = os.path.join(tmpdir,
                                        os.path.basename(context.dest),
                                        context.me)
    crmutils.mkdirp(context.work_dir)
    logger.debug2(f"Setup work directory in {context.work_dir}")


def load_context(context: Context) -> None:
    """
    Load context attributes from master process
    """
    for key, value in json.loads(sys.argv[2]).items():
        context[key] = value
    context.me = crmutils.this_node()
    adjust_verbosity(context)
    logger.debug2(f"Loading context from collector: {context}")


def find_ssh_user(context: Context) -> None:
    """
    Finds the SSH user for passwordless SSH access to nodes in the context's node_list
    """
    cluster_shell = crmsh.sh.cluster_shell()
    user_of_host = crmsh.user_of_host.UserOfHost.instance()
    for n in context.node_list:
        ret = crmsh.report.sh.Shell.find_shell(cluster_shell, n, context.ssh_user)
        if ret is not None:
            logger.debug("passwordless ssh to %s is OK", n)
            context.passwordless_shell_for_nodes[n] = ret
        elif user_of_host.use_ssh_agent() and 'SSH_AUTH_SOCK' not in os.environ:
            with StringIO() as buf:
                buf.write('Environment variable SSH_AUTH_SOCK does not exist.')
                if 'SUDO_USER' in os.environ:
                    buf.write(' Please check whether ssh-agent is available and consider using "sudo --preserve-env=SSH_AUTH_SOCK".')
                logger.warning('%s', buf.getvalue())
        else:
            logger.warning("passwordless ssh to node %s does not work", n)
            if not crmutils.can_ask():
                logger.error('Cannot create a report non-interactively. Interactive authentication is required.')
                if userdir.getuser() == 'hacluster':
                    logger.warning('Passwordless ssh does not work. Run "crm cluster health hawk2 --fix" to set it up.')
                raise ValueError('Cannot create a report.')


def load_from_crmsh_config(context: Context) -> None:
    """
    load context attributes from crmsh.config
    """
    config_context_map = {
        "crm_config": "cib_dir",
        "crm_daemon_dir": "pcmk_exec_dir",
        "pe_state_dir": "pe_dir"
    }
    context_str_map = {
        "cib_dir": "CIB",
        "pcmk_exec_dir": "Pacemaker exec",
        "pe_dir": "PE"
    }
    for config_item, context_attr in config_context_map.items():
        value = getattr(config.path, config_item, None)
        if not value or not os.path.isdir(value):
            raise utils.ReportGenericError(f"Cannot find {context_str_map[context_attr]} directory")
        setattr(context, context_attr, value)


def load_context_attributes(context: Context) -> None:
    """
    load context attributes from crmsh.config and corosync.conf
    """
    load_from_crmsh_config(context)

    context.pcmk_lib_dir = os.path.dirname(context.cib_dir)
    context.cores_dir_list = [os.path.join(context.pcmk_lib_dir, "cores")]
    context.cores_dir_list.extend([constants.COROSYNC_LIB] if os.path.isdir(constants.COROSYNC_LIB) else [])


def load_context_trace_dir_list(context: Context) -> None:
    # since the "trace_dir" attribute been removed from cib after untrace
    # need to parse crmsh log file to extract custom trace ra log directory on each node
    log_contents = ""
    cmd = f"grep 'INFO: Trace for .* is written to ' {log.CRMSH_LOG_FILE}*|grep -v 'collect'"
    for node in context.node_list:
        shell = context.passwordless_shell_for_nodes.get(node)
        if shell is not None:
            ret = shell.subprocess_run_without_input(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            # This is a last effort when passwordless ssh is not available
            cmd = cmd.replace('"', '\\"')
            ret = _interactive_ssh_run_as_root(node, context.ssh_user, cmd)
        if ret.returncode == 0:
            log_contents += ret.stdout.decode('utf-8')
    context.trace_dir_list = list(set(re.findall("written to (.*)/.*", log_contents)))


def _interactive_ssh_run_as_root(host: str, ssh_user: str, cmd: str):
    # cmd MUST be escaped to make sure it works as an arugment of ssh command
    target = f"{ssh_user}@{host}" if ssh_user else host
    logger.info('Creating ssh connection to %s...', target)
    cmd = 'ssh {} {} "{}{}"'.format(
        constants.SSH_OPTS,
        target,
        '' if ssh_user is None or ssh_user == 'root' else 'sudo ',
        cmd,
    )
    shell = crmsh.sh.LocalShell()
    return shell.su_subprocess_run(None, cmd, tty=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def adjust_verbosity(context: Context) -> None:
    if context.debug > 0:
        config.report.verbosity = context.debug
    elif config.core.debug:
        config.report.verbosity = 1
        context.debug = 1


def parse_arguments(context: Context) -> None:
    """
    Add, parse and process arguments
    """
    args = add_arguments()
    crmutils.check_empty_option_value(args)
    for arg in vars(args):
        value = getattr(args, arg)
        if value or not hasattr(context, arg):
            setattr(context, arg, value)
    adjust_verbosity(context)
    process_arguments(context)


def is_collector() -> bool:
    """
    collector is for collecting logs and data
    """
    return len(sys.argv) > 1 and sys.argv[1] == "__collector"


def run_impl() -> None:
    """
    Major work flow
    """
    ctx = Context()

    if is_collector():
        load_context(ctx)
    else:
        ctx.load()
        parse_arguments(ctx)
        load_context_attributes(ctx)

    setup_workdir(ctx)

    if is_collector():
        collect_logs_and_info(ctx)
        push_data(ctx)
    else:
        find_ssh_user(ctx)
        load_context_trace_dir_list(ctx)
        collect_for_nodes(ctx)
        process_results(ctx)


def run() -> None:
    """
    crm report entry
    """
    try:
        run_impl()
    except UnicodeDecodeError:
        utils.print_traceback()
        sys.exit(1)
    except utils.ReportGenericError as err:
        if str(err):
            logger.error(str(err))
        sys.exit(1)
# vim:ts=4:sw=4:et:
