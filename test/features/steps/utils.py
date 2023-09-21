import concurrent.futures
import difflib
import tarfile
import glob
import re
import socket
from crmsh import utils, userdir
from crmsh.sh import ShellUtils
import behave_agent


COLOR_MODE = r'\x1b\[[0-9]+m'


def get_file_type(file_path):
    rc, out, _ = ShellUtils().get_stdout_stderr("file {}".format(file_path))
    if re.search(r'{}: bzip2'.format(file_path), out):
        return "bzip2"
    if re.search(r'{}: directory'.format(file_path), out):
        return "directory"


def get_all_files(archive_path):
    archive_type = get_file_type(archive_path)
    if archive_type == "bzip2":
        with tarfile.open(archive_path) as tar:
            return tar.getnames()
    if archive_type == "directory":
        all_files = glob.glob("{}/*".format(archive_path)) + glob.glob("{}/*/*".format(archive_path))
        return all_files


def file_in_archive(f, archive_path):
    for item in get_all_files(archive_path):
        if re.search(r'/{}$'.format(f), item):
            return True
    return False


def me():
    return socket.gethostname()


def _wrap_cmd_non_root(cmd):
    """
    When running command under sudoer, or the current user is not root,
    wrap crm cluster join command with '<user>@', and for the -N option, too
    """
    sudoer = userdir.get_sudoer()
    current_user = userdir.getuser()
    if sudoer:
        user = sudoer
    elif current_user != 'root':
        user = current_user
    else:
        return cmd
    if re.search('cluster (:?join|geo_join|geo_init_arbitrator)', cmd) and "@" not in cmd:
        cmd = re.sub(r'''((?:-c|-N|--qnetd-hostname|--cluster-node)(?:\s+|=)['"]?)(\S{2,}['"]?)''', f'\\1{user}@\\2', cmd)
    elif "cluster init" in cmd and ("-N" in cmd or "--qnetd-hostname" in cmd) and "@" not in cmd:
        cmd = re.sub(r'''((?:-c|-N|--qnetd-hostname|--cluster-node)(?:\s+|=)['"]?)(\S{2,}['"]?)''', f'\\1{user}@\\2', cmd)
    elif "cluster init" in cmd and "--node" in cmd and "@" not in cmd:
        search_patt = r"--node [\'\"](.*)[\'\"]"
        res = re.search(search_patt, cmd)
        if res:
            node_str = ' '.join([f"{user}@{n}" for n in res.group(1).split()])
            cmd = re.sub(search_patt, f"--node '{node_str}'", cmd)
    return cmd


def run_command(context, cmd, exit_on_fail=True):
    cmd = _wrap_cmd_non_root(cmd)
    rc, out, err = ShellUtils().get_stdout_stderr(cmd)
    context.return_code = rc
    if out:
        out = re.sub(COLOR_MODE, '', out)
        context.stdout = out
    if err:
        err = re.sub(COLOR_MODE, '', err)
        context.stderr = err
    if rc != 0 and exit_on_fail:
        if out:
            context.logger.info("\n{}\n".format(out))
        context.logger.error("\n{}\n".format(err))
        context.failed = True
    return rc, out, err


def run_command_local_or_remote(context, cmd, addr, exit_on_fail=True):
    if addr == me():
        return run_command(context, cmd, exit_on_fail)
    cmd = _wrap_cmd_non_root(cmd)
    sudoer = userdir.get_sudoer()
    if sudoer is None:
        user = None
    else:
        user = sudoer
        cmd = f'sudo {cmd}'
    hosts = addr.split(',')
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(hosts)) as executor:
        results = list(executor.map(lambda x: (x, behave_agent.call(x, 1122, cmd, user=user)), hosts))
    out = utils.to_ascii(results[0][1][1])
    err = utils.to_ascii(results[0][1][2])
    context.stdout = out
    context.stderr = err
    context.return_code = 0
    for host, (rc, stdout, stderr) in results:
        if rc != 0:
            err = re.sub(COLOR_MODE, '', utils.to_ascii(stderr))
            context.stderr = err
            if exit_on_fail:
                import os
                context.logger.error("Failed to run %s on %s@%s :%s", cmd, os.geteuid(), host, err)
                raise ValueError("{}".format(err))
            else:
                return
    return 0, out, err


def check_service_state(context, service_name, state, addr):
    if state not in ["started", "stopped", "enabled", "disabled"]:
        context.logger.error("\nService state should be \"started/stopped/enabled/disabled\"\n")
        context.failed = True
    if state in {'enabled', 'disabled'}:
        rc, _, _ = behave_agent.call(addr, 1122, f'systemctl is-enabled {service_name}', 'root')
        return (state == 'enabled') == (rc == 0)
    elif state in {'started', 'stopped'}:
        rc, _, _ = behave_agent.call(addr, 1122, f'systemctl is-active {service_name}', 'root')
        return (state == 'started') == (rc == 0)
    else:
        context.logger.error("\nService state should be \"started/stopped/enabled/disabled\"\n")
        raise ValueError("Service state should be \"started/stopped/enabled/disabled\"")


def check_cluster_state(context, state, addr):
    return check_service_state(context, 'pacemaker.service', state, addr)


def is_unclean(node):
    rc, out, err = ShellUtils().get_stdout_stderr("crm_mon -1")
    return "{}: UNCLEAN".format(node) in out


def online(context, nodelist):
    rc = True
    _, out = ShellUtils().get_stdout("sudo crm_node -l")
    for node in nodelist.split():
        node_info = "{} member".format(node)
        if not node_info in out:
            rc = False
            context.logger.error("\nNode \"{}\" not online\n".format(node))
    return rc

def assert_eq(expected, actual):
    if expected != actual:
        msg = "\033[32m" "Expected" "\033[31m" " != Actual" "\033[0m" "\n" \
              "\033[32m" "Expected:" "\033[0m" " {}\n" \
              "\033[31m" "Actual:" "\033[0m" " {}".format(expected, actual)
        if isinstance(expected, str) and '\n' in expected:
            try:
                diff = '\n'.join(difflib.unified_diff(
                    expected.splitlines(),
                    actual.splitlines(),
                    fromfile="expected",
                    tofile="actual",
                    lineterm="",
                ))
                msg = "{}\n" "\033[31m" "Diff:" "\033[0m" "\n{}".format(msg, diff)
            except Exception:
                pass
        raise AssertionError(msg)

def assert_in(expected, actual):
    if expected not in actual:
        msg = "\033[32m" "Expected" "\033[31m" " not in Actual" "\033[0m" "\n" \
              "\033[32m" "Expected:" "\033[0m" " {}\n" \
              "\033[31m" "Actual:" "\033[0m" " {}".format(expected, actual)
        raise AssertionError(msg)
