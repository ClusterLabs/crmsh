# prun.py - run command or copy files on multiple hosts concurrently
import os
import random
import socket
import tempfile
import typing

import crmsh.constants
import crmsh.userdir
from crmsh.prun.runner import Task, Runner
from crmsh.user_of_host import UserOfHost
from crmsh.sh import Utils

_DEFAULT_CONCURRENCY = 32

_SUDO_SFTP_SERVER = 'sudo --preserve-env=SSH_AUTH_SOCK PATH=/usr/lib/ssh:/usr/lib/openssh:/usr/libexec/ssh:/usr/libexec/openssh /bin/sh -c "exec sftp-server"'


class ProcessResult:
    def __init__(self, returncode: int, stdout: bytes, stderr: bytes):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class PRunError(Exception):
    """Base exception class for all error in prun module."""
    def __init__(self, user, host, *args):
        super().__init__(*args)
        self.user = user
        self.host = host


class SSHError(PRunError):
    def __init__(self, user, host, msg):
        super().__init__(user, host, f"Cannot create SSH connection to {user}@{host}: {msg}")


class TimeOutError(PRunError):
    def __init__(self, user, host):
        super().__init__(user, host, f"Timed out on {user}@{host}.")


class PRunInterceptor:
    def task(self, task: Task) -> Task:
        return task
    def result(self, result: ProcessResult) -> ProcessResult:
        return result
    def exception(self, exc: PRunError) -> PRunError:
        return exc


def prun(
        host_cmdline: typing.Mapping[str, str],
        *,
        timeout_seconds: int = -1,
        concurrency: int = _DEFAULT_CONCURRENCY,
        interceptor: PRunInterceptor = PRunInterceptor(),
) -> typing.Dict[str, typing.Union[ProcessResult, SSHError]]:
    """Run a command on multiple hosts concurrently.

    Args:
        host_cmdline: A mapping from hosts to command lines to be run on that host.
        timeout_seconds: (optional) The maximum number of seconds to wait for all the commands to complete.
        concurrency: (optional) The maximum number of commands to be run concurrently.
        interceptor: (optional) An interceptor that can modify the inputs of tasks before they are run,
                        and the results after they are finished.

    Returns:
        A mapping from the host to the results of the command run on that host.
    """
    tasks = [_build_run_task(host, cmdline) for host, cmdline in host_cmdline.items()]
    runner = Runner(concurrency)
    for task in tasks:
        task = interceptor.task(task)
        runner.add_task(task)
    runner.run(timeout_seconds)
    return {task.context['host']: _handle_run_result(task, interceptor) for task in tasks}


def prun_multimap(
        host_cmdline: typing.Sequence[typing.Tuple[str, str]],
        *,
        concurrency: int = _DEFAULT_CONCURRENCY,
        timeout_seconds: int = -1,
        interceptor: PRunInterceptor = PRunInterceptor(),
) -> typing.Sequence[typing.Tuple[str, typing.Union[ProcessResult, SSHError]]]:
    """A varient of prun that allow run multiple commands on the same host."""
    tasks = [_build_run_task(host, cmdline) for host, cmdline in host_cmdline]
    runner = Runner(concurrency)
    for task in tasks:
        task = interceptor.task(task)
        runner.add_task(task)
    runner.run(timeout_seconds)
    return [
        (task.context['host'], _handle_run_result(task, interceptor))
        for task in tasks
    ]


def _build_run_task(remote: str, cmdline: str) -> Task:
    if _is_local_host(remote):
        if 0 == os.geteuid():
            args = ['/bin/sh']
            remote_sudoer = 'root'
        else:
            remote_sudoer = crmsh.userdir.get_sudoer()
            if remote_sudoer == crmsh.userdir.getuser():
                args = ['sudo', '/bin/sh']
            else:
                raise AssertionError('trying to run sudo as a non-root user')
        return Task(
            args,
            cmdline.encode('utf-8'),
            stdout=Task.Capture,
            stderr=Task.Capture,
            context={"host": remote, "ssh_user": remote_sudoer},
        )
    else:
        local_sudoer, remote_sudoer = UserOfHost.instance().user_pair_for_ssh(remote)
        shell = 'ssh -A {} {}@{} sudo -H /bin/sh'.format(crmsh.constants.SSH_OPTION, remote_sudoer, remote)
        if local_sudoer == crmsh.userdir.getuser():
            args = ['/bin/sh', '-c', shell]
        elif os.geteuid() == 0:
            args = ['su', local_sudoer, '--login', '-c', shell, '-w', 'SSH_AUTH_SOCK']
        else:
            raise AssertionError('trying to run su as a non-root user')
        return Task(
            args,
            cmdline.encode('utf-8'),
            stdout=Task.Capture,
            stderr=Task.Capture,
            context={"host": remote, "ssh_user": remote_sudoer},
        )


def _handle_run_result(task: Task, interceptor: PRunInterceptor = PRunInterceptor()):
    if task.returncode is None:
        return interceptor.exception(TimeOutError(task.context['ssh_user'], task.context['host']))
    elif task.returncode == 255:
        return interceptor.exception(SSHError(task.context['ssh_user'], task.context['host'], Utils.decode_str(task.stderr)))
    else:
        return interceptor.result(ProcessResult(task.returncode, task.stdout, task.stderr))


def pcopy_to_remote(
        src: str,
        hosts: typing.Sequence[str], dst: str,
        recursive: bool = False,
        *,
        atomic_write: bool = False,
        timeout_seconds: int = -1,
        concurrency: int = _DEFAULT_CONCURRENCY,
        interceptor: PRunInterceptor = PRunInterceptor(),
) -> typing.Dict[str, typing.Optional[PRunError]]:
    """Copy file or directory from local to remote hosts concurrently."""
    if src == dst:
        # copy a file to itself will ruin the data
        hosts_filtered = [x for x in hosts if not _is_local_host(x)]
        if hosts_filtered:
            hosts = hosts_filtered
        else:
            return {x: None for x in hosts}
    flags = '-pr' if recursive else '-p'
    local_sudoer, _ = UserOfHost.instance().user_pair_for_ssh(hosts[0])
    if atomic_write:
        suffix = '{:x}-{}'.format(random.SystemRandom().getrandbits(64), socket.gethostname())
        script = f"put {flags} '{src}' '{dst}.{suffix}'\nrename '{dst}.{suffix}' '{dst}'\n"
    else:
        script = "put {} '{}' '{}'\n".format(flags, src, dst)
    ssh = None
    try:
        # sftp -S does not parse args, it accepts only a single executable. So we create one.
        if local_sudoer == crmsh.userdir.getuser():
            tasks = [_build_copy_task('', script, host) for host in hosts]
        else:
            ssh = tempfile.NamedTemporaryFile('w', encoding='utf-8', delete=False)
            os.fchmod(ssh.fileno(), 0o700)
            ssh.write(f'''#!/bin/sh
exec sudo --preserve-env=SSH_AUTH_SOCK -u {local_sudoer} ssh "$@"''')
        # It is necessary to close the file before executing, or we will get an EBUSY.
            ssh.close()
            tasks = [_build_copy_task("-S '{}'".format(ssh.name), script, host) for host in hosts]
        runner = Runner(concurrency)
        for task in tasks:
            runner.add_task(interceptor.task(task))
        runner.run(timeout_seconds)
    finally:
        if ssh is not None:
            os.unlink(ssh.name)
            ssh.close()
    return {task.context['host']: _parse_copy_result(task, interceptor) for task in tasks}


def _build_copy_task(ssh: str, script: str, host: str):
    _, remote_sudoer = UserOfHost.instance().user_pair_for_ssh(host)
    cmd = "sftp {} {} -o BatchMode=yes -s '{}' -b - {}@{}".format(
        ssh,
        crmsh.constants.SSH_OPTION,
        _SUDO_SFTP_SERVER,
        remote_sudoer, _enclose_inet6_addr(host),
    )
    return Task(
        ['/bin/sh', '-c', cmd],
        input=script.encode('utf-8'),
        stdout=Task.Capture,
        stderr=Task.Stdout,
        context={"host": host, "ssh_user": remote_sudoer},
    )


def _parse_copy_result(task: Task, interceptor: PRunInterceptor) -> typing.Optional[PRunError]:
    if task.returncode == 0:
        return None
    elif task.returncode == 255:
        return interceptor.exception(SSHError(task.context['ssh_user'], task.context['host'], Utils.decode_str(task.stdout)))
    else:
        return interceptor.exception(PRunError(task.context['ssh_user'], task.context['host'], Utils.decode_str(task.stdout)))


def pfetch_from_remote(
        hosts: typing.Sequence[str], src: str,
        dst: str,
        recursive=False,
        *,
        concurrency: int = _DEFAULT_CONCURRENCY,
        interceptor: PRunInterceptor = PRunInterceptor(),
) -> typing.Dict[str, typing.Union[str, PRunError]]:
    """Copy files from remote hosts to local concurrently.

    Files are copied to directory <dst>/<host>/ corresponding to each source host."""
    flags = '-pR' if recursive else '-p'
    local_sudoer, _ = UserOfHost.instance().user_pair_for_ssh(hosts[0])
    ssh = None
    try:
        if local_sudoer == crmsh.userdir.getuser():
            tasks = [_build_fetch_task('', host, src, dst, flags) for host in hosts]
        else:
            ssh = tempfile.NamedTemporaryFile('w', encoding='utf-8', delete=False)
            os.fchmod(ssh.fileno(), 0o700)
            ssh.write(f'''#!/bin/sh
    exec sudo --preserve-env=SSH_AUTH_SOCK -u {local_sudoer} ssh "$@"''')
            # It is necessary to close the file before executing
            ssh.close()
            tasks = [_build_fetch_task("-S '{}'".format(ssh.name), host, src, dst, flags) for host in hosts]
        runner = Runner(concurrency)
        for task in tasks:
            runner.add_task(interceptor.task(task))
        runner.run()
    finally:
        if ssh is not None:
            os.unlink(ssh.name)
            ssh.close()
    basename = os.path.basename(src)
    return {
        host: v if v is not None else f"{dst}/{host}/{basename}"
        for host, v in ((task.context['host'], _parse_copy_result(task, interceptor)) for task in tasks)
    }


def _build_fetch_task( ssh: str, host: str, src: str, dst: str, flags: str) -> Task:
    _, remote_sudoer = UserOfHost.instance().user_pair_for_ssh(host)
    cmd = "sftp {} {} -o BatchMode=yes -s '{}' -b - {}@{}".format(
        ssh,
        crmsh.constants.SSH_OPTION,
        _SUDO_SFTP_SERVER,
        remote_sudoer, _enclose_inet6_addr(host),
    )
    os.makedirs(f"{dst}/{host}", exist_ok=True)
    return Task(
        ['/bin/sh', '-c', cmd],
        input='get {} "{}" "{}/{}/"\n'.format(flags, src, dst, host).encode('utf-8'),
        stdout=Task.Capture,
        stderr=Task.Stdout,
        context={"host": host, "ssh_user": remote_sudoer},
    )


def _enclose_inet6_addr(addr: str):
    if ':' in addr:
        return f'[{addr}]'
    else:
        return addr


def _is_local_host(host):
    """
    Check if the host is local
    """
    try:
        socket.inet_aton(host)
        hostname = socket.gethostbyaddr(host)[0]
    except OSError:
        hostname = host
    return hostname == socket.gethostname()
