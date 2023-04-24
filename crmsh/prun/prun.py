import os
import socket
import tempfile
import typing

import crmsh.constants
import crmsh.userdir
import crmsh.utils
from crmsh.prun.runner import Task, Runner


_DEFAULT_CONCURRENCY = 32


class ProcessResult:
    def __init__(self, returncode: int, stdout: bytes, stderr: bytes):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class PRunError(Exception):
    def __init__(self, user, host, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        self.host = host


class SSHError(PRunError):
    def __init__(self, user, host, msg):
        super().__init__(user, host, f"Cannot create SSH connection to {user}@{host}: {msg}")


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
        concurrency: int = _DEFAULT_CONCURRENCY,
        interceptor: PRunInterceptor = PRunInterceptor(),
) -> typing.Dict[str, typing.Union[ProcessResult, SSHError]]:
    tasks = [_build_run_task(host, cmdline) for host, cmdline in host_cmdline.items()]
    runner = Runner(concurrency)
    for task in tasks:
        task = interceptor.task(task)
        runner.add_task(task)
    runner.run()
    return {
        task.context['host']: (
            interceptor.result(ProcessResult(task.returncode, task.stdout, task.stderr)) if task.returncode != 255
            else interceptor.exception(SSHError(task.context['ssh_user'], task.context['host'], crmsh.utils.to_ascii(task.stderr)))
        )
        for task in tasks
    }


def prun_multimap(
        host_cmdline: typing.Sequence[typing.Tuple[str, str]],
        *,
        concurrency: int = _DEFAULT_CONCURRENCY,
        interceptor: PRunInterceptor = PRunInterceptor(),
) -> typing.Sequence[typing.Tuple[str, typing.Union[ProcessResult, SSHError]]]:
    tasks = [_build_run_task(host, cmdline) for host, cmdline in host_cmdline]
    runner = Runner(concurrency)
    for task in tasks:
        task = interceptor.task(task)
        runner.add_task(task)
    runner.run()
    return [(
        task.context['host'],
        interceptor.result(ProcessResult(task.returncode, task.stdout, task.stderr)) if task.returncode != 255
        else interceptor.exception(SSHError(task.context['ssh_user'], task.context['host'], crmsh.utils.to_ascii(task.stderr))),
    ) for task in tasks]


def _build_run_task(remote: str, cmdline: str) -> Task:
    local_sudoer, remote_sudoer = crmsh.utils.user_pair_for_ssh(remote)
    if _is_local_host(remote):
        if 0 == os.geteuid():
            args = ['/bin/sh']
        elif local_sudoer == crmsh.userdir.getuser():
            args = ['sudo', '/bin/sh']
        else:
            raise AssertionError('trying to run sudo as a non-root user')
    else:
        shell = 'ssh {} {}@{} sudo -H /bin/sh'.format(crmsh.constants.SSH_OPTION, remote_sudoer, remote)
        if local_sudoer == crmsh.userdir.getuser():
            args = ['/bin/sh', '-c', shell]
        elif os.geteuid() == 0:
            args = ['su', local_sudoer, '--login', '-c', shell]
        else:
            raise AssertionError('trying to run su as a non-root user')
    return Task(
        args,
        cmdline.encode('utf-8'),
        stdout=Task.Capture,
        stderr=Task.Capture,
        context={"host": remote, "ssh_user": remote_sudoer},
    )


def pcopy_to_remote(
        src: str,
        hosts: typing.Sequence[str], dst: str,
        recursive: bool = False,
        *,
        concurrency: int = _DEFAULT_CONCURRENCY,
) -> typing.Dict[str, typing.Optional[PRunError]]:
    """Copy file or directory from local to remote hosts concurrently."""
    if src == dst:
        hosts_filtered = [x for x in hosts if not _is_local_host(x)]
        if hosts_filtered:
            hosts = hosts_filtered
        else:
            return {x: None for x in hosts}
    flags = '-pr' if recursive else '-p'
    local_sudoer, _ = crmsh.utils.user_pair_for_ssh(hosts[0])
    script = "put {} '{}' '{}'\n".format(flags, src, dst)
    ssh = None
    try:
        ssh = tempfile.NamedTemporaryFile('w', encoding='utf-8', delete=False)
        os.fchmod(ssh.fileno(), 0o700)
        ssh.write(f'''#!/bin/sh
exec sudo -u {local_sudoer} ssh "$@"''')
        # It is necessary to close the file before executing
        ssh.close()
        tasks = [_build_copy_task("-S '{}'".format(ssh.name), script, host) for host in hosts]
        runner = Runner(concurrency)
        for task in tasks:
            runner.add_task(task)
        runner.run()
    finally:
        if ssh is not None:
            os.unlink(ssh.name)
            ssh.close()
    return {task.context['host']: _parse_copy_result(task) for task in tasks}


def _build_copy_task(ssh: str, script: str, host: str):
    _, remote_sudoer = crmsh.utils.user_pair_for_ssh(host)
    cmd = "sftp {} {} -o BatchMode=yes -s 'sudo PATH=/usr/lib/ssh:/usr/libexec/ssh /bin/sh -c \"exec sftp-server\"' -b - {}@{}".format(
        ssh,
        crmsh.constants.SSH_OPTION,
        remote_sudoer, _enclose_inet6_addr(host),
    )
    return Task(
        ['/bin/sh', '-c', cmd],
        input=script.encode('utf-8'),
        stdout=Task.Capture,
        stderr=Task.Stdout,
        context={"host": host, "ssh_user": remote_sudoer},
    )


def _parse_copy_result(task: Task) -> typing.Optional[PRunError]:
    if task.returncode == 0:
        return None
    elif task.returncode == 255:
        return SSHError(task.context['ssh_user'], task.context['host'], crmsh.utils.to_ascii(task.stdout))
    else:
        return PRunError(task.context['ssh_user'], task.context['host'], crmsh.utils.to_ascii(task.stdout))


def pfetch_from_remote(
        hosts: typing.Sequence[str], src: str,
        dst: str,
        recursive=False,
        *,
        concurrency: int = _DEFAULT_CONCURRENCY,
) -> typing.Dict[str, typing.Union[str, PRunError]]:
    """Copy files from remote hosts to local concurrently.

    Files are copied to directory <dst>/<host>/ corresponding to each source host."""
    flags = '-pR' if recursive else '-p'
    local_sudoer, _ = crmsh.utils.user_pair_for_ssh(hosts[0])
    ssh = None
    try:
        ssh = tempfile.NamedTemporaryFile('w', encoding='utf-8', delete=False)
        os.fchmod(ssh.fileno(), 0o700)
        ssh.write(f'''#!/bin/sh
exec sudo -u {local_sudoer} ssh "$@"''')
        # It is necessary to close the file before executing
        ssh.close()
        tasks = [_build_fetch_task("-S '{}'".format(ssh.name), host, src, dst, flags) for host in hosts]
        runner = Runner(concurrency)
        for task in tasks:
            runner.add_task(task)
        runner.run()
    finally:
        if ssh is not None:
            os.unlink(ssh.name)
            ssh.close()
    basename = os.path.basename(src)
    return {
        host: v if v is not None else f"{dst}/{host}/{basename}"
        for host, v in ((task.context['host'], _parse_copy_result(task)) for task in tasks)
    }


def _build_fetch_task( ssh: str, host: str, src: str, dst: str, flags: str) -> Task:
    _, remote_sudoer = crmsh.utils.user_pair_for_ssh(host)
    cmd = "sftp {} {} -o BatchMode=yes -s 'sudo PATH=/usr/lib/ssh:/usr/libexec/ssh /bin/sh -c \"exec sftp-server\"' -b - {}@{}".format(
        ssh,
        crmsh.constants.SSH_OPTION,
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
