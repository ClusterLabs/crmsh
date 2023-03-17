import os
import typing

import crmsh.constants
import crmsh.userdir
import crmsh.utils
from crmsh.prun.runner import Task, Runner


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


def prun(host_cmdline: typing.Mapping[str, str]) -> typing.Dict[str, typing.Union[ProcessResult, SSHError]]:
    tasks = [_build_run_task(host, cmdline) for host, cmdline in host_cmdline.items()]
    runner = Runner()
    for task in tasks:
        runner.add_task(task)
    runner.run()
    return {
        task.context['host']: (
            ProcessResult(task.returncode, task.stdout, task.stderr) if task.returncode != 255
            else SSHError(task.context['ssh_user'], task.context['host'], crmsh.utils.to_ascii(task.stderr))
        )
        for task in tasks
    }


def _build_run_task(remote: str, cmdline: str) -> Task:
    local_sudoer, remote_sudoer = crmsh.utils.user_pair_for_ssh(remote)
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
        capture_stdout=True, capture_stderr=True,
        context={"host": remote, "ssh_user": remote_sudoer},
    )
