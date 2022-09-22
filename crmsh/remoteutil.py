#!/usr/bin/env python3
import contextlib
import shlex
import struct
import subprocess
import sys
import threading
import typing
# This script is intended to be run on a remote host. Only modules from standard library can be import here.


class Error(Exception):
    """base exception for this module"""
    pass


class ProtocolException(Error):
    # failure to deserialize arguments or results
    pass


class SshError(Error):
    """ssh errors, such as authentication problems and connection problems"""
    pass


class RemoteException(Error):
    # remote agent is not working as expected
    pass


class CalledProcessError(Error):
    """remote calling finished successfully, but cmd exits with a non-zero code."""
    def __init__(self, returncode, cmd, stdout, stderr):
        self.returncode = returncode
        self.cmd = cmd
        self.stdout = stdout
        self.stderr = stderr

    @property
    def output(self):
        return self.stdout


class RemoteCallArguments:
    # data structure to pass calling arguments to remote host, used only internally.
    def __init__(
            self,
            cmdline: str,
            cwd: str = None,
            stdin: typing.Union[str, bytes] = None,
            use_shell: bool = False,
            capture_output: bool = False
    ):
        self.cmdline = cmdline
        self.cwd = cwd
        self.stdin = stdin
        self.use_shell = use_shell
        self.capture_output = capture_output

    def serialize(self):
        cmdline = self.cmdline.encode('utf-8')
        cwd = b'' if self.cwd is None else self.cwd.encode('utf-8')
        if self.stdin is None:
            stdin = b''
        elif isinstance(self.stdin, str):
            stdin = self.stdin.encode('utf-8')
        else:
            stdin = self.stdin
        return struct.pack(
            '!III??',
            len(cmdline),
            len(cwd),
            len(stdin),
            self.use_shell,
            self.capture_output,
        ) + cmdline + cwd + stdin

    @staticmethod
    def deserialize(data):
        len_cmdline, len_cwd, len_stdin, use_shell, capture_stdout = struct.unpack_from('!III??', data)
        _, _, _, _, _, cmdline, cwd, stdin = struct.unpack('!III??{}s{}s{}s'.format(len_cmdline, len_cwd, len_stdin), data)
        cmdline = cmdline.decode('utf-8')
        cwd = None if len_cwd == 0 else cwd.decode('utf-8')
        stdin = None if len_stdin == 0 else stdin
        return RemoteCallArguments(cmdline, cwd, stdin, use_shell, capture_stdout)


class RemoteCallResult:
    """result of a remote call

    stdout and stderr is returned as bytes.
    """
    def __init__(self, rc: int, stdout: bytes = None, stderr: bytes = None):
        self.rc = rc
        self.stdout = stdout
        self.stderr = stderr

    def serialize(self):
        stdout = b'' if self.stdout is None else self.stdout
        stderr = b'' if self.stderr is None else self.stderr
        data = struct.pack('!III', self.rc, len(stdout), len(stderr)) + stdout + stderr
        return data

    @staticmethod
    def deserialize(data):
        rc, len_stdout, len_stderr = struct.unpack_from('!III', data)
        _, _, _, stdout, stderr = struct.unpack('!III{}s{}s'.format(len_stdout, len_stderr), data)
        return RemoteCallResult(rc, stdout, stderr)


def remote_agent(stdin: typing.BinaryIO, stdout: typing.BinaryIO, stderr: typing.TextIO):
    # read calling arguments
    request = stdin.read()
    try:
        arguments = RemoteCallArguments.deserialize(request)
    except (ValueError, struct.error) as e:
        raise ProtocolException(e, request) from None
    process = subprocess.Popen(
        arguments.cmdline if arguments.use_shell else shlex.split(arguments.cmdline),
        shell=arguments.use_shell,
        cwd=arguments.cwd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # TODO: implement not capturing outputs
    # run the cmd and capture outputs
    with contextlib.closing(process.stdin), contextlib.closing(process.stdout), contextlib.closing(process.stderr):
        def reader(f, bb):
            bb.append(f.read())
        stdout_buf_box = []
        stdout_reader = threading.Thread(target=reader, args=(process.stdout, stdout_buf_box), daemon=True)
        stdout_reader.start()
        stderr_buf_box = []
        stderr_reader = threading.Thread(target=reader, args=(process.stderr, stderr_buf_box), daemon=True)
        stderr_reader.start()
        if arguments.stdin is not None:
            process.stdin.write(arguments.stdin)
        process.stdin.close()
        process.wait()
        stdout_reader.join()
        stderr_reader.join()

    # write results
    result = RemoteCallResult(process.returncode, stdout_buf_box[0], stderr_buf_box[0])
    stdout.write(result.serialize())
    stdout.flush()


def remote_client(ifile: typing.BinaryIO, ofile: typing.BinaryIO, parameters: RemoteCallArguments):
    # write calling arguments to remote host
    ofile.write(parameters.serialize())
    ofile.flush()
    ofile.close()
    # read calling result from remote host
    ret = ifile.read()
    try:
        return RemoteCallResult.deserialize(ret)
    except struct.error as e:
        raise ProtocolException(e, ret) from None


# public API
def run(
        host: typing.Union[str, typing.Tuple[str, int, str]],
        cmd: str,
        cwd: str = None,
        stdin: typing.Union[str, bytes] = None,
        # TODO: implement sudo
        use_shell: bool = False,
        capture_output: bool = True,
        ssh_options: typing.List[str] = None
) -> RemoteCallResult:
    """ Run a command on specified host.

    By default, the cmd is not run with a shell, so redirections/substitutions will not work. Set `use_shell` to True to
    enable these features.

    Warning: enable `use_shell` make it vulnerable to shell injection, avoid using it if unnecessary.
    """
    if ssh_options is None:
        ssh_options = ['-o', 'StrictHostKeyChecking=no']
    args = ['ssh']
    args.extend(ssh_options)
    if isinstance(host, str):
        args.append(host)
    else:
        args.extend(['-p', str(host[1]), '{}@{}'.format(host[2], host[0])])
    with open(__file__, 'rb') as f:
        script = f.read()
    args.extend(['/bin/sh', '-c', ';F=$(mktemp)&&head -c {} >"$F"&&chmod +x "$F"&&"$F";rm -f "$F"'.format(len(script))])
    # run a shell oneliner on remote host with ssh, which load and execute a larger executable from stdin.
    process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with contextlib.closing(process.stdin), contextlib.closing(process.stdout), contextlib.closing(process.stderr):
        # fork a thread to consume stderr pipe so that the other end will not be blocked
        def reader(f, bb):
            bb.append(f.read())
        stderr_buf_box = []
        stderr_reader = threading.Thread(target=reader, args=(process.stderr, stderr_buf_box), daemon=True)
        stderr_reader.start()
        # send this script to the oneliner, so remote_agent() is executed on remote host
        process.stdin.write(script)
        arguments = RemoteCallArguments(cmd, cwd, stdin, use_shell, capture_output)
        try:
            result = remote_client(process.stdout, process.stdin, arguments)
        except ProtocolException:
            ssh_rc = process.wait()
            stderr_reader.join()
            if ssh_rc == 255:
                raise SshError(stderr_buf_box[0].decode('utf-8', 'replace')) from None
            else:
                raise RemoteException(ssh_rc, stderr_buf_box[0].decode('utf-8', 'replace'))
        else:
            ssh_rc = process.wait()
            stderr_reader.join()
            if ssh_rc == 255:
                raise SshError(stderr_buf_box[0].decode('utf-8', 'replace'))
            elif ssh_rc != 0:
                raise RemoteException(ssh_rc, stderr_buf_box[0].decode('utf-8', 'replace'))
            else:
                return result


# public API
def check_call(
        host: typing.Union[str, typing.Tuple[str, int, str]],
        cmd: str,
        cwd: str = None,
        stdin: typing.Union[str, bytes] = None,
        # TODO: implement sudo
        use_shell: bool = False,
        capture_output: bool = True,
        ssh_options: typing.List[str] = None
):
    """Run a command on remote host and raise CalledProcessError when it exits with non-zero code."""
    result = run(host, cmd, cwd, stdin, use_shell, capture_output, ssh_options)
    if result.rc != 0:
        raise CalledProcessError(result.rc, cmd, result.stdout, result.stderr)


if __name__ == '__main__':
    # use BinaryIO instead of TextIO, since we are working with binary streams
    remote_agent(sys.stdin.buffer, sys.stdout.buffer, sys.stderr)
