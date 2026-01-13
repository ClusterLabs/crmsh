#!/usr/bin/env python3
# behave_agent.py - a simple agent to execute command
# NO AUTHENTICATIONS. It should only be used in behave test.
import contextlib
import io
import itertools
import os
import pwd
import socket
import struct
import time
import typing


MSG_EOF  = 0
MSG_USER = 1
MSG_CMD  = 2
MSG_OUT  = 4 
MSG_ERR  = 5
MSG_RC   = 6


class Message:
    @staticmethod
    def write(output, type: int, data: bytes):
        output.write(struct.pack('!ii', type, len(data)))
        output.write(data)

    @staticmethod
    def read(input):
        buf = input.read(8)
        type, length = struct.unpack('!ii', buf)
        if length > 0:
            buf = input.read(length)
        else:
            buf = b''
        return type, buf


class SocketIO(io.RawIOBase):
    def __init__(self, s: socket.socket):
        self._socket = s

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return True

    def read(self, __size: int = -1) -> bytes:
        return self._socket.recv(__size)

    def readinto(self, __buffer) -> int:
        return self._socket.recv_into(__buffer)

    def readall(self) -> bytes:
        raise NotImplementedError

    def write(self, __b) -> int:
        return self._socket.send(__b)


def call(host: str, port: int, cmdline: str, user: typing.Optional[str] = None):
    family, type, proto, _, sockaddr =  socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0]
    with _socket_connect(family, type, proto, sockaddr) as s:
        sout = io.BufferedWriter(SocketIO(s), 4096)
        Message.write(sout, MSG_USER, user.encode('utf-8') if user else _getuser().encode('utf-8'))
        Message.write(sout, MSG_CMD, cmdline.encode('utf-8'))
        Message.write(sout, MSG_EOF, b'')
        sout.flush()
        s.shutdown(socket.SHUT_WR)
        rc = None
        stdout = []
        stderr = []
        sin = io.BufferedReader(SocketIO(s), 4096)
        while True:
            type, buf = Message.read(sin)
            if type == MSG_OUT:
                stdout.append(buf)
            elif type == MSG_ERR:
                stderr.append(buf)
            elif type == MSG_RC:
                rc, = struct.unpack('!i', buf)
            elif type == MSG_EOF:
                assert rc is not None
                return rc, b''.join(stdout), b''.join(stderr)
            else:
                raise ValueError(f"Unknown message type: {type}")


def _getuser():
    return pwd.getpwuid(os.geteuid()).pw_name


@contextlib.contextmanager
def _socket_connect(family, type, proto, sockaddr):
    for retry_count in itertools.count():
        with socket.socket(family, type, proto) as s:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 3)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            except Exception:
                pass
            try:
                s.connect(sockaddr)
                yield s
                return
            except PermissionError as e:
                if retry_count < 3:
                    time.sleep((retry_count + 1) * 3)
                else:
                    raise
