import logging
import socket
import subprocess
import typing

from . import config
from . import constants
from . import userdir
from .pyshim import cache


logger = logging.getLogger(__name__)


class UserNotFoundError(ValueError):
    pass


class UserOfHost:
    @staticmethod
    def instance():
        return _user_of_host_instance

    @staticmethod
    @cache
    def this_node():
        return socket.gethostname()

    def __init__(self):
        self._user_cache = dict()
        self._user_pair_cache = dict()

    def user_of(self, host):
        cached = self._user_cache.get(host)
        if cached is None:
            ret = self._get_user_of_host_from_config(host)
            if ret is None:
                raise UserNotFoundError()
            else:
                self._user_cache[host] = ret
                return ret
        else:
            return cached

    def user_pair_for_ssh(self, host: str) -> typing.Tuple[str, str]:
        """Return (local_user, remote_user) pair for ssh connection"""
        local_user = None
        remote_user = None
        try:
            local_user = 'root' if self._use_ssh_agent() else self.user_of(self.this_node())
            remote_user = self.user_of(host)
            return local_user, remote_user
        except UserNotFoundError:
            cached = self._user_pair_cache.get(host)
            if cached is None:
                if local_user is not None:
                    ret = local_user, local_user
                    self._user_pair_cache[host] = ret
                    return ret
                else:
                    ret = self._guess_user_for_ssh(host)
                    if ret is None:
                        raise UserNotFoundError
                    else:
                        self._user_pair_cache[host] = ret
                        return ret
            else:
                return cached

    @staticmethod
    def _use_ssh_agent() -> bool:
        return config.get_option('core', 'no_generating_ssh_key')

    @staticmethod
    def _get_user_of_host_from_config(host):
        try:
            canonical, aliases, _ = socket.gethostbyaddr(host)
            aliases = set(aliases)
            aliases.add(canonical)
            aliases.add(host)
        except (socket.herror, socket.gaierror):
            aliases = {host}
        hosts = config.get_option('core', 'hosts')
        if hosts == ['']:
            return None
        for item in hosts:
            if item.find('@') != -1:
                user, node = item.split('@')
            else:
                user = userdir.getuser()
                node = item
            if node in aliases:
                return user
        logger.debug('Failed to get the user of host %s (aliases: %s). Known hosts are %s', host, aliases, hosts)
        return None

    @staticmethod
    def _guess_user_for_ssh(host: str) -> typing.Tuple[str, str]:
        args = ['ssh']
        args.extend(constants.SSH_OPTION_ARGS)
        args.extend(['-o', 'BatchMode=yes', host, 'sudo', 'true'])
        rc = subprocess.call(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if rc == 0:
            user = userdir.getuser()
            return user, user
        else:
            return None


_user_of_host_instance = UserOfHost()


def instance():
    return _user_of_host_instance
