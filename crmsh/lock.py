# Copyright (C) 2020 Xin Liang <XLiang@suse.com>
# See COPYING for license information.


import re
import time
from contextlib import contextmanager

from . import utils
from . import config
from . import log


logger = log.setup_logger(__name__)


class SSHError(Exception):
    """
    Custom exception for ssh error
    """


class ClaimLockError(Exception):
    """
    Custom exception if claiming lock failed or wait lock release timed out
    """


class Lock(object):
    """
    A base class define a lock mechanism used to exclude other nodes
    """

    LOCK_DIR_DEFAULT = "/run/.crmsh_lock_directory"

    def __init__(self, lock_dir=None):
        """
        Init function
        """
        # only the lock owner can unlock
        self.lock_owner = False
        self.lock_dir = lock_dir or self.LOCK_DIR_DEFAULT

    def _run(self, cmd):
        """
        Run command on local
        """
        return utils.get_stdout_stderr(cmd)

    def _create_lock_dir(self):
        """
        Create lock directory, mkdir command was atomic
        """
        cmd = "mkdir {}".format(self.lock_dir)
        rc, _, _ = self._run(cmd)
        if rc == 0:
            self.lock_owner = True
            return True
        return False

    def _lock_or_fail(self):
        """
        Raise ClaimLockError if claiming lock failed
        """
        if not self._create_lock_dir():
            raise ClaimLockError("Failed to claim lock (the lock directory exists at {})".format(self.lock_dir))

    def _unlock(self):
        """
        Remove the lock directory
        """
        if self.lock_owner:
            cmd = "rm -rf {}".format(self.lock_dir)
            self._run(cmd)

    @contextmanager
    def lock(self):
        """
        Create lock directory on local, and remove it finally
        Might raise ClaimLockError
        """
        try:
            self._lock_or_fail()
            yield
        except:
            raise
        finally:
            self._unlock()


class RemoteLock(Lock):
    """
    A class inherited from Lock class
    Define the behavior how to claim lock on remote node and how to wait the lock released
    """

    SSH_TIMEOUT = 10
    SSH_OPTION = "-o ConnectTimeout={} -o StrictHostKeyChecking=no".format(SSH_TIMEOUT)
    SSH_EXIT_ERR = 255
    MIN_LOCK_TIMEOUT = 120
    WAIT_INTERVAL = 10

    def __init__(self, remote_node, for_join=True, lock_dir=None, wait=True, no_warn=False):
        """
        Init function
        """
        self.remote_node = remote_node
        self.for_join = for_join
        self.wait = wait
        self.no_warn = no_warn
        super(__class__, self).__init__(lock_dir=lock_dir)

    def _run(self, cmd):
        """
        Run command on remote node
        """
        cmd = "ssh {} root@{} \"{}\"".format(self.SSH_OPTION, self.remote_node, cmd)
        rc, out, err = utils.get_stdout_stderr(cmd)
        if rc == self.SSH_EXIT_ERR:
            raise SSHError(err)
        return rc, out, err

    @property
    def lock_timeout(self):
        """
        Get lock_timeout from config.core
        """
        try:
            value = int(config.core.lock_timeout)
        except ValueError:
            raise ValueError("Invalid format of core.lock_timeout(should be a number)")
        if value < self.MIN_LOCK_TIMEOUT:
            raise ValueError("Minimum value of core.lock_timeout should be {}".format(self.MIN_LOCK_TIMEOUT))
        return value

    def _get_online_nodelist(self):
        """
        Get the online node list from remote node
        """
        rc, out, err = self._run("crm_node -l")
        if rc != 0 and err:
            raise ValueError(err)
        return re.findall('[0-9]+ (.*) member', out)

    def _lock_or_wait(self):
        """
        Try to claim lock on remote node, wait if failed to claim
        raise ClaimLockError if reached the lock_timeout
        """
        warned_once = False
        online_list = []
        pre_online_list = []
        expired_error_str = "Cannot continue since the lock directory exists at the node ({}:{})".format(self.remote_node, self.lock_dir)

        current_time = int(time.time())
        timeout = current_time + self.lock_timeout
        while current_time <= timeout:

            # Try to claim the lock
            if self._create_lock_dir():
                # Success
                break

            if self.for_join:
                # Might lose claiming lock again, start to wait again
                online_list = self._get_online_nodelist()
                if pre_online_list and pre_online_list != online_list:
                    timeout = current_time + self.lock_timeout
                pre_online_list = online_list

            if not self.no_warn and not warned_once:
                warned_once = True
                logger.warning("Might have unfinished process on other nodes, wait %ss...", self.lock_timeout)

            time.sleep(self.WAIT_INTERVAL)
            current_time = int(time.time())

        else:
            raise ClaimLockError("Timed out after {} seconds. {}".format(self.lock_timeout, expired_error_str))

    @contextmanager
    def lock(self):
        """
        Create lock directory on remote, and remove it finally
        Might raise SSHError, ClaimLockError and ValueError
        """
        try:
            if self.wait:
                self._lock_or_wait()
            else:
                self._lock_or_fail()
            yield
        except:
            raise
        finally:
            self._unlock()
