# Copyright (C) 2020 Xin Liang <XLiang@suse.com>
# See COPYING for license information.


import re
import time
from contextlib import contextmanager

from . import utils
from . import config


class SSHError(Exception):
    pass


class JoinLock(object):
    """
    Class to manage lock for multiple nodes join in parallel
    """

    JOIN_LOCK_DIR = "/tmp/.crmsh_join_lock_directory"
    MKDIR_CMD = "mkdir {}".format(JOIN_LOCK_DIR)
    RM_CMD = "rm -rf {}".format(JOIN_LOCK_DIR)
    SSH_TIMEOUT = 10
    SSH_OPTION = "-o ConnectTimeout={} -o StrictHostKeyChecking=no".format(SSH_TIMEOUT)
    SSH_EXIT_ERR = 255
    MIN_JOIN_TIMEOUT = 120
    WAIT_INTERVAL = 10

    def __init__(self, init_node):
        """
        Init function
        """
        self.init_node = init_node
        # only the lock owner can unlock
        self.lock_owner = False

    @property
    def join_timeout(self):
        """
        Get join_timeout from config.core
        """
        try:
            value = int(config.core.join_timeout)
        except ValueError:
            raise ValueError("Invalid format of core.join_timeout(should be a number)")
        if value < self.MIN_JOIN_TIMEOUT:
            raise ValueError("Minimum value of core.join_timeout should be {}".format(self.MIN_JOIN_TIMEOUT))
        return value

    def _run(self, cmd):
        """
        Run command on target node, consider specific exceptions
        """
        cmd_with_ssh = "ssh {} root@{} \"{}\"".format(self.SSH_OPTION, self.init_node, cmd)
        rc, out, err = utils.get_stdout_stderr(cmd_with_ssh)
        if rc == self.SSH_EXIT_ERR:
            raise SSHError(err)
        return rc, out, err

    def _create_lock_dir(self):
        """
        Create lock directory, mkdir command was atomic
        """
        rc, _, _ = self._run(self.MKDIR_CMD)
        return rc == 0

    def _get_online_nodelist(self):
        """
        Get the online node list from init node
        """
        rc, out, err = self._run("crm_node -l")
        if rc != 0 and err:
            raise RuntimeError(err)
        return re.findall('[0-9]+ (.*) member', out)

    def _lock_or_wait(self):
        """
        Try to claim lock on init node,
        wait if failed to claim
        exit if reached the join_timeout
        """
        from . import bootstrap

        warned_once = False
        online_list = []
        pre_online_list = []
        expired_error_str = "Cannot continue since the lock directory exists at the init node ({}:{})".format(self.init_node, self.JOIN_LOCK_DIR)

        current_time = int(time.time())
        timeout = current_time + self.join_timeout
        while current_time <= timeout:

            # Try to claim the lock
            if self._create_lock_dir():
                # Success
                self.lock_owner = True
                break

            # Might lose claiming lock again, start to wait again
            online_list = self._get_online_nodelist()
            if pre_online_list and pre_online_list != online_list:
                warned_once = False
                current_time = int(time.time())
                timeout = current_time + self.join_timeout
                continue
            else:
                pre_online_list = online_list

            if not warned_once:
                warned_once = True
                bootstrap.warn("Other node still joining, wait at most {}s...".format(self.join_timeout))

            time.sleep(self.WAIT_INTERVAL)
            current_time = int(time.time())

        else:
            raise TimeoutError("Join process failed after {} seconds. {}".format(self.join_timeout, expired_error_str))

    @contextmanager
    def lock(self):
        """
        Create lock directory on target node
        """
        from . import bootstrap

        try:
            self._lock_or_wait()
            yield
        except SSHError as err:
            bootstrap.error(str(err))
        except:
            raise
        finally:
            self.unlock()

    def unlock(self):
        """
        Remove the lock directory on target node
        """
        if self.lock_owner:
            self._run(self.RM_CMD)
