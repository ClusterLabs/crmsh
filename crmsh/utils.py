# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.
import asyncio
import errno
import os
import sys
import typing
from tempfile import mkstemp
import subprocess
import re
import time
import datetime
import shutil
import shlex
import fnmatch
import gc
import ipaddress
import argparse
import random
import string
import pwd
import grp
import functools
import gzip
import bz2
import lzma
import json
import socket
from pathlib import Path
from collections import defaultdict
from contextlib import contextmanager, closing
from stat import S_ISBLK
from lxml import etree
from packaging import version
from enum import IntFlag, auto

import crmsh.parallax
import crmsh.user_of_host
from . import config, sh, corosync, cibquery
from . import userdir
from . import constants
from . import options
from . import term
from . import log
from . import xmlutil
from .prun import prun
from .sh import ShellUtils
from .service_manager import ServiceManager

logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)


class TerminateSubCommand(Exception):
    """
    This is an exception to jump out of subcommand when meeting errors while staying interactive shell
    """
    def __init__(self, success=False):
        self.success = success


def to_ascii(input_str):
    """Convert the bytes string to a ASCII string
    Usefull to remove accent (diacritics)"""
    if input_str is None:
        return input_str
    if isinstance(input_str, str):
        return input_str
    try:
        return str(input_str, 'utf-8')
    except UnicodeDecodeError:
        if config.core.debug or options.regression_tests:
            import traceback
            traceback.print_exc()
        return input_str.decode('utf-8', errors='ignore')


def filter_keys(key_list, args, sign="="):
    """Return list item which not be completed yet"""
    return [s+sign for s in key_list if any_startswith(args, s+sign) is None]


def any_startswith(iterable, prefix):
    """Return first element in iterable which startswith prefix, or None."""
    for element in iterable:
        if element.startswith(prefix):
            return element
    return None


def rindex(iterable, value):
    return len(iterable) - iterable[::-1].index(value) - 1


def raise_exception(e):
    # a wrapper for raising an exception in lambda function
    raise e


def memoize(function):
    "Decorator to invoke a function once only for any argument"
    memoized = {}

    @functools.wraps(function)
    def inner(*args):
        if args in memoized:
            return memoized[args]
        r = function(*args)
        memoized[args] = r
        return r
    return inner


@contextmanager
def nogc():
    gc.disable()
    try:
        yield
    finally:
        gc.enable()


getuser = userdir.getuser
gethomedir = userdir.gethomedir


def user_of(host):
    return crmsh.user_of_host.instance().user_of(host)


def user_pair_for_ssh(host):
    try:
        return crmsh.user_of_host.instance().user_pair_for_ssh(host)
    except crmsh.user_of_host.UserNotFoundError:
        raise ValueError('Can not create ssh session from {} to {}.'.format(this_node(), host))


@memoize
def this_node():
    'returns name of this node (hostname)'
    return os.uname()[1]


_cib_shadow = 'CIB_shadow'
_cib_in_use = ''


def set_cib_in_use(name):
    os.environ[_cib_shadow] = name
    global _cib_in_use
    _cib_in_use = name


def clear_cib_in_use():
    if _cib_shadow in os.environ:
        del os.environ[_cib_shadow]
    global _cib_in_use
    _cib_in_use = ''


def get_cib_in_use():
    return _cib_in_use


def get_tempdir():
    return os.getenv("TMPDIR") or "/tmp"


def is_program(prog):
    """Is this program available?"""
    def isexec(filename):
        return os.path.isfile(filename) and os.access(filename, os.X_OK)
    for p in os.getenv("PATH").split(os.pathsep):
        f = os.path.join(p, prog)
        if isexec(f):
            return f
    return None


def get_cluster_option_metadata(show_xml=True) -> str:
    output_type = "xml" if show_xml else "text"
    cmd = f"crm_attribute --list-options=cluster --all --output-as={output_type}"
    rc, out, _ = ShellUtils().get_stdout_stderr(cmd)
    if rc == 0 and out:
        return out
    return None


def get_resource_metadata(show_xml=True) -> str:
    output_type = "xml" if show_xml else "text"
    cmd = f"crm_resource --list-options=primitive --all --output-as={output_type}"
    rc, out, _ = ShellUtils().get_stdout_stderr(cmd)
    if rc == 0 and out:
        return out
    return None


def pacemaker_20_daemon(new, old):
    "helper to discover renamed pacemaker daemons"
    if is_program(new):
        return new
    return old


@memoize
def pacemaker_attrd():
    return pacemaker_20_daemon("pacemaker-attrd", "attrd")


@memoize
def pacemaker_based():
    return pacemaker_20_daemon("pacemaker-based", "cib")


@memoize
def pacemaker_controld():
    return pacemaker_20_daemon("pacemaker-controld", "crmd")


@memoize
def pacemaker_execd():
    return pacemaker_20_daemon("pacemaker-execd", "lrmd")


@memoize
def pacemaker_fenced():
    return pacemaker_20_daemon("pacemaker-fenced", "stonithd")


@memoize
def pacemaker_remoted():
    return pacemaker_20_daemon("pacemaker-remoted", "pacemaker_remoted")


@memoize
def pacemaker_schedulerd():
    return pacemaker_20_daemon("pacemaker-schedulerd", "pengine")


def pacemaker_daemon(name):
    if name == "attrd" or name == "pacemaker-attrd":
        return pacemaker_attrd()
    if name == "cib" or name == "pacemaker-based":
        return pacemaker_based()
    if name == "crmd" or name == "pacemaker-controld":
        return pacemaker_controld()
    if name == "lrmd" or name == "pacemaker-execd":
        return pacemaker_execd()
    if name == "stonithd" or name == "pacemaker-fenced":
        return pacemaker_fenced()
    if name == "pacemaker_remoted" or name == "pacemeaker-remoted":
        return pacemaker_remoted()
    if name == "pengine" or name == "pacemaker-schedulerd":
        return pacemaker_schedulerd()
    raise ValueError("Not a Pacemaker daemon name: {}".format(name))


def can_ask(background_wait=True):
    """
    Is user-interactivity possible?
    Checks if connected to a TTY.
    """
    can_ask =  (not options.ask_no) and sys.stdin.isatty()
    if not background_wait:
        try:
            can_ask = can_ask and os.tcgetpgrp(sys.stdin.fileno()) == os.getpgrp()
        except OSError as e:
            if e.errno == errno.ENOTTY:
                can_ask = False
    return can_ask


def ask(msg, background_wait=True, cancel_option=False):
    """Ask for user confirmation.

    Parameters:
    * background_wait: When set to False, return False without asking if current process is in background. Otherwise,
    block until the process is brought to foreground.

    Global Options:
    * core.force: always return true without asking
    * options.ask_no: do not ask and return false
    """
    if config.core.force:
        logger.info("%s [YES]", msg)
        return True
    if not can_ask(background_wait):
        return False

    option_str = "y/n" + ("/c" if cancel_option else "")
    msg += ' '
    if msg.endswith('? '):
        msg = msg[:-2] + f'  ({option_str})? '

    while True:
        try:
            ans = input(msg)
        except EOFError:
            ans = 'n'
        if ans:
            ans = ans[0].lower()
            if ans == 'c':
                raise TerminateSubCommand
            if ans in 'yn':
                return ans == 'y'


def ask_for_choice(question: str, choices: typing.List[str], default: int = None, background_wait=True, yes_to_all=False) -> int:
    msg = '{} ({})? '.format(question, '/'.join((choice if i != default else '[{}]'.format(choice) for i, choice in enumerate(choices))))
    if yes_to_all and default is not None:
        logger.info('%s %s', msg, choices[default])
        return default
    if not can_ask(background_wait):
        if default is None:
            fatal("User input is impossible in a non-interactive session.")
        else:
            logger.info('%s %s', msg, choices[default])
            return default
    while True:
        try:
            choice = input(msg)
        except EOFError:
            choice = ''
        if choice == '':
            if default is not None:
                return default
        else:
            for i, x in enumerate(choices):
                if choice == x:
                    return i


# holds part of line before \ split
# for a multi-line input
_LINE_BUFFER = ''


def get_line_buffer():
    return _LINE_BUFFER


def multi_input(prompt=''):
    """
    Get input from user
    Allow multiple lines using a continuation character
    """
    global _LINE_BUFFER
    line = []
    _LINE_BUFFER = ''
    while True:
        try:
            text = input(prompt)
        except EOFError:
            return None
        if options.regression_tests:
            logger_utils.incr_lineno()
            print(".INP:", text)
            sys.stdout.flush()
            sys.stderr.flush()
        stripped = text.strip()
        if stripped.endswith('\\'):
            stripped = stripped.rstrip('\\')
            line.append(stripped)
            _LINE_BUFFER += stripped
            if prompt:
                prompt = '   > '
        else:
            line.append(stripped)
            break
    return ''.join(line)


def verify_boolean(opt):
    return opt.lower() in ("yes", "true", "on", "1") or \
        opt.lower() in ("no", "false", "off", "0")


def is_boolean_true(opt):
    if opt in (None, False):
        return False
    if opt is True:
        return True
    return opt.lower() in ("yes", "true", "on", "1")


def is_boolean_false(opt):
    if opt in (None, False):
        return True
    if opt is True:
        return False
    return opt.lower() in ("no", "false", "off", "0")


def get_boolean(opt, dflt=False):
    if not opt:
        return dflt
    return is_boolean_true(opt)


def canonical_boolean(opt):
    return 'true' if is_boolean_true(opt) else 'false'


def keyword_cmp(string1, string2):
    return string1.lower() == string2.lower()


class olist(list):
    """
    Implements the 'in' operator
    in a case-insensitive manner,
    allowing "if x in olist(...)"
    """
    def __init__(self, keys):
        super(olist, self).__init__([k.lower() for k in keys])

    def __contains__(self, key):
        return super(olist, self).__contains__(key.lower())

    def append(self, key):
        super(olist, self).append(key.lower())


def listtemplates():
    l = []
    templates_dir = os.path.join(config.path.sharedir, 'templates')
    for f in os.listdir(templates_dir):
        if os.path.isfile("%s/%s" % (templates_dir, f)):
            l.append(f)
    return l


def listconfigs():
    l = []
    for f in os.listdir(userdir.CRMCONF_DIR):
        if os.path.isfile("%s/%s" % (userdir.CRMCONF_DIR, f)):
            l.append(f)
    return l


def add_sudo(cmd):
    if config.core.user:
        return "sudo -E -u %s %s" % (config.core.user, cmd)
    return cmd


def chown(path, user, group):
    if isinstance(user, int):
        uid = user
    else:
        uid = pwd.getpwnam(user).pw_uid
    if isinstance(group, int):
        gid = group
    else:
        gid = grp.getgrnam(group).gr_gid
    try:
        os.chown(path, uid, gid)
    except os.error as err:
        cmd = "sudo chown {}:{} {}".format(user, group, path)
        rc, out, err = ShellUtils().get_stdout_stderr(cmd, no_reg=True)
        if rc != 0:
            fatal("Failed to chown {}: {}".format(path, err))


def chmod(path, mod):
    try:
        os.chmod(path, mod)
    except os.error as err:
        cmd = "sudo chmod {} {}".format(format(mod,'o'), path)
        rc, out, err = ShellUtils().get_stdout_stderr(cmd, no_reg=True)
        if rc != 0:
            fatal("Failed to chmod {}: {}".format(path, err))


def copy_local_file(src, dest):
    try:
        shutil.copyfile(src, dest)
    except os.error as err:
        if err.errno not in (errno.EPERM, errno.EACCES):
            raise
        rc, out, err = ShellUtils().get_stdout_stderr("sudo cp {} {}".format(src, dest), no_reg=True)
        if rc != 0:
            fatal("Failed to copy file from {} to {}: {}".format(src, dest, err))
        cmd = "sudo chown {}:{} {}".format(userdir.getuser(), "haclient", dest)
        rc, out, err = ShellUtils().get_stdout_stderr(cmd, no_reg=True)
        if rc != 0:
            fatal("Failed to chown {}: {}".format(dest, err))


def rmfile(path, ignore_errors=False):
    """
    Try to remove the given file, and
    report an error on failure
    """
    try:
        os.remove(path)
    except os.error as err:
        if err.errno in (errno.EPERM, errno.EACCES):
            rc, out, err = ShellUtils().get_stdout_stderr("sudo rm " + path, no_reg=True)
            if rc != 0 and not ignore_errors:
                fatal("Failed to remove {}: {}".format(path, err))
        elif not ignore_errors:
            raise


def ensure_sudo_readable(f):
    # make sure the tempfile is readable to crm_diff (bsc#999683)
    if config.core.user:
        from pwd import getpwnam
        uid = getpwnam(config.core.user).pw_uid
        try:
            os.chown(f, uid, -1)
        except os.error as err:
            logger.error('Failed setting temporary file permissions: %s', err)
            return False
    return True


def pipe_string(cmd, s):
    rc = -1  # command failed
    cmd = add_sudo(cmd)
    logger.debug("piping string to %s", cmd)
    if options.regression_tests:
        print(".EXT", cmd)
    p = subprocess.Popen(
        cmd,
        shell=True,
        stdin=subprocess.PIPE,
        env=os.environ,  # bsc#1205925
    )
    try:
        # communicate() expects encoded bytes
        if isinstance(s, str):
            s = s.encode('utf-8')
        p.communicate(s)
        p.wait()
        rc = p.returncode
    except IOError as msg:
        if "Broken pipe" not in str(msg):
            logger.error(msg)
    return rc


def filter_string(cmd, s, stderr_on=True, shell=True):
    rc = -1  # command failed
    outp = ''
    if stderr_on is True:
        stderr = None
    else:
        stderr = subprocess.PIPE
    cmd = add_sudo(cmd)
    logger.debug("pipe through %s", cmd)
    if options.regression_tests:
        print(".EXT", cmd)
    p = subprocess.Popen(cmd,
                         shell=shell,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=stderr,
                         env=os.environ,  # bsc#1205925
                         )
    try:
        # bytes expected here
        if isinstance(s, str):
            s = s.encode('utf-8')
        ret = p.communicate(s)
        if stderr_on == 'stdout':
            outp = b"\n".join(ret)
        else:
            outp = ret[0]
        p.wait()
        rc = p.returncode
    except OSError as err:
        if err.errno != os.errno.EPIPE:
            logger.error(err.strerror)
        logger.error("from: %s", cmd)
    except Exception as msg:
        logger.error("from: %s: %s", cmd, str(msg))
    return rc, to_ascii(outp)


def str2tmp(_str, suffix=".pcmk"):
    '''
    Write the given string to a temporary file. Return the name
    of the file.
    '''
    s = to_ascii(_str)
    fd, tmp = mkstemp(suffix=suffix)
    try:
        f = os.fdopen(fd, "w")
    except IOError as msg:
        logger.error(msg)
        return
    f.write(s)
    if not s.endswith('\n'):
        f.write("\n")
    f.close()
    return tmp


@contextmanager
def create_tempfile(suffix='', dir=None):
    """ Context for temporary file.

    Will find a free temporary filename upon entering
    and will try to delete the file on leaving, even in case of an exception.

    Parameters
    ----------
    suffix : string
        optional file suffix
    dir : string
        optional directory to save temporary file in

    (from http://stackoverflow.com/a/29491523)
    """
    import tempfile
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=suffix, dir=dir)
    tf.file.close()
    try:
        yield tf.name
    finally:
        try:
            os.remove(tf.name)
        except OSError as e:
            if e.errno == 2:
                pass
            else:
                raise


@contextmanager
def open_atomic(filepath, mode="r", buffering=-1, fsync=False, encoding=None):
    """ Open temporary file object that atomically moves to destination upon
    exiting.

    Allows reading and writing to and from the same filename.

    The file will not be moved to destination in case of an exception.

    Parameters
    ----------
    filepath : string
        the file path to be opened
    fsync : bool
        whether to force write the file to disk

    (from http://stackoverflow.com/a/29491523)
    """

    with create_tempfile(dir=os.path.dirname(os.path.abspath(filepath))) as tmppath:
        with open(tmppath, mode, buffering, encoding=encoding) as file:
            yield file
            if fsync:
                file.flush()
                os.fsync(file.fileno())
        os.rename(tmppath, filepath)


def str2file(s, fname, mod=0o644):
    '''
    Write a string to a file.
    '''
    try:
        with open_atomic(fname, 'w', encoding='utf-8', fsync=True) as dst:
            dst.write(to_ascii(s))
        os.chmod(fname, mod)
    except IOError as msg:
        # If we failed under current user, repeat under root
        escaped = s.translate(str.maketrans({'"':  r'\"'})) # other symbols are already escaped
        cmd = 'printf "{}" | sudo tee {} >/dev/null'.format(escaped, fname)
        cmd += ' && sudo chmod {} {}'.format(format(mod,'o'), fname)
        rc, out, err = ShellUtils().get_stdout_stderr(cmd, no_reg=True)
        if rc != 0:
            #raise ValueError("Failed to write to {}: {}".format(s, err)) # fatal?
            logger.error(err)
            return False
    return True

def copy_remote_textfile(remote_user, remote_node, remote_text_file, local_path):
    """
    scp might lack permissions to copy the file for a non-root user.
    And the root might be disabled (PermitRootLogin No).
    So lets do $ ssh alice@node1 sudo cat <file-name>
    and save it locally.
    """
    # First try an easy way
    cmd = "scp %s@%s:'%s' %s" % (remote_user, remote_node, remote_text_file, local_path)
    rc, out, err = get_stdout_stderr_as_local_sudoer(cmd)
    # If failed, try the hard way
    if rc != 0:
        rc, out, err = sh.cluster_shell().get_rc_stdout_stderr_without_input(remote_node, 'cat {}'.format(remote_text_file))
        if rc != 0:
            raise ValueError("Failed to read {}@{}/{}: {}".format(remote_user, remote_node, remote_text_file, err))
        full_path = os.path.join(local_path, os.path.basename(remote_text_file))
        str2file(out, full_path)

def file2str(fname, noerr=True):
    '''
    Read a one line file into a string, strip whitespace around.
    '''
    try:
        f = open(fname, "r")
    except IOError as msg:
        if not noerr:
            logger.error(msg)
        return None
    s = f.readline()
    f.close()
    return s.strip()


def safe_open_w(fname):
    if fname == "-":
        f = sys.stdout
    else:
        if not options.batch and os.access(fname, os.F_OK):
            if not ask("File %s exists. Do you want to overwrite it?" % fname):
                return None
        try:
            f = open(fname, "w")
        except IOError as msg:
            logger.error(msg)
            return None
    return f


def safe_close_w(f):
    if f and f != sys.stdout:
        f.close()


def is_path_sane(name):
    if re.search(r"['`#*?$\[\];]", name):
        logger.error("%s: bad path", name)
        return False
    return True


def is_filename_sane(name):
    if re.search(r"['`/#*?$\[\];]", name):
        logger.error("%s: bad filename", name)
        return False
    return True


def is_name_sane(name):
    if re.search("[']", name):
        logger.error("%s: bad name", name)
        return False
    return True


def show_dot_graph(dotfile, keep_file=False, desc="transition graph"):
    cmd = "%s %s" % (config.core.dotty, dotfile)
    if not keep_file:
        cmd = "(%s; rm -f %s)" % (cmd, dotfile)
    if options.regression_tests:
        print(".EXT", cmd)
    subprocess.Popen(cmd, shell=True, bufsize=0,
                     stdin=None, stdout=None, stderr=None, close_fds=True,
                     env=os.environ,  # bsc#1205925
                     )
    logger.info("starting %s to show %s", config.core.dotty, desc)


def ext_cmd(cmd, shell=True):
    cmd = add_sudo(cmd)
    if options.regression_tests:
        print(".EXT", cmd)
    logger.debug("invoke: %s", cmd)
    return subprocess.call(
        cmd,
        shell=shell,
        env=os.environ,  # bsc#1205925
    )


def ext_cmd_nosudo(cmd, shell=True):
    if options.regression_tests:
        print(".EXT", cmd)
    return subprocess.call(
        cmd,
        shell=shell,
        env=os.environ,  # bsc#1205925
    )


def rmdir_r(d):
    # TODO: Make sure we're not deleting something we shouldn't!
    if d and os.path.isdir(d):
        shutil.rmtree(d)


def nvpairs2dict(pairs):
    '''
    takes a list of string of form ['a=b', 'c=d']
    and returns {'a':'b', 'c':'d'}
    '''
    data = []
    for var in pairs:
        if '=' in var:
            data.append(var.split('=', 1))
        else:
            data.append([var, None])
    return dict(data)


def is_check_always():
    '''
    Even though the frequency may be set to always, it doesn't
    make sense to do that with non-interactive sessions.
    '''
    return options.interactive and config.core.check_frequency == "always"


def get_check_rc():
    '''
    If the check mode is set to strict, then on errors we
    return 2 which is the code for error. Otherwise, we
    pretend that errors are warnings.
    '''
    if config.core.check_mode == "strict":
        return VerifyResult.NON_FATAL_ERROR
    return VerifyResult.WARNING


_LOCKDIR = ".lockdir"
_PIDF = "pid"


def check_locker(lockdir):
    if not os.path.isdir(os.path.join(lockdir, _LOCKDIR)):
        return
    s = file2str(os.path.join(lockdir, _LOCKDIR, _PIDF))
    pid = convert2ints(s)
    if not isinstance(pid, int):
        logger.warning("history: removing malformed lock")
        rmdir_r(os.path.join(lockdir, _LOCKDIR))
        return
    try:
        os.kill(pid, 0)
    except OSError as err:
        if err.errno == os.errno.ESRCH:
            logger.info("history: removing stale lock")
            rmdir_r(os.path.join(lockdir, _LOCKDIR))
        else:
            logger.error("%s: %s", _LOCKDIR, err.strerror)


@contextmanager
def lock(lockdir):
    """
    Ensure that the lock is released properly
    even in the face of an exception between
    acquire and release.
    """
    def acquire_lock():
        check_locker(lockdir)
        while True:
            try:
                os.makedirs(os.path.join(lockdir, _LOCKDIR))
                str2file("%d" % os.getpid(), os.path.join(lockdir, _LOCKDIR, _PIDF))
                return True
            except OSError as err:
                if err.errno != os.errno.EEXIST:
                    logger.error("Failed to acquire lock to %s: %s", lockdir, err.strerror)
                    return False
                time.sleep(0.1)
                continue
            else:
                return False

    has_lock = acquire_lock()
    try:
        yield
    finally:
        if has_lock:
            rmdir_r(os.path.join(lockdir, _LOCKDIR))


def mkdirp(directory, mode=0o777, parents=True, exist_ok=True):
    """
    Same behavior as the POSIX mkdir -p command
    """
    Path(directory).mkdir(mode, parents, exist_ok)

def mkdirs_owned(dirs, mode=0o777, uid=-1, gid=-1):
    """
    Create directory path, setting the mode and
    ownership of the leaf directory to mode/uid/gid.
    It won't fail if the directory already exist (exist_ok===true).
    """
    if not os.path.exists(dirs):
        try:
            if not os.path.exists(dirs):
                os.makedirs(dirs, mode)
        except OSError as err:
            # If we failed under current user, repeat under root
            cmd = "sudo mkdir {}".format(dirs)
            cmd += " && sudo chmod {} {}".format(format(mode,'o'), dirs)
            if gid == -1:
                gid = "haclient"
            if uid == -1:
                uid = userdir.getuser()
            cmd += " && sudo chown {} {}".format(uid, dirs)
            cmd += " && sudo chgrp {} {}".format(gid, dirs)
            rc, out, err = ShellUtils().get_stdout_stderr(cmd, no_reg=True)
            if rc != 0:
                fatal("Failed to create {}: {}".format(' '.join(dirs), err))
            return
        if uid != -1 or gid != -1:
            chown(dirs, uid, gid)

def pipe_cmd_nosudo(cmd):
    if options.regression_tests:
        print(".EXT", cmd)
    proc = subprocess.Popen(cmd,
                            shell=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            env=os.environ,  # bsc#1205925
                            )
    (outp, err_outp) = proc.communicate()
    proc.wait()
    rc = proc.returncode
    if rc != 0:
        print(outp)
        print(err_outp)
    return rc


def get_stdout_stderr_as_local_sudoer(cmd, input_s=None):
    try:
        user = user_of(this_node())
    except crmsh.user_of_host.UserNotFoundError:
        user = 'root'
    return sh.LocalShell().get_rc_stdout_stderr(user, cmd, input_s)


def stdout2list(cmd, stderr_on=True, shell=True):
    '''
    Run a cmd, fetch output, return it as a list of lines.
    stderr_on controls whether to show output which comes on stderr.
    '''
    rc, s = ShellUtils().get_stdout(add_sudo(cmd), stderr_on=stderr_on, shell=shell)
    if not s:
        return rc, []
    return rc, s.split('\n')


def append_file(dest, src):
    'Append src to dest'
    try:
        open(dest, "a").write(open(src).read())
        return True
    except IOError as msg:
        logger.error("append %s to %s: %s", src, dest, msg)
        return False


def is_dc_idle():
    dc = get_dc()
    if not dc:
        return False
    cmd = f"crmadmin -S {dc}"
    rc, out, err = ShellUtils().get_stdout_stderr(cmd)
    if rc != 0 and err:
        logger.error("Failed to get DC status: %s", err)
        return False
    if not out:
        return False
    return "ok" in out and "S_IDLE" in out


def get_dc(peer=None):
    cmd = "crmadmin -D -t 1"
    _, out, _ = sh.cluster_shell().get_rc_stdout_stderr_without_input(peer, cmd)
    if not out or not out.startswith("Designated") or "not yet elected" in out:
        return None
    return out.split()[-1]


def wait_for_dc(node: str = None):
    """
    Wait for the cluster's DC to become available
    """
    if not ServiceManager().service_is_active("pacemaker.service", remote_addr=node):
        raise ValueError("Pacemaker is not running. No DC.")
    dc_deadtime = get_property("dc-deadtime", peer=node) or str(constants.DC_DEADTIME_DEFAULT)
    dc_timeout = crm_msec(dc_deadtime) // 1000 + 5
    try:
        return retry_with_timeout(lambda: get_dc(node) or raise_exception(Exception()), dc_timeout)
    except TimeoutError:
        raise ValueError("No DC found currently, please wait if the cluster is still starting")


def wait_dc_stable(what="", show_progress=True):
    '''
    Wait for the DC to get into the S_IDLE state. This should be
    invoked only after a CIB modification which would exercise
    the PE. Parameter "what" is whatever the caller wants to be
    printed if showing progress.

    It is assumed that the DC is already in a different state,
    usually it should be either PENGINE or TRANSITION. This
    assumption may not be true, but there's a high chance that it
    is since crmd should be faster to move through states than
    this shell.

    Further, it may also be that crmd already calculated the new
    graph, did transition, and went back to the idle state. This
    may in particular be the case if the transition turned out to
    be empty.

    Tricky. Though in practice it shouldn't be an issue.

    There's no timeout, as we expect the DC to eventually becomes
    idle.
    '''

    if not wait_for_dc():
        logger.warning("can't find DC")
        return False
    delay = get_property("transition-delay")
    if delay:
        delaymsec = crm_msec(delay)
        if delaymsec > 0:
            logger.info("The transition-delay is configured. Waiting %d msec before check DC status.", delaymsec)
            time.sleep(delaymsec // 1000)
    cnt = 0
    output_started = 0
    init_sleep = 0.25
    max_sleep = 1.00
    sleep_time = init_sleep
    while True:
        dc = wait_for_dc()
        if not dc:
            logger.warning("DC lost during wait")
            return False
        cmd = "crmadmin -S %s" % dc
        rc, s = ShellUtils().get_stdout(add_sudo(cmd))
        if rc != 0:
            logger.error("Exit code of command {} is {}".format(cmd, rc))
            return False
        if re.search("S_IDLE.*ok", s):
            if output_started:
                sys.stderr.write(" done\n")
            return True
        time.sleep(sleep_time)
        if sleep_time < max_sleep:
            sleep_time *= 2
        if show_progress:
            if not output_started:
                output_started = 1
                sys.stderr.write("waiting for %s to finish ." % what)
            cnt += 1
            if cnt % 5 == 0:
                sys.stderr.write(".")


def run_ptest(graph_s, nograph, scores, utilization, actions, verbosity):
    '''
    Pipe graph_s thru ptest(8). Show graph using dotty if requested.
    '''
    actions_filter = "grep LogActions: | grep -vw Leave"
    ptest = "2>&1 %s -x -" % config.core.ptest
    if re.search("simulate", ptest) and \
            not re.search("-[RS]", ptest):
        ptest = "%s -S" % ptest
    if verbosity:
        if actions:
            verbosity = 'v' * max(3, len(verbosity))
        ptest = "%s -%s" % (ptest, verbosity.upper())
    if scores:
        ptest = "%s -s" % ptest
    if utilization:
        ptest = "%s -U" % ptest
    if config.core.dotty and not nograph:
        fd, dotfile = mkstemp()
        ptest = "%s -D %s" % (ptest, dotfile)
    else:
        dotfile = None
    # ptest prints to stderr
    if actions:
        ptest = "%s | %s" % (ptest, actions_filter)
    if options.regression_tests:
        ptest = ">/dev/null %s" % ptest
    logger.debug("invoke: %s", ptest)
    rc, s = ShellUtils().get_stdout(ptest, input_s=graph_s)
    if rc != 0:
        logger.debug("'%s' exited with (rc=%d)", ptest, rc)
        if actions and rc == 1:
            logger.warning("No actions found.")
        else:
            logger.warning("Simulation was unsuccessful (RC=%d).", rc)
    if dotfile:
        if os.path.getsize(dotfile) > 0:
            show_dot_graph(dotfile)
        else:
            logger.warning("ptest produced empty dot file")
    else:
        if not nograph:
            logger.info("install graphviz to see a transition graph")
    if s:
        page_string(s)
    return True


def is_id_valid(ident):
    """
    Verify that the id follows the definition:
    http://www.w3.org/TR/1999/REC-xml-names-19990114/#ns-qualnames
    """
    if not ident:
        return False
    id_re = r"^[A-Za-z_][\w._-]*$"
    return re.match(id_re, ident)


def check_range(a):
    """
    Verify that the integer range in list a is valid.
    """
    if len(a) != 2:
        return False
    if not isinstance(a[0], int) or not isinstance(a[1], int):
        return False
    return int(a[0]) <= int(a[1])


def crm_msec(t):
    '''
    See lib/common/utils.c:crm_get_msec().
    '''
    convtab = {
        'ms': (1, 1),
        'msec': (1, 1),
        'us': (1, 1000),
        'usec': (1, 1000),
        '': (1000, 1),
        's': (1000, 1),
        'sec': (1000, 1),
        'm': (60*1000, 1),
        'min': (60*1000, 1),
        'h': (60*60*1000, 1),
        'hr': (60*60*1000, 1),
    }
    if not t:
        return -1
    r = re.match(r"\s*(\d+)\s*([a-zA-Z]+)?", str(t))
    if not r:
        return -1
    if not r.group(2):
        q = ''
    else:
        q = r.group(2).lower()
    try:
        mult, div = convtab[q]
    except KeyError:
        return -1
    return (int(r.group(1))*mult) // div


def crm_time_cmp(a, b):
    return crm_msec(a) - crm_msec(b)


def shorttime(ts):
    if isinstance(ts, datetime.datetime):
        return ts.strftime("%X")
    if ts is not None:
        return time.strftime("%X", time.localtime(ts))
    return time.strftime("%X", time.localtime(0))


def shortdate(ts):
    if isinstance(ts, datetime.datetime):
        return ts.strftime("%F")
    if ts is not None:
        return time.strftime("%F", time.localtime(ts))
    return time.strftime("%F", time.localtime(0))


def file_find_by_name(root, filename):
    'Find a file within a tree matching fname'
    assert root
    assert filename
    for root, dirnames, filenames in os.walk(root):
        for filename in fnmatch.filter(filenames, filename):
            return os.path.join(root, filename)
    return None


def convert2ints(l):
    """
    Convert a list of strings (or a string) to a list of ints.
    All strings must be ints, otherwise conversion fails and None
    is returned!
    """
    try:
        if isinstance(l, (tuple, list)):
            return [int(x) for x in l]
        # it's a string then
        return int(l)
    except ValueError:
        return None


def is_int(s):
    'Check if the string can be converted to an integer.'
    try:
        int(s)
        return True
    except ValueError:
        return False


def edit_file(fname):
    'Edit a file.'
    if not fname:
        return
    if not config.core.editor:
        return
    return ext_cmd_nosudo("%s %s" % (config.core.editor, fname))


def edit_file_ext(fname: str, validator: typing.Callable[[typing.IO], bool] = None) -> bool:
    '''
    Edit a file via a temporary file.
    Raises IOError on any error.

    returns True if the file was changed
    '''
    with create_tempfile() as tmpfile:
        shutil.copyfile(fname, tmpfile)
        if edit_file(tmpfile) != 0:
            raise IOError(f"Cannot edit file \"{fname}\"")
        changed_data = read_from_file(tmpfile)
        source_data = read_from_file(fname)
        if changed_data != source_data:
            if validator and not validator(tmpfile):
                return False
            # The original file needs to be replaced atomically
            str2file(changed_data, fname)
            return True
        else:
            return False


def need_pager(s, w, h):
    from math import ceil
    cnt = 0
    for l in s.split('\n'):
        # need to remove color codes
        l = re.sub(r'\${\w+}', '', l)
        cnt += int(ceil((len(l) + 0.5) / w))
        if cnt >= h:
            return True
    return False


def term_render(s):
    'Render for TERM.'
    try:
        return term.render(s)
    except:
        return s


def get_pager_cmd(*extra_opts):
    'returns a commandline which calls the configured pager'
    cmdline = [config.core.pager]
    if os.path.basename(config.core.pager) == "less":
        cmdline.append('-R')
    cmdline.extend(extra_opts)
    return ' '.join(cmdline)


def page_string(s):
    'Page string rendered for TERM.'
    if not s:
        return
    constants.need_reset = True
    w, h = get_winsize()
    if not need_pager(s, w, h):
        print(term_render(s))
    elif not config.core.pager or not can_ask() or options.batch:
        print(term_render(s))
    else:
        pipe_string(get_pager_cmd(), term_render(s).encode('utf-8'))
    constants.need_reset = False


def page_gen(g):
    'Page lines generated by generator g'
    w, h = get_winsize()
    if not config.core.pager or not can_ask() or options.batch:
        for line in g:
            sys.stdout.write(term_render(line))
    else:
        pipe_string(get_pager_cmd(), term_render("".join(g)))


def page_file(filename):
    'Open file in pager'
    if not os.path.isfile(filename):
        return
    return ext_cmd_nosudo(get_pager_cmd(filename), shell=True)


def get_winsize():
    try:
        import curses
        curses.setupterm()
        w = curses.tigetnum('cols')
        h = curses.tigetnum('lines')
    except:
        try:
            w = os.environ['COLS']
            h = os.environ['LINES']
        except KeyError:
            w = 80
            h = 25
    return w, h


def multicolumn(l):
    '''
    A ls-like representation of a list of strings.
    A naive approach.
    '''
    min_gap = 2
    w, _ = get_winsize()
    max_len = 8
    for s in l:
        if len(s) > max_len:
            max_len = len(s)
    cols = w // (max_len + min_gap)  # approx.
    if not cols:
        cols = 1
    col_len = w // cols
    for i in range(len(l) // cols + 1):
        s = ''
        for j in range(i * cols, (i + 1) * cols):
            if not j < len(l):
                break
            if not s:
                s = "%-*s" % (col_len, l[j])
            elif (j + 1) % cols == 0:
                s = "%s%s" % (s, l[j])
            else:
                s = "%s%-*s" % (s, col_len, l[j])
        if s:
            print(s)


def lines2cli(s):
    '''
    Convert a string into a list of lines. Replace continuation
    characters. Strip white space, left and right. Drop empty lines.
    '''
    cl = []
    l = s.split('\n')
    cum = []
    for p in l:
        p = p.strip()
        if p.endswith('\\'):
            p = p.rstrip('\\')
            cum.append(p)
        else:
            cum.append(p)
            cl.append(''.join(cum).strip())
            cum = []
    if cum:  # in case s ends with backslash
        cl.append(''.join(cum))
    return [x for x in cl if x]


def datetime_is_aware(dt):
    """
    Determines if a given datetime.datetime is aware.

    The logic is described in Python's docs:
    http://docs.python.org/library/datetime.html#datetime.tzinfo
    """
    return dt and dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None


def make_datetime_naive(dt):
    """
    Ensures that the datetime is not time zone-aware:

    The returned datetime object is a naive time in UTC.
    """
    if dt and datetime_is_aware(dt):
        return dt.replace(tzinfo=None) - dt.utcoffset()
    return dt


def total_seconds(td):
    """
    Backwards compatible implementation of timedelta.total_seconds()
    """
    if hasattr(datetime.timedelta, 'total_seconds'):
        return td.total_seconds()
    return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) // 10**6


def datetime_to_timestamp(dt):
    """
    Convert a datetime object into a floating-point second value
    """
    try:
        return total_seconds(make_datetime_naive(dt) - datetime.datetime(1970, 1, 1))
    except Exception as e:
        logger.error("datetime_to_timestamp error: %s", e)
        return None


def timestamp_to_datetime(ts):
    """
    Convert a timestamp into a naive datetime object
    """
    import dateutil
    import dateutil.tz
    return make_datetime_naive(datetime.datetime.fromtimestamp(ts).replace(tzinfo=dateutil.tz.tzlocal()))


def parse_time(t, quiet=False):
    '''
    Try to make sense of the user provided time spec.
    Use dateutil if available, otherwise strptime.
    Return the datetime value.

    Also does time zone elimination by passing the datetime
    through a timestamp conversion if necessary

    TODO: dateutil is very slow, avoid it if possible
    '''
    try:
        from dateutil import parser, tz
        dt = parser.parse(t)

        if datetime_is_aware(dt):
            ts = datetime_to_timestamp(dt)
            if ts is None:
                return None
            dt = datetime.datetime.fromtimestamp(ts)
        else:
            # convert to UTC from local time
            dt = dt - tz.tzlocal().utcoffset(dt)
    except ValueError as msg:
        if not quiet:
            logger.error("parse_time %s: %s", t, msg)
        return None
    except ImportError as msg:
        try:
            tm = time.strptime(t)
            dt = datetime.datetime(*tm[0:7])
        except ValueError as msg:
            logger.error("no dateutil, please provide times as printed by date(1)")
            return None
    return dt


def parse_to_timestamp(t, quiet=False):
    '''
    Read a string and convert it into a UNIX timestamp.
    Added as an optimization of parse_time to avoid
    extra conversion steps when result would be converted
    into a timestamp anyway
    '''
    try:
        from dateutil import parser, tz
        dt = parser.parse(t)

        if datetime_is_aware(dt):
            return datetime_to_timestamp(dt)
        # convert to UTC from local time
        return total_seconds(dt - tz.tzlocal().utcoffset(dt) - datetime.datetime(1970, 1, 1))
    except ValueError as msg:
        if not quiet:
            logger.error("parse_time %s: %s", t, msg)
        return None
    except ImportError as msg:
        try:
            tm = time.strptime(t)
            dt = datetime.datetime(*tm[0:7])
            return datetime_to_timestamp(dt)
        except ValueError as msg:
            logger.error("no dateutil, please provide times as printed by date(1)")
            return None


def save_graphviz_file(ini_f, attr_d):
    '''
    Save graphviz settings to an ini file, if it does not exist.
    '''
    if os.path.isfile(ini_f):
        logger.error("%s exists, please remove it first", ini_f)
        return False
    try:
        f = open(ini_f, "wb")
    except IOError as msg:
        logger.error(msg)
        return False
    import configparser
    p = configparser.ConfigParser()
    for section, sect_d in attr_d.items():
        p.add_section(section)
        for n, v in sect_d.items():
            p.set(section, n, v)
    try:
        p.write(f)
    except IOError as msg:
        logger.error(msg)
        return False
    f.close()
    logger.info("graphviz attributes saved to %s", ini_f)
    return True


def load_graphviz_file(ini_f):
    '''
    Load graphviz ini file, if it exists.
    '''
    if not os.path.isfile(ini_f):
        return True, None
    import configparser
    p = configparser.ConfigParser()
    try:
        p.read(ini_f)
    except Exception as msg:
        logger.error(msg)
        return False, None
    _graph_d = {}
    for section in p.sections():
        d = {}
        for n, v in p.items(section):
            d[n] = v
        _graph_d[section] = d
    return True, _graph_d


def get_pcmk_version():
    cmd = "/usr/sbin/pacemakerd --version"
    out = sh.cluster_shell().get_stdout_or_raise_error(cmd)
    version = out.split()[1]
    logger.debug("Found pacemaker version: %s", version)
    return version


def get_cib_property(cib_f, attr, dflt=None):
    """A poor man's get attribute procedure.
    We don't want heavy parsing, this needs to be relatively
    fast.
    """
    open_t = "<cluster_property_set"
    close_t = "</cluster_property_set"
    attr_s = 'name="%s"' % attr
    ver_patt = re.compile('value="([^"]+)"')
    ver = dflt  # return some version in any case
    try:
        f = open(cib_f, "r")
    except IOError as msg:
        logger.error(msg)
        return ver
    state = 0
    for s in f:
        if state == 0:
            if open_t in s:
                state += 1
        elif state == 1:
            if close_t in s:
                break
            if attr_s in s:
                r = ver_patt.search(s)
                if r:
                    ver = r.group(1)
                break
    f.close()
    return ver


def get_cib_attributes(cib_f, tag, attr_l, dflt_l):
    """A poor man's get attribute procedure.
    We don't want heavy parsing, this needs to be relatively
    fast.
    """
    open_t = "<%s " % tag
    val_patt_l = [re.compile('%s="([^"]+)"' % x) for x in attr_l]
    val_l = []
    try:
        f = open(cib_f, "rb").read()
    except IOError as msg:
        logger.error(msg)
        return dflt_l
    if os.path.splitext(cib_f)[-1] == '.bz2':
        cib_bits = bz2.decompress(f)
    else:
        cib_bits = f
    cib_s = to_ascii(cib_bits)
    for s in cib_s.split('\n'):
        if s.startswith(open_t):
            i = 0
            for patt in val_patt_l:
                r = patt.search(s)
                val_l.append(r and r.group(1) or dflt_l[i])
                i += 1
            break
    return val_l


def is_larger_than_min_version(this_version, min_version):
    """
    Compare two version strings
    """
    version_re = re.compile(version.VERSION_PATTERN, re.VERBOSE | re.IGNORECASE)
    match_this_version = version_re.search(this_version)
    if not match_this_version:
        raise ValueError(f"Invalid version string: {this_version}")
    match_min_version = version_re.search(min_version)
    if not match_min_version:
        raise ValueError(f"Invalid version string: {min_version}")
    return version.parse(match_this_version.group(0)) >= version.parse(match_min_version.group(0))


def is_min_pcmk_ver(min_ver, cib_f=None):
    if not constants.pcmk_version:
        if cib_f:
            constants.pcmk_version = get_cib_property(cib_f, "dc-version")
            if constants.pcmk_version:
                logger.debug("Found pacemaker version: %s in cib: %s", constants.pcmk_version, cib_f)
            else:
                fatal(f"Failed to get 'dc-version' from {cib_f}")
        else:
            constants.pcmk_version = get_pcmk_version()
    return is_larger_than_min_version(constants.pcmk_version, min_ver)


# quote function from python module shlex.py in python 3.3

_find_unsafe = re.compile(r'[^\w@%+=:,./-]').search


def quote(s):
    """Return a shell-escaped version of the string *s*."""
    if not s:
        return "''"
    if _find_unsafe(s) is None:
        return s

    # use single quotes, and put single quotes into double quotes
    # the string $'b is then quoted as '$'"'"'b'
    return "'" + s.replace("'", "'\"'\"'") + "'"


def doublequote(s):
    """Return a shell-escaped version of the string *s*."""
    if not s:
        return '""'
    if _find_unsafe(s) is None:
        return s

    # use double quotes
    return '"' + s.replace('"', "\\\"") + '"'


def fetch_opts(args, opt_l):
    '''
    Get and remove option keywords from args.
    They are always listed last, at the end of the line.
    Return a list of options found. The caller can do
    if keyw in optlist: ...
    '''
    re_opt = None
    if opt_l[0].startswith("@"):
        re_opt = re.compile("^%s$" % opt_l[0][1:])
        del opt_l[0]
    l = []
    for i in reversed(list(range(len(args)))):
        if (args[i] in opt_l) or (re_opt and re_opt.search(args[i])):
            l.append(args.pop())
        else:
            break
    return l


_LIFETIME = ["reboot", "forever"]
_ISO8601_RE = re.compile("(PT?[0-9]|[0-9]+.*[:-])")


def fetch_lifetime_opt(args, iso8601=True):
    '''
    Get and remove a lifetime option from args. It can be one of
    lifetime_options or an ISO 8601 formatted period/time. There
    is apparently no good support in python for this format, so
    we cheat a bit.
    '''
    if args:
        opt = args[-1]
        if opt in _LIFETIME or (iso8601 and _ISO8601_RE.match(opt)):
            return args.pop()
    return None


def get_address_list_from_corosync_conf():
    """
    Return a list of addresses configured in corosync.conf
    """
    from . import corosync
    if not os.path.exists(corosync.conf()):
        return []
    return corosync.get_values("nodelist.node.ring0_addr")


def list_cluster_nodes(no_reg=False) -> list[str]:
    '''
    Returns a list of nodes in the cluster.
    '''
    rc, out, err = ShellUtils().get_stdout_stderr(constants.CIB_QUERY, no_reg=no_reg)
    # When cluster service running
    if rc == 0:
        cib = etree.fromstring(out)
    # Static situation
    else:
        cib_path = os.getenv('CIB_file', constants.CIB_RAW_FILE)
        if not os.path.isfile(cib_path):
            return None
        cib = xmlutil.file2cib_elem(cib_path)
    if cib is None:
        return None
    return [x.uname for x in cibquery.get_cluster_nodes(cib)]


def cluster_run_cmd(cmd, node_list=[]):
    """
    Run cmd in cluster nodes
    """
    nodelist = node_list or list_cluster_nodes()
    if not nodelist:
        raise ValueError("Failed to get node list from cluster")
    return crmsh.parallax.parallax_call(nodelist, cmd)


def list_cluster_nodes_except_me():
    """
    Get cluster node list and filter out self
    """
    node_list = list_cluster_nodes()
    if not node_list:
        raise ValueError("Failed to get node list from cluster")
    me = this_node()
    if me in node_list:
        node_list.remove(me)
    return node_list


def service_info(name):
    p = is_program('systemctl')
    if p:
        rc, outp = ShellUtils().get_stdout([p, 'show',
                               '-p', 'UnitFileState',
                               '-p', 'ActiveState',
                               '-p', 'SubState',
                               name + '.service'], shell=False)
        if rc == 0:
            info = []
            for line in outp.split('\n'):
                data = line.split('=', 1)
                if len(data) == 2:
                    info.append(data[1].strip())
            return '/'.join(info)
    return None


def running_on(resource):
    "returns list of node names where the given resource is running"
    rsc_locate = "crm_resource --resource '%s' --locate"
    rc, out, err = ShellUtils().get_stdout_stderr(rsc_locate % (resource))
    if rc != 0:
        return []
    nodes = []
    head = "resource %s is running on: " % (resource)
    for line in out.split('\n'):
        if line.strip().startswith(head):
            w = line[len(head):].split()
            if w:
                nodes.append(w[0])
    logger.debug("%s running on: %s", resource, nodes)
    return nodes


# This RE matches nvpair values that can
# be left unquoted
_NOQUOTES_RE = re.compile(r'^[\w\.-]+$')


def noquotes(v):
    return _NOQUOTES_RE.match(v) is not None


def unquote(s):
    """
    Reverse shell-quoting a string, so the string '"a b c"'
    becomes 'a b c'
    """
    sp = shlex.split(s)
    if sp:
        return sp[0]
    return ""


def parse_sysconfig(sysconfig_file):
    """
    Reads a sysconfig file into a dict
    """
    ret = {}
    if os.path.isfile(sysconfig_file):
        for line in open(sysconfig_file).readlines():
            if line.lstrip().startswith('#'):
                continue
            try:
                key, val = line.split("=", 1)
                ret[key] = unquote(val)
            except ValueError:
                pass
    return ret


def sysconfig_set(sysconfig_file, **values):
    """
    Set the values in the sysconfig file, updating the variables
    if they exist already, appending them if not.
    """
    outp = ""
    if os.path.isfile(sysconfig_file):
        for line in open(sysconfig_file).readlines():
            if line.lstrip().startswith('#'):
                outp += line
            else:
                matched = False
                try:
                    key, _ = line.split("=", 1)
                    for k, v in values.items():
                        if k == key:
                            matched = True
                            outp += '%s=%s\n' % (k, doublequote(v))
                            del values[k]
                            break
                    if not matched:
                        outp += line
                except ValueError:
                    outp += line

    for k, v in values.items():
        outp += '%s=%s\n' % (k, doublequote(v))
    str2file(outp, sysconfig_file)


def remote_diff_slurp(nodes, filename):
    from . import tmpfiles
    tmpdir = tmpfiles.create_dir()
    return crmsh.parallax.parallax_slurp(nodes, tmpdir, filename)


def remote_diff_this(local_path, nodes, this_node):
    by_host = remote_diff_slurp(nodes, local_path)
    for host, result in by_host:
        if isinstance(result, crmsh.parallax.Error):
            raise ValueError("Failed on %s: %s" % (host, str(result)))
        path = result
        _, s = ShellUtils().get_stdout("diff -U 0 -d -b --label %s --label %s %s %s" %
                          (host, this_node, path, local_path))
        page_string(s)


def remote_diff(local_path, nodes):
    by_host = remote_diff_slurp(nodes, local_path)
    for host, result in by_host:
        if isinstance(result, crmsh.parallax.Error):
            raise ValueError("Failed on %s: %s" % (host, str(result)))
    h1, r1 = by_host[0]
    h2, r2 = by_host[1]
    _, s = ShellUtils().get_stdout("diff -U 0 -d -b --label %s --label %s %s %s" %
                      (h1, h2, r1[3], r2[3]))
    page_string(s)


def remote_checksum(local_path, nodes, this_node):
    import hashlib

    by_host = remote_diff_slurp(nodes, local_path)
    for host, result in by_host:
        if isinstance(result, crmsh.parallax.Error):
            raise ValueError(str(result))

    print("%-16s  SHA1 checksum of %s" % ('Host', local_path))
    if this_node not in nodes:
        with open(local_path, 'rb') as f:
            print("%-16s: %s" % (this_node, hashlib.sha1(f.read()).hexdigest()))
    for host, path in by_host:
        with open(path, 'rb') as f:
            print("%-16s: %s" % (host, hashlib.sha1(f.read()).hexdigest()))


def cluster_copy_file(local_path, nodes=None, output=True):
    """
    Copies given file to all other cluster nodes.
    """
    if not nodes:
        nodes = list_cluster_nodes_except_me()
    rc = True
    if not nodes:
        return rc
    results = prun.pcopy_to_remote(local_path, nodes, local_path)
    for host, exc in results.items():
        if exc is not None:
            logger.error("Failed to copy %s to %s@%s: %s", local_path, exc.user, host, exc)
            rc = False
        else:
            logger.info("%s", host)
            logger.debug("Sync file %s to %s", local_path, host)
    return rc


# a set of fnmatch patterns to match attributes whose values
# should be obscured as a sequence of **** when printed
_obscured_nvpairs = []


def obscured(key, value):
    if key is not None and value is not None:
        for o in _obscured_nvpairs:
            if fnmatch.fnmatch(key, o):
                return '*' * 6
    return value


@contextmanager
def obscure(obscure_list):
    global _obscured_nvpairs
    prev = _obscured_nvpairs
    _obscured_nvpairs = obscure_list
    try:
        yield
    finally:
        _obscured_nvpairs = prev


def _cloud_metadata_request(uri, headers={}):
    try:
        import urllib2 as urllib
    except ImportError:
        import urllib.request as urllib
    req = urllib.Request(uri)
    for header, value in headers.items():
        req.add_header(header, value)
    try:
        resp = urllib.urlopen(req, timeout=5)
        content = resp.read()
        if type(content) != str:
            return content.decode('utf-8').strip()
        return content.strip()
    except urllib.URLError:
        return None


def detect_aws():
    """
    Detect if in AWS
    """
    shell = sh.cluster_shell()
    # will match on xen instances
    xen_test = shell.get_stdout_or_raise_error("dmidecode -s system-version").lower()
    # will match on nitro/kvm instances
    kvm_test = shell.get_stdout_or_raise_error("dmidecode -s system-manufacturer").lower()
    if "amazon" in xen_test or "amazon" in kvm_test:
        return True
    return False


def detect_azure():
    """
    Detect if in Azure
    """
    # Should check both system-manufacturer and chassis-asset-tag
    # In some azure environment, dmidecode -s system-manufacturer
    # might return American Megatrends Inc. instead of Microsoft Corporation in Azure.
    # The better way is to check the result of dmidecode -s chassis-asset-tag is
    # 7783-7084-3265-9085-8269-3286-77, aka. the ascii code of MSFT AZURE VM
    shell = sh.cluster_shell()
    system_manufacturer = shell.get_stdout_or_raise_error("dmidecode -s system-manufacturer")
    chassis_asset_tag = shell.get_stdout_or_raise_error("dmidecode -s chassis-asset-tag")
    if "microsoft corporation" in system_manufacturer.lower() or \
            ''.join([chr(int(n)) for n in re.findall(r"\d\d", chassis_asset_tag)]) == "MSFT AZURE VM":
        # To detect azure we also need to make an API request
        result = _cloud_metadata_request(
            "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/privateIpAddress?api-version=2017-08-01&format=text",
            headers={"Metadata": "true"})
        if result:
            return True
    return False


def detect_gcp():
    """
    Detect if in GCP
    """
    bios_vendor = sh.cluster_shell().get_stdout_or_raise_error("dmidecode -s bios-vendor")
    if "Google" in bios_vendor:
        # To detect GCP we also need to make an API request
        result = _cloud_metadata_request(
            "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip",
            headers={"Metadata-Flavor": "Google"})
        if result:
            return True
    return False


@memoize
def detect_cloud():
    """
    Tries to determine which (if any) cloud environment
    the cluster is running on.

    This is mainly done using dmidecode.

    If the host cannot be determined, this function
    returns None. Otherwise, it returns a string
    identifying the platform.

    These are the currently known platforms:

    * amazon-web-services
    * microsoft-azure
    * google-cloud-platform

    """
    if not is_program("dmidecode"):
        return None
    aws = detect_aws()
    if aws:
        return constants.CLOUD_AWS
    azure = detect_azure()
    if azure:
        return constants.CLOUD_AZURE
    gcp = detect_gcp()
    if gcp:
        return constants.CLOUD_GCP
    return None


def debug_timestamp():
    return datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')


def check_ssh_passwd_need(local_user, remote_user, host, shell: sh.LocalShell = None):
    """
    Check whether access to host need password
    """
    ssh_options = "-o StrictHostKeyChecking=no -o EscapeChar=none -o ConnectTimeout=15"
    ssh_cmd = "ssh {} -T -o Batchmode=yes {}@{} true".format(ssh_options, remote_user, host)
    if shell is None:
        shell = sh.LocalShell()
    rc, _ = shell.get_rc_and_error(local_user, ssh_cmd)
    return rc != 0


def check_port_open(host, port, timeout=3) -> bool:
    """
    Check whether the port is open on the host
    Use getaddrinfo to support both IPv4 and IPv6
    """
    try:
        addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        af, socktype, proto, canonname, sa = addrinfo[0]
        with closing(socket.socket(af, socktype, proto)) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex(sa) == 0:
                return True
        return False
    except socket.error:
        return False


def valid_port(port):
    return int(port) >= 1024 and int(port) <= 65535


def get_nodeinfo_from_cmaptool():
    nodeid_ip_dict = {}
    rc, out = ShellUtils().get_stdout("corosync-cmapctl -b runtime.members")
    if rc != 0:
        return nodeid_ip_dict

    for line in out.split('\n'):
        match = re.search(r'members\.(.*)\.ip', line)
        if match:
            node_id = match.group(1)
            iplist = re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', line)
            nodeid_ip_dict[node_id] = iplist
    return nodeid_ip_dict


def get_iplist_from_name(name):
    """
    Given node host name, return this host's ip list in corosync cmap
    """
    ip_list = []
    nodeid = get_nodeid_from_name(name)
    if not nodeid:
        return ip_list
    nodeinfo = {}
    nodeinfo = get_nodeinfo_from_cmaptool()
    if not nodeinfo:
        return ip_list
    return nodeinfo[nodeid]


def valid_nodeid(nodeid):
    if not ServiceManager().service_is_active('corosync.service'):
        return False

    for _id, _ in get_nodeinfo_from_cmaptool().items():
        if _id == nodeid:
            return True
    return False


def get_nodeid_from_name(name):
    if xmlutil.CrmMonXmlParser().is_node_remote(name):
        return name
    rc, out = ShellUtils().get_stdout('crm_node -l')
    if rc != 0:
        return None
    res = re.search(r'^([0-9]+) {} '.format(name), out, re.M)
    if res:
        return res.group(1)
    else:
        return None


def check_empty_option_value(options):
    if not isinstance(options, argparse.Namespace):
        raise ValueError("Expected type of \"options\" is \"argparse.Namespace\", not \"{}\"".format(type(options)))

    for opt in vars(options):
        value = getattr(options, opt)
        if isinstance(value, str) and len(value.strip()) == 0:
            raise ValueError("Empty value not allowed for dest \"{}\"".format(opt))


class IP(object):
    """
    Class to get some properties of IP address
    """

    def __init__(self, addr):
        """
        Init function
        """
        self.addr = addr

    @property
    def ip_address(self):
        """
        Create ipaddress instance
        """
        return ipaddress.ip_address(self.addr)

    @property
    def version(self):
        """
        Get IP address version
        """
        return self.ip_address.version

    @classmethod
    def is_mcast(cls, addr):
        """
        Check whether the address is multicast address
        """
        cls_inst = cls(addr)
        return cls_inst.ip_address.is_multicast

    @classmethod
    def is_ipv6(cls, addr):
        """
        Check whether the address is IPV6 address
        """
        return cls(addr).version == 6

    @property
    def is_loopback(self):
        """
        Check whether the address is loopback address
        """
        return self.ip_address.is_loopback

    @classmethod
    def is_valid_ip(cls, addr):
        """
        Check whether the address is valid IP address
        """
        cls_inst = cls(addr)
        try:
            cls_inst.ip_address
        except ValueError:
            return False
        else:
            return True


class Interface(IP):
    """
    Class to get information from one interface
    """

    def __init__(self, ip_with_mask):
        """
        Init function
        """
        self.ip, self.mask = ip_with_mask.split('/')
        super(__class__, self).__init__(self.ip)

    @property
    def ip_with_mask(self):
        """
        Get ip with netmask
        """
        return '{}/{}'.format(self.ip, self.mask)

    @property
    def ip_interface(self):
        """
        Create ip_interface instance
        """
        return ipaddress.ip_interface(self.ip_with_mask)

    @property
    def network(self):
        """
        Get network address
        """
        return str(self.ip_interface.network.network_address)


class InterfacesInfo(object):
    """
    Class to collect interfaces information on local node
    """

    def __init__(self, ipv6: bool = False, custom_nic_addr_list: typing.List[str] = []) -> None:
        """
        Init function

        On init process,
        "ipv6" is provided by -I option
        "custom_nic_addr_list" is provided by -i option
        """
        self.ip_version = 6 if ipv6 else 4
        self._custom_nic_addr_list = custom_nic_addr_list
        self._nic_info_dict = {}
        self._ip_nic_dict = {}
        self._input_nic_list = []
        self._input_addr_list = []

    def get_interfaces_info(self):
        """
        Try to get interfaces info dictionary via "ip" command

        IMPORTANT: This is the method that populates the data, should always be called after initialize
        """
        cmd = "ip -{} -o addr show".format(self.ip_version)
        rc, out, err = ShellUtils().get_stdout_stderr(cmd)
        if rc != 0:
            raise ValueError(err)

        # format on each line will like:
        # 2: enp1s0    inet 192.168.122.241/24 brd 192.168.122.255 scope global enp1s0\       valid_lft forever preferred_lft forever
        for line in out.splitlines():
            _, nic, _, ip_with_mask, *_ = line.split()
            # maybe from tun interface
            if not '/' in ip_with_mask:
                continue
            interface_inst = Interface(ip_with_mask)
            if interface_inst.is_loopback:
                continue
            # one nic might configured multi IP addresses
            if nic not in self._nic_info_dict:
                self._nic_info_dict[nic] = []
            self._nic_info_dict[nic].append(interface_inst)

        if not self._nic_info_dict:
            raise ValueError("No address configured")

        for nic, inst_list in self._nic_info_dict.items():
            for inst in inst_list:
                self._ip_nic_dict[inst.ip] = nic

    def flatten_custom_nic_addr_list(self) -> None:
        """
        If NIC or IP is provided by the -i option, convert them to
        nic list and address list, and do some validations
        """
        for item in self._custom_nic_addr_list:
            if item in self.nic_list:
                ip = self.nic_first_ip(item)
                if ip in self._input_addr_list:
                    raise ValueError(f"Invalid input '{item}': The same NIC already used")
                self._input_nic_list.append(item)
                self._input_addr_list.append(ip)
            elif IP.is_valid_ip(item):
                nic = self.get_nic_name_by_addr(item)
                if nic in self._input_nic_list:
                    raise ValueError(f"Invalid input '{item}': the IP in the same NIC already used")
                self._input_nic_list.append(nic)
                self._input_addr_list.append(item)
            else:
                raise ValueError(f"Invalid value '{item}' for -i/--interface option, should be {', '.join(self.nic_list)} or {', '.join(self.ip_list)}")

    @property
    def nic_list(self):
        """
        Get interfaces name list
        """
        return list(self._nic_info_dict.keys())

    @property
    def interface_list(self):
        """
        Get instance list of class Interface
        """
        _interface_list = []
        for interface in self._nic_info_dict.values():
            _interface_list.extend(interface)
        return _interface_list

    @property
    def ip_list(self):
        """
        Get IP address list
        """
        return [interface.ip for interface in self.interface_list]

    @property
    def input_nic_list(self) -> typing.List[str]:
        return self._input_nic_list

    @property
    def input_addr_list(self) -> typing.List[str]:
        return self._input_addr_list

    @classmethod
    def get_local_ip_list(cls, is_ipv6):
        """
        Get IP address list
        """
        cls_inst = cls(is_ipv6)
        cls_inst.get_interfaces_info()
        return cls_inst.ip_list

    @classmethod
    def ip_in_local(cls, addr):
        """
        Check whether given address was in one of local address
        """
        cls_inst = cls(IP.is_ipv6(addr))
        cls_inst.get_interfaces_info()
        return addr in cls_inst.ip_list

    def get_nic_name_by_addr(self, addr: str) -> str:
        """
        Return NIC name by given local IP address
        Raise error if this IP is not the local address
        """
        if addr not in self.ip_list:
            raise ValueError(f"'{addr}' is not in the local address: {self.ip_list}")
        return self._ip_nic_dict[addr]

    @property
    def network_list(self):
        """
        Get network list
        """
        return list(set([interface.network for interface in self.interface_list]))

    def nic_first_ip(self, nic) -> str:
        """
        Get the first IP of specific nic
        """
        return self._nic_info_dict[nic][0].ip

    def get_default_nic_from_route(self) -> str:
        """
        Get default nic from route
        """
        #TODO what if user only has ipv6 route?
        cmd = "ip -o route show"
        out = sh.cluster_shell().get_stdout_or_raise_error(cmd)
        res = re.search(r'^default via .* dev (.*?) ', out)
        return res.group(1) if res else self.nic_list[0]


def package_is_installed(pkg, remote_addr=None):
    """
    Check if package is installed
    """
    cmd = "rpm -q --quiet {}".format(pkg)
    if remote_addr:
        # check on remote
        rc, _, _ = sh.cluster_shell().get_rc_stdout_stderr_without_input(remote_addr, cmd)
    else:
        # check on local
        rc, _ = ShellUtils().get_stdout(cmd)
    return rc == 0


def node_reachable_check(node, ping_count=1, port=22, timeout=3):
    """
    Check if node is reachable by using ping and socket to ssh port
    """
    rc, _, _ = ShellUtils().get_stdout_stderr(f"ping -n -c {ping_count} -W {timeout} {node}")
    if rc == 0:
        return True
    # ping failed, try to connect to ssh port by socket
    if check_port_open(node, port, timeout):
        return True
    # both ping and socket failed
    raise ValueError(f"host \"{node}\" is unreachable")


def get_reachable_node_list(node_list:list[str]) -> list[str]:
    reachable_node_list = []
    for node in node_list:
        try:
            if node == this_node() or node_reachable_check(node):
                reachable_node_list.append(node)
        except ValueError as e:
            logger.warning(str(e))
    return reachable_node_list


def calculate_quorate_status(expected_votes, actual_votes):
    """
    Given expected votes and actual votes, calculate if is quorated
    """
    return int(actual_votes)/int(expected_votes) > 0.5


def get_quorum_votes_dict(remote=None):
    """
    Return a dictionary which contain expect votes and total votes
    """
    out = sh.cluster_shell().get_stdout_or_raise_error("corosync-quorumtool -s", remote, success_exit_status={0, 2})
    return dict(re.findall(r"(Expected|Total) votes:\s+(\d+)", out))


class DeadNodeError(ValueError):
    def __init__(self, msg: str, dead_nodes=None):
        super().__init__(msg)
        self.dead_nodes = dead_nodes or []


def check_all_nodes_reachable(action_to_do: str, peer_node: str = None):
    """
    Check if all cluster nodes are reachable
    """
    online_nodes = xmlutil.CrmMonXmlParser.get_node_list(online=True, node_type="member", peer=peer_node)
    offline_nodes = xmlutil.CrmMonXmlParser.get_node_list(online=False, peer=peer_node)
    dead_nodes = []
    for node in offline_nodes:
        try:
            node_reachable_check(node)
        except ValueError:
            dead_nodes.append(node)
    if dead_nodes:
        # dead nodes bring risk to cluster, either bring them online or remove them
        msg = f"""There are offline nodes also unreachable: {', '.join(dead_nodes)}.
Please bring them online before {action_to_do}.
Or use `crm cluster remove <offline_node> --force` to remove the offline node.
        """
        raise DeadNodeError(msg, dead_nodes)

    for node in online_nodes:
        node_reachable_check(node)


def re_split_string(reg, string):
    """
    Split a string by a regrex, filter out empty items
    """
    return [x for x in re.split(reg, string) if x]


def is_block_device(dev):
    """
    Check if dev is a block device
    """
    try:
        rc = S_ISBLK(os.stat(dev).st_mode)
    except OSError:
        return False
    return rc


def detect_duplicate_device_path(device_list: typing.List[str]):
    """
    Resolve device path and check if there are duplicated device path
    """
    path_dict = defaultdict(list)
    for dev in device_list:
        resolved_path = Path(dev).resolve()
        path_dict[resolved_path].append(dev)
    for path, dev_list in path_dict.items():
        if len(dev_list) > 1:
            raise ValueError(f"Duplicated device path detected: {','.join(dev_list)}. They are all pointing to {path}")


def has_stonith_running():
    """
    Check if any stonith device registered
    """
    from . import sbd
    out = sh.cluster_shell().get_stdout_or_raise_error("stonith_admin -L")
    has_stonith_device = re.search("[1-9]+ fence device[s]* found", out) is not None
    using_diskless_sbd = sbd.SBDUtils.is_using_diskless_sbd()
    return has_stonith_device or using_diskless_sbd


def has_disk_mounted(dev):
    """
    Check if device already mounted
    """
    out = sh.cluster_shell().get_stdout_or_raise_error("mount")
    return re.search("\n{} on ".format(dev), out) is not None


def has_mount_point_used(directory):
    """
    Check if mount directory already mounted
    """
    out = sh.cluster_shell().get_stdout_or_raise_error("mount")
    return re.search(" on {}".format(directory), out) is not None


def all_exist_id():
    """
    Get current exist id list
    """
    from .cibconfig import cib_factory
    cib_factory.refresh()
    return cib_factory.id_list()


def randomword(length=6):
    """
    Generate random word
    """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def gen_unused_id(exist_id_list, prefix="", length=6):
    """
    Generate unused id
    """
    unused_id = prefix or randomword(length)
    while unused_id in exist_id_list:
        unused_id = re.sub("$", "-{}".format(randomword(length)), unused_id)
    return unused_id


def get_all_vg_name():
    """
    Get all available VGs
    """
    out = sh.cluster_shell().get_stdout_or_raise_error("vgdisplay")
    return re.findall(r"VG Name\s+(.*)", out)


def get_pe_number(vg_id):
    """
    Get pe number
    """
    output = sh.cluster_shell().get_stdout_or_raise_error("vgdisplay {}".format(vg_id))
    res = re.search(r"Total PE\s+(\d+)", output)
    if not res:
        raise ValueError("Cannot find PE on VG({})".format(vg_id))
    return int(res.group(1))


def has_dev_partitioned(dev, peer=None):
    """
    Check if device has partitions
    """
    return len(get_dev_info(dev, "NAME", peer=peer).splitlines()) > 1


def get_dev_uuid(dev, peer=None):
    """
    Get UUID of device on local or peer node
    """
    out = get_dev_info(dev, "UUID", peer=peer).splitlines()
    return out[0] if out else get_dev_uuid_2(dev, peer)


def get_dev_uuid_2(dev, peer=None):
    """
    Get UUID of device using blkid
    """
    out = sh.cluster_shell().get_stdout_or_raise_error("blkid {}".format(dev), peer)
    res = re.search("UUID=\"(.*?)\"", out)
    return res.group(1) if res else None


def get_dev_fs_type(dev, peer=None):
    """
    Get filesystem type of device
    """
    return get_dev_info(dev, "FSTYPE", peer=peer)


def get_dev_info(dev, *_type, peer=None):
    """
    Get device info using lsblk
    """
    cmd = "lsblk -fno {} {}".format(','.join(_type), dev)
    return sh.cluster_shell().get_stdout_or_raise_error(cmd, peer)


def is_dev_used_for_lvm(dev, peer=None):
    """
    Check if device is LV
    """
    return "lvm" in get_dev_info(dev, "TYPE", peer=peer)


def is_dev_a_plain_raw_disk_or_partition(dev, peer=None):
    """
    Check if device is a raw disk or partition
    """
    out = get_dev_info(dev, "TYPE", peer=peer)
    return re.search("(disk|part)", out) is not None


def compare_uuid_with_peer_dev(dev_list, peer):
    """
    Check if device UUID is the same with peer's device
    """
    for dev in dev_list:
        local_uuid = get_dev_uuid(dev)
        if not local_uuid:
            raise ValueError("Cannot find UUID for {} on local".format(dev))
        peer_uuid = get_dev_uuid(dev, peer)
        if not peer_uuid:
            raise ValueError("Cannot find UUID for {} on {}".format(dev, peer))
        if local_uuid != peer_uuid:
            raise ValueError("UUID of {} not same with peer {}".format(dev, peer))


def append_res_to_group(group_id, res_id):
    """
    Append resource to exist group
    """
    cmd = "crm configure modgroup {} add {}".format(group_id, res_id)
    sh.cluster_shell().get_stdout_or_raise_error(cmd)


def get_qdevice_sync_timeout():
    """
    Get qdevice sync_timeout
    """
    out = sh.cluster_shell().get_stdout_or_raise_error("crm corosync status qdevice")
    res = re.search(r"Sync HB interval:\s+(\d+)ms", out)
    if not res:
        raise ValueError("Cannot find qdevice sync timeout")
    return int(int(res.group(1))/1000)


def detect_virt():
    """
    Detect if running in virt environment
    """
    rc, _, _ = ShellUtils().get_stdout_stderr("systemd-detect-virt")
    return rc == 0


def fatal(error_msg):
    """
    Raise exception to jump over this module,
    handled by Context.run in ui_context.py
    """
    raise ValueError(error_msg)


def get_dlm_option_dict(peer=None):
    """
    Get dlm config option dictionary
    """
    out = sh.cluster_shell().get_stdout_or_raise_error("dlm_tool dump_config", peer)
    return dict(re.findall(r"(\w+)=(\w+)", out))


def set_dlm_option(peer=None, **kargs):
    """
    Set dlm option
    """
    shell = sh.cluster_shell()
    dlm_option_dict = get_dlm_option_dict(peer=peer)
    for option, value in kargs.items():
        if option not in dlm_option_dict:
            raise ValueError(f'"{option}" is not dlm config option')
        if dlm_option_dict[option] != value:
            shell.get_stdout_or_raise_error(f'dlm_tool set_config "{option}={value}"', peer)


def is_dlm_running(peer=None):
    """
    Check if dlm ra controld is running
    """
    return is_resource_running(constants.DLM_CONTROLD_RA, peer=peer)


def has_resource_configured(ra_type, peer=None):
    """
    Check if the RA configured
    """
    out = sh.cluster_shell().get_stdout_or_raise_error("crm_mon -1rR", peer)
    return re.search(ra_type, out) is not None


def is_resource_running(ra_type, peer=None):
    """
    Check if the RA running
    """
    out = sh.cluster_shell().get_stdout_or_raise_error("crm_mon -1rR", peer)
    patt = f"\\({ra_type}\\):\\s*Started"
    return re.search(patt, out) is not None


def is_dlm_configured(peer=None):
    """
    Check if dlm configured
    """
    return has_resource_configured(constants.DLM_CONTROLD_RA, peer=peer)


def is_quorate(peer=None):
    """
    Check if cluster is quorated
    """
    out = sh.cluster_shell().get_stdout_or_raise_error("corosync-quorumtool -s", peer, success_exit_status={0, 2})
    res = re.search(r'Quorate:\s+(.*)', out)
    if res:
        return res.group(1) == "Yes"
    else:
        raise ValueError("Failed to get quorate status from corosync-quorumtool")


def is_2node_cluster_without_qdevice():
    """
    Check if current cluster has two nodes without qdevice
    """
    current_num = len(list_cluster_nodes())
    qdevice_num = 1 if corosync.is_qdevice_configured() else 0
    return (current_num + qdevice_num) == 2


def get_pcmk_delay_max(two_node_without_qdevice=False):
    """
    Get value of pcmk_delay_max
    """
    if ServiceManager().service_is_active("pacemaker.service") and two_node_without_qdevice:
        return constants.PCMK_DELAY_MAX
    return 0


def get_property(name, property_type="crm_config", peer=None, get_default=True):
    """
    Get cluster properties

    "property_type" can be crm_config|rsc_defaults|op_defaults
    "get_default" is used to get the default value from cluster metadata,
    when it is False, the property value will be got from cib
    """
    if property_type == "crm_config" and get_default:
        cib_path = os.getenv('CIB_file', constants.CIB_RAW_FILE)
        cmd = "CIB_file={} sudo --preserve-env=CIB_file crm configure get_property {}".format(cib_path, name)
    else:
        cmd = "sudo crm_attribute -t {} -n {} -Gq".format(property_type, name)
    rc, stdout, _ = sh.cluster_shell().get_rc_stdout_stderr_without_input(peer, cmd)
    return stdout if rc == 0 else None


def delete_property(name, property_type="crm_config") -> bool:
    cmd = f"crm_attribute -D -t {property_type} -n {name}"
    rc, _, stderr = ShellUtils().get_stdout_stderr(cmd)
    if rc == 0:
        logger.info("Delete cluster property \"%s\" in %s", name, property_type)
        return True
    elif stderr:
        logger.error(stderr)
    return False


def is_cluster_in_maintenance_mode() -> bool:
    maintenance_mode = get_property("maintenance-mode")
    return maintenance_mode and is_boolean_true(maintenance_mode)


@contextmanager
def leverage_maintenance_mode() -> typing.Generator[bool, None, None]:
    """
    Set cluster to maintenance mode, and set it back to normal when exiting

    Yield True if cluster is in maintenance mode or already in maintenance mode
    Yield False if not using -F/--force option or DC is not IDLE
    """
    if is_cluster_in_maintenance_mode():
        logger.info("Cluster is already in maintenance mode")
        yield True
        return
    if not config.core.force:
        yield False
        return

    if is_dc_idle():
        try:
            logger.info("Set cluster to maintenance mode")
            set_property("maintenance-mode", "true")
            yield True
        finally:
            logger.info("Set cluster from maintenance mode to normal")
            delete_property("maintenance-mode")
    else:
        logger.warning("Pacemaker state transition is in progress. Skip restarting cluster in maintenance mode.")
        yield False


def check_no_quorum_policy_with_dlm():
    """
    Give warning when no-quorum-policy not freeze while configured DLM
    """
    if not is_dlm_configured():
        return
    res = get_property("no-quorum-policy")
    if not res or res != "freeze":
        logger.warning("The DLM cluster best practice suggests to set the cluster property \"no-quorum-policy=freeze\"")


def set_property(property_name, property_value, property_type="crm_config", conditional=False):
    """
    Set property for cluster, resource and operator

    "property_type" can be crm_config|rsc_defaults|op_defaults
    When "conditional" is True, set the property if given "property_value" is larger then value from cib
    """
    origin_value = get_property(property_name, property_type)
    if origin_value and str(origin_value) == str(property_value):
        return
    if conditional and crm_msec(origin_value) >= crm_msec(property_value):
        return
    if not origin_value and property_value:
        logger.info("Set property \"%s\" in %s to %s", property_name, property_type, property_value)
    if origin_value and str(origin_value) != str(property_value):
        logger.warning("\"%s\" in %s is set to %s, it was %s", property_name, property_type, property_value, origin_value)
    property_sub_cmd = "property" if property_type == "crm_config" else property_type
    cmd = "crm configure {} {}={}".format(property_sub_cmd, property_name, property_value)
    sh.cluster_shell().get_stdout_or_raise_error(cmd)


def get_systemd_timeout_start_in_sec(time_res):
    """
    Get the TimeoutStartUSec value in second unit
    The origin format was like: 1min 30s
    """
    res_seconds = re.search(r"(\d+)s", time_res)
    start_timeout = int(res_seconds.group(1)) if res_seconds else 0
    res_min = re.search(r"(\d+)min", time_res)
    start_timeout += 60 * int(res_min.group(1)) if res_min else 0
    return start_timeout


def is_ocf_1_1_cib_schema_detected():
    """
    Only turn on ocf_1_1 feature the cib schema version is pacemaker-3.7 or above
    """
    from .cibconfig import cib_factory
    cib_factory.get_cib()
    return is_larger_than_min_version(cib_factory.get_schema(), constants.SCHEMA_MIN_VER_SUPPORT_OCF_1_1)


def compatible_role(role1, role2):
    master_or_promoted = (constants.RSC_ROLE_PROMOTED_LEGACY, constants.RSC_ROLE_PROMOTED)
    slave_or_unpromoted = (constants.RSC_ROLE_UNPROMOTED_LEGACY, constants.RSC_ROLE_UNPROMOTED)
    res1 = role1 in master_or_promoted and role2 in master_or_promoted
    res2 = role1 in slave_or_unpromoted and role2 in slave_or_unpromoted
    return res1 or res2


auto_convert_role = True


def handle_role_for_ocf_1_1(value, name='role'):
    """
    * Convert the role from Promoted/Unpromoted to Master/Slave if the schema does not support OCF 1.1.
    * Revert the role conversion if the schema supports OCF 1.1.
    """
    role_names = ["role", "target-role"]
    downgrade_dict = {
            constants.RSC_ROLE_PROMOTED: constants.RSC_ROLE_PROMOTED_LEGACY,
            constants.RSC_ROLE_UNPROMOTED: constants.RSC_ROLE_UNPROMOTED_LEGACY
            }
    upgrade_dict = {v: k for k, v in downgrade_dict.items()}

    if name not in role_names:
        return value
    if value in downgrade_dict and not is_ocf_1_1_cib_schema_detected():
        logger.warning('Convert "%s" to "%s" since the current schema version is old and not upgraded yet. Please consider "%s"', value, downgrade_dict[value], constants.CIB_UPGRADE)
        return downgrade_dict[value]
    if value in upgrade_dict and is_ocf_1_1_cib_schema_detected() and auto_convert_role:
        logger.info('Convert deprecated "%s" to "%s"', value, upgrade_dict[value])
        return upgrade_dict[value]

    return value


def diff_and_patch(orig_cib_str, current_cib_str):
    """
    Use crm_diff to generate patch, then apply
    """
    # In cibconfig.py, _patch_cib method doesn't include status section
    # So here should make a function to handle common cases
    from . import tmpfiles
    orig_cib_file = str2tmp(orig_cib_str, suffix=".xml")
    current_cib_file = str2tmp(current_cib_str, suffix=".xml")
    tmpfiles.add(orig_cib_file)
    tmpfiles.add(current_cib_file)

    cmd = "crm_diff -u -o '{}' -n '{}'".format(orig_cib_file, current_cib_file)
    rc, cib_diff, err = ShellUtils().get_stdout_stderr(cmd)
    if rc == 0: # no difference
        return True
    if err:
        logger.error("Failed to run crm_diff: %s", err)
        return False
    logger.debug("Diff: %s", cib_diff)
    rc = pipe_string("cibadmin -p -P --force", cib_diff)
    if rc != 0:
        logger.error("Failed to patch")
        return False
    return True


def retry_with_timeout(callable, timeout_sec: float, interval_sec=1):
    """Try callable repeatedly until it returns without raising an exception.

    Return the return value of callable,
    or raises TimeoutError if it does not return a value after retrying for timeout_sec.

    The callable runs in the calling thread and should not block for a long time.
    """
    async def wrapper():
        while True:
            try:
                return callable()
            except Exception:
                pass
            await asyncio.sleep(interval_sec)
    return asyncio.get_event_loop_policy().get_event_loop().run_until_complete(asyncio.wait_for(wrapper(), timeout_sec))


def fetch_cluster_node_list_from_node(init_node):
    """
    Fetch cluster member list from one known cluster node
    """
    cluster_nodes_list = []
    out = sh.cluster_shell().get_stdout_or_raise_error("crm_node -l", init_node)
    for line in out.splitlines():
        # Parse line in format: <id> <nodename> <state>, and collect the nodename.
        tokens = line.split()
        if len(tokens) == 0:
            pass  # Skip any spurious empty line.
        elif len(tokens) < 3:
            logger.warning("The node '%s' has no known name and/or state information", tokens[0])
        elif tokens[2] != "member":
            logger.warning("The node '%s'(state '%s') is not a current member", tokens[1], tokens[2])
        else:
            cluster_nodes_list.append(tokens[1])
    return cluster_nodes_list


def has_sudo_access():
    """
    Check if current user has sudo access
    """
    rc, _, _ = ShellUtils().get_stdout_stderr("sudo -S -k -n id -u")
    return rc == 0


def in_haclient():
    """
    Check if current user is in haclient group
    """
    return grp.getgrnam(constants.HA_GROUP).gr_gid in (os.getgroups() + [os.getegid()])


def check_user_access(level_name):
    """
    Check current user's privilege and give hints to user
    """
    current_user = userdir.getuser()
    if current_user == "root" or in_haclient():
        return

    if not has_sudo_access():
        logger.error("Operation is denied. The current user lacks the necessary privilege.")
    else:
        logger.error("Please run this command starting with \"sudo\"")
    raise TerminateSubCommand


class HostUserConfig:
    """Keep the username used for ssh connection corresponding to each host.

    The data is saved in configuration option `core.hosts`.
    """
    def __init__(self):
        self._hosts_users = dict()
        self.load()

    def load(self):
        self._load_hosts_users()

    def _load_hosts_users(self):
        users = list()
        hosts = list()
        li = config.get_option('core', 'hosts')
        if li == ['']:
            self._hosts_users = dict()
            return
        for s in li:
            parts = s.split('@', 2)
            if len(parts) != 2:
                raise ValueError('Malformed config core.hosts: {}'.format(s))
            users.append(parts[0])
            hosts.append(parts[1])
        self._hosts_users = {host: user for user, host in zip(users, hosts)}

    def save_local(self):
        value = [f'{user}@{host}' for host, user in sorted(self._hosts_users.items(), key=lambda x: x[0])]
        config.set_option('core', 'hosts', value)
        debug_on = config.get_option('core', 'debug')
        if debug_on:
            config.set_option('core', 'debug', 'false')
        config.save()
        if debug_on:
            config.set_option('core', 'debug', 'true')

    def save_remote(self, remote_hosts: typing.Iterable[str]):
        self.save_local()
        value = [f'{user}@{host}' for host, user in sorted(self._hosts_users.items(), key=lambda x: x[0])]
        crmsh.parallax.parallax_call(remote_hosts, "crm options set core.hosts '{}'".format(', '.join(value)))

    def clear(self):
        self._hosts_users = dict()

    def get(self, host):
        return self._hosts_users[host]

    def remove(self, host):
        if host in self._hosts_users:
            del self._hosts_users[host]

    def add(self, user, host):
        self._hosts_users[host] = user


def parse_user_at_host(s: str):
    i = s.find('@')
    if i == -1:
        return None, s
    else:
        return s[:i], s[i+1:]


def file_is_empty(file: str) -> bool:
    return os.stat(file).st_size == 0


def get_open_method(infile):
    """
    Get the appropriate file open method based on the file extension
    """
    file_type_open_dict = {
        "gz": gzip.open,
        "bz2": bz2.open,
        "xz": lzma.open
    }
    file_ext = infile.split('.')[-1]
    return file_type_open_dict.get(file_ext, open)


def read_from_file(infile: str) -> str:
    """
    Read content from a file
    """
    _open = get_open_method(infile)
    try:
        with _open(infile, 'rt', encoding='utf-8', errors='replace') as f:
            data = f.read()
    except PermissionError as err:
        logger.warning("When reading file \"%s\": %s", infile, str(err))
        return ""
    except Exception as err:
        logger.error("When reading file \"%s\": %s", infile, str(err))
        return ""

    return data


def add_time_unit_if_needed(time_value):
    """
    Add time unit if needed
    """
    return "{}s".format(time_value) if not time_value_with_unit(time_value) else time_value


def time_value_with_unit(time_value):
    """
    Check if the time value contains unit
    """
    return re.search(r'^\d+[a-z]+$', time_value) is not None


def ansible_installed():
    return shutil.which('ansible')


def ansible_facts(module_name) -> dict:
    proc = subprocess.run(['ansible', '-m', module_name, 'localhost']
                        , capture_output=True, text=True)
    out = proc.stdout
    # output format 'localhost | SUCCESS => { json...'
    bracket_pos = out.find('{')
    if bracket_pos == -1:
        logger.error("Parsing ansible output.")
        return {}
    is_ok = out[:bracket_pos].find('SUCCESS =>')
    if is_ok == -1:
        logger.error("Failure calling ansible module.")
        return {}
    # get the json part
    out = out[bracket_pos:]
    json_tree = json.loads(out)
    return json_tree['ansible_facts']


class NoSSHError(Exception):
    pass


def ssh_command():
    """
    Wrapper function for ssh command

    When ssh between cluster nodes is blocked, core.no_ssh
    should be set to 'yes', then this function will raise NoSSHError
    """
    if config.core.no_ssh:
        raise NoSSHError(constants.NO_SSH_ERROR_MSG)
    return "ssh"


def load_cib_file_env():
    if options.regression_tests or ServiceManager().service_is_active(constants.PCMK_SERVICE):
        return
    cib_file = os.environ.setdefault('CIB_file', constants.CIB_RAW_FILE)
    logger.warning("Cluster is not running, loading the CIB file from %s", cib_file)
    if not os.path.exists(cib_file):
        raise ValueError(f"Cannot find cib file: {cib_file}")


def fuzzy_get(items, s):
    """
    Finds s in items using a fuzzy
    matching algorithm:

    1. if exact match, return value
    2. if unique prefix, return value
    3. if unique prefix substring, return value
    """
    found = items.get(s)
    if found:
        return found

    def fuzzy_match(rx):
        try:
            matcher = re.compile(rx, re.I)
            matches = [c
                       for m, c in items.items()
                       if matcher.match(m)]
            if len(matches) == 1:
                return matches[0]
        except re.error as e:
            raise ValueError(e)
        return None

    # prefix match
    m = fuzzy_match(s + '.*')
    if m:
        return m
    # substring match
    m = fuzzy_match('.*'.join(s) + '.*')
    if m:
        return m
    return None


def cleanup_stonith_related_properties():
    for p in ("stonith-watchdog-timeout", "stonith-timeout", "priority-fencing-delay"):
        if get_property(p, get_default=False):
            delete_property(p)
    if get_property("stonith-enabled") == "true":
        set_property("stonith-enabled", "false")


def strip_ansi_escape_sequences(text):
    """
    Remove ANSI escape sequences from text
    """
    ansi_escape_pattern = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape_pattern.sub('', text)


class VerifyResult(IntFlag):
    SUCCESS = auto()
    WARNING = auto()
    NON_FATAL_ERROR = auto()
    FATAL_ERROR = auto()

    def __bool__(self):
        return self in self.SUCCESS | self.WARNING


def validate_and_get_reachable_nodes(
        nodes_from_args: typing.List[str] = [],
        all_nodes: bool = False,
        include_remote: bool = False
    ) -> typing.List[str]:

    no_cib = False
    cluster_member_list = list_cluster_nodes()
    if not cluster_member_list:
        cluster_member_list = get_address_list_from_corosync_conf()
        if cluster_member_list:
            no_cib = True

    if not cluster_member_list:
        fatal("Cannot get the member list of the cluster")
    pcmk_remote_list = []
    if include_remote:
        pcmk_remote_list = xmlutil.CrmMonXmlParser.get_node_list(online=True, node_type="remote")
    for node in nodes_from_args:
        if node not in cluster_member_list and node not in pcmk_remote_list:
            fatal(f"Node '{node}' is not a member of the cluster")

    local_node = this_node()
    # Return local node if no nodes specified
    if not nodes_from_args and not all_nodes:
        return [local_node]

    # Use all nodes if no nodes specified and all_nodes is True
    node_list = nodes_from_args or cluster_member_list + pcmk_remote_list
    member_list = [node for node in node_list if node not in pcmk_remote_list]
    remote_list = [node for node in node_list if node in pcmk_remote_list]
    # Filter out unreachable nodes
    member_list = get_reachable_node_list(member_list)
    if no_cib:
        return member_list

    shell = sh.cluster_shell()
    crm_mon_inst = xmlutil.CrmMonXmlParser()
    for node in member_list[:]:
        if node == local_node or crm_mon_inst.is_node_online(node):
            continue
        out = shell.get_stdout_or_raise_error("crm node show", node)
        if not re.search(rf"^{local_node}\(\d\): member", out, re.M):
            logger.error("From the view of node '%s', node '%s' is not a member of the cluster", node, local_node)
            member_list.remove(node)

    return member_list + remote_list
# vim:ts=4:sw=4:et:
