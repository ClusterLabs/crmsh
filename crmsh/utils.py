# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.

import os
import sys
from tempfile import mkstemp
import subprocess
import re
import glob
import time
import datetime
import shutil
import shlex
import bz2
import fnmatch
import gc
import ipaddress
import argparse
from contextlib import contextmanager, closing
from . import config
from . import userdir
from . import constants
from . import options
from . import term
from . import parallax
from .msg import common_warn, common_info, common_debug, common_err, err_buf


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


def memoize(function):
    "Decorator to invoke a function once only for any argument"
    memoized = {}

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


@memoize
def this_node():
    'returns name of this node (hostname)'
    return os.uname()[1]


_cib_shadow = 'CIB_shadow'
_cib_in_use = ''


def set_cib_in_use(name):
    os.putenv(_cib_shadow, name)
    global _cib_in_use
    _cib_in_use = name


def clear_cib_in_use():
    os.unsetenv(_cib_shadow)
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


def can_ask():
    """
    Is user-interactivity possible?
    Checks if connected to a TTY.
    """
    return (not options.ask_no) and sys.stdin.isatty()


def ask(msg):
    """
    Ask for user confirmation.
    If core.force is true, always return true.
    If not interactive and core.force is false, always return false.
    """
    if config.core.force:
        common_info("%s [YES]" % (msg))
        return True
    if not can_ask():
        return False

    msg += ' '
    if msg.endswith('? '):
        msg = msg[:-2] + ' (y/n)? '

    while True:
        try:
            ans = input(msg)
        except EOFError:
            ans = 'n'
        if ans:
            ans = ans[0].lower()
            if ans in 'yn':
                return ans == 'y'


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
        err_buf.incr_lineno()
        if options.regression_tests:
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


def os_types_list(path):
    l = []
    for f in glob.glob(path):
        if os.access(f, os.X_OK) and os.path.isfile(f):
            a = f.split("/")
            l.append(a[-1])
    return l


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
        import pwd
        uid = pwd.getpwnam(user).pw_uid
    if isinstance(group, int):
        gid = group
    else:
        import grp
        gid = grp.getgrnam(group).gr_gid
    os.chown(path, uid, gid)


def ensure_sudo_readable(f):
    # make sure the tempfile is readable to crm_diff (bsc#999683)
    if config.core.user:
        from pwd import getpwnam
        uid = getpwnam(config.core.user).pw_uid
        try:
            os.chown(f, uid, -1)
        except os.error as err:
            common_err('Failed setting temporary file permissions: %s' % (err))
            return False
    return True


def pipe_string(cmd, s):
    rc = -1  # command failed
    cmd = add_sudo(cmd)
    common_debug("piping string to %s" % cmd)
    if options.regression_tests:
        print(".EXT", cmd)
    p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE)
    try:
        # communicate() expects encoded bytes
        if isinstance(s, str):
            s = s.encode('utf-8')
        p.communicate(s)
        p.wait()
        rc = p.returncode
    except IOError as msg:
        if "Broken pipe" not in str(msg):
            common_err(msg)
    return rc


def filter_string(cmd, s, stderr_on=True, shell=True):
    rc = -1  # command failed
    outp = ''
    if stderr_on is True:
        stderr = None
    else:
        stderr = subprocess.PIPE
    cmd = add_sudo(cmd)
    common_debug("pipe through %s" % cmd)
    if options.regression_tests:
        print(".EXT", cmd)
    p = subprocess.Popen(cmd,
                         shell=shell,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=stderr)
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
            common_err(err.strerror)
        common_info("from: %s" % cmd)
    except Exception as msg:
        common_err(msg)
        common_info("from: %s" % cmd)
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
        common_err(msg)
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
            try:
                yield file
            finally:
                if fsync:
                    file.flush()
                    os.fsync(file.fileno())
        os.rename(tmppath, filepath)


def str2file(s, fname):
    '''
    Write a string to a file.
    '''
    try:
        with open_atomic(fname, 'w', encoding='utf-8') as dst:
            dst.write(to_ascii(s))
    except IOError as msg:
        common_err(msg)
        return False
    return True


def file2str(fname, noerr=True):
    '''
    Read a one line file into a string, strip whitespace around.
    '''
    try:
        f = open(fname, "r")
    except IOError as msg:
        if not noerr:
            common_err(msg)
        return None
    s = f.readline()
    f.close()
    return s.strip()


def file2list(fname):
    '''
    Read a file into a list (newlines dropped).
    '''
    try:
        return open(fname).read().split('\n')
    except IOError as msg:
        common_err(msg)
        return None


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
            common_err(msg)
            return None
    return f


def safe_close_w(f):
    if f and f != sys.stdout:
        f.close()


def is_path_sane(name):
    if re.search(r"['`#*?$\[\]]", name):
        common_err("%s: bad path" % name)
        return False
    return True


def is_filename_sane(name):
    if re.search(r"['`/#*?$\[\]]", name):
        common_err("%s: bad filename" % name)
        return False
    return True


def is_name_sane(name):
    if re.search("[']", name):
        common_err("%s: bad name" % name)
        return False
    return True


def show_dot_graph(dotfile, keep_file=False, desc="transition graph"):
    cmd = "%s %s" % (config.core.dotty, dotfile)
    if not keep_file:
        cmd = "(%s; rm -f %s)" % (cmd, dotfile)
    if options.regression_tests:
        print(".EXT", cmd)
    subprocess.Popen(cmd, shell=True, bufsize=0,
                     stdin=None, stdout=None, stderr=None, close_fds=True)
    common_info("starting %s to show %s" % (config.core.dotty, desc))


def ext_cmd(cmd, shell=True):
    cmd = add_sudo(cmd)
    if options.regression_tests:
        print(".EXT", cmd)
    common_debug("invoke: %s" % cmd)
    return subprocess.call(cmd, shell=shell)


def ext_cmd_nosudo(cmd, shell=True):
    if options.regression_tests:
        print(".EXT", cmd)
    return subprocess.call(cmd, shell=shell)


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
    return 2 if config.core.check_mode == "strict" else 1


_LOCKDIR = ".lockdir"
_PIDF = "pid"


def check_locker(lockdir):
    if not os.path.isdir(os.path.join(lockdir, _LOCKDIR)):
        return
    s = file2str(os.path.join(lockdir, _LOCKDIR, _PIDF))
    pid = convert2ints(s)
    if not isinstance(pid, int):
        common_warn("history: removing malformed lock")
        rmdir_r(os.path.join(lockdir, _LOCKDIR))
        return
    try:
        os.kill(pid, 0)
    except OSError as err:
        if err.errno == os.errno.ESRCH:
            common_info("history: removing stale lock")
            rmdir_r(os.path.join(lockdir, _LOCKDIR))
        else:
            common_err("%s: %s" % (_LOCKDIR, err.strerror))


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
                    common_err("Failed to acquire lock to %s: %s" % (lockdir, err.strerror))
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


def mkdirp(d, mode=0o777):
    if os.path.isdir(d):
        return True
    os.makedirs(d, mode=mode)


def pipe_cmd_nosudo(cmd):
    if options.regression_tests:
        print(".EXT", cmd)
    proc = subprocess.Popen(cmd,
                            shell=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    (outp, err_outp) = proc.communicate()
    proc.wait()
    rc = proc.returncode
    if rc != 0:
        print(outp)
        print(err_outp)
    return rc


def run_cmd_on_remote(cmd, remote_addr, prompt_msg=None):
    """
    Run a cmd on remote node
    return (rc, stdout, err_msg)
    """
    rc = 1
    out_data = None
    err_data = None

    need_pw = check_ssh_passwd_need(remote_addr)
    if need_pw and prompt_msg:
        print(prompt_msg)
    try:
        result = parallax.parallax_call([remote_addr], cmd, need_pw)
        rc, out_data, _ = result[0][1]
    except ValueError as err:
        err_match = re.search("Exited with error code ([0-9]+), Error output: (.*)", str(err))
        if err_match:
            rc, err_data = err_match.groups()
    finally:
        return int(rc), to_ascii(out_data), err_data


def get_stdout(cmd, input_s=None, stderr_on=True, shell=True, raw=False):
    '''
    Run a cmd, return stdout output.
    Optional input string "input_s".
    stderr_on controls whether to show output which comes on stderr.
    '''
    if stderr_on:
        stderr = None
    else:
        stderr = subprocess.PIPE
    if options.regression_tests:
        print(".EXT", cmd)
    proc = subprocess.Popen(cmd,
                            shell=shell,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=stderr)
    stdout_data, stderr_data = proc.communicate(input_s)
    if raw:
        return proc.returncode, stdout_data
    return proc.returncode, to_ascii(stdout_data).strip()


def get_stdout_stderr(cmd, input_s=None, shell=True, raw=False):
    '''
    Run a cmd, return (rc, stdout, stderr)
    '''
    if options.regression_tests:
        print(".EXT", cmd)
    proc = subprocess.Popen(cmd,
                            shell=shell,
                            stdin=input_s and subprocess.PIPE or None,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    stdout_data, stderr_data = proc.communicate(input_s)
    if raw:
        return proc.returncode, stdout_data, stderr_data
    return proc.returncode, to_ascii(stdout_data).strip(), to_ascii(stderr_data).strip()


def stdout2list(cmd, stderr_on=True, shell=True):
    '''
    Run a cmd, fetch output, return it as a list of lines.
    stderr_on controls whether to show output which comes on stderr.
    '''
    rc, s = get_stdout(add_sudo(cmd), stderr_on=stderr_on, shell=shell)
    if not s:
        return rc, []
    return rc, s.split('\n')


def append_file(dest, src):
    'Append src to dest'
    try:
        open(dest, "a").write(open(src).read())
        return True
    except IOError as msg:
        common_err("append %s to %s: %s" % (src, dest, msg))
        return False


def get_dc():
    cmd = "crmadmin -D"
    rc, s = get_stdout(add_sudo(cmd))
    if rc != 0:
        return None
    if not s.startswith("Designated"):
        return None
    return s.split()[-1]


def wait4dc(what="", show_progress=True):
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
    dc = get_dc()
    if not dc:
        common_warn("can't find DC")
        return False
    cmd = "crm_attribute -Gq -t crm_config -n crmd-transition-delay 2> /dev/null"
    delay = get_stdout(add_sudo(cmd))[1]
    if delay:
        delaymsec = crm_msec(delay)
        if delaymsec > 0:
            common_info("The crmd-transition-delay is configured. Waiting %d msec before check DC status." % delaymsec)
            time.sleep(delaymsec // 1000)
    cnt = 0
    output_started = 0
    init_sleep = 0.25
    max_sleep = 1.00
    sleep_time = init_sleep
    while True:
        dc = get_dc()
        if not dc:
            common_warn("DC lost during wait")
            return False
        cmd = "crmadmin -S %s" % dc
        rc, s = get_stdout(add_sudo(cmd))
        if not s.startswith("Status"):
            common_warn("%s unexpected output: %s (exit code: %d)" %
                        (cmd, s, rc))
            return False
        try:
            dc_status = s.split()[-2]
        except:
            common_warn("%s unexpected output: %s" % (cmd, s))
            return False
        if dc_status == "S_IDLE":
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
    common_debug("invoke: %s" % ptest)
    rc, s = get_stdout(ptest, input_s=graph_s)
    if rc != 0:
        common_debug("'%s' exited with (rc=%d)" % (ptest, rc))
        if actions and rc == 1:
            common_warn("No actions found.")
        else:
            common_warn("Simulation was unsuccessful (RC=%d)." % (rc))
    if dotfile:
        if os.path.getsize(dotfile) > 0:
            show_dot_graph(dotfile)
        else:
            common_warn("ptest produced empty dot file")
    else:
        if not nograph:
            common_info("install graphviz to see a transition graph")
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
    r = re.match(r"\s*(\d+)\s*([a-zA-Z]+)?", t)
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


def sort_by_mtime(l):
    'Sort a (small) list of files by time mod.'
    l2 = [(os.stat(x).st_mtime, x) for x in l]
    l2.sort()
    return [x[1] for x in l2]


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


def is_process(s):
    """
    Returns true if argument is the name of a running process.

    s: process name
    returns Boolean
    """
    from os.path import join, basename
    # find pids of running processes
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    for pid in pids:
        try:
            cmdline = open(join('/proc', pid, 'cmdline'), 'rb').read()
            procname = basename(to_ascii(cmdline).replace('\x00', ' ').split(' ')[0])
            if procname == s:
                return True
        except EnvironmentError:
            # a process may have died since we got the list of pids
            pass
    return False


def print_stacktrace():
    """
    Print the stack at the site of call
    """
    import traceback
    import inspect
    sf = inspect.currentframe().f_back.f_back
    traceback.print_stack(sf)


@memoize
def cluster_stack():
    if is_process("heartbeat:.[m]aster"):
        return "heartbeat"
    elif is_process("[a]isexec"):
        return "openais"
    elif os.path.exists("/etc/corosync/corosync.conf") or is_program('corosync-cfgtool'):
        return "corosync"
    return ""


def edit_file(fname):
    'Edit a file.'
    if not fname:
        return
    if not config.core.editor:
        return
    return ext_cmd_nosudo("%s %s" % (config.core.editor, fname))


def edit_file_ext(fname, template=''):
    '''
    Edit a file via a temporary file.
    Raises IOError on any error.
    '''
    if not os.path.isfile(fname):
        s = template
    else:
        s = open(fname).read()
    filehash = hash(s)
    tmpfile = str2tmp(s)
    try:
        try:
            if edit_file(tmpfile) != 0:
                return
            s = open(tmpfile, 'r').read()
            if hash(s) == filehash:  # file unchanged
                return
            f2 = open(fname, 'w')
            f2.write(s)
            f2.close()
        finally:
            os.unlink(tmpfile)
    except OSError as e:
        raise IOError(e)


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


def find_value(pl, name):
    for n, v in pl:
        if n == name:
            return v
    return None


def cli_replace_attr(pl, name, new_val):
    for i, attr in enumerate(pl):
        if attr[0] == name:
            attr[1] = new_val
            return


def cli_append_attr(pl, name, val):
    pl.append([name, val])


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
        common_err("datetime_to_timestamp error: %s" % (e))
        return None


def timestamp_to_datetime(ts):
    """
    Convert a timestamp into a naive datetime object
    """
    import dateutil
    import dateutil.tz
    return make_datetime_naive(datetime.datetime.fromtimestamp(ts).replace(tzinfo=dateutil.tz.tzlocal()))


def parse_time(t):
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
        common_err("parse_time %s: %s" % (t, msg))
        return None
    except ImportError as msg:
        try:
            tm = time.strptime(t)
            dt = datetime.datetime(*tm[0:7])
        except ValueError as msg:
            common_err("no dateutil, please provide times as printed by date(1)")
            return None
    return dt


def parse_to_timestamp(t):
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
        common_err("parse_time %s: %s" % (t, msg))
        return None
    except ImportError as msg:
        try:
            tm = time.strptime(t)
            dt = datetime.datetime(*tm[0:7])
            return datetime_to_timestamp(dt)
        except ValueError as msg:
            common_err("no dateutil, please provide times as printed by date(1)")
            return None


def save_graphviz_file(ini_f, attr_d):
    '''
    Save graphviz settings to an ini file, if it does not exist.
    '''
    if os.path.isfile(ini_f):
        common_err("%s exists, please remove it first" % ini_f)
        return False
    try:
        f = open(ini_f, "wb")
    except IOError as msg:
        common_err(msg)
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
        common_err(msg)
        return False
    f.close()
    common_info("graphviz attributes saved to %s" % ini_f)
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
        common_err(msg)
        return False, None
    _graph_d = {}
    for section in p.sections():
        d = {}
        for n, v in p.items(section):
            d[n] = v
        _graph_d[section] = d
    return True, _graph_d


def get_pcmk_version(dflt):
    version = dflt

    crmd = pacemaker_controld()
    if crmd:
        cmd = crmd
    else:
        return version

    try:
        rc, s, err = get_stdout_stderr("%s version" % (cmd))
        if rc != 0:
            common_err("%s exited with %d [err: %s][out: %s]" % (cmd, rc, err, s))
        else:
            common_debug("pacemaker version: [err: %s][out: %s]" % (err, s))
            if err.startswith("CRM Version:"):
                version = s.split()[0]
            else:
                version = s.split()[2]
            common_debug("found pacemaker version: %s" % version)
    except Exception as msg:
        common_warn("could not get the pacemaker version, bad installation?")
        common_warn(msg)
    return version


def get_cib_property(cib_f, attr, dflt):
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
        common_err(msg)
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
        common_err(msg)
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


def is_min_pcmk_ver(min_ver, cib_f=None):
    if not constants.pcmk_version:
        if cib_f:
            constants.pcmk_version = get_cib_property(cib_f, "dc-version", "1.1.11")
            common_debug("found pacemaker version: %s in cib: %s" %
                         (constants.pcmk_version, cib_f))
        else:
            constants.pcmk_version = get_pcmk_version("1.1.11")
    from distutils.version import LooseVersion
    return LooseVersion(constants.pcmk_version) >= LooseVersion(min_ver)


def is_pcmk_118(cib_f=None):
    return is_min_pcmk_ver("1.1.8", cib_f=cib_f)


@memoize
def cibadmin_features():
    '''
    # usage example:
    if 'corosync-plugin' in cibadmin_features()
    '''
    rc, outp = get_stdout(['cibadmin', '-!'], shell=False)
    if rc == 0:
        m = re.match(r'Pacemaker\s(\S+)\s\(Build: ([^\)]+)\):\s(.*)', outp.strip())
        if m and len(m.groups()) > 2:
            return m.group(3).split()
    return []


@memoize
def cibadmin_can_patch():
    # cibadmin -P doesn't handle comments in <1.1.11 (unless patched)
    return is_min_pcmk_ver("1.1.11")


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


def resolve_hostnames(hostnames):
    '''
    Tries to resolve the given list of hostnames.
    returns (ok, failed-hostname)
    ok: True if all hostnames resolved
    failed-hostname: First failed hostname resolution
    '''
    import socket
    for node in hostnames:
        try:
            socket.gethostbyname(node)
        except socket.error:
            return False, node
    return True, None


def list_corosync_node_names():
    '''
    Returns list of nodes configured
    in corosync.conf
    '''
    try:
        cfg = os.getenv('COROSYNC_MAIN_CONFIG_FILE', '/etc/corosync/corosync.conf')
        lines = open(cfg).read().split('\n')
        name_re = re.compile(r'\s*name:\s+(.*)')
        names = []
        for line in lines:
            name = name_re.match(line)
            if name:
                names.append(name.group(1))
        return names
    except Exception:
        return []


def list_corosync_nodes():
    '''
    Returns list of nodes configured
    in corosync.conf
    '''
    try:
        cfg = os.getenv('COROSYNC_MAIN_CONFIG_FILE', '/etc/corosync/corosync.conf')
        lines = open(cfg).read().split('\n')
        addr_re = re.compile(r'\s*ring0_addr:\s+(.*)')
        nodes = []
        for line in lines:
            addr = addr_re.match(line)
            if addr:
                nodes.append(addr.group(1))
        return nodes
    except Exception:
        return []


def print_cluster_nodes():
    """
    Print the output of crm_node -l
    """
    rc, out, _ = get_stdout_stderr("crm_node -l")
    if rc == 0 and out:
        print("{}\n".format(out))


def list_cluster_nodes():
    '''
    Returns a list of nodes in the cluster.
    '''
    def getname(toks):
        if toks and len(toks) >= 2:
            return toks[1]
        return None

    try:
        # when pacemaker running
        rc, outp = stdout2list(['crm_node', '-l'], stderr_on=False, shell=False)
        if rc == 0:
            return [x for x in [getname(line.split()) for line in outp] if x and x != '(null)']

        # when corosync running
        ip_list = get_member_iplist()
        if ip_list:
            return ip_list

        # static situation
        cib_path = os.getenv('CIB_file', '/var/lib/pacemaker/cib/cib.xml')
        if not os.path.isfile(cib_path):
            return None
        from . import xmlutil
        node_list = []
        cib = xmlutil.file2cib_elem(cib_path)
        if cib is None:
            return None
        for node in cib.xpath('/cib/configuration/nodes/node'):
            name = node.get('uname') or node.get('id')
            if node.get('type') == 'remote':
                srv = cib.xpath("//primitive[@id='%s']/instance_attributes/nvpair[@name='server']" % (name))
                if srv:
                    continue
            node_list.append(name)
        return node_list
    except OSError as msg:
        raise ValueError("Error listing cluster nodes: %s" % (msg))


def cluster_run_cmd(cmd):
    """
    Run cmd in cluster nodes
    """
    node_list = list_cluster_nodes()
    if not node_list:
        raise ValueError("Failed to get node list from cluster")
    parallax.parallax_call(node_list, cmd)


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
        rc, outp = get_stdout([p, 'show',
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
    rc, out, err = get_stdout_stderr(rsc_locate % (resource))
    if rc != 0:
        return []
    nodes = []
    head = "resource %s is running on: " % (resource)
    for line in out.split('\n'):
        if line.strip().startswith(head):
            w = line[len(head):].split()
            if w:
                nodes.append(w[0])
    common_debug("%s running on: %s" % (resource, nodes))
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
    try:
        import parallax
    except ImportError:
        raise ValueError("Parallax is required to diff")
    from . import tmpfiles

    tmpdir = tmpfiles.create_dir()
    opts = parallax.Options()
    opts.localdir = tmpdir
    dst = os.path.basename(filename)
    return list(parallax.slurp(nodes, filename, dst, opts).items())


def remote_diff_this(local_path, nodes, this_node):
    try:
        import parallax
    except ImportError:
        raise ValueError("Parallax is required to diff")

    by_host = remote_diff_slurp(nodes, local_path)
    for host, result in by_host:
        if isinstance(result, parallax.Error):
            raise ValueError("Failed on %s: %s" % (host, str(result)))
        _, _, _, path = result
        _, s = get_stdout("diff -U 0 -d -b --label %s --label %s %s %s" %
                          (host, this_node, path, local_path))
        page_string(s)


def remote_diff(local_path, nodes):
    try:
        import parallax
    except ImportError:
        raise ValueError("parallax is required to diff")

    by_host = remote_diff_slurp(nodes, local_path)
    for host, result in by_host:
        if isinstance(result, parallax.Error):
            raise ValueError("Failed on %s: %s" % (host, str(result)))
    h1, r1 = by_host[0]
    h2, r2 = by_host[1]
    _, s = get_stdout("diff -U 0 -d -b --label %s --label %s %s %s" %
                      (h1, h2, r1[3], r2[3]))
    page_string(s)


def remote_checksum(local_path, nodes, this_node):
    try:
        import parallax
    except ImportError:
        raise ValueError("Parallax is required to diff")
    import hashlib

    by_host = remote_diff_slurp(nodes, local_path)
    for host, result in by_host:
        if isinstance(result, parallax.Error):
            raise ValueError(str(result))

    print("%-16s  SHA1 checksum of %s" % ('Host', local_path))
    if this_node not in nodes:
        print("%-16s: %s" % (this_node, hashlib.sha1(open(local_path).read()).hexdigest()))
    for host, result in by_host:
        _, _, _, path = result
        print("%-16s: %s" % (host, hashlib.sha1(open(path).read()).hexdigest()))


def cluster_copy_file(local_path, nodes=None):
    """
    Copies given file to all other cluster nodes.
    """
    try:
        import parallax
    except ImportError:
        raise ValueError("parallax is required to copy cluster files")
    if not nodes:
        nodes = list_cluster_nodes()
        nodes.remove(this_node())
    opts = parallax.Options()
    opts.timeout = 60
    opts.ssh_options += ['ControlPersist=no']
    ok = True
    for host, result in parallax.copy(nodes,
                                      local_path,
                                      local_path, opts).items():
        if isinstance(result, parallax.Error):
            err_buf.error("Failed to push %s to %s: %s" % (local_path, host, result))
            ok = False
        else:
            err_buf.ok(host)
    return ok


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


def gen_nodeid_from_ipv6(addr):
    return int(ipaddress.ip_address(addr)) % 1000000000


# Set by detect_cloud()
# to avoid multiple requests
_ip_for_cloud = None


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
    global _ip_for_cloud

    if not is_program("dmidecode"):
        return None
    rc, system_version = get_stdout("dmidecode -s system-version")
    if re.search(r".*amazon.*", system_version) is not None:
        return "amazon-web-services"
    if rc != 0:
        return None
    rc, system_manufacturer = get_stdout("dmidecode -s system-manufacturer")
    if rc == 0 and "microsoft corporation" in system_manufacturer.lower():
        # To detect azure we also need to make an API request
        result = _cloud_metadata_request(
            "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/privateIpAddress?api-version=2017-08-01&format=text",
            headers={"Metadata": "true"})
        if result:
            _ip_for_cloud = result
            return "microsoft-azure"
    rc, bios_vendor = get_stdout("dmidecode -s bios-vendor")
    if rc == 0 and "Google" in bios_vendor:
        # To detect GCP we also need to make an API request
        result = _cloud_metadata_request(
            "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip",
            headers={"Metadata-Flavor": "Google"})
        if result:
            _ip_for_cloud = result
            return "google-cloud-platform"
    return None


def debug_timestamp():
    return datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')


def get_member_iplist():
    rc, out, err= get_stdout_stderr("corosync-cmapctl -b runtime.totem.pg.mrp.srp.members")
    if rc != 0:
        common_debug(err)
        return None

    ip_list = []
    for line in out.split('\n'):
        match = re.search(r'ip\((.*?)\)', line)
        if match:
            ip_list.append(match.group(1))
    return ip_list


def get_iplist_corosync_using():
    """
    Get ip list used by corosync
    """
    rc, out, err = get_stdout_stderr("corosync-cfgtool -s")
    if rc != 0:
        raise ValueError(err)
    return re.findall(r'id\s*=\s*(.*)', out)


def check_ssh_passwd_need(host):
    """
    Check whether access to host need password
    """
    ssh_options = "-o StrictHostKeyChecking=no -o EscapeChar=none -o ConnectTimeout=15"
    ssh_cmd = "ssh {} -T -o Batchmode=yes {} true".format(ssh_options, host)
    rc, _, _ = get_stdout_stderr(ssh_cmd)
    return rc != 0


def check_port_open(ip, port):
    import socket

    family = socket.AF_INET6 if IP.is_ipv6(ip) else socket.AF_INET
    with closing(socket.socket(family, socket.SOCK_STREAM)) as sock:
        if sock.connect_ex((ip, port)) == 0:
            return True
        else:
            return False


def valid_port(port):
    return int(port) >= 1024 and int(port) <= 65535


def is_qdevice_configured():
    from . import corosync
    return corosync.get_value("quorum.device.model") == "net"


def is_qdevice_tls_on():
    from . import corosync
    return corosync.get_value("quorum.device.net.tls") == "on"


def get_nodeinfo_from_cmaptool():
    nodeid_ip_dict = {}
    rc, out = get_stdout("corosync-cmapctl -b runtime.totem.pg.mrp.srp.members")
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
    from . import bootstrap
    if not service_is_active('corosync.service'):
        return False

    for _id, _ in get_nodeinfo_from_cmaptool().items():
        if _id == nodeid:
            return True
    return False


def get_nodeid_from_name(name):
    rc, out = get_stdout('crm_node -l')
    if rc != 0:
        return None
    res = re.search(r'^([0-9]+) {} '.format(name), out, re.M)
    if res:
        return res.group(1)
    else:
        return None


def check_space_option_value(options):
    if not isinstance(options, argparse.Namespace):
        raise ValueError("Expected type of \"options\" is \"argparse.Namespace\", not \"{}\"".format(type(options)))

    for opt in vars(options):
        value = getattr(options, opt)
        if isinstance(value, str) and len(value.strip()) == 0:
            raise ValueError("Space value not allowed for dest \"{}\"".format(opt))


def interface_choice():
    _, out = get_stdout("ip a")
    # should consider interface format like "ethx@xxx"
    interface_list = re.findall(r'(?:[0-9]+:) (.*?)(?=: |@.*?: )', out)
    return [nic for nic in interface_list if nic != "lo"]


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

    @property
    def is_loopback(self):
        """
        Check whether the address is loopback address
        """
        return self.ip_address.is_loopback

    @property
    def is_link_local(self):
        """
        Check whether the address is link-local address
        """
        return self.ip_address.is_link_local


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

    def ip_in_network(self, addr):
        """
        Check whether the addr in the network
        """
        return IP(addr).ip_address in self.ip_interface.network


class InterfacesInfo(object):
    """
    Class to collect interfaces information on local node
    """

    def __init__(self, ipv6=False, second_heartbeat=False, custom_nic_list=[]):
        """
        Init function

        On init process,
        "ipv6" is provided by -I option
        "second_heartbeat" is provided by -M option
        "custom_nic_list" is provided by -i option
        """
        self.ip_version = 6 if ipv6 else 4
        self.second_heartbeat = second_heartbeat
        self._default_nic_list = custom_nic_list
        self._nic_info_dict = {}

    def get_interfaces_info(self):
        """
        Try to get interfaces info dictionary via "ip" command

        IMPORTANT: This is the method that populates the data, should always be called after initialize
        """
        cmd = "ip -{} -o addr show".format(self.ip_version)
        rc, out, err = get_stdout_stderr(cmd)
        if rc != 0:
            raise ValueError(err)

        # format on each line will like:
        # 2: enp1s0    inet 192.168.122.241/24 brd 192.168.122.255 scope global enp1s0\       valid_lft forever preferred_lft forever
        for line in out.splitlines():
            _, nic, _, ip_with_mask, *_ = line.split()
            # maybe from tun interface
            if not '/' in ip_with_mask:
                continue
            #TODO change this condition when corosync support link-local address
            interface_inst = Interface(ip_with_mask)
            if interface_inst.is_loopback or interface_inst.is_link_local:
                continue
            # one nic might configured multi IP addresses
            if nic not in self._nic_info_dict:
                self._nic_info_dict[nic] = []
            self._nic_info_dict[nic].append(interface_inst)

        if not self._nic_info_dict:
            raise ValueError("No address configured")
        if self.second_heartbeat and len(self._nic_info_dict) == 1:
            raise ValueError("Cannot configure second heartbeat, since only one address is available")

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

    @property
    def network_list(self):
        """
        Get network list
        """
        return list(set([interface.network for interface in self.interface_list]))

    def _nic_first_ip(self, nic):
        """
        Get the first IP of specific nic
        """
        return self._nic_info_dict[nic][0].ip

    def get_default_nic_list_from_route(self):
        """
        Get default nic list from route
        """
        if self._default_nic_list:
            return self._default_nic_list

        #TODO what if user only has ipv6 route?
        cmd = "ip -o route show"
        rc, out, err = get_stdout_stderr(cmd)
        if rc != 0:
            raise ValueError(err)
        res = re.search(r'^default via .* dev (.*?) ', out)
        if res:
            self._default_nic_list = [res.group(1)]
        else:
            if not self.nic_list:
                self.get_interfaces_info()
            common_warn("No default route configured. Using the first found nic")
            self._default_nic_list = [self.nic_list[0]]
        return self._default_nic_list

    def get_default_ip_list(self):
        """
        Get default IP list will be used by corosync
        """
        if not self._default_nic_list:
            self.get_default_nic_list_from_route()
        if not self.nic_list:
            self.get_interfaces_info()

        _ip_list = []
        for nic in self._default_nic_list:
            # in case given interface not exist
            if nic not in self.nic_list:
                raise ValueError("Failed to detect IP address for {}".format(nic))
            _ip_list.append(self._nic_first_ip(nic))
        # in case -M specified but given one interface via -i
        if self.second_heartbeat and len(self._default_nic_list) == 1:
            for nic in self.nic_list:
                if nic not in self._default_nic_list:
                    _ip_list.append(self._nic_first_ip(nic))
                    break
        return _ip_list

    @classmethod
    def ip_in_network(cls, addr):
        """
        Check whether given address was in one of local networks
        """
        cls_inst = cls(IP.is_ipv6(addr))
        cls_inst.get_interfaces_info()
        for interface_inst in cls_inst.interface_list:
            if interface_inst.ip_in_network(addr):
                return True
        return False


def check_file_content_included(source_file, target_file):
    """
    Check whether target_file includes contents of source_file
    """
    if not os.path.exists(source_file):
        raise ValueError("File {} not exist".format(source_file))
    if not os.path.exists(target_file):
        return False

    with open(target_file, 'r') as target_fd:
        target_data = target_fd.read()
    with open(source_file, 'r') as source_fd:
        source_data = source_fd.read()
    return source_data in target_data


class ServiceManager(object):
    """
    Class to manage systemctl services
    """
    ACTION_MAP = {
            "enable": "enable",
            "disable": "disable",
            "start": "start",
            "stop": "stop",
            "is_enabled": "is-enabled",
            "is_active": "is-active",
            "is_available": "list-unit-files"
            }

    def __init__(self, service_name, remote_addr=None):
        """
        Init function
        """
        self.service_name = service_name
        self.remote_addr = remote_addr

    def _do_action(self, action_type):
        """
        Actual do actions to manage service
        """
        if action_type not in self.ACTION_MAP.values():
            raise ValueError("status_type should be {}".format('/'.join(list(self.ACTION_MAP.values()))))

        cmd = "systemctl {} {}".format(action_type, self.service_name)
        if self.remote_addr:
            prompt_msg = "Run \"{}\" on {}".format(cmd, self.remote_addr)
            rc, output, err = run_cmd_on_remote(cmd, self.remote_addr, prompt_msg)
        else:
            rc, output, err = get_stdout_stderr(cmd)
        if rc != 0 and err:
            raise ValueError("Run \"{}\" error: {}".format(cmd, err))
        return rc == 0, output

    @property
    def is_available(self):
        return self.service_name in self._do_action(self.ACTION_MAP["is_available"])[1]

    @property
    def is_enabled(self):
        return self._do_action(self.ACTION_MAP["is_enabled"])[0]

    @property
    def is_active(self):
        return self._do_action(self.ACTION_MAP["is_active"])[0]

    def start(self):
        self._do_action(self.ACTION_MAP["start"])

    def stop(self):
        self._do_action(self.ACTION_MAP["stop"])

    def enable(self):
        self._do_action(self.ACTION_MAP["enable"])

    def disable(self):
        self._do_action(self.ACTION_MAP["disable"])

    @classmethod
    def service_is_available(cls, name, remote_addr=None):
        """
        Check whether service is available
        """
        inst = cls(name, remote_addr)
        return inst.is_available

    @classmethod
    def service_is_enabled(cls, name, remote_addr=None):
        """
        Check whether service is enabled
        """
        inst = cls(name, remote_addr)
        return inst.is_enabled

    @classmethod
    def service_is_active(cls, name, remote_addr=None):
        """
        Check whether service is active
        """
        inst = cls(name, remote_addr)
        return inst.is_active

    @classmethod
    def start_service(cls, name, enable=False, remote_addr=None):
        """
        Start service
        """
        inst = cls(name, remote_addr)
        if enable:
            inst.enable()
        inst.start()

    @classmethod
    def stop_service(cls, name, disable=False, remote_addr=None):
        """
        Stop service
        """
        inst = cls(name, remote_addr)
        if disable:
            inst.disable()
        inst.stop()

    @classmethod
    def enable_service(cls, name, remote_addr=None):
        """
        Enable service
        """
        inst = cls(name, remote_addr)
        if inst.is_available and not inst.is_enabled:
            inst.enable()

    @classmethod
    def disable_service(cls, name, remote_addr=None):
        """
        Disable service
        """
        inst = cls(name, remote_addr)
        if inst.is_available and inst.is_enabled:
            inst.disable()


service_is_available = ServiceManager.service_is_available
service_is_enabled = ServiceManager.service_is_enabled
service_is_active = ServiceManager.service_is_active
start_service = ServiceManager.start_service
stop_service = ServiceManager.stop_service
enable_service = ServiceManager.enable_service
disable_service = ServiceManager.disable_service


def package_is_installed(pkg, remote_addr=None):
    """
    Check if package is installed
    """
    cmd = "rpm -q --quiet {}".format(pkg)
    if remote_addr:
        # check on remote
        prompt_msg = "Check whether {} is installed on {}".format(pkg, remote_addr)
        rc, _, _ = run_cmd_on_remote(cmd, remote_addr, prompt_msg)
    else:
        # check on local
        rc, _ = get_stdout(cmd)
    return rc == 0


def ping_node(node):
    """
    Check if the remote node is reachable
    """
    rc, _, err = get_stdout_stderr("ping -c 1 {}".format(node))
    if rc != 0:
        raise ValueError("host \"{}\" is unreachable: {}".format(node, err))
# vim:ts=4:sw=4:et:
