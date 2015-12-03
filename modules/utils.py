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
import bz2
from . import config
from . import userdir
from . import constants
from . import options
from . import term
from .msg import common_warn, common_info, common_debug, common_err, err_buf


class memoize:
    "Decorator to invoke a function once only for any argument"
    def __init__(self, function):
        self.function = function
        self.memoized = {}

    def __call__(self, *args):
        try:
            return self.memoized[args]
        except KeyError:
            self.memoized[args] = self.function(*args)
            return self.memoized[args]


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
            ans = raw_input(msg)
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
            text = raw_input(prompt)
        except EOFError:
            return None
        err_buf.incr_lineno()
        if options.regression_tests:
            print ".INP:", text
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
    return opt.lower() in ("yes", "true", "on", "1")


def is_boolean_false(opt):
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


def pipe_string(cmd, s):
    rc = -1  # command failed
    cmd = add_sudo(cmd)
    common_debug("piping string to %s" % cmd)
    if options.regression_tests:
        print ".EXT", cmd
    p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE)
    try:
        p.communicate(s)
        p.wait()
        rc = p.returncode
    except IOError, msg:
        if "Broken pipe" not in msg:
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
        print ".EXT", cmd
    p = subprocess.Popen(cmd,
                         shell=shell,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=stderr)
    try:
        ret = p.communicate(s)
        if stderr_on == 'stdout':
            outp = "\n".join(ret)
        else:
            outp = ret[0]
        p.wait()
        rc = p.returncode
    except OSError, (errno, strerror):
        if errno != os.errno.EPIPE:
            common_err(strerror)
        common_info("from: %s" % cmd)
    except Exception, msg:
        common_err(msg)
        common_info("from: %s" % cmd)
    return rc, outp


def str2tmp(s, suffix=".pcmk"):
    '''
    Write the given string to a temporary file. Return the name
    of the file.
    '''
    fd, tmp = mkstemp(suffix=suffix)
    try:
        f = os.fdopen(fd, "w")
    except IOError, msg:
        common_err(msg)
        return
    f.write(s)
    if not s.endswith('\n'):
        f.write("\n")
    f.close()
    return tmp


def str2file(s, fname):
    '''
    Write a string to a file.
    '''
    try:
        f = open(fname, "w")
    except IOError, msg:
        common_err(msg)
        return False
    f.write(s)
    f.close()
    return True


def file2str(fname, noerr=True):
    '''
    Read a one line file into a string, strip whitespace around.
    '''
    try:
        f = open(fname, "r")
    except IOError, msg:
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
    except IOError, msg:
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
        except IOError, msg:
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
        print ".EXT", cmd
    subprocess.Popen(cmd, shell=True, bufsize=0,
                     stdin=None, stdout=None, stderr=None, close_fds=True)
    common_info("starting %s to show %s" % (config.core.dotty, desc))


def ext_cmd(cmd, shell=True):
    cmd = add_sudo(cmd)
    if options.regression_tests:
        print ".EXT", cmd
    common_debug("invoke: %s" % cmd)
    return subprocess.call(cmd, shell=shell)


def ext_cmd_nosudo(cmd, shell=True):
    if options.regression_tests:
        print ".EXT", cmd
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
    return config.core.check_mode == "strict" and 2 or 1


_LOCKDIR = ".lockdir"
_PIDF = "pid"


def check_locker(dir):
    if not os.path.isdir(os.path.join(dir, _LOCKDIR)):
        return
    s = file2str(os.path.join(dir, _LOCKDIR, _PIDF))
    pid = convert2ints(s)
    if not isinstance(pid, int):
        common_warn("history: removing malformed lock")
        rmdir_r(os.path.join(dir, _LOCKDIR))
        return
    try:
        os.kill(pid, 0)
    except OSError, (errno, strerror):
        if errno == os.errno.ESRCH:
            common_info("history: removing stale lock")
            rmdir_r(os.path.join(dir, _LOCKDIR))
        else:
            common_err("%s: %s" % (_LOCKDIR, strerror))


def acquire_lock(dir):
    check_locker(dir)
    while True:
        try:
            os.makedirs(os.path.join(dir, _LOCKDIR))
            str2file("%d" % os.getpid(), os.path.join(dir, _LOCKDIR, _PIDF))
            return True
        except OSError, (errno, strerror):
            if errno != os.errno.EEXIST:
                common_err(strerror)
                return False
            time.sleep(0.1)
            continue
        else:
            return False


def release_lock(dir):
    rmdir_r(os.path.join(dir, _LOCKDIR))


def pipe_cmd_nosudo(cmd):
    if options.regression_tests:
        print ".EXT", cmd
    proc = subprocess.Popen(cmd,
                            shell=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    (outp, err_outp) = proc.communicate()
    proc.wait()
    rc = proc.returncode
    if rc != 0:
        print outp
        print err_outp
    return rc


def get_stdout(cmd, input_s=None, stderr_on=True, shell=True):
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
        print ".EXT", cmd
    proc = subprocess.Popen(cmd,
                            shell=shell,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=stderr)
    stdout_data, stderr_data = proc.communicate(input_s)
    return proc.returncode, stdout_data.strip()


def get_stdout_stderr(cmd, input_s=None, shell=True):
    '''
    Run a cmd, return (rc, stdout, stderr)
    '''
    if options.regression_tests:
        print ".EXT", cmd
    proc = subprocess.Popen(cmd,
                            shell=shell,
                            stdin=input_s and subprocess.PIPE or None,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    stdout_data, stderr_data = proc.communicate(input_s)
    return proc.returncode, stdout_data.strip(), stderr_data.strip()


def stdout2list(cmd, stderr_on=True, shell=True):
    '''
    Run a cmd, fetch output, return it as a list of lines.
    stderr_on controls whether to show output which comes on stderr.
    '''
    rc, s = get_stdout(add_sudo(cmd), stderr_on=stderr_on, shell=shell)
    if not s:
        return rc, []
    else:
        return rc, s.split('\n')


def append_file(dest, src):
    'Append src to dest'
    try:
        open(dest, "a").write(open(src).read())
        return True
    except IOError, msg:
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
        if 0 < delaymsec:
            common_info("The crmd-transition-delay is configured. Waiting %d msec before check DC status." % delaymsec)
            time.sleep(delaymsec / 1000)
    cmd = "crmadmin -S %s" % dc
    cnt = 0
    output_started = 0
    init_sleep = 0.25
    max_sleep = 1.00
    sleep_time = init_sleep
    while True:
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


def is_id_valid(id):
    """
    Verify that the id follows the definition:
    http://www.w3.org/TR/1999/REC-xml-names-19990114/#ns-qualnames
    """
    if not id:
        return False
    id_re = r"^[A-Za-z_][\w._-]*$"
    return re.match(id_re, id)


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
    return (int(r.group(1))*mult)/div


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


def dirwalk(dir):
    "walk a directory tree, using a generator"
    # http://code.activestate.com/recipes/105873/
    for f in os.listdir(dir):
        fullpath = os.path.join(dir, f)
        if os.path.isdir(fullpath) and not os.path.islink(fullpath):
            for x in dirwalk(fullpath):  # recurse into subdir
                yield x
        else:
            yield fullpath


def file_find_by_name(dir, fname):
    'Find a file within a tree matching fname.'
    if not dir:
        common_err("cannot dirwalk nothing!")
        return None
    if not fname:
        common_err("file to find not provided")
        return None
    for f in dirwalk(dir):
        if os.path.basename(f) == fname:
            return f
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
        else:  # it's a string then
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
    cmd = "ps -e -o pid,command | grep -qs '%s'" % s
    if options.regression_tests:
        print ".EXT", cmd
    proc = subprocess.Popen(cmd,
                            shell=True,
                            stdout=subprocess.PIPE)
    proc.wait()
    return proc.returncode == 0


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
    except OSError, e:
        raise IOError(e)


def need_pager(s, w, h):
    from math import ceil
    cnt = 0
    for l in s.split('\n'):
        # need to remove color codes
        l = re.sub(r'\${\w+}', '', l)
        cnt += int(ceil((len(l) + 0.5)/w))
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
    w, h = get_winsize()
    if not need_pager(s, w, h):
        print term_render(s)
    elif not config.core.pager or not can_ask() or options.batch:
        print term_render(s)
    else:
        pipe_string(get_pager_cmd(), term_render(s))


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
    cols = w/(max_len + min_gap)  # approx.
    if not cols:
        cols = 1
    col_len = w/cols
    for i in range(len(l)/cols + 1):
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
            print s


def find_value(pl, name):
    for n, v in pl:
        if n == name:
            return v
    return None


def cli_replace_attr(pl, name, new_val):
    for i in range(len(pl)):
        if pl[i][0] == name:
            pl[i][1] = new_val
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
    else:
        return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 10**6


def datetime_to_timestamp(dt):
    """
    Convert a datetime object into a floating-point second value
    """
    try:
        return total_seconds(make_datetime_naive(dt) - datetime.datetime(1970, 1, 1))
    except Exception as e:
        common_err("datetime_to_timestamp error: %s" % (e))
        return None


def parse_time(t):
    '''
    Try to make sense of the user provided time spec.
    Use dateutil if available, otherwise strptime.
    Return the datetime value.

    Also does time zone elimination by passing the datetime
    through a timestamp conversion if necessary
    '''
    try:
        import dateutil.parser
        import dateutil.tz
        dt = dateutil.parser.parse(t)

        if datetime_is_aware(dt):
            ts = datetime_to_timestamp(dt)
            if ts is None:
                return None
            dt = datetime.datetime.fromtimestamp(ts)
        else:
            # convert to UTC from local time
            dt = make_datetime_naive(dt.replace(tzinfo=dateutil.tz.tzlocal()))
    except ValueError, msg:
        common_err("%s: %s" % (t, msg))
        return None
    except ImportError, msg:
        try:
            tm = time.strptime(t)
            dt = datetime.datetime(*tm[0:7])
        except ValueError, msg:
            common_err("no dateutil, please provide times as printed by date(1)")
            return None
    return dt


def save_graphviz_file(ini_f, attr_d):
    '''
    Save graphviz settings to an ini file, if it does not exist.
    '''
    if os.path.isfile(ini_f):
        common_err("%s exists, please remove it first" % ini_f)
        return False
    try:
        f = open(ini_f, "wb")
    except IOError, msg:
        common_err(msg)
        return False
    import ConfigParser
    p = ConfigParser.SafeConfigParser()
    for section, sect_d in attr_d.iteritems():
        p.add_section(section)
        for n, v in sect_d.iteritems():
            p.set(section, n, v)
    try:
        p.write(f)
    except IOError, msg:
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
    import ConfigParser
    p = ConfigParser.SafeConfigParser()
    try:
        p.read(ini_f)
    except Exception, msg:
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

    crmd = is_program('crmd')
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
    except Exception, msg:
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
    except IOError, msg:
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
        f = open(cib_f).read()
    except IOError, msg:
        common_err(msg)
        return dflt_l
    if os.path.splitext(cib_f)[-1] == '.bz2':
        cib_s = bz2.decompress(f)
    else:
        cib_s = f
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
    for i in reversed(range(len(args))):
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


def list_cluster_nodes():
    '''
    Returns a list of nodes in the cluster.
    '''

    def getname(toks):
        if toks and len(toks) >= 2:
            return toks[1]
        return None

    try:
        rc, outp = stdout2list(['crm_node', '-l'], stderr_on=False, shell=False)
        if rc != 0:
            raise ValueError("Error listing cluster nodes: crm_node (rc=%d)" % (rc))
        return [x for x in [getname(line.split()) for line in outp] if x and x != '(null)']
    except OSError, msg:
        raise ValueError("Error listing cluster nodes: %s" % (msg))


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
    return parallax.slurp(nodes, filename, dst, opts).items()


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

    print "%-16s  SHA1 checksum of %s" % ('Host', local_path)
    if this_node not in nodes:
        print "%-16s: %s" % (this_node, hashlib.sha1(open(local_path).read()).hexdigest())
    for host, result in by_host:
        _, _, _, path = result
        print "%-16s: %s" % (host, hashlib.sha1(open(path).read()).hexdigest())


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
                                      local_path, opts).iteritems():
        if isinstance(result, parallax.Error):
            err_buf.error("Failed to push %s to %s: %s" % (local_path, host, result))
            ok = False
        else:
            err_buf.ok(host)
    return ok


# vim:ts=4:sw=4:et:
