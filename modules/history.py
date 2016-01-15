# Copyright (C) 2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.

import os
import time
import datetime
import re
import glob
import ConfigParser

from . import config
from . import constants
from . import userdir
from .msg import common_debug, common_warn, common_err, common_error, common_info, warn_once
from .xmlutil import file2cib_elem, get_rsc_children_ids, get_prim_children_ids, compressed_file_to_cib
from .utils import file2str, shortdate, acquire_lock, append_file, ext_cmd, shorttime
from .utils import page_string, release_lock, rmdir_r, parse_time, get_cib_attributes
from .utils import is_pcmk_118, pipe_cmd_nosudo, file_find_by_name, get_stdout, quote
from .utils import make_datetime_naive, datetime_to_timestamp

_HAS_PARALLAX = False
try:
    from .crm_pssh import next_loglines, next_peinputs
    _HAS_PARALLAX = True
except:
    pass


YEAR = None


#
# hb_report interface
#
# read hb_report generated report, show interesting stuff, search
# through logs, get PE input files, get log slices (perhaps even
# coloured nicely!)
#


def mk_re_list(patt_l, repl):
    'Build a list of regular expressions, replace "%%" with repl'
    l = []
    for re_l in patt_l:
        l += [x.replace("%%", repl) for x in re_l]
    if not repl:
        l = [x.replace(".*.*", ".*") for x in l]
    return l


def set_year(ts=None):
    '''
    ts: optional time in seconds
    '''
    global YEAR
    year = time.strftime("%Y", time.localtime(ts))
    if YEAR is not None:
        t = (" (ts: %s)" % (ts)) if ts is not None else ""
        common_debug("history: setting year to %s%s" % (year, t))
    YEAR = year


def make_time(t):
    '''
    t: time in seconds / datetime / other
    returns: time in floating point
    '''
    if t is None:
        return None
    elif isinstance(t, datetime.datetime):
        return datetime_to_timestamp(t)
    return t


_syslog2node_formats = (re.compile(r'^[a-zA-Z]{2,4} \d{1,2} \d{2}:\d{2}:\d{2}\s+(?:\[\d+\])?\s*([\S]+)'),
                        re.compile(r'^\d{4}-\d{2}-\d{2}T\S+\s+(?:\[\d+\])?\s*([\S]+)'))


def syslog_ts(s):
    """
    Finds the timestamp in the given line
    Returns as floating point, seconds
    """
    fmt1, fmt2 = _syslog2node_formats
    m = fmt1.match(s)
    if m:
        if YEAR is None:
            set_year()
        tstr = ' '.join([YEAR] + s.split()[0:3])
        return datetime_to_timestamp(parse_time(tstr))

    m = fmt2.match(s)
    if m:
        tstr = s.split()[0]
        return datetime_to_timestamp(parse_time(tstr))

    common_debug("malformed line: %s" % s)
    return None


def syslog2node(s):
    '''
    Get the node from a syslog line.

    old format:
    Aug 14 11:07:04 <node> ...
    new format:
    Aug 14 11:07:04 [<PID>] <node> ...
    RFC5424:
    <TS> <node> ...
    RFC5424 (2):
    <TS> [<PID>] <node> ...
    '''

    fmt1, fmt2 = _syslog2node_formats
    m = fmt1.search(s)
    if m:
        return m.group(1)

    m = fmt2.search(s)
    if m:
        return m.group(1)

    try:
        # strptime defaults year to 1900 (sigh)
        time.strptime(' '.join(s.split()[0:3]),
                      "%b %d %H:%M:%S")
        return s.split()[3]
    except:  # try the rfc5424
        try:
            parse_time(s.split()[0])
            return s.split()[1]
        except Exception:
            return None


def seek_to_edge(f, ts, to_end):
    '''
    f contains lines with exactly the timestamp ts.
    Read forward (or backward) till we find the edge.
    Linear search, but should be short.
    '''
    if not to_end:
        beg = 0
        while ts == get_timestamp(f):
            if f.tell() < 1000:
                f.seek(0)    # otherwise, the seek below throws an exception
                if beg > 0:  # avoid infinite loop
                    return   # goes all the way to the top
                beg += 1
            else:
                f.seek(-1000, 1)  # go back 10 or so lines
    while True:
        pos = f.tell()
        s = f.readline()
        if not s:
            break
        curr_ts = syslog_ts(s)
        if (to_end and curr_ts > ts) or \
                (not to_end and curr_ts >= ts):
            break
    f.seek(pos)


def log_seek(f, ts, to_end=False):
    '''
    f is an open log. Do binary search for the timestamp.
    Return the position of the (more or less) first line with an
    earlier (or later) time.
    '''
    first = 0
    f.seek(0, 2)
    last = f.tell()
    if not ts:
        return to_end and last or first
    badline = 0
    maxbadline = 10
    common_debug("seek %s:%s in %s" %
                 (time.ctime(ts),
                  to_end and "end" or "start",
                  f.name))
    while first <= last:
        # we can skip some iterations if it's about few lines
        if abs(first-last) < 120:
            break
        mid = (first+last)/2
        f.seek(mid)
        log_ts = get_timestamp(f)
        if not log_ts:
            badline += 1
            if badline > maxbadline:
                common_warn("giving up on log %s" % f.name)
                return -1
            first += 120  # move forward a bit
            continue
        if log_ts > ts:
            last = mid-1
        elif log_ts < ts:
            first = mid+1
        else:
            seek_to_edge(f, log_ts, to_end)
            break
    fpos = f.tell()
    common_debug("sought to %s (%d)" % (f.readline(), fpos))
    f.seek(fpos)
    return fpos


def get_timestamp(f):
    '''
    Get the whole line from f. The current file position is
    usually in the middle of the line.
    Then get timestamp and return it.
    '''
    step = 30  # no line should be longer than 30
    cnt = 1
    current_pos = f.tell()
    s = f.readline()
    if not s:  # EOF?
        f.seek(-step, 1)  # backup a bit
        current_pos = f.tell()
        s = f.readline()
    while s and current_pos < f.tell():
        if cnt*step >= f.tell():  # at 0?
            f.seek(0)
            break
        f.seek(-cnt*step, 1)
        s = f.readline()
        cnt += 1
    pos = f.tell()     # save the position ...
    s = f.readline()   # get the line
    f.seek(pos)        # ... and move the cursor back there
    if not s:          # definitely EOF (probably cannot happen)
        return None
    return syslog_ts(s)


def is_our_log(s, node_l):
    return syslog2node(s) in node_l


def log2node(log):
    return os.path.basename(os.path.dirname(log))


def filter_log(sl, log_l):
    '''
    Filter list of messages to get only those from the given log
    files list.
    '''
    node_l = [log2node(x) for x in log_l if x]
    ret = [x for x in sl if is_our_log(x, node_l)]
    common_debug("filter_log: %s in, %s out" % (len(sl), len(ret)))
    return ret


def first_log_lines(log_l):
    '''
    Return a list of all first lines of the logs.
    '''
    f_list = [open(x) for x in log_l if x]
    l = [x.readline().rstrip() for x in f_list if x]
    for x in f_list:
        if x:
            x.close()
    return l


def last_log_lines(log_l):
    '''
    Return a list of all last lines of the logs.
    '''
    f_list = [open(x) for x in log_l if x]
    l = [x.readlines()[-1].rstrip() for x in f_list if x]
    for x in f_list:
        if x:
            x.close()
    return l


class LogSyslog(object):
    '''
    Slice log, search log.
    '''

    def __init__(self, log_l, from_dt, to_dt):
        self.log_l = log_l
        self.f = {}
        self.startpos = {}
        self.endpos = {}
        self.cache = {}
        self.open_logs()
        self.set_log_timeframe(from_dt, to_dt)

    def open_log(self, log):
        import bz2
        import gzip
        try:
            if log.endswith(".bz2"):
                self.f[log] = bz2.BZ2File(log)
            elif log.endswith(".gz"):
                self.f[log] = gzip.open(log)
            else:
                self.f[log] = open(log)
        except IOError, msg:
            common_err("open %s: %s" % (log, msg))

    def open_logs(self):
        for log in self.log_l:
            common_debug("opening log %s" % log)
            self.open_log(log)

    def set_log_timeframe(self, from_dt, to_dt):
        '''
        Convert datetime to timestamps (i.e. seconds), then
        find out start/end file positions. Logs need to be
        already open.
        '''
        self.from_ts = make_time(from_dt)
        self.to_ts = make_time(to_dt)
        bad_logs = []
        for log in self.f:
            f = self.f[log]
            start = log_seek(f, self.from_ts)
            end = log_seek(f, self.to_ts, to_end=True)
            if start == -1 or end == -1:
                common_debug("%s is a bad log" % (log))
                bad_logs.append(log)
            else:
                common_debug("%s start=%s, end=%s" % (log, start, end))
                self.startpos[f] = start
                self.endpos[f] = end
        for log in bad_logs:
            del self.f[log]
            self.log_l.remove(log)

    def get_match_line(self, f, relist):
        '''
        Get first line from f that matches one of
        the REs in relist, but is not behind endpos[f].
        if relist is empty, return all lines
        '''
        while f.tell() < self.endpos[f]:
            fpos = f.tell()
            s = f.readline().rstrip()
            if not s:
                continue
            if not relist or any(r.search(s) for r in relist):
                return s, fpos
        return '', -1

    def single_log_list(self, f, patt):
        l = []
        while True:
            s = self.get_match_line(f, patt)[0]
            if not s:
                return l
            l.append(s)
        return l

    def search_logs(self, log_l, relist):
        '''
        Search logs for any of the regexps in relist.
        '''
        fl = [self.f[f] for f in self.f if self.f[f].name in log_l]
        for f in fl:
            f.seek(self.startpos[f])
        # get head lines of all nodes
        top_line = [self.get_match_line(x, relist)[0] for x in fl]
        top_line_ts = []
        rm_idx_l = []
        # calculate time stamps for head lines
        for i in range(len(top_line)):
            if not top_line[i]:
                rm_idx_l.append(i)
            else:
                top_line_ts.append(syslog_ts(top_line[i]))
        # remove files with no matches found
        rm_idx_l.reverse()
        for i in rm_idx_l:
            del fl[i], top_line[i]
        common_debug("search in %s" % ", ".join(f.name for f in fl))
        if len(fl) == 0:  # nothing matched ?
            return []
        if len(fl) == 1:
            # no need to merge if there's only one log
            return [top_line[0]] + self.single_log_list(fl[0], relist)
        # search through multiple logs, merge sorted by time
        l = []
        first = 0
        while True:
            for i in range(len(fl)):
                try:
                    if i == first:
                        continue
                    if top_line_ts[i] and top_line_ts[i] < top_line_ts[first]:
                        first = i
                except:
                    pass
            if not top_line[first]:
                break
            l.append(top_line[first])
            top_line[first] = self.get_match_line(fl[first], relist)[0]
            if not top_line[first]:
                top_line_ts[first] = time.time()
            else:
                top_line_ts[first] = syslog_ts(top_line[first])
        return l

    def get_matches(self, re_l, log_l=None):
        '''
        Return a list of log messages which
        match one of the regexes in re_l.
        if re_l is an empty list, return all lines.
        '''
        log_l = log_l or self.log_l
        return filter_log(self.search_logs(log_l, re_l), log_l)


def human_date(dt):
    'Some human date representation. Date defaults to now.'
    if not dt:
        dt = make_datetime_naive(datetime.datetime.now())
    # here, dt is in UTC. Convert to localtime:
    localdt = datetime.datetime.fromtimestamp(datetime_to_timestamp(dt))
    # drop microseconds
    return re.sub("[.].*", "", "%s %s" % (localdt.date(), localdt.time()))


def is_log(p):
    return os.path.isfile(p) and os.path.getsize(p) > 0


def pe_file_in_range(pe_f, a):
    pe_num = get_pe_num(pe_f)
    if not a or (a[0] <= int(pe_num) <= a[1]):
        return pe_f
    return None


def read_log_info(log):
    'Read <log>.info and return logfile and next pos'
    s = file2str("%s.info" % log)
    try:
        logf, pos = s.split()
        return logf, int(pos)
    except:
        warn_once("crm report too old, you need to update cluster-glue")
        return '', -1


def update_loginfo(rptlog, logfile, oldpos, appended_file):
    'Update <log>.info with new next pos'
    newpos = oldpos + os.stat(appended_file).st_size
    try:
        f = open("%s.info" % rptlog, "w")
        f.write("%s %d\n" % (logfile, newpos))
        f.close()
    except IOError, msg:
        common_err("couldn't the update %s.info: %s" % (rptlog, msg))


def get_pe_num(pe_file):
    try:
        return re.search("pe-[^-]+-([0-9]+)[.]", pe_file).group(1)
    except:
        return "-1"


def run_graph_msg_actions(msg):
    '''
    crmd: [13667]: info: run_graph: Transition 399 (Complete=5,
    Pending=1, Fired=1, Skipped=0, Incomplete=3,
    Source=...
    Returns dict: d[Pending]=np, d[Fired]=nf, ...
    '''
    d = {}
    s = msg
    while True:
        r = re.search("([A-Z][a-z]+)=([0-9]+)", s)
        if not r:
            return d
        d[r.group(1)] = int(r.group(2))
        s = s[r.end():]


def get_pe_file_num_from_msg(msg):
    """
    Get PE file name and number from log message
    Returns: (file, num)
    """
    msg_a = msg.split()
    if len(msg_a) < 5:
        # this looks too short
        common_warn("log message <%s> unexpected format, please report a bug" % msg)
        return ("", "-1")
    return (msg_a[-1], get_pe_num(msg_a[-1]))


def transition_start_re(number_re):
    """
    Return regular expression matching transition start.
    number_re can be a specific transition or a regexp matching
    any transition number.
    The resulting RE has groups
    1: transition number
    2: full path of pe file
    3: pe file number
    """
    m1 = "crmd.*Processing graph ([0-9]+).*derived from (.*/pe-[^-]+-(%s)[.]bz2)" % (number_re)
    m2 = "pengine.*Transition ([0-9]+):.*([^ ]*/pe-[^-]+-(%s)[.]bz2)" % (number_re)
    try:
        return re.compile("(?:%s)|(?:%s)" % (m1, m2))
    except re.error, e:
        common_debug("RE compilation failed: %s" % (e))
        raise ValueError("Error in search expression")


def transition_end_re(number_re):
    """
    Return RE matching transition end.
    See transition_start_re for more details.
    """
    try:
        return re.compile("crmd.*Transition ([0-9]+).*Source=(.*/pe-[^-]+-(%s)[.]bz2).:.*(Stopped|Complete|Terminated)" % (number_re))
    except re.error, e:
        common_debug("RE compilation failed: %s" % (e))
        raise ValueError("Error in search expression")


def find_transition_end(trnum, messages):
    """
    Find the end of the given transition in the list of messages
    """
    matcher = transition_end_re(trnum)
    for msg in messages:
        if matcher.search(msg):
            return msg
    matcher = transition_start_re(str(int(trnum) + 1))
    for msg in messages:
        if matcher.search(msg):
            return msg
    return None


def find_transition_end_msg(transition_start_msg, trans_msg_l):
    """
    Given the start of a transition log message, find
    and return the end of the transition log messages.
    """
    pe_file, pe_num = get_pe_file_num_from_msg(transition_start_msg)
    if pe_num == "-1":
        common_warn("%s: strange, transition number not found" % pe_file)
        return ""
    return find_transition_end(pe_num, trans_msg_l) or ""


def trans_str(node, pe_file):
    '''Convert node,pe_file to transition string.'''
    return "%s:%s" % (node, os.path.basename(pe_file).replace(".bz2", ""))


def rpt_pe2t_str(rpt_pe_file):
    '''Convert report's pe_file path to transition sting.'''
    node = os.path.basename(os.path.dirname(os.path.dirname(rpt_pe_file)))
    return trans_str(node, rpt_pe_file)


class Transition(object):
    '''
    Capture transition related information.
    '''

    def __init__(self, start_msg, end_msg):
        self.start_msg = start_msg
        self.end_msg = end_msg
        self.tags = set()
        self.pe_file, self.pe_num = get_pe_file_num_from_msg(start_msg)
        self.dc = syslog2node(start_msg)
        self.start_ts = syslog_ts(start_msg)
        if end_msg:
            self.end_ts = syslog_ts(end_msg)
        else:
            common_warn("end of transition %s not found in logs (transition not complete yet?)" % self)
            self.end_ts = datetime_to_timestamp(datetime.datetime(2525, 1, 1))

    def __str__(self):
        return self.get_node_file()

    def get_node_file(self):
        return trans_str(self.dc, self.pe_file)

    def actions_count(self):
        if self.end_msg:
            act_d = run_graph_msg_actions(self.end_msg)
            return sum(act_d.values())
        else:
            return -1

    def shortname(self):
        return os.path.basename(self.pe_file).replace(".bz2", "")

    def transition_info(self):
        print "Transition %s (%s -" % (self, shorttime(self.start_ts)),
        if self.end_msg:
            print "%s):" % shorttime(self.end_ts)
            act_d = run_graph_msg_actions(self.end_msg)
            total = sum(act_d.values())
            s = ", ".join(["%d %s" % (act_d[x], x) for x in act_d if act_d[x]])
            print "\ttotal %d actions: %s" % (total, s)
        else:
            print "[unfinished])"


def mkarchive(dir):
    "Create an archive from a directory"
    home = userdir.gethomedir()
    if not home:
        common_err("no home directory, nowhere to pack report")
        return False
    archive = '%s.tar.bz2' % os.path.join(home, os.path.basename(dir))
    cmd = "tar -C '%s/..' -cj -f '%s' %s" % \
        (dir, archive, os.path.basename(dir))
    if pipe_cmd_nosudo(cmd) != 0:
        common_err('could not pack report, command "%s" failed' % cmd)
        return False
    else:
        print "Report saved in '%s'" % archive
    return True

CH_SRC, CH_TIME, CH_UPD = 1, 2, 3


class Report(object):
    '''
    A hb_report class.
    '''
    live_recent = 6*60*60   # recreate live hb_report once every 6 hours
    short_live_recent = 60  # update once a minute
    nodecolors = ("NORMAL",
                  "GREEN",
                  "CYAN",
                  "MAGENTA",
                  "YELLOW",
                  "WHITE",
                  "BLUE",
                  "RED")
    session_sub = "session"
    report_cache_dir = os.path.join(config.path.cache, 'history')
    outdir = os.path.join(config.path.cache, 'history', "psshout")
    errdir = os.path.join(config.path.cache, 'history', "pssherr")

    def __init__(self):
        # main source attributes
        self._creation_time = "--:--:--"
        self._creator = "unknown"
        self.source = None
        self.from_dt = None
        self.to_dt = None
        self.log_l = []
        self.setnodes = []  # optional
        # derived
        self.loc = None
        self.ready = False
        self.nodecolor = {}
        self.logobj = None
        self.desc = None
        self._transitions = []
        self.cibgrp_d = {}
        self.cibcln_d = {}
        self.cibrsc_l = []
        self.cibnotcloned_l = []
        self.cibcloned_l = []
        self.node_l = []
        self.last_live_update = 0
        self.detail = 0
        self.log_filter_out = []
        self.log_filter_out_re = []
        # change_origin may be 0, CH_SRC, CH_TIME, CH_UPD
        # depending on the change_origin, we update our attributes
        self.change_origin = CH_SRC
        set_year()

    def error(self, s):
        common_err("%s: %s" % (self.source, s))

    def warn(self, s):
        common_warn("%s: %s" % (self.source, s))

    def rsc_list(self):
        return self.cibgrp_d.keys() + self.cibcln_d.keys() + self.cibrsc_l

    def node_list(self):
        return self.node_l

    def peinputs_list(self):
        return [x.pe_num for x in self._transitions]

    def session_subcmd_list(self):
        return ["save", "load", "pack", "delete", "list", "update"]

    def session_list(self):
        l = os.listdir(self.get_session_dir(None))
        l.sort()
        return l

    def unpack_report(self, tarball):
        '''
        Unpack hb_report tarball.
        Don't unpack if the directory already exists!
        '''
        bfname = os.path.basename(tarball)
        parentdir = os.path.dirname(tarball)
        common_debug("tarball: %s, in dir: %s" % (bfname, parentdir))
        if bfname.endswith(".tar.bz2"):
            loc = tarball.replace(".tar.bz2", "")
            tar_unpack_option = "j"
        elif bfname.endswith(".tar.gz"):  # hmm, must be ancient
            loc = tarball.replace(".tar.gz", "")
            tar_unpack_option = "z"
        elif bfname.endswith(".tar.xz"):
            loc = tarball.replace(".tar.xz", "")
            tar_unpack_option = "J"
        else:
            self.error("this doesn't look like a report tarball")
            return None
        self.set_change_origin(CH_SRC)
        if os.path.isdir(loc):
            if (os.stat(tarball).st_mtime - os.stat(loc).st_mtime) < 60:
                return loc
            rmdir_r(loc)
        cwd = os.getcwd()
        if parentdir:
            try:
                os.chdir(parentdir)
            except OSError, msg:
                self.error(msg)
                return None
        try:
            rc, tf_loc = get_stdout("tar -t%s < %s 2> /dev/null | head -1" % (tar_unpack_option, quote(bfname)))
            if os.path.abspath(tf_loc) != os.path.abspath(loc):
                common_debug("top directory in tarball: %s, doesn't match the tarball name: %s" %
                             (tf_loc, loc))
                loc = os.path.join(os.path.dirname(loc), tf_loc)
        except Exception, msg:
            common_err("%s: %s" % (tarball, msg))
            return None
        common_debug("tar -x%s < %s" % (tar_unpack_option, bfname))
        rc = pipe_cmd_nosudo("tar -x%s < %s" % (tar_unpack_option, bfname))
        if self.source == "live":
            os.remove(bfname)
        os.chdir(cwd)
        if rc != 0:
            return None
        return loc

    def pe_report_path(self, t_obj):
        pe_base = os.path.basename(t_obj.pe_file)
        return os.path.join(self.loc, t_obj.dc, "pengine", pe_base)

    def short_pe_path(self, pe_file):
        return pe_file.replace("%s/" % self.loc, "")

    def get_nodes(self):
        return sorted([os.path.basename(p)
                       for p in os.listdir(self.loc)
                       if self.find_node_log(p) is not None])

    def check_nodes(self):
        'Verify if the nodes in cib match the nodes in the report.'
        nl = self.get_nodes()
        if not nl:
            self.error("no nodes in report")
            return False
        for n in self.node_l:
            if n not in nl:
                self.warn("node %s not in report" % n)
            else:
                nl.remove(n)
        return True

    def check_report(self):
        '''
        Check some basic properties of the report.
        '''
        if not self.loc:
            return False
        if not os.access(self.desc, os.F_OK):
            self.error("no description file in the report")
            return False
        if not self.check_nodes():
            return False
        return True

    def _live_loc(self):
        return os.path.join(self.report_cache_dir, "live")

    def is_live_recent(self):
        '''
        Look at the last live report. If it's recent enough,
        return True.
        '''
        try:
            last_ts = os.stat(self.desc).st_mtime
            return time.time() - last_ts <= self.live_recent
        except:
            return False

    def is_live_very_recent(self):
        '''
        Look at the last live report. If it's recent enough,
        return True.
        '''
        return (time.time() - self.last_live_update) <= self.short_live_recent

    def prevent_live_update(self):
        '''
        Don't update live report if to_time is set (not open end).
        '''
        return self.to_dt is not None

    def find_node_log(self, node):
        p = os.path.join(self.loc, node)
        for lf in ("ha-log.txt", "messages", "journal.log", "pacemaker.log"):
            if is_log(os.path.join(p, lf)):
                return os.path.join(p, lf)
        return None

    def find_logs(self):
        'Return a list of logs found (one per node).'
        l = []
        for node in self.node_l:
            log = self.find_node_log(node)
            if log:
                l.append(log)
            else:
                self.warn("no log found for node %s" % node)
        return l

    def append_newlogs(self, a):
        '''
        Append new logs fetched from nodes.
        '''
        if not os.path.isdir(self.outdir):
            return
        for node, rptlog, logfile, nextpos in a:
            fl = glob.glob("%s/*%s*" % (self.outdir, node))
            if not fl:
                continue
            append_file(rptlog, fl[0])
            update_loginfo(rptlog, logfile, nextpos, fl[0])

    def unpack_new_peinputs(self, node, pe_l):
        '''
        Untar PE inputs fetched from nodes.
        '''
        if not os.path.isdir(self.outdir):
            return
        fl = glob.glob("%s/*%s*" % (self.outdir, node))
        if not fl:
            return -1
        u_dir = os.path.join(self.loc, node)
        return pipe_cmd_nosudo("tar -C %s -x < %s" % (u_dir, fl[0]))

    def read_new_log(self, node):
        '''
        Get a list of log lines.
        The log is put in self.outdir/node by parallax.
        '''
        if not os.path.isdir(self.outdir):
            return []
        fl = glob.glob("%s/*%s*" % (self.outdir, node))
        if not fl:
            return []
        try:
            f = open(fl[0])
        except IOError, msg:
            common_err("open %s: %s" % (fl[0], msg))
            return []
        return f.readlines()

    def update_live_report(self):
        '''
        Update the existing live report, if it's older than
        self.short_live_recent:
        - append newer logs
        - get new PE inputs
        '''
        a = []
        common_info("fetching new logs, please wait ...")
        for rptlog in self.log_l:
            node = log2node(rptlog)
            logf, pos = read_log_info(rptlog)
            if logf:
                a.append([node, rptlog, logf, pos])
        if not a:
            common_info("no elligible logs found")
            return False
        rmdir_r(self.outdir)
        rmdir_r(self.errdir)
        self.last_live_update = time.time()
        rc1 = next_loglines(a, self.outdir, self.errdir)
        self.append_newlogs(a)
        node_pe_l = []
        for node in [x[0] for x in a]:
            log_l = self.read_new_log(node)
            if not log_l:
                continue
            pe_l = []
            for new_t_obj in self.list_transitions(log_l, future_pe=True):
                self._new_transition(new_t_obj)
                pe_l.append(new_t_obj.pe_file)
            if pe_l:
                node_pe_l.append([node, pe_l])
        rmdir_r(self.outdir)
        rmdir_r(self.errdir)
        if not node_pe_l:
            return rc1
        rc2 = next_peinputs(node_pe_l, self.outdir, self.errdir)
        unpack_rc = 0
        for node, pe_l in node_pe_l:
            unpack_rc |= self.unpack_new_peinputs(node, pe_l)
        rc2 |= (unpack_rc == 0)
        rmdir_r(self.outdir)
        rmdir_r(self.errdir)
        return rc1 and rc2

    def get_live_report(self):
        if not acquire_lock(self.report_cache_dir):
            return None
        loc = self.new_live_report()
        release_lock(self.report_cache_dir)
        return loc

    def manage_live_report(self, force=False, no_live_update=False):
        '''
        Update or create live report.
        '''
        d = self._live_loc()

        created_now = False

        # Create live report if it doesn't exist
        if not d or not os.path.isdir(d):
            created_now, d = True, self.get_live_report()
        if not self.loc:
            # the live report is there, but we were just invoked
            self.loc = d
            self.report_setup()
        if not force and self.is_live_recent():
            # try just to refresh the live report
            if self.to_dt or self.is_live_very_recent() or no_live_update:
                return self._live_loc()
            if _HAS_PARALLAX:
                if not acquire_lock(self.report_cache_dir):
                    return None
                rc = self.update_live_report()
                release_lock(self.report_cache_dir)
                if rc:
                    self.set_change_origin(CH_UPD)
                    return self._live_loc()
            else:
                warn_once("parallax library not installed, slow live updates ahead")
        if not created_now:
            return self.get_live_report()
        return self.loc

    def new_live_report(self):
        '''
        Run the report command to get logs now.
        '''
        from . import ui_report

        extcmd = ui_report.report_tool()
        if extcmd is None:
            self.error("No reporting tool found")
            return None

        d = self._live_loc()
        rmdir_r(d)
        tarball = "%s.tar.bz2" % d
        to_option = ""
        if self.to_dt:
            to_option = "-t '%s'" % human_date(self.to_dt)
        nodes_option = ""
        if self.setnodes:
            nodes_option = "'-n %s'" % ' '.join(self.setnodes)
        if pipe_cmd_nosudo("mkdir -p %s" % os.path.dirname(d)) != 0:
            return None
        common_info("Retrieving information from cluster nodes, please wait...")
        rc = pipe_cmd_nosudo("%s -Z -Q -f '%s' %s %s %s %s" %
                             (extcmd,
                              self.from_dt.ctime(),
                              to_option,
                              nodes_option,
                              str(config.core.report_tool_options),
                              d))
        if rc != 0:
            if os.path.isfile(tarball):
                self.warn("report thinks it failed, proceeding anyway")
            else:
                self.error("report failed")
                return None
        self.last_live_update = time.time()
        return self.unpack_report(tarball)

    def set_source(self, src):
        'Set our source.'
        if self.source != src:
            self.set_change_origin(CH_SRC)
            self.source = src
            self.loc = None
            self.ready = False

    def set_period(self, from_dt, to_dt):
        '''
        Set from/to_dt.
        '''
        common_debug("setting report times: <%s> - <%s>" % (from_dt, to_dt))
        self.from_dt = from_dt
        self.to_dt = to_dt

        refresh = False
        if self.source == "live" and self.ready:
            top_dt = self.get_rpt_dt(None, "top")
            if top_dt is None:
                return False
            refresh = from_dt and top_dt > from_dt
        if refresh:
            self.set_change_origin(CH_UPD)
            return self.refresh_source(force=True)
        else:
            self.set_change_origin(CH_TIME)
            self.report_setup()
        return True

    def set_detail(self, detail_lvl):
        '''
        Set the detail level.
        '''
        self.detail = int(detail_lvl)

    def set_nodes(self, *args):
        '''
        Allow user to set the node list (necessary if the host is
        not part of the cluster).
        '''
        self.setnodes = args

    def get_cib_loc(self):
        if not self.node_l:
            return ""
        return os.path.join(self.loc, self.node_l[0], "cib.xml")

    def read_cib(self):
        '''
        Get some information from the report's CIB (node list,
        resource list, groups). If "live" then use cibadmin.
        '''
        cib_elem = None
        cib_f = self.get_cib_loc()
        if cib_f:
            cib_elem = file2cib_elem(cib_f)
        if cib_elem is None:
            return  # no cib?
        try:
            conf = cib_elem.find("configuration")
        except:  # bad cib?
            return
        self.cibrsc_l = [x.get("id")
                         for x in conf.xpath("//resources//primitive")]
        self.cibgrp_d = {}
        for grp in conf.xpath("//resources/group"):
            self.cibgrp_d[grp.get("id")] = get_rsc_children_ids(grp)
        self.cibcln_d = {}
        self.cibcloned_l = []
        for cln in conf.xpath("//resources/clone") + \
                conf.xpath("//resources/master"):
            try:
                self.cibcln_d[cln.get("id")] = get_prim_children_ids(cln)
                self.cibcloned_l += self.cibcln_d[cln.get("id")]
            except:
                pass
        self.cibnotcloned_l = [x for x in self.cibrsc_l if x not in self.cibcloned_l]

    def _new_transition(self, transition):
        t_obj = self.find_transition(transition.get_node_file())
        if t_obj:
            common_debug("duplicate %s, replacing older PE file" % transition)
            self._transitions.remove(t_obj)
        common_debug("appending new PE %s" % transition)
        self._transitions.append(transition)

    def set_node_colors(self):
        i = 0
        for n in self.node_l:
            self.nodecolor[n] = self.nodecolors[i]
            i = (i+1) % len(self.nodecolors)

    def get_invoke_trans_msgs(self, msg_l):
        te_invoke_patt = transition_start_re("[0-9]+")
        return (x for x in msg_l if te_invoke_patt.search(x))

    def get_all_trans_msgs(self, msg_l=None):
        trans_re_l = (transition_start_re("[0-9]+"), transition_end_re("[0-9]+"))
        if msg_l is None:
            return self.logobj.get_matches(trans_re_l)
        else:
            return (x for x in msg_l if trans_re_l[0].search(x) or trans_re_l[1].search(x))

    def is_empty_transition(self, t0, t1):
        if not (t0 and t1):
            return False
        old_pe_l_file = self.pe_report_path(t0)
        new_pe_l_file = self.pe_report_path(t1)
        if not (os.path.isfile(old_pe_l_file) or os.path.isfile(new_pe_l_file)):
            return True
        num_actions = t1.actions_count()
        old_cib = compressed_file_to_cib(old_pe_l_file)
        new_cib = compressed_file_to_cib(new_pe_l_file)
        if old_cib is None or new_cib is None:
            return num_actions == 0
        prev_epoch = old_cib.attrib.get("epoch", "0")
        epoch = new_cib.attrib.get("epoch", "0")
        prev_admin_epoch = old_cib.attrib.get("admin_epoch", "0")
        admin_epoch = new_cib.attrib.get("admin_epoch", "0")
        return num_actions == 0 and epoch == prev_epoch and admin_epoch == prev_admin_epoch

    def list_transitions(self, msg_l=None, future_pe=False):
        '''
        List transitions by reading logs.
        Empty transitions are skipped.
        Some callers need original PE file path (future_pe),
        otherwise we produce the path within the report and check
        if the transition files exist.
        NB: future_pe means that the peinput has not been fetched yet.
        If the caller doesn't provide the message list, then we
        build it from the collected log files (self.logobj).
        Otherwise, we get matches for transition patterns.

        WARN: We rely here on the message format (syslog,
        pacemaker).
        '''
        trans_msg_l = self.get_all_trans_msgs(msg_l)
        trans_start_msg_l = self.get_invoke_trans_msgs(trans_msg_l)
        prev_transition = None
        for msg in trans_start_msg_l:
            transition_end_msg = find_transition_end_msg(msg, trans_msg_l)
            t_obj = Transition(msg, transition_end_msg)
            if self.is_empty_transition(prev_transition, t_obj):
                common_debug("skipping empty transition (%s)" % t_obj)
                continue
            self._set_transition_tags(t_obj)
            if not future_pe:
                pe_l_file = self.pe_report_path(t_obj)
                if not os.path.isfile(pe_l_file):
                    warn_once("%s in the logs, but not in the report" % t_obj)
                    continue
            common_debug("found PE input: %s" % t_obj)
            prev_transition = t_obj
            yield t_obj

    def _report_setup_source(self):
        constants.pcmk_version = None
        # is this an hb_report or a crm_report?
        for descname in ("description.txt", "report.summary"):
            self.desc = os.path.join(self.loc, descname)
            if os.path.isfile(self.desc):
                yr = os.stat(self.desc).st_mtime
                common_debug("Found %s, created %s" % (descname, yr))
                self._creation_time = time.strftime("%a %d %b %H:%M:%S %Z %Y",
                                                    time.localtime(yr))
                if descname == 'report.summary':
                    self._creator = "crm_report"
                else:
                    self._creator = 'unknown'
                set_year(yr)
                break
        else:
            self.error("Invalid report: No description found")
            return

        self.node_l = self.get_nodes()
        self.set_node_colors()
        self.log_l = self.find_logs()
        self.read_cib()

    def _report_setup_update(self):
        l = self.get_nodes()
        if self.node_l != l:
            self.node_l = l
            self.set_node_colors()
            self.log_l = self.find_logs()
            self.read_cib()

    def report_setup(self):
        if self.change_origin == 0:
            return False
        if not self.loc:
            return False

        if self.change_origin == CH_SRC:
            self._report_setup_source()
        elif self.change_origin == CH_UPD:
            self._report_setup_update()

        self.logobj = LogSyslog(self.log_l,
                                self.from_dt,
                                self.to_dt)

        if self.change_origin != CH_UPD:
            common_debug("getting transitions from logs")
            self._transitions = []
            for new_t_obj in self.list_transitions():
                self._new_transition(new_t_obj)

        self.ready = self.check_report()
        self.set_change_origin(0)

    def prepare_source(self, no_live_update=False):
        '''
        Unpack a report tarball.
        For "live", create an ad-hoc report and unpack it
        somewhere in the cache area.
        Parse the period.
        '''
        if not self.source:
            common_error("no source set yet")
            return False
        if self.ready and (no_live_update or self.source != "live"):
            return True
        if self.source == "live":
            self.loc = self.manage_live_report(no_live_update=no_live_update)
        elif os.path.isfile(self.source):
            self.loc = self.unpack_report(self.source)
        elif os.path.isdir(self.source):
            self.loc = self.source
        if not self.loc:
            return False
        self.report_setup()
        return self.ready

    def refresh_source(self, force=False):
        '''
        Refresh report from live.
        '''
        if self.source != "live":
            self.error("refresh not supported")
            return False
        self.last_live_update = 0
        self.loc = self.manage_live_report(force=force)
        self.report_setup()
        return self.ready

    def get_patt_l(self, type):
        '''
        get the list of patterns for this type, up to and
        including current detail level
        '''
        cib_f = None
        if self.source != "live":
            cib_f = self.get_cib_loc()
        if is_pcmk_118(cib_f=cib_f):
            from .log_patterns_118 import log_patterns
        else:
            from .log_patterns import log_patterns
        if type not in log_patterns:
            common_error("%s not featured in log patterns" % type)
            return None
        return log_patterns[type][0:self.detail+1]

    def build_re(self, type, args):
        '''
        Prepare a regex string for the type and args.
        For instance, "resource" and rsc1, rsc2, ...
        '''
        patt_l = self.get_patt_l(type)
        if not patt_l:
            return None
        if not args:
            re_l = mk_re_list(patt_l, "")
        else:
            re_l = mk_re_list(patt_l, r'(?:%s)' % "|".join(args))
        return re_l

    def _str_nodecolor(self, node, s):
        try:
            clr = self.nodecolor[node]
        except:
            return s
        try:
            return "${%s}%s${NORMAL}" % (clr, s)
        except:
            s = s.replace("${", "$.{")
            return "${%s}%s${NORMAL}" % (clr, s)

    def disp(self, s):
        'color output'
        node = syslog2node(s)
        if node is None:
            return s
        return self._str_nodecolor(node, s)

    def match_filter_out(self, s):
        for regexp in self.log_filter_out_re:
            if regexp.search(s):
                return True
        return False

    def display_logs(self, l):
        if self.log_filter_out_re:
            l = [x for x in l if not self.match_filter_out(x)]
        page_string('\n'.join([self.disp(x) for x in l]))

    def show_logs(self, log_l=None, re_l=[]):
        '''
        Print log lines, either matched by re_l or all.
        '''
        def process(r):
            return re.compile(r) if isinstance(r, basestring) else r
        if not log_l:
            log_l = self.log_l
        if not log_l:
            self.error("no logs found")
            return
        self.display_logs(self.logobj.get_matches([process(r) for r in re_l], log_l))

    def get_source(self):
        return self.source

    def get_desc_line(self, fld):
        try:
            f = open(self.desc)
        except IOError, msg:
            common_err("open %s: %s" % (self.desc, msg))
            return
        for s in f:
            if s.startswith("%s: " % fld):
                f.close()
                s = s.replace("%s: " % fld, "").rstrip()
                return s
        f.close()

    def short_peinputs_list(self):
        '''There could be quite a few transitions, limit the
        output'''
        max_output = 20
        s = ""
        if len(self._transitions) > max_output:
            s = "... "

        def fmt(t):
            if 'error' in t.tags:
                return self._str_nodecolor(t.dc, t.pe_num) + "*"
            return self._str_nodecolor(t.dc, t.pe_num)

        return "%s%s" % (s, ' '.join([fmt(x) for x in self._transitions[-max_output:]]))

    def get_rpt_dt(self, dt, whence):
        '''
        Figure out the time of the start/end of the report.
        The ts input is the time stamp set by user (it can be
        empty). whence is set either to "top" or "bottom".
        '''
        if dt:
            return dt
        try:
            if whence == "top":
                myts = min([syslog_ts(x) for x in first_log_lines(self.log_l)])
            elif whence == "bottom":
                myts = max([syslog_ts(x) for x in last_log_lines(self.log_l)])
            if myts:
                import dateutil.tz
                return make_datetime_naive(datetime.datetime.fromtimestamp(myts).replace(tzinfo=dateutil.tz.tzlocal()))
            common_debug("No log lines with timestamps found in report")
        except Exception, e:
            common_debug("Error: %s" % (e))
        return None

    def _str_dt(self, dt):
        return dt and human_date(dt) or "--/--/-- --:--:--"

    def info(self):
        '''
        Print information about the source.
        '''
        if not self.prepare_source():
            return False

        created_on = self.get_desc_line("Date") or self._creation_time
        created_by = self.get_desc_line("By") or self._creator

        page_string('\n'.join(("Source: %s" % self.source,
                               "Created on: %s" % (created_on),
                               "By: %s" % (created_by),
                               "Period: %s - %s" %
                               (self._str_dt(self.get_rpt_dt(self.from_dt, "top")),
                                self._str_dt(self.get_rpt_dt(self.to_dt, "bottom"))),
                               "Nodes: %s" % ' '.join([self._str_nodecolor(x, x)
                                                       for x in self.node_l]),
                               "Groups: %s" % ' '.join(self.cibgrp_d.keys()),
                               "Resources: %s" % ' '.join(self.cibrsc_l),
                               "Transitions: %s" % self.short_peinputs_list()
                               )))

    def events(self):
        '''
        Show all events.
        '''
        if not self.prepare_source():
            return False
        rsc_l = self.cibnotcloned_l
        rsc_l += ["%s(?::[0-9]+)?" % x for x in self.cibcloned_l]
        all_re_l = self.build_re("resource", rsc_l) + \
            self.build_re("node", self.node_l) + \
            self.build_re("events", [])
        if not all_re_l:
            self.error("no resources or nodes found")
            return False
        return self.show_logs(re_l=all_re_l)

    def find_transition(self, t_str):
        for t_obj in self._transitions:
            if t_obj.get_node_file() == t_str:
                return t_obj
        return None

    def show_transition_log(self, rpt_pe_file, full_log=False):
        '''
        Search for events within the given transition.
        '''
        if not self.prepare_source(no_live_update=self.prevent_live_update()):
            return False
        t_obj = self.find_transition(rpt_pe2t_str(rpt_pe_file))
        if not t_obj:
            common_err("%s: transition not found" % rpt_pe_file)
            return False
        # limit the log scope temporarily
        self.logobj.set_log_timeframe(t_obj.start_ts, t_obj.end_ts)
        if full_log:
            self.show_logs()
        else:
            t_obj.transition_info()
            self.events()
        self.logobj.set_log_timeframe(self.from_dt, self.to_dt)
        return True

    def show_transition_tags(self, rpt_pe_file):
        '''
        prints the tags for the transition
        '''
        t_obj = self.find_transition(rpt_pe2t_str(rpt_pe_file))
        if not t_obj:
            common_err("%s: transition not found" % rpt_pe_file)
            return False
        for tag in t_obj.tags:
            print tag
        return True

    def _set_transition_tags(self, transition):
        # limit the log scope temporarily
        self.logobj.set_log_timeframe(transition.start_ts, transition.end_ts)

        # search log, match regexes to tags
        regexes = [
            re.compile(r"(error|unclean)", re.I),
            re.compile(r"crmd.*notice:\s+Operation\s+([^:]+):\s+(?!ok)"),
        ]

        for l in self.logobj.get_matches(regexes):
            for rx in regexes:
                m = rx.search(l)
                if m:
                    transition.tags.add(m.group(1).lower())

        self.logobj.set_log_timeframe(self.from_dt, self.to_dt)

    def resource(self, *args):
        '''
        Show resource relevant logs.
        '''
        if not self.prepare_source(no_live_update=self.prevent_live_update()):
            return False
        # expand groups (if any)
        expanded_l = []
        for a in args:
            # add group members, groups aren't logged
            if a in self.cibgrp_d:
                expanded_l += self.cibgrp_d[a]
            # add group members, groups aren't logged
            elif a in self.cibcln_d:
                expanded_l += self.cibcln_d[a]
            else:
                expanded_l.append(a)
        exp_cloned_l = []
        for rsc in expanded_l:
            if rsc in self.cibcloned_l:
                exp_cloned_l.append("%s(?::[0-9]+)?" % rsc)
            else:
                exp_cloned_l.append(rsc)
        rsc_re_l = self.build_re("resource", exp_cloned_l)
        if not rsc_re_l:
            return False
        self.show_logs(re_l=rsc_re_l)

    def node(self, *args):
        '''
        Show node relevant logs.
        '''
        if not self.prepare_source(no_live_update=self.prevent_live_update()):
            return False
        node_re_l = self.build_re("node", args)
        if not node_re_l:
            return False
        self.show_logs(re_l=node_re_l)

    def log(self, *args):
        '''
        Show logs for a node or all nodes.
        '''
        if not self.prepare_source():
            return False
        if not args:
            self.show_logs()
        else:
            l = []
            for n in args:
                if n not in self.node_l:
                    self.warn("%s: no such node" % n)
                    continue
                l.append(self.find_node_log(n))
            if not l:
                return False
            self.show_logs(log_l=l)

    pe_details_header = "Date       Start    End       Filename      Client     User       Origin"
    pe_details_separator = "====       =====    ===       ========      ======     ====       ======"

    def pe_detail_format(self, t_obj):
        l = [
            shortdate(t_obj.start_ts),
            shorttime(t_obj.start_ts),
            t_obj.end_ts and shorttime(t_obj.end_ts) or "--:--:--",
            # the format string occurs also below
            self._str_nodecolor(t_obj.dc, '%-13s' % t_obj.shortname())
        ]
        l += get_cib_attributes(self.pe_report_path(t_obj), "cib",
                                ("update-client", "update-user", "update-origin"),
                                ("no-client", "no-user", "no-origin"))
        return '%s %s %s  %-13s %-10s %-10s %s' % tuple(l)

    def pelist(self, a=None, long=False):
        if not self.prepare_source(no_live_update=self.prevent_live_update()):
            return []
        if isinstance(a, (tuple, list)):
            if len(a) == 1:
                a.append(a[0])
        elif a is not None:
            a = [a, a]
        l = [long and self.pe_detail_format(t_obj) or self.pe_report_path(t_obj)
             for t_obj in self._transitions if pe_file_in_range(t_obj.pe_file, a)]
        if long:
            l = [self.pe_details_header, self.pe_details_separator] + l
        return l

    def dotlist(self, a=None):
        l = [x.replace("bz2", "dot") for x in self.pelist(a)]
        return [x for x in l if os.path.isfile(x)]

    def find_pe_files(self, path):
        'Find a PE or dot file matching part of the path.'
        pe_l = path.endswith(".dot") and self.dotlist() or self.pelist()
        return [x for x in pe_l if x.endswith(path)]

    def pe2dot(self, f):
        f = f.replace("bz2", "dot")
        if os.path.isfile(f):
            return f
        return None

    def find_file(self, f):
        return file_find_by_name(self.loc, f)

    def get_session_dir(self, name):
        try:
            return os.path.join(self.report_cache_dir, self.session_sub, name)
        except:
            return os.path.join(self.report_cache_dir, self.session_sub)
    state_file = 'history_state.cfg'
    rpt_section = 'report'

    def save_state(self, dir):
        '''
        Save the current history state. It should include:
        - directory
        - timeframe
        - detail
        TODO
        '''
        p = ConfigParser.SafeConfigParser()
        p.add_section(self.rpt_section)
        p.set(self.rpt_section, 'dir',
              self.source == "live" and dir or self.source)
        p.set(self.rpt_section, 'from_time',
              self.from_dt and human_date(self.from_dt) or '')
        p.set(self.rpt_section, 'to_time',
              self.to_dt and human_date(self.to_dt) or '')
        p.set(self.rpt_section, 'detail', str(self.detail))
        self.manage_excludes("save", p)
        fname = os.path.join(dir, self.state_file)
        try:
            f = open(fname, "wb")
        except IOError, msg:
            common_err(msg)
            return False
        p.write(f)
        f.close()
        return True

    def load_state(self, dir):
        '''
        Load the history state from a file.
        '''
        p = ConfigParser.SafeConfigParser()
        fname = os.path.join(dir, self.state_file)
        try:
            p.read(fname)
        except Exception, msg:
            common_err(msg)
            return False
        rc = True
        try:
            for n, v in p.items(self.rpt_section):
                if n == 'dir':
                    self.source = self.loc = v
                    if not os.path.exists(self.loc):
                        common_err("session state file %s points to a non-existing directory: %s" %
                                   (fname, self.loc))
                        rc = False
                elif n == 'from_time':
                    self.from_dt = v and parse_time(v) or None
                elif n == 'to_time':
                    self.to_dt = v and parse_time(v) or None
                elif n == 'detail':
                    self.detail = int(v)
                else:
                    common_warn("unknown item %s in the session state file %s" %
                                (n, fname))
            rc |= self.manage_excludes("load", p)
        except ConfigParser.NoSectionError, msg:
            common_err("session state file %s: %s" % (fname, msg))
            rc = False
        except Exception, msg:
            common_err("%s: bad value '%s' for '%s' in session state file %s" %
                       (msg, v, n, fname))
            rc = False
        if rc:
            self.set_change_origin(CH_SRC)
        return rc

    def set_change_origin(self, org):
        '''Set origin only to a smaller value (if current > 0).
        This prevents lesser change_origin overwriting a greater
        one.
        '''
        if self.change_origin == 0 or org < self.change_origin:
            self.change_origin = org

    def manage_session(self, subcmd, name):
        dir = self.get_session_dir(name)
        if subcmd == "save" and os.path.exists(dir):
            common_err("history session %s exists" % name)
            return False
        elif subcmd in ("load", "pack", "update", "delete") and not os.path.exists(dir):
            common_err("history session %s does not exist" % name)
            return False
        if subcmd == "save":
            if pipe_cmd_nosudo("mkdir -p %s" % dir) != 0:
                return False
            if self.source == "live":
                rc = pipe_cmd_nosudo("tar -C '%s' -c . | tar -C '%s' -x" %
                                     (self._live_loc(), dir))
                if rc != 0:
                    return False
            return self.save_state(dir)
        elif subcmd == "update":
            return self.save_state(dir)
        elif subcmd == "load":
            return self.load_state(dir)
        elif subcmd == "delete":
            rmdir_r(dir)
        elif subcmd == "list":
            ext_cmd("ls %s" % self.get_session_dir(None))
        elif subcmd == "pack":
            return mkarchive(dir)
        return True
    log_section = 'log'

    def manage_excludes(self, cmd, arg=None):
        '''Exclude messages from log files.
        arg: None (show, clear)
             regex (add)
             instance of ConfigParser.SafeConfigParser (load, save)
        '''
        if not self.prepare_source(no_live_update=True):
            return False
        rc = True
        if cmd == "show":
            print '\n'.join(self.log_filter_out)
        elif cmd == "clear":
            self.log_filter_out = []
            self.log_filter_out_re = []
        elif cmd == "add":
            try:
                regex = re.compile(arg)
                self.log_filter_out.append(arg)
                self.log_filter_out_re.append(regex)
            except Exception, msg:
                common_err("bad regex %s: %s" % (arg, msg))
                rc = False
        elif cmd == "save" and self.log_filter_out:
            arg.add_section(self.log_section)
            for i in range(len(self.log_filter_out)):
                arg.set(self.log_section, 'exclude_%d' % i,
                        self.log_filter_out[i])
        elif cmd == "load":
            self.manage_excludes("clear")
            try:
                for n, v in arg.items(self.log_section):
                    if n.startswith('exclude_'):
                        rc |= self.manage_excludes("add", v)
                    else:
                        common_warn("unknown item %s in the section %s" %
                                    (n, self.log_section))
            except ConfigParser.NoSectionError:
                pass
        return rc

# vim:ts=4:sw=4:et:
