# Copyright (C) 2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# 
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

import os
import sys
import time
import datetime
import copy
import re
import glob
import ConfigParser

from singletonmixin import Singleton
from userprefs import Options, UserPrefs
from cibconfig import CibFactory
from vars import Vars, getuser, gethomedir
from xmlutil import *
from utils import *
from msg import *
_NO_PSSH = False
try:
    from crm_pssh import next_loglines, next_peinputs
except:
    _NO_PSSH = True

#
# hb_report interface
#
# read hb_report generated report, show interesting stuff, search
# through logs, get PE input files, get log slices (perhaps even
# coloured nicely!)
#

def mk_re_list(patt_l,repl):
    'Build a list of regular expressions, replace "%%" with repl'
    l = []
    for re_l in patt_l:
        l += [ x.replace("%%",repl) for x in re_l ]
    if not repl:
        l = [ x.replace(".*.*",".*") for x in l ]
    return l


def set_year(ts = None):
    global YEAR
    YEAR = time.strftime("%Y", time.localtime(ts))
    common_debug("setting year to %s (ts: %s)" % (YEAR, str(ts)))

def syslog_ts(s):
    global YEAR
    try:
        # strptime defaults year to 1900 (sigh)
        tm = time.strptime(' '.join([YEAR] + s.split()[0:3]),"%Y %b %d %H:%M:%S")
        return time.mktime(tm)
    except:
        common_debug("malformed line: %s" % s)
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
                f.seek(0) # otherwise, the seek below throws an exception
                if beg > 0: # avoid infinite loop
                    return # goes all the way to the top
                beg += 1
            else:
                f.seek(-1000, 1) # go back 10 or so lines
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

def log_seek(f, ts, to_end = False):
    '''
    f is an open log. Do binary search for the timestamp.
    Return the position of the (more or less) first line with an
    earlier (or later) time.
    '''
    first = 0
    f.seek(0,2)
    last = f.tell()
    if not ts:
        return to_end and last or first
    badline = 0
    maxbadline = 10
    common_debug("seek %s:%s in %s" %
        (time.ctime(ts), to_end and "end" or "start", f.name))
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
            first += 120 # move forward a bit
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
    step = 30 # no line should be longer than 30
    cnt = 1
    current_pos = f.tell()
    s = f.readline()
    if not s: # EOF?
        f.seek(-step, 1) # backup a bit
        current_pos = f.tell()
        s = f.readline()
    while s and current_pos < f.tell():
        if cnt*step >= f.tell(): # at 0?
            f.seek(0)
            break
        f.seek(-cnt*step, 1)
        s = f.readline()
        cnt += 1
    pos = f.tell() # save the position ...
    s = f.readline() # get the line
    f.seek(pos) # ... and move the cursor back there
    if not s: # definitely EOF (probably cannot happen)
        return None
    return syslog_ts(s)

def is_our_log(s, node_l):
    try: return s.split()[3] in node_l
    except: return False
def log2node(log):
    return os.path.basename(os.path.dirname(log))
def filter(sl, log_l):
    '''
    Filter list of messages to get only those from the given log
    files list.
    '''
    node_l = [log2node(x) for x in log_l if x]
    return [x for x in sl if is_our_log(x, node_l)]
def first_log_lines(log_l):
    '''
    Return a list of all first lines of the logs.
    '''
    f_list = [ open(x) for x in log_l if x ]
    l = [ x.readline().rstrip() for x in f_list if x ]
    junk = [ x.close() for x in f_list if x ]
    return l
def last_log_lines(log_l):
    '''
    Return a list of all last lines of the logs.
    '''
    f_list = [ open(x) for x in log_l if x ]
    l = [ x.readlines()[-1].rstrip() for x in f_list if x ]
    junk = [ x.close() for x in f_list if x ]
    return l
def convert_dt(dt):
    try: return time.mktime(dt.timetuple())
    except: return None

class LogSyslog(object):
    '''
    Slice log, search log.
    '''
    def __init__(self, central_log, log_l, from_dt, to_dt):
        self.log_l = log_l
        self.central_log = central_log
        self.f = {}
        self.startpos = {}
        self.endpos = {}
        self.cache = {}
        self.open_logs()
        self.set_log_timeframe(from_dt, to_dt)
    def open_log(self, log):
        import bz2, gzip
        try:
            if log.endswith(".bz2"):
                self.f[log] = bz2.BZ2File(log)
            elif log.endswith(".gz"):
                self.f[log] = gzip.open(log)
            else:
                self.f[log] = open(log)
        except IOError,msg:
            common_err("open %s: %s"%(log,msg))
    def open_logs(self):
        if self.central_log:
            common_debug("opening central log %s" % self.central_log)
            self.open_log(self.central_log)
        else:
            for log in self.log_l:
                common_debug("opening log %s" % log)
                self.open_log(log)
    def set_log_timeframe(self, from_dt, to_dt):
        '''
        Convert datetime to timestamps (i.e. seconds), then
        find out start/end file positions. Logs need to be
        already open.
        '''
        if isinstance(from_dt, datetime.datetime):
            self.from_ts = convert_dt(from_dt)
            self.to_ts = convert_dt(to_dt)
        else:
            self.from_ts = from_dt
            self.to_ts = to_dt
        bad_logs = []
        for log in self.f:
            f = self.f[log]
            start = log_seek(f, self.from_ts)
            end = log_seek(f, self.to_ts, to_end = True)
            if start == -1 or end == -1:
                bad_logs.append(log)
            else:
                self.startpos[f] = start
                self.endpos[f] = end
        for log in bad_logs:
            del self.f[log]
            self.log_l.remove(log)
    def get_match_line(self, f, patt):
        '''
        Get first line from f that matches re_s, but is not
        behind endpos[f].
        '''
        while f.tell() < self.endpos[f]:
            fpos = f.tell()
            s = f.readline().rstrip()
            if not patt or patt.search(s):
                return s,fpos
        return '',-1
    def single_log_list(self, f, patt):
        l = []
        while True:
            s = self.get_match_line(f, patt)[0]
            if not s:
                return l
            l.append(s)
        return l
    def search_logs(self, log_l, re_s = ''):
        '''
        Search logs for re_s and sort by time.
        '''
        patt = None
        if re_s:
            patt = re.compile(re_s)
        # if there's central log, there won't be merge
        if self.central_log:
            fl = [ self.f[f] for f in self.f ]
        else:
            fl = [ self.f[f] for f in self.f if self.f[f].name in log_l ]
        for f in fl:
            f.seek(self.startpos[f])
        # get head lines of all nodes
        top_line = [ self.get_match_line(x, patt)[0] for x in fl ]
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
            del fl[i],top_line[i]
        common_debug("search <%s> in %s" % (re_s, [ f.name for f in fl ]))
        if len(fl) == 0: # nothing matched ?
            return []
        if len(fl) == 1:
            # no need to merge if there's only one log
            return [top_line[0]] + self.single_log_list(fl[0],patt)
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
                except: pass
            if not top_line[first]:
                break
            l.append(top_line[first])
            top_line[first] = self.get_match_line(fl[first], patt)[0]
            if not top_line[first]:
                top_line_ts[first] = time.time()
            else:
                top_line_ts[first] = syslog_ts(top_line[first])
        return l
    def get_matches(self, re_l, log_l = None):
        '''
        Return a list of log messages which
        match one of the regexes in re_l.
        '''
        if not log_l:
            log_l = self.log_l
        re_s = '|'.join(re_l)
        return filter(self.search_logs(log_l, re_s), log_l)
        # caching is not ready!
        # gets complicated because of different time frames
        # (TODO)
        #if not re_s: # just list logs
        #    return filter(self.search_logs(log_l), log_l)
        #if re_s not in self.cache: # cache regex search
        #    self.cache[re_s] = self.search_logs(log_l, re_s)
        #return filter(self.cache[re_s], log_l)

def human_date(dt):
    'Some human date representation. Date defaults to now.'
    if not dt:
        dt = datetime.datetime.now()
    # drop microseconds
    return re.sub("[.].*","","%s %s" % (dt.date(),dt.time()))

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
        logf,pos = s.split()
        return logf, int(pos)
    except:
        warn_once("hb_report too old, you need to update cluster-glue")
        return '',-1

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

def extract_pe_file(msg):
    msg_a = msg.split()
    if len(msg_a) < 8:
        # this looks too short
        common_warn("log message <%s> unexpected format, please report a bug" % msg)
        return ""
    return msg_a[-1]
def extract_node(msg):
    msg_a = msg.split()
    if len(msg_a) < 8:
        # this looks too short
        common_warn("log message <%s> unexpected format, please report a bug" % msg)
        return ""
    return msg_a[3]

def get_matching_run_msg(te_invoke_msg, trans_msg_l):
    run_msg = ""
    pe_file = extract_pe_file(te_invoke_msg)
    pe_num = get_pe_num(pe_file)
    if pe_num == "-1":
        common_warn("%s: strange, transition number not found" % pe_file)
        return ""
    run_patt = vars.transition_patt[1].replace("%%", pe_num)
    for msg in trans_msg_l:
        if re.search(run_patt, msg):
            run_msg = msg
            break
    return run_msg

def trans_str(node, pe_file):
    '''Convert node,pe_file to transition sting.'''
    return "%s:%s" % (node, os.path.basename(pe_file).replace(".bz2",""))
def rpt_pe2t_str(rpt_pe_file):
    '''Convert report's pe_file path to transition sting.'''
    node = os.path.basename(os.path.dirname(os.path.dirname(rpt_pe_file)))
    return trans_str(node, rpt_pe_file)
class Transition(object):
    '''
    Capture transition related information.
    '''
    def __init__(self, te_invoke_msg, run_msg):
        self.te_invoke_msg = te_invoke_msg
        self.run_msg = run_msg
        self.parse_msgs()
    def __str__(self):
        return trans_str(self.dc, self.pe_file)
    def parse_msgs(self):
        self.pe_file = extract_pe_file(self.te_invoke_msg)
        self.pe_num = get_pe_num(self.pe_file)
        self.dc = extract_node(self.te_invoke_msg)
        self.start_ts = syslog_ts(self.te_invoke_msg)
        if self.run_msg:
            self.end_ts = syslog_ts(self.run_msg)
        else:
            common_warn("end of transition %s not found in logs (transition not complete yet?)" % self)
            self.end_ts = time.time()
    def actions_count(self):
        if self.run_msg:
            act_d = run_graph_msg_actions(self.run_msg)
            return sum(act_d.values())
        else:
            return -1
    def shortname(self):
        return os.path.basename(self.pe_file).replace(".bz2","")
    def transition_info(self):
        print "Transition %s (%s -" % (self, shorttime(self.start_ts)),
        if self.run_msg:
            print "%s):" % shorttime(self.end_ts)
            act_d = run_graph_msg_actions(self.run_msg)
            total = sum(act_d.values())
            s = ", ".join(["%d %s" % (act_d[x], x) for x in act_d if act_d[x]])
            print "\ttotal %d actions: %s" % (total, s)
        else:
            print "[unfinished])"

def mkarchive(dir):
    "Create an archive from a directory"
    home = gethomedir()
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
class Report(Singleton):
    '''
    A hb_report class.
    '''
    live_recent = 6*60*60 # recreate live hb_report once every 6 hours
    short_live_recent = 60 # update once a minute
    nodecolors = (
    "NORMAL", "GREEN", "CYAN", "MAGENTA", "YELLOW", "WHITE", "BLUE", "RED"
    )
    session_sub = "session"
    outdir = os.path.join(vars.report_cache, "psshout")
    errdir = os.path.join(vars.report_cache, "pssherr")
    def __init__(self):
        # main source attributes
        self.source = None
        self.from_dt = None
        self.to_dt = None
        self.log_l = []
        self.central_log = None
        self.setnodes = [] # optional
        # derived
        self.loc = None
        self.ready = False
        self.nodecolor = {}
        self.logobj = None
        self.desc = None
        self.peinputs_l = []
        self.cibgrp_d = {}
        self.cibcln_d = {}
        self.cibrsc_l = []
        self.cibnotcloned_l = []
        self.cibcloned_l = []
        self.cibnode_l = []
        self.last_live_update = 0
        self.detail = 0
        self.log_filter_out = []
        self.log_filter_out_re = []
        # change_origin may be CH_SRC, CH_TIME, CH_UPD
        # depending on the change_origin, we update our attributes
        self.change_origin = CH_SRC
        set_year()
    def error(self, s):
        common_err("%s: %s" % (self.source, s))
    def warn(self, s):
        common_warn("%s: %s" % (self.source, s))
    def rsc_list(self):
        return self.cibgrp_d.keys() + self.cibcln_d.keys() + self.cibnotcloned_l
    def node_list(self):
        return self.cibnode_l
    def peinputs_list(self):
        return [x.pe_num for x in self.peinputs_l]
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
        common_debug("tarball: %s, in dir: %s" % (bfname,parentdir))
        if bfname.endswith(".tar.bz2"):
            loc = tarball.replace(".tar.bz2","")
            tar_unpack_option = "j"
        elif bfname.endswith(".tar.gz"): # hmm, must be ancient
            loc = tarball.replace(".tar.gz","")
            tar_unpack_option = "z"
        else:
            self.error("this doesn't look like a report tarball")
            return None
        self.set_change_origin(CH_SRC)
        if os.path.isdir(loc):
            return loc
        cwd = os.getcwd()
        if parentdir:
            try:
                os.chdir(parentdir)
            except OSError,msg:
                self.error(msg)
                return None
        import tarfile
        try:
            tf = tarfile.open(bfname)
            tf_loc = tf.getmembers()[0].name
            if tf_loc != loc:
                common_debug("top directory in tarball: %s, doesn't match the tarball name: %s" % (tf_loc,loc))
                loc = os.path.join(os.path.dirname(loc), tf_loc)
        except Exception, msg:
            common_err("%s: %s" % (tarball, msg))
            return None
        common_debug("tar -x%s < %s" % (tar_unpack_option,bfname))
        rc = pipe_cmd_nosudo("tar -x%s < %s" % (tar_unpack_option,bfname))
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
        return pe_file.replace("%s/" % self.loc,"")
    def get_nodes(self):
        return [ os.path.basename(p)
            for p in os.listdir(self.loc)
                if os.path.isdir(os.path.join(self.loc, p)) and
                os.path.isfile(os.path.join(self.loc, p, "cib.txt"))
        ]
    def check_nodes(self):
        'Verify if the nodes in cib match the nodes in the report.'
        nl = self.get_nodes()
        if not nl:
            self.error("no nodes in report")
            return False
        for n in self.cibnode_l:
            if not (n in nl):
                self.warn("node %s not in report" % n)
            else:
                nl.remove(n)
        if nl:
            self.warn("strange, extra node(s) %s in report" % ','.join(nl))
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
        return os.path.join(vars.report_cache,"live")
    def is_live_recent(self):
        '''
        Look at the last live hb_report. If it's recent enough,
        return True.
        '''
        try:
            last_ts = os.stat(self.desc).st_mtime
            return (time.time() - last_ts <= self.live_recent)
        except:
            return False
    def is_live_very_recent(self):
        '''
        Look at the last live hb_report. If it's recent enough,
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
        for lf in ("ha-log.txt", "messages"):
            if is_log(os.path.join(p, lf)):
                return os.path.join(p, lf)
        return None
    def find_central_log(self):
        'Return common log, if found.'
        central_log = os.path.join(self.loc, "ha-log.txt")
        if is_log(central_log):
            logf, pos = read_log_info(central_log)
            if logf == '':
                # assume it's not a central log (we don't
                # know really)
                return
            if logf.startswith("synthetic"):
                # not central log
                return
            common_debug("found central log %s" % logf)
            self.central_log = central_log
    def find_logs(self):
        'Return a list of logs found (one per node).'
        l = []
        for node in self.get_nodes():
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
        for node,rptlog,logfile,nextpos in a:
            fl = glob.glob("%s/*%s*" % (self.outdir,node))
            if not fl:
                continue
            append_file(rptlog,fl[0])
            update_loginfo(rptlog, logfile, nextpos, fl[0])
    def unpack_new_peinputs(self, node, pe_l):
        '''
        Untar PE inputs fetched from nodes.
        '''
        if not os.path.isdir(self.outdir):
            return
        fl = glob.glob("%s/*%s*" % (self.outdir,node))
        if not fl:
            return -1
        u_dir = os.path.join(self.loc, node)
        return pipe_cmd_nosudo("tar -C %s -x < %s" % (u_dir,fl[0]))
    def read_new_log(self, node):
        '''
        Get a list of log lines.
        The log is put in self.outdir/node by pssh.
        '''
        if not os.path.isdir(self.outdir):
            return []
        fl = glob.glob("%s/*%s*" % (self.outdir,node))
        if not fl:
            return []
        try:
            f = open(fl[0])
        except IOError,msg:
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
                self.new_peinput(new_t_obj)
                pe_l.append(new_t_obj.pe_file)
            if pe_l:
                node_pe_l.append([node, pe_l])
        rmdir_r(self.outdir)
        rmdir_r(self.errdir)
        if not node_pe_l:
            return rc1
        rc2 = next_peinputs(node_pe_l, self.outdir, self.errdir)
        unpack_rc = 0
        for node,pe_l in node_pe_l:
            unpack_rc |= self.unpack_new_peinputs(node, pe_l)
        rc2 |= (unpack_rc == 0)
        rmdir_r(self.outdir)
        rmdir_r(self.errdir)
        return (rc1 and rc2)
    def get_live_report(self):
        if not acquire_lock(vars.report_cache):
            return None
        loc = self.new_live_report()
        release_lock(vars.report_cache)
        return loc
    def manage_live_report(self, force=False, no_live_update=False):
        '''
        Update or create live report.
        '''
        d = self._live_loc()
        if not d or not os.path.isdir(d):
            return self.get_live_report()
        if not self.loc:
            # the live report is there, but we were just invoked
            self.loc = d
            self.report_setup()
        if not force and self.is_live_recent():
            # try just to refresh the live report
            if self.to_dt or self.is_live_very_recent() or no_live_update:
                return self._live_loc()
            if not _NO_PSSH:
                if not acquire_lock(vars.report_cache):
                    return None
                rc = self.update_live_report()
                release_lock(vars.report_cache)
                if rc:
                    self.set_change_origin(CH_UPD)
                    return self._live_loc()
            else:
                warn_once("pssh not installed, slow live updates ahead")
        return self.get_live_report()
    def new_live_report(self):
        '''
        Run hb_report to get logs now.
        '''
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
        common_info("retrieving information from cluster nodes, please wait ...")
        rc = pipe_cmd_nosudo("hb_report -Z -f '%s' %s %s %s" %
                (self.from_dt.ctime(), to_option, nodes_option, d))
        if rc != 0:
            if os.path.isfile(tarball):
                self.warn("hb_report thinks it failed, proceeding anyway")
            else:
                self.error("hb_report failed")
                return None
        self.last_live_update = time.time()
        return self.unpack_report(tarball)
    def set_source(self,src):
        'Set our source.'
        if self.source != src:
            self.set_change_origin(CH_SRC)
            self.source = src
            self.ready = False
    def set_period(self,from_dt,to_dt):
        '''
        Set from/to_dt.
        '''
        common_debug("setting report times: <%s> - <%s>" % (from_dt,to_dt))
        need_refresh = (self.source == "live") and self.ready and \
            (from_dt and self.get_rpt_dt(None, "top") > from_dt)
        self.from_dt = from_dt
        self.to_dt = to_dt
        if need_refresh:
            self.set_change_origin(CH_UPD)
            self.refresh_source(force = True)
        else:
            self.set_change_origin(CH_TIME)
            self.report_setup()
        return True
    def set_detail(self,detail_lvl):
        '''
        Set the detail level.
        '''
        self.detail = int(detail_lvl)
    def set_nodes(self,*args):
        '''
        Allow user to set the node list (necessary if the host is
        not part of the cluster).
        '''
        self.setnodes = args
    def get_cib_loc(self):
        nl = self.get_nodes()
        if not nl:
            return ""
        return os.path.join(self.loc, nl[0], "cib.xml")
    def read_cib(self):
        '''
        Get some information from the report's CIB (node list,
        resource list, groups). If "live" and not central log,
        then use cibadmin.
        '''
        doc = None
        cib_f = self.get_cib_loc()
        if cib_f:
            doc = file2doc(cib_f)
        if not doc:
            return  # no cib?
        try: conf = doc.getElementsByTagName("configuration")[0]
        except: # bad cib?
            return
        self.cibrsc_l = [ x.getAttribute("id")
            for x in conf.getElementsByTagName("primitive") ]
        self.cibnode_l = [ x.getAttribute("uname")
            for x in conf.getElementsByTagName("node") ]
        self.cibgrp_d = {}
        for grp in conf.getElementsByTagName("group"):
            self.cibgrp_d[grp.getAttribute("id")] = get_rsc_children_ids(grp)
        self.cibcln_d = {}
        self.cibcloned_l = []
        for cln in conf.getElementsByTagName("clone") + \
                conf.getElementsByTagName("master"):
            try:
                self.cibcln_d[cln.getAttribute("id")] = get_prim_children_ids(cln)
                self.cibcloned_l += self.cibcln_d[cln.getAttribute("id")]
            except: pass
        self.cibnotcloned_l = [x for x in self.cibrsc_l if x not in self.cibcloned_l]
    def new_peinput(self, new_pe):
        t_obj = self.find_peinput(str(new_pe))
        if t_obj:
            common_debug("duplicate %s, replacing older PE file" % t_obj)
            self.peinputs_l.remove(t_obj)
        common_debug("appending new PE %s" % new_pe)
        self.peinputs_l.append(new_pe)
    def set_node_colors(self):
        i = 0
        for n in self.cibnode_l:
            self.nodecolor[n] = self.nodecolors[i]
            i = (i+1) % len(self.nodecolors)
    def get_invoke_trans_msgs(self, msg_l):
        te_invoke_patt = vars.transition_patt[0].replace("%%", "[0-9]+")
        return [x for x in msg_l if re.search(te_invoke_patt, x)]
    def get_all_trans_msgs(self, msg_l=None):
        trans_re_l = [x.replace("%%", "[0-9]+") for x in vars.transition_patt]
        if not msg_l:
            return self.logobj.get_matches(trans_re_l)
        else:
            re_s = '|'.join(trans_re_l)
            return [x for x in msg_l if re.search(re_s, x)]
    def list_transitions(self, msg_l = None, future_pe = False):
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
        for msg in trans_start_msg_l:
            run_msg = get_matching_run_msg(msg, trans_msg_l)
            t_obj = Transition(msg, run_msg)
            num_actions = t_obj.actions_count()
            if num_actions == 0: # empty transition
                common_debug("skipping empty transition (%s)" % t_obj)
                continue
            if not future_pe:
                pe_l_file = self.pe_report_path(t_obj)
                if not os.path.isfile(pe_l_file):
                    warn_once("%s in the logs, but not in the report" % t_obj)
                    continue
            common_debug("found PE input: %s" % t_obj)
            yield t_obj
    def report_setup(self):
        if not self.change_origin:
            return
        if not self.loc:
            return
        if self.change_origin == CH_SRC:
            vars.pcmk_version = None
            self.desc = os.path.join(self.loc,"description.txt")
            set_year(os.stat(self.desc).st_mtime)
            self.log_l = self.find_logs()
            self.find_central_log()
            self.read_cib()
            self.set_node_colors()
        elif self.change_origin == CH_UPD:
            l = self.find_logs()
            if self.log_l != l:
                self.log_l = l
                self.read_cib()
                self.set_node_colors()
        self.logobj = LogSyslog(self.central_log, self.log_l, \
                self.from_dt, self.to_dt)
        if self.change_origin != CH_UPD:
            common_debug("getting transitions from logs")
            self.peinputs_l = []
            for new_t_obj in self.list_transitions():
                self.new_peinput(new_t_obj)
        self.ready = self.check_report()
        self.set_change_origin(0)
    def prepare_source(self, no_live_update=False):
        '''
        Unpack a hb_report tarball.
        For "live", create an ad-hoc hb_report and unpack it
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
    def get_patt_l(self,type):
        '''
        get the list of patterns for this type, up to and
        including current detail level
        '''
        cib_f = None
        if self.source != "live" or self.central_log:
            cib_f = self.get_cib_loc()
        if is_pcmk_118(cib_f=cib_f):
            from log_patterns_118 import log_patterns
        else:
            from log_patterns import log_patterns
        if not type in log_patterns:
            common_error("%s not featured in log patterns" % type)
            return None
        return log_patterns[type][0:self.detail+1]
    def build_re(self,type,args):
        '''
        Prepare a regex string for the type and args.
        For instance, "resource" and rsc1, rsc2, ...
        '''
        patt_l = self.get_patt_l(type)
        if not patt_l:
            return None
        if not args:
            re_l = mk_re_list(patt_l,"")
        else:
            re_l = mk_re_list(patt_l,r'(%s)' % "|".join(args))
        return re_l
    def _str_nodecolor(self, node, s):
        try: clr = self.nodecolor[node]
        except: return s
        try:
            return "${%s}%s${NORMAL}" % (clr,s)
        except:
            s = s.replace("${","$.{")
            return "${%s}%s${NORMAL}" % (clr,s)
    def disp(self, s):
        'color output'
        a = s.split()
        try: node = a[3]
        except: return s
        return self._str_nodecolor(node, s)
    def match_filter_out(self, s):
        for re in self.log_filter_out_re:
            if re.search(s):
                return True
        return False
    def display_logs(self, l):
        if self.log_filter_out_re:
            l = [x for x in l if not self.match_filter_out(x)]
        page_string('\n'.join([ self.disp(x) for x in l ]))
    def show_logs(self, log_l = None, re_l = []):
        '''
        Print log lines, either matched by re_l or all.
        '''
        if not log_l:
            log_l = self.log_l
        if not self.central_log and not log_l:
            self.error("no logs found")
            return
        self.display_logs(self.logobj.get_matches(re_l, log_l))
    def get_source(self):
        return self.source
    def get_desc_line(self,fld):
        try:
            f = open(self.desc)
        except IOError,msg:
            common_err("open %s: %s"%(self.desc,msg))
            return
        for s in f:
            if s.startswith("%s: " % fld):
                f.close()
                s = s.replace("%s: " % fld,"").rstrip()
                return s
        f.close()
    def dumpdescln(self, pfx, field):
        s = self.get_desc_line(field)
        if s:
            return "%s: %s" % (pfx, s)
    def short_peinputs_list(self):
        '''There could be quite a few transitions, limit the
        output'''
        max_output = 20
        s = ""
        if len(self.peinputs_l) > max_output:
            s = "... "
        return "%s%s" % (s, \
            ' '.join([self._str_nodecolor(x.dc, x.pe_num) \
                for x in self.peinputs_l[-max_output:]]))
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
            return datetime.datetime.fromtimestamp(myts)
        except:
            return None
    def _str_dt(self, dt):
        return dt and human_date(dt) or "--/--/-- --:--:--"
    def info(self):
        '''
        Print information about the source.
        '''
        if not self.prepare_source():
            return False
        page_string('\n'.join((
        "Source: %s" % self.source,
        self.dumpdescln("Created on", "Date") or "Created on: --:--:--",
        self.dumpdescln("By", "By") or "By: unknown",
        "Period: %s - %s" % \
            (self._str_dt(self.get_rpt_dt(self.from_dt, "top")), \
            self._str_dt(self.get_rpt_dt(self.to_dt, "bottom"))),
        "Nodes: %s" % ' '.join([ self._str_nodecolor(x, x) \
            for x in self.cibnode_l ]),
        "Groups: %s" % ' '.join(self.cibgrp_d.keys()),
        "Resources: %s" % ' '.join(self.cibrsc_l),
        "Transitions: %s" % self.short_peinputs_list(),
        )))
    def events(self):
        '''
        Show all events.
        '''
        rsc_l = self.cibnotcloned_l
        rsc_l += ["%s(:[0-9]+)?" % x for x in self.cibcloned_l]
        all_re_l = self.build_re("resource", rsc_l) + \
            self.build_re("node", self.cibnode_l) + \
            self.build_re("events", [])
        if not all_re_l:
            self.error("no resources or nodes found")
            return False
        self.show_logs(re_l = all_re_l)
    def find_peinput(self, t_str):
        for t_obj in self.peinputs_l:
            if str(t_obj) == t_str:
                return t_obj
        return None
    def show_transition_log(self, rpt_pe_file, full_log=False):
        '''
        Search for events within the given transition.
        '''
        if not self.prepare_source(no_live_update=self.prevent_live_update()):
            return False
        t_obj = self.find_peinput(rpt_pe2t_str(rpt_pe_file))
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
    def resource(self,*args):
        '''
        Show resource relevant logs.
        '''
        if not self.prepare_source(no_live_update=self.prevent_live_update()):
            return False
        # expand groups (if any)
        expanded_l = []
        for a in args:
            if a in self.cibgrp_d: # add group members, groups aren't logged
                expanded_l += self.cibgrp_d[a]
            elif a in self.cibcln_d: # add group members, groups aren't logged
                expanded_l += self.cibcln_d[a]
            else:
                expanded_l.append(a)
        exp_cloned_l = []
        for rsc in expanded_l:
            if rsc in self.cibcloned_l:
                exp_cloned_l.append("%s(:[0-9]+)?" % rsc)
            else:
                exp_cloned_l.append(rsc)
        rsc_re_l = self.build_re("resource", exp_cloned_l)
        if not rsc_re_l:
            return False
        self.show_logs(re_l = rsc_re_l)
    def node(self,*args):
        '''
        Show node relevant logs.
        '''
        if not self.prepare_source(no_live_update=self.prevent_live_update()):
            return False
        node_re_l = self.build_re("node",args)
        if not node_re_l:
            return False
        self.show_logs(re_l = node_re_l)
    def log(self,*args):
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
                if n not in self.cibnode_l:
                    self.warn("%s: no such node" % n)
                    continue
                l.append(self.find_node_log(n))
            if not l:
                return False
            self.show_logs(log_l = l)
    pe_details_header = \
"Date       Start    End       Filename      Client     User       Origin"
    pe_details_separator = \
"====       =====    ===       ========      ======     ====       ======"
    def pe_detail_format(self, t_obj):
        l = [
            shortdate(t_obj.start_ts),
            shorttime(t_obj.start_ts),
            t_obj.end_ts and shorttime(t_obj.end_ts) or "--:--:--",
            # the format string occurs also below
            self._str_nodecolor(t_obj.dc, '%-13s' % t_obj.shortname())
        ]
        l += get_cib_attributes(self.pe_report_path(t_obj), "cib", \
            ("update-client", "update-user", "update-origin"), \
            ("no-client", "no-user", "no-origin"))
        return '%s %s %s  %-13s %-10s %-10s %s' % tuple(l)
    def pelist(self, a=None, long=False):
        if not self.prepare_source(no_live_update=self.prevent_live_update()):
            return []
        if isinstance(a,(tuple,list)):
            if len(a) == 1:
                a.append(a[0])
        elif a is not None:
            a = [a,a]
        l = [ long and self.pe_detail_format(x) or self.pe_report_path(x)
            for x in self.peinputs_l if pe_file_in_range(x.pe_file, a) ]
        if long:
            l = [self.pe_details_header, self.pe_details_separator] + l
        return l
    def dotlist(self, a = None):
        l = [x.replace("bz2","dot") for x in self.pelist(a)]
        return [x for x in l if os.path.isfile(x)]
    def find_pe_files(self, path):
        'Find a PE or dot file matching part of the path.'
        pe_l = path.endswith(".dot") and self.dotlist() or self.pelist()
        return [x for x in pe_l if x.endswith(path)]
    def pe2dot(self, f):
        f = f.replace("bz2","dot")
        if os.path.isfile(f):
            return f
        return None
    def find_file(self, f):
        return file_find_by_name(self.loc, f)
    def get_session_dir(self, name):
        try:
            return os.path.join(vars.report_cache, self.session_sub, name)
        except:
            return os.path.join(vars.report_cache, self.session_sub)
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
        p.set(self.rpt_section, 'dir', \
            self.source == "live" and dir or self.source)
        p.set(self.rpt_section, 'from_time', \
            self.from_dt and human_date(self.from_dt) or '')
        p.set(self.rpt_section, 'to_time', \
            self.to_dt and human_date(self.to_dt) or '')
        p.set(self.rpt_section, 'detail', str(self.detail))
        self.manage_excludes("save", p)
        fname = os.path.join(dir, self.state_file)
        try:
            f = open(fname,"wb")
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
                        common_err("session state file %s points to a "
                            "non-existing directory: %s" % (fname, self.loc))
                        rc = False
                elif n == 'from_time':
                    self.from_dt = v and parse_time(v) or None
                elif n == 'to_time':
                    self.to_dt = v and parse_time(v) or None
                elif n == 'detail':
                    self.detail = int(v)
                else:
                    common_warn("unknown item %s in the "
                        "session state file %s" % (n, fname))
            rc |= self.manage_excludes("load", p)
        except ConfigParser.NoSectionError, msg:
            common_err("session state file %s: %s" % (fname, msg))
            rc = False
        except Exception, msg:
            common_err("%s: bad value '%s' for '%s' in "
                "session state file %s" % (msg, v, n, fname))
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
                rc = pipe_cmd_nosudo("tar -C '%s' -c . | tar -C '%s' -x" % \
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
            if self.source != "live":
                common_err("only live sessions can be packed")
                return False
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
            except Exception,msg:
                common_err("bad regex %s: %s" % (arg, msg))
                rc = False
        elif cmd == "save" and self.log_filter_out:
            arg.add_section(self.log_section)
            for i in range(len(self.log_filter_out)):
                arg.set(self.log_section, 'exclude_%d' % i, \
                    self.log_filter_out[i])
        elif cmd == "load":
            self.manage_excludes("clear")
            try:
                for n, v in arg.items(self.log_section):
                    if n.startswith('exclude_'):
                        rc |= self.manage_excludes("add", v)
                    else:
                        common_warn("unknown item %s in the "
                            "section %s" % (n, self.log_section))
            except ConfigParser.NoSectionError:
                pass
        return rc

vars = Vars.getInstance()
options = Options.getInstance()
cib_factory = CibFactory.getInstance()
crm_report = Report.getInstance()
# vim:ts=4:sw=4:et:
