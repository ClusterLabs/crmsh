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

from singletonmixin import Singleton
from userprefs import Options, UserPrefs
from cibconfig import CibFactory
from vars import Vars, getuser
from term import TerminalController
from xmlutil import *
from utils import *
from msg import *
from log_patterns import log_patterns
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

YEAR = time.strftime("%Y")
def syslog_ts(s):
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
def convert_dt(dt):
    try: return time.mktime(dt.timetuple())
    except: return None

class LogSyslog(object):
    '''
    Slice log, search log.
    self.fp is an array of dicts.
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
        try:
            self.f[log] = open(log)
        except IOError,msg:
            common_err("open %s: %s"%(log,msg))
    def open_logs(self):
        if self.central_log:
            self.open_log(self.central_log)
        else:
            for log in self.log_l:
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
    def get_matches(self, re_l, log_l = []):
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

# r.group(1) transition number (a different thing from file number)
# r.group(2) contains full path
# r.group(3) file number
transition_patt = (
	"crmd: .* do_te_invoke: Processing graph ([0-9]+) .*derived from (.*/pe-[^-]+-(%%)[.]bz2)", # transition start
	"crmd: .* run_graph: Transition ([0-9]+).*Source=(.*/pe-[^-]+-(%%)[.]bz2).: (Stopped|Complete|Terminated)", # and stop
# r.group(1) transition number
# r.group(2) number of actions
	"crmd: .* unpack_graph: Unpacked transition (%%): ([0-9]+) actions", # number of actions
)

def run_graph_msg_actions(msg):
    '''
    crmd: [13667]: info: run_graph: Transition 399 (Complete=5,
    Pending=1, Fired=1, Skipped=0, Incomplete=3,
    Source=...
    '''
    d = {}
    s = msg
    while True:
        r = re.search("([A-Z][a-z]+)=([0-9]+)", s)
        if not r:
            return d
        d[r.group(1)] = int(r.group(2))
        s = s[r.end():]
def transition_actions(msg_l, te_invoke_msg, pe_file):
    '''
    Get the number of actions for the transition.
    '''
    # check if there were any actions in this transition
    pe_num = get_pe_num(pe_file)
    te_invoke_patt = transition_patt[0].replace("%%", pe_num)
    run_patt = transition_patt[1].replace("%%", pe_num)
    r = re.search(te_invoke_patt, te_invoke_msg)
    trans_num = r.group(1)
    unpack_patt = transition_patt[2].replace("%%", trans_num)
    for msg in msg_l:
        try:
            return int(re.search(unpack_patt, msg).group(2))
        except:
            if re.search(run_patt, msg):
                act_d = run_graph_msg_actions(msg)
                return sum(act_d.values())
    return -1

class Report(Singleton):
    '''
    A hb_report class.
    '''
    live_recent = 6*60*60 # recreate live hb_report once every 6 hours
    short_live_recent = 60 # update once a minute
    nodecolors = (
    "NORMAL", "GREEN", "CYAN", "MAGENTA", "YELLOW", "WHITE", "BLUE", "RED"
    )
    def __init__(self):
        self.source = None
        self.loc = None
        self.ready = False
        self.from_dt = None
        self.to_dt = None
        self.detail = 0
        self.nodecolor = {}
        self.logobj = None
        self.desc = None
        self.log_l = []
        self.central_log = None
        self.peinputs_l = []
        self.cibgrp_d = {}
        self.cibrsc_l = []
        self.cibnode_l = []
        self.setnodes = []
        self.outdir = os.path.join(vars.report_cache,"psshout")
        self.errdir = os.path.join(vars.report_cache,"pssherr")
        self.last_live_update = 0
    def error(self, s):
        common_err("%s: %s" % (self.source, s))
    def warn(self, s):
        common_warn("%s: %s" % (self.source, s))
    def rsc_list(self):
        return self.cibgrp_d.keys() + self.cibrsc_l
    def node_list(self):
        return self.cibnode_l
    def peinputs_list(self):
        return [get_pe_num(x) for x in self.peinputs_l]
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
        if os.path.isdir(loc):
            return loc
        cwd = os.getcwd()
        try:
            os.chdir(parentdir)
        except OSError,msg:
            self.error(msg)
            return None
        rc = ext_cmd_nosudo("tar -x%s < %s" % (tar_unpack_option,bfname))
        if self.source == "live":
            os.remove(bfname)
        os.chdir(cwd)
        if rc != 0:
            return None
        return loc
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
    def is_last_live_recent(self):
        '''
        Look at the last live hb_report. If it's recent enough,
        return True.
        '''
        try:
            last_ts = os.stat(self.desc).st_mtime
            return (time.time() - last_ts <= self.live_recent)
        except Exception, msg:
            self.warn(msg)
            self.warn("strange, couldn't stat %s" % self.desc)
            return False
    def find_node_log(self, node):
        p = os.path.join(self.loc, node)
        if is_log(os.path.join(p, "ha-log.txt")):
            return os.path.join(p, "ha-log.txt")
        elif is_log(os.path.join(p, "messages")):
            return os.path.join(p, "messages")
        else:
            return None
    def find_central_log(self):
        'Return common log, if found.'
        central_log = os.path.join(self.loc, "ha-log.txt")
        if is_log(central_log):
            logf, pos = read_log_info(central_log)
            if logf.startswith("synthetic"):
                # not really central log
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
        self.log_l = l
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
    def unpack_new_peinputs(self, a):
        '''
        Untar PE inputs fetched from nodes.
        '''
        if not os.path.isdir(self.outdir):
            return
        for node,pe_l in a:
            fl = glob.glob("%s/*%s*" % (self.outdir,node))
            if not fl:
                continue
            u_dir = os.path.join(self.loc, node)
            rc = ext_cmd_nosudo("tar -C %s -x < %s" % (u_dir,fl[0]))
    def find_new_peinputs(self, node_l):
        '''
        Get a list of pe inputs appearing in new logs.
        The log is put in self.outdir/node by pssh.
        '''
        if not os.path.isdir(self.outdir):
            return []
        l = []
        for node in node_l:
            fl = glob.glob("%s/*%s*" % (self.outdir,node))
            if not fl:
                continue
            try:
                f = open(fl[0])
            except IOError,msg:
                common_err("open %s: %s"%(fl[0],msg))
                continue
            pe_l = self.list_transitions([x for x in f], future_pe = True)
            if pe_l:
                l.append([node,pe_l])
        return l
    def update_live(self):
        '''
        Update the existing live report, if it's older than
        self.short_live_recent:
        - append newer logs
        - get new PE inputs
        '''
        if (time.time() - self.last_live_update) <= self.short_live_recent:
            return True
        if _NO_PSSH:
            warn_once("pssh not installed, slow live updates ahead")
            return False
        a = []
        common_info("fetching new logs, please wait ...")
        for rptlog in self.log_l:
            node = log2node(rptlog)
            logf, pos = read_log_info(rptlog)
            if logf:
                a.append([node, rptlog, logf, pos])
        if not a:
            common_info("no elligible logs found :(")
            return False
        rmdir_r(self.outdir)
        rmdir_r(self.errdir)
        rc1 = next_loglines(a, self.outdir, self.errdir)
        self.append_newlogs(a)
        pe_l = self.find_new_peinputs([x[0] for x in a])
        rmdir_r(self.outdir)
        rmdir_r(self.errdir)
        rc2 = True
        if pe_l:
            rc2 = next_peinputs(pe_l, self.outdir, self.errdir)
        self.unpack_new_peinputs(pe_l)
        self.logobj = None
        rmdir_r(self.outdir)
        rmdir_r(self.errdir)
        self.last_live_update = time.time()
        return (rc1 and rc2)
    def get_live_report(self):
        acquire_lock(vars.report_cache)
        loc = self.new_live_hb_report()
        release_lock(vars.report_cache)
        return loc
    def manage_live_report(self, force = False):
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
        if not force and self.is_last_live_recent():
            acquire_lock(vars.report_cache)
            rc = self.update_live()
            release_lock(vars.report_cache)
            if rc:
                return self._live_loc()
        return self.get_live_report()
    def new_live_hb_report(self):
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
        if ext_cmd_nosudo("mkdir -p %s" % os.path.dirname(d)) != 0:
            return None
        common_info("retrieving information from cluster nodes, please wait ...")
        rc = ext_cmd_nosudo("hb_report -Z -f '%s' %s %s %s" %
                (self.from_dt.ctime(), to_option, nodes_option, d))
        if rc != 0:
            if os.path.isfile(tarball):
                self.warn("hb_report thinks it failed, proceeding anyway")
            else:
                self.error("hb_report failed")
                return None
        self.last_live_update = time.time()
        return self.unpack_report(tarball)
    def reset_period(self):
        self.from_dt = None
        self.to_dt = None
    def set_source(self,src):
        'Set our source.'
        self.source = src
    def set_period(self,from_dt,to_dt):
        '''
        Set from/to_dt.
        '''
        common_debug("setting report times: <%s> - <%s>" % (from_dt,to_dt))
        if not self.from_dt:
            self.from_dt = from_dt
            self.to_dt = to_dt
        elif self.source != "live":
            if self.from_dt > from_dt:
                self.error("from time %s not within report" % from_dt)
                return False
            if to_dt and self.to_dt < to_dt:
                self.error("end time %s not within report" % to_dt)
                return False
            self.from_dt = from_dt
            self.to_dt = to_dt
        else:
            need_ref = (self.from_dt > from_dt or \
                    (to_dt and self.to_dt < to_dt))
            self.from_dt = from_dt
            self.to_dt = to_dt
            if need_ref:
                self.refresh_source(force = True)
        if self.logobj:
            self.logobj.set_log_timeframe(self.from_dt, self.to_dt)
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
    def read_cib(self):
        '''
        Get some information from the report's CIB (node list,
        resource list, groups). If "live" and not central log,
        then use cibadmin.
        '''
        nl = self.get_nodes()
        if not nl:
            return
        if self.source == "live" and not self.central_log:
            doc = cibdump2doc()
        else:
            doc = file2doc(os.path.join(self.loc,nl[0],"cib.xml"))
        if not doc:
            return  # no cib?
        try: conf = doc.getElementsByTagName("configuration")[0]
        except: # bad cib?
            return
        self.cibrsc_l = [ x.getAttribute("id")
            for x in conf.getElementsByTagName("primitive") ]
        self.cibnode_l = [ x.getAttribute("uname")
            for x in conf.getElementsByTagName("node") ]
        for grp in conf.getElementsByTagName("group"):
            self.cibgrp_d[grp.getAttribute("id")] = get_rsc_children_ids(grp)
    def set_node_colors(self):
        i = 0
        for n in self.cibnode_l:
            self.nodecolor[n] = self.nodecolors[i]
            i = (i+1) % len(self.nodecolors)
    def list_transitions(self, msg_l = None, future_pe = False):
        '''
        List transitions by reading logs.
        Empty transitions are skipped.
        Some callers need original PE file path (future_pe),
        otherwise we produce the path within the report and check
        if the transition files exist.
        If the caller doesn't provide the message list, then we
        build it from the collected log files (self.logobj).
        Otherwise, we get matches for transition patterns.
        '''
        trans_re_l = [x.replace("%%", "[0-9]+") for x in transition_patt]
        if not msg_l:
            msg_l = self.logobj.get_matches(trans_re_l)
        else:
            re_s = '|'.join(trans_re_l)
            msg_l = [x for x in msg_l if re.search(re_s, x)]
        pe_l = []
        for msg in msg_l:
            msg_a = msg.split()
            if len(msg_a) < 8:
                # this looks too short
                common_warn("log message <%s> unexpected format, please report a bug" % msg)
                continue
            if msg_a[7] in ("unpack_graph:","run_graph:"):
                continue # we want another message
            node = msg_a[3]
            pe_file = msg_a[-1]
            pe_base = os.path.basename(pe_file)
            num_actions = transition_actions(msg_l, msg, pe_file)
            if num_actions == 0: # empty transition
                common_debug("skipping empty transition (%s)" % pe_base)
                continue
            elif num_actions == -1: # couldn't find messages
                common_warn("could not find number of actions for transition (%s)" % pe_base)
            if not future_pe:
                pe_l_file = os.path.join(self.loc, node, "pengine", pe_base)
                if not os.path.isfile(pe_l_file):
                    warn_once("%s in the logs, but not in the report" % pe_l_file)
                    continue
            else:
                pe_l_file = "%s:%s" % (node, pe_file)
            if pe_l_file in pe_l:
                common_warn("duplicate %s, replacing older PE file" % pe_l_file)
                pe_l.remove(pe_l_file)
            common_debug("found PE input: %s" % pe_l_file)
            pe_l.append(pe_l_file)
        return pe_l
    def report_setup(self):
        if not self.loc:
            return
        self.desc = os.path.join(self.loc,"description.txt")
        self.find_logs()
        self.find_central_log()
        self.read_cib()
        self.set_node_colors()
        self.logobj = LogSyslog(self.central_log, self.log_l, \
                self.from_dt, self.to_dt)
        self.peinputs_l = self.list_transitions()
    def prepare_source(self):
        '''
        Unpack a hb_report tarball.
        For "live", create an ad-hoc hb_report and unpack it
        somewhere in the cache area.
        Parse the period.
        '''
        if self.ready and self.source != "live":
            return True
        if self.source == "live":
            self.loc = self.manage_live_report()
        elif os.path.isfile(self.source):
            self.loc = self.unpack_report(self.source)
        elif os.path.isdir(self.source):
            self.loc = self.source
        if not self.loc:
            return False
        self.report_setup()
        self.ready = self.check_report()
        return self.ready
    def refresh_source(self, force = False):
        '''
        Refresh report from live.
        '''
        if self.source != "live":
            self.error("refresh not supported")
            return False
        self.last_live_update = 0
        self.loc = self.manage_live_report(force)
        self.report_setup()
        self.ready = self.check_report()
        return self.ready
    def get_patt_l(self,type):
        '''
        get the list of patterns for this type, up to and
        including current detail level
        '''
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
    def disp(self, s):
        'color output'
        a = s.split()
        try: clr = self.nodecolor[a[3]]
        except: return s
        return termctrl.render("${%s}%s${NORMAL}" % (clr,s))
    def display_logs(self, l):
        if not options.batch and sys.stdout.isatty():
            page_string('\n'.join([ self.disp(x) for x in l ]))
        else: # raw output
            try: # in case user quits the next prog in pipe
                for s in l: print s
            except IOError, msg:
                if not ("Broken pipe" in msg):
                    common_err(msg)
    def show_logs(self, log_l = [], re_l = []):
        '''
        Print log lines, either matched by re_l or all.
        '''
        if not log_l:
            log_l = self.log_l
        if not self.central_log and not log_l:
            self.error("no logs found")
            return
        self.display_logs(self.logobj.get_matches(re_l, log_l))
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
    def info(self):
        '''
        Print information about the source.
        '''
        if not self.prepare_source():
            return False
        print "Source: %s" % self.source
        if self.source != "live":
            print "Created:", self.get_desc_line("Date")
            print "By:", self.get_desc_line("By")
        print "Period: %s - %s" % \
            ((self.from_dt and human_date(self.from_dt) or "start"),
            (self.to_dt and human_date(self.to_dt) or "end"))
        print "Nodes:",' '.join(self.cibnode_l)
        print "Groups:",' '.join(self.cibgrp_d.keys())
        print "Resources:",' '.join(self.cibrsc_l)
    def events(self):
        '''
        Show all events.
        '''
        all_re_l = self.build_re("resource", self.cibrsc_l) + \
            self.build_re("node", self.cibnode_l) + \
            self.build_re("events", [])
        if not all_re_l:
            self.error("no resources or nodes found")
            return False
        self.show_logs(re_l = all_re_l)
    def get_transition_msgs(self, pe_file, msg_l = []):
        if not msg_l:
            trans_re_l = [x.replace("%%", "[0-9]+") for x in transition_patt]
            msg_l = self.logobj.get_matches(trans_re_l)
        te_invoke_msg = ""
        run_msg = ""
        unpack_msg = ""
        pe_num = get_pe_num(pe_file)
        te_invoke_patt = transition_patt[0].replace("%%", pe_num)
        run_patt = transition_patt[1].replace("%%", pe_num)
        r = None
        msg_l.reverse()
        for msg in msg_l:
            r = re.search(te_invoke_patt, msg)
            if r:
                te_invoke_msg = msg
                break
        if not r:
            return ["", "", ""]
        trans_num = r.group(1)
        unpack_patt = transition_patt[2].replace("%%", trans_num)
        for msg in msg_l:
            if re.search(run_patt, msg):
                run_msg = msg
            elif re.search(unpack_patt, msg):
                unpack_msg = msg
            if run_msg and unpack_msg:
                break
        return [unpack_msg, te_invoke_msg, run_msg]
    def show_transition_log(self, pe_file):
        '''
        Search for events within the given transition.
        '''
        if not self.prepare_source():
            return False
        pe_base = os.path.basename(pe_file)
        pe_num = get_pe_num(pe_base)
        unpack_msg, te_invoke_msg, run_msg = self.get_transition_msgs(pe_file)
        if not te_invoke_msg:
            common_warn("start of transition %s not found in logs" % pe_base)
            return False
        if not run_msg:
            common_warn("end of transition %s not found in logs (transition not complete yet?)" % pe_base)
            return False
        common_debug("transition start: %s" % te_invoke_msg)
        common_debug("transition end: %s" % run_msg)
        start_ts = syslog_ts(te_invoke_msg)
        end_ts = syslog_ts(run_msg)
        if not start_ts or not end_ts:
            self.warn("strange, no timestamps found")
            return False
        act_d = run_graph_msg_actions(run_msg)
        total = sum(act_d.values())
        s = ""
        for a in act_d:
            if not act_d[a]:
                continue
            s = "%s %s=%d" % (s, a, act_d[a])
        common_info("transition %s %d actions: %s" %
            (pe_file.replace(self.loc+"/",""), total, s))
        common_info("logs for transition %s (%s-%s)" %
            (pe_file.replace(self.loc+"/",""), \
            shorttime(start_ts), shorttime(end_ts)))
        # limit the log scope temporarily
        self.logobj.set_log_timeframe(start_ts, end_ts)
        self.events()
        self.logobj.set_log_timeframe(self.from_dt, self.to_dt)
        return True
    def resource(self,*args):
        '''
        Show resource relevant logs.
        '''
        if not self.prepare_source():
            return False
        # expand groups (if any)
        expanded_l = []
        for a in args:
            if a in self.cibgrp_d:
                expanded_l += self.cibgrp_d[a]
            else:
                expanded_l.append(a)
        rsc_re_l = self.build_re("resource",expanded_l)
        if not rsc_re_l:
            return False
        self.show_logs(re_l = rsc_re_l)
    def node(self,*args):
        '''
        Show node relevant logs.
        '''
        if not self.prepare_source():
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
    def pelist(self, a = []):
        if not self.prepare_source():
            return []
        if isinstance(a,(tuple,list)):
            if len(a) == 1:
                a.append(a[0])
        elif a is not None:
            a = [a,a]
        return [x for x in self.peinputs_l \
            if pe_file_in_range(x, a)]
    def dotlist(self, a = []):
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

vars = Vars.getInstance()
options = Options.getInstance()
termctrl = TerminalController.getInstance()
cib_factory = CibFactory.getInstance()
crm_report = Report.getInstance()
# vim:ts=4:sw=4:et:
