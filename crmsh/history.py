# Copyright (C) 2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013-2016 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import os
import time
import re
import glob
import configparser

from . import config
from . import constants
from . import userdir
from . import logtime
from . import logparser
from . import utils
from . import log


logger = log.setup_logger(__name__)


_LOG_FILES = ("ha-log.txt", "messages", "ha-log", "cluster-log.txt", "journal.log", "pacemaker.log")


#
# crm report interface
#
# read crm report generated report, show interesting stuff, search
# through logs, get PE input files, get log slices (perhaps even
# coloured nicely!)
#


def is_our_log(s, node_l):
    return logtime.syslog2node(s) in node_l


def log2node(log):
    return os.path.basename(os.path.dirname(log))


def is_log(p):
    return os.path.isfile(p) and os.path.getsize(p) > 0


_PE_NUM_RE = re.compile("pe-[^-]+-([0-9]+)[.]")


def get_pe_num(pe_file):
    m = _PE_NUM_RE.search(pe_file)
    if m:
        return m.group(1)
    return "-1"


def pe_file_in_range(pe_f, a):
    if not a:
        return pe_f
    if a[0] <= int(get_pe_num(pe_f)) <= a[1]:
        return pe_f
    return None


def read_log_info(log):
    'Read <log>.info and return logfile and next pos'
    s = utils.file2str(log + ".info")
    m = re.match(r"^(.+)\s+(\d+)$", s or '')
    if m:
        logf, pos = m.groups()
        return logf, int(pos)
    return '', -1


def append_newlogs(outdir, to_update):
    '''
    Append new logs fetched from nodes.
    Update <log>.info with new next pos
    '''
    if not os.path.isdir(outdir):
        return
    for node, rptlog, logfile, nextpos in to_update:
        fl = glob.glob("%s/*%s*" % (outdir, node))
        if not fl:
            continue
        utils.append_file(rptlog, fl[0])

        newpos = nextpos + os.stat(fl[0]).st_size
        try:
            f = open(rptlog + ".info", "w")
            f.write("%s %d\n" % (logfile, newpos))
            f.close()
        except IOError as msg:
            logger.error("couldn't the update %s.info: %s", rptlog, msg)


def rpt_pe2t_str(rpt_pe_file):
    '''Convert report's pe_file path to transition string.'''
    node = os.path.basename(os.path.dirname(os.path.dirname(rpt_pe_file)))
    return logparser.trans_str(node, rpt_pe_file)


def mkarchive(idir):
    "Create an archive from a directory"
    home = userdir.gethomedir()
    if not home:
        logger.error("no home directory, nowhere to pack report")
        return False
    archive = '%s.tar.bz2' % os.path.join(home, os.path.basename(idir))
    cmd = "tar -C '%s/..' -cj -f '%s' %s" % \
        (idir, archive, os.path.basename(idir))
    if utils.pipe_cmd_nosudo(cmd) != 0:
        logger.error('could not pack report, command "%s" failed', cmd)
        return False
    else:
        print("Report saved in '%s'" % archive)
    return True


CH_SRC, CH_TIME, CH_UPD = 1, 2, 3


class Report(object):
    '''
    A crm report class.
    '''
    live_recent = 6*60*60   # recreate live crm report once every 6 hours
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
    report_cache_dir = os.path.join(config.path.cache, 'history-%s' % (utils.getuser()))
    outdir = os.path.join(report_cache_dir, "psshout")
    errdir = os.path.join(report_cache_dir, "pssherr")

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
        self.logparser = None
        self.desc = None
        self.cib = None
        self.node_l = []
        self.last_live_update = 0
        self.detail = 0
        self.log_filter_out = []
        self.log_filter_out_re = []
        # change_origin may be 0, CH_SRC, CH_TIME, CH_UPD
        # depending on the change_origin, we update our attributes
        self.change_origin = CH_SRC
        logtime.set_year()

    def error(self, s):
        logger.error("%s: %s", self.source, s)

    def warn(self, s):
        logger.warning("%s: %s", self.source, s)

    def rsc_list(self):
        return self.cib.resources()

    def node_list(self):
        return self.node_l

    def peinputs_list(self):
        if self.logparser:
            return [x.pe_num for x in self.logparser.get_transitions()]
        return []

    def session_subcmd_list(self):
        return ["save", "load", "pack", "delete", "list", "update"]

    def session_list(self):
        d = self.get_session_dir(None)
        return os.listdir(d).sort() if os.path.isdir(d) else []

    def unpack_report(self, tarball):
        '''
        Unpack crm report tarball.
        Don't unpack if the directory already exists!
        '''
        bfname = os.path.basename(tarball)
        parentdir = os.path.dirname(tarball)
        logger.debug("tarball: %s, in dir: %s", bfname, parentdir)
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
            utils.rmdir_r(loc)
        cwd = os.getcwd()
        if parentdir:
            try:
                os.chdir(parentdir)
            except OSError as msg:
                self.error(msg)
                return None
        try:
            rc, tf_loc = utils.get_stdout("tar -t%s < %s 2> /dev/null | head -1" % (tar_unpack_option, utils.quote(bfname)))
            if os.path.abspath(tf_loc) != os.path.abspath(loc):
                logger.debug("top directory in tarball: %s, doesn't match the tarball name: %s", tf_loc, loc)
                loc = os.path.join(os.path.dirname(loc), tf_loc)
        except Exception as msg:
            logger.error("%s: %s", tarball, msg)
            return None
        logger.debug("tar -x%s < %s", tar_unpack_option, utils.quote(bfname))
        rc = utils.pipe_cmd_nosudo("tar -x%s < %s" % (tar_unpack_option, utils.quote(bfname)))
        if self.source == "live":
            os.remove(bfname)
        os.chdir(cwd)
        if rc != 0:
            return None
        return loc

    def short_pe_path(self, pe_file):
        return pe_file.replace("%s/" % self.loc, "")

    def get_nodes(self):
        def check_node(p):
            pp = os.path.join(self.loc, p)
            if os.path.isfile(os.path.join(pp, 'cib.xml')):
                return p
            return os.path.isdir(pp) and self.find_node_log(p)
        nodes = sorted([os.path.basename(p)
                        for p in os.listdir(self.loc)
                        if check_node(p)])
        if self.source == "live" and len(nodes) == 0:
            nodes = [utils.this_node()]
        return nodes

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
        for lf in _LOG_FILES:
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
                if self.source == "live" and node == utils.this_node():
                    self.warn("Data collection fails if '%s' is not in sudoers file" % (utils.getuser()))
        if len(l) == 0:
            for lf in _LOG_FILES:
                global_log = os.path.join(self.loc, lf)
                if os.path.isfile(global_log):
                    l.append(global_log)
                    break
        return l

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
        return utils.pipe_cmd_nosudo("tar -C %s -x < %s" % (u_dir, fl[0]))

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
        except IOError as msg:
            logger.error("open %s: %s", fl[0], msg)
            return []
        return f.readlines()

    def update_live_report(self, next_loglines, next_peinputs):
        '''
        Update the existing live report, if it's older than
        self.short_live_recent:
        - append newer logs
        - get new PE inputs
        TODO: FIXME: broken now
        '''
        logger.info("Fetching updated logs from cluster nodes. Please wait...")
        logger.debug("Candidate logs: %s", self.log_l)
        to_update = []
        for rptlog in self.log_l:
            node = log2node(rptlog)
            logf, pos = read_log_info(rptlog)
            if logf:
                logger.debug("Updating %s : %s : %s : %s", node, rptlog, logf, pos)
                to_update.append([node, rptlog, logf, pos])
        if not to_update:
            logger.info("No updatable logs found (missing .info for logs)")
            return False

        utils.rmdir_r(self.outdir)
        utils.rmdir_r(self.errdir)
        self.last_live_update = time.time()

        end_time = self._str_dt(self.get_rpt_dt(self.to_dt, "bottom"))
        rc1 = next_loglines(to_update, self.outdir, self.errdir, end_time)
        append_newlogs(self.outdir, to_update)

        # read new logs
        # find any missing pefiles
        # return list of missing pefiles
        # fetch missing pefiles from nodes
        # unpack missing pefiles
        # node_pe_l: [(node, [pefile ...]) ...]
        node_pe_l = self.logparser.scan(mode='refresh')
        rc2 = next_peinputs(node_pe_l, self.outdir, self.errdir)
        unpack_rc = 0
        for node, pe_l in node_pe_l:
            unpack_rc |= self.unpack_new_peinputs(node, pe_l)
        rc2 |= (unpack_rc == 0)
        utils.rmdir_r(self.outdir)
        utils.rmdir_r(self.errdir)

        return rc1 and rc2

    def get_live_report(self):
        loc = None
        with utils.lock(self.report_cache_dir):
            loc = self.new_live_report()
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
            _HAS_PARALLAX = False
            try:
                from .crm_pssh import next_loglines, next_peinputs
                _HAS_PARALLAX = True
            except:
                pass
            if _HAS_PARALLAX:
                rc = None
                with utils.lock(self.report_cache_dir):
                    rc = self.update_live_report(next_loglines, next_peinputs)
                if rc is None:
                    return None
                if rc:
                    self.set_change_origin(CH_UPD)
                    return self._live_loc()
            else:
                logger.warning("parallax library not installed, slow live updates ahead")
        if not created_now:
            return self.get_live_report()
        return self.loc

    def new_live_report(self):
        '''
        Run the report command to get logs now.
        '''
        extcmd = "crm report"

        d = self._live_loc()
        if not utils.is_path_sane(d):
            return None
        utils.rmdir_r(d)
        tarball = "%s.tar.bz2" % d
        to_option = ""
        if self.to_dt:
            to_option = "-t '%s'" % logtime.human_date(self.to_dt)
        nodes_option = ""
        if self.setnodes:
            nodes_option = "'-n %s'" % ' '.join(self.setnodes)
        utils.mkdirp(os.path.dirname(d))
        logger.info("Retrieving information from cluster nodes, please wait...")
        rc = utils.pipe_cmd_nosudo("%s -Z -Q -f '%s' %s %s %s %s" %
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
        logger.debug("setting report times: <%s> - <%s>", from_dt, to_dt)
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
        if self.logparser:
            self.logparser.detail = self.detail

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
        self.cib = logparser.CibInfo(self.loc)

    def set_node_colors(self):
        i = 0
        for n in self.node_l:
            self.nodecolor[n] = self.nodecolors[i]
            i = (i+1) % len(self.nodecolors)

    def _report_setup_source(self):
        constants.pcmk_version = None
        # is this an crm report or a crm_report?
        for descname in ("description.txt", "report.summary"):
            self.desc = os.path.join(self.loc, descname)
            if os.path.isfile(self.desc):
                yr = os.stat(self.desc).st_mtime
                logger.debug("Found %s, created %s", descname, yr)
                self._creation_time = time.strftime("%a %d %b %H:%M:%S %Z %Y",
                                                    time.localtime(yr))
                if descname == 'report.summary':
                    self._creator = "crm_report"
                else:
                    self._creator = 'unknown'
                logtime.set_year(yr)
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

        if self.logparser is None:
            self.logparser = logparser.LogParser(self.loc, self.cib, self.log_l, self.detail)
            self.logparser.scan()
        self.logparser.set_timeframe(self.from_dt, self.to_dt)

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
            logger.error("no source set yet")
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
        Refresh report from live,
        or clear metadata cache for non-live report
        '''
        if self.source == "live":
            self.last_live_update = 0
            self.loc = self.manage_live_report(force=force)
            self.report_setup()
            return self.ready
        else:
            print("Refreshing log data...")
            if not self.ready:
                self.set_change_origin(CH_TIME)
                self.prepare_source()
            missing_pes = self.logparser.scan(mode='force')
            if len(missing_pes):
                print("%d transitions, %d events and %d missing PE input files." % tuple(self.logparser.count() + (len(missing_pes),)))
            else:
                print("%d transitions, %d events." % self.logparser.count())

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

    def match_filter_out(self, s):
        for regexp in self.log_filter_out_re:
            if regexp.search(s):
                return True
        return False

    def display_logs(self, l):
        def color_nodes(s):
            node = logtime.syslog2node(s)
            return self._str_nodecolor(node, s) if node is not None else s

        if self.log_filter_out_re:
            utils.page_gen(color_nodes(x) for x in l if not self.match_filter_out(x))
        else:
            utils.page_gen(color_nodes(x) for x in l)

    def show_logs(self, nodes=None):
        '''
        Print log lines, either all or matching a given node
        '''
        self.display_logs(self.logparser.get_logs(nodes=nodes))

    def get_source(self):
        return self.source

    def get_desc_line(self, fld):
        try:
            f = open(self.desc)
        except IOError as msg:
            logger.error("open %s: %s", self.desc, msg)
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
        transitions = list(self.logparser.get_transitions())
        if len(transitions) > max_output:
            s = "... "

        def fmt(t):
            if len(t.tags):
                return self._str_nodecolor(t.dc, t.pe_num) + "*"
            return self._str_nodecolor(t.dc, t.pe_num)

        return "%s%s" % (s, ' '.join([fmt(x) for x in transitions[-max_output:]]))

    def get_rpt_dt(self, dt, whence):
        '''
        Figure out the time of the start/end of the report.
        The ts input is the time stamp set by user (it can be
        empty). whence is set either to "top" or "bottom".
        '''
        def first_line(l):
            l.seek(0)
            return utils.to_ascii(l.readline()).rstrip()

        def last_line(l):
            '''Note: assumes that the last log line isn't > 2048 characters'''
            l.seek(-2048, os.SEEK_END)
            return utils.to_ascii(l.readlines()[-1]).rstrip()

        if dt:
            return dt
        try:
            if whence == "top":
                myts = min(logtime.syslog_ts(x) for x in (first_line(l) for l in self.logparser.fileobjs))
            elif whence == "bottom":
                myts = max(logtime.syslog_ts(x) for x in (last_line(l) for l in self.logparser.fileobjs))
            if myts:
                return utils.timestamp_to_datetime(myts)
            logger.debug("No log lines with timestamps found in report")
        except Exception as e:
            logger.debug("Error: %s", e)
        return None

    def _str_dt(self, dt):
        return dt and logtime.human_date(dt) or "--/--/-- --:--:--"

    def info(self):
        '''
        Print information about the source.
        '''
        if not self.prepare_source():
            return False

        created_on = self.get_desc_line("Date") or self._creation_time
        created_by = self.get_desc_line("By") or self._creator

        utils.page_string(
            '\n'.join(("Source: %s" % self.source,
                       "Created on: %s" % (created_on),
                       "By: %s" % (created_by),
                       "Period: %s - %s" %
                       (self._str_dt(self.get_rpt_dt(self.from_dt, "top")),
                        self._str_dt(self.get_rpt_dt(self.to_dt, "bottom"))),
                       "Nodes: %s" % ' '.join([self._str_nodecolor(x, x)
                                               for x in self.node_l]),
                       "Groups: %s" % ' '.join(list(self.cib.groups.keys())),
                       "Clones: %s" % ' '.join(list(self.cib.clones.keys())),
                       "Resources: %s" % ' '.join(self.cib.primitives),
                       "Transitions: %s" % self.short_peinputs_list())))

    def events(self):
        '''
        Show all events.
        '''
        if not self.prepare_source():
            return False

        self.display_logs(self.logparser.get_events())

    def find_transition(self, t_str):
        for t_obj in self.logparser.get_transitions():
            if str(t_obj) == t_str:
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
            logger.error("%s: transition not found", rpt_pe_file)
            return False
        # limit the log scope temporarily
        self.logparser.set_timeframe(t_obj.start_ts, t_obj.end_ts)
        if full_log:
            self.show_logs()
        else:
            t_obj.transition_info()
            self.events()
        self.logparser.set_timeframe(self.from_dt, self.to_dt)
        return True

    def get_transition_tags(self, rpt_pe_file):
        '''
        Returns the tags for the transition as a sorted list
        '''
        t_obj = self.find_transition(rpt_pe2t_str(rpt_pe_file))
        if not t_obj:
            logger.error("%s: transition not found", rpt_pe_file)
            return None
        return sorted(t_obj.tags)

    def resource(self, *args):
        '''
        Show resource events.
        '''
        if not self.prepare_source(no_live_update=self.prevent_live_update()):
            return False
        self.display_logs(self.logparser.get_events(event="resource", resources=args))

    def node(self, *args):
        '''
        Show node events.
        '''
        if not self.prepare_source(no_live_update=self.prevent_live_update()):
            return False
        self.display_logs(self.logparser.get_events(event="node", nodes=args))

    def show_log(self, *nodes):
        '''
        Show logs for a node or all nodes.
        '''
        if not self.prepare_source():
            return False
        self.show_logs(nodes=nodes)

    def pe_detail_format(self, t_obj):
        l = [
            utils.shortdate(t_obj.start_ts),
            utils.shorttime(t_obj.start_ts),
            t_obj.end_ts and utils.shorttime(t_obj.end_ts) or "--:--:--",
            # the format string occurs also below
            self._str_nodecolor(t_obj.dc, '%-13s' % t_obj.shortname())
        ]
        l += utils.get_cib_attributes(t_obj.path(), "cib",
                                      ("update-client", "update-user", "update-origin"),
                                      ("no-client", "no-user", "no-origin"))
        l += [" ".join(sorted(t_obj.tags))]
        return '%s %s %s  %-13s %-10s %-10s %s   %s' % tuple(l)

    def pelist(self, a=None, verbose=False):
        pe_details_hdr = "Date       Start    End       Filename      Client     User       Origin      Tags"
        pe_details_sep = "====       =====    ===       ========      ======     ====       ======      ===="
        if not self.prepare_source(no_live_update=self.prevent_live_update()):
            return []
        if isinstance(a, (tuple, list)):
            if len(a) == 1:
                a.append(a[0])
        elif a is not None:
            a = [a, a]
        l = [verbose and self.pe_detail_format(t_obj) or t_obj.path()
             for t_obj in self.logparser.get_transitions() if pe_file_in_range(t_obj.pe_file, a)]
        if verbose:
            l = [pe_details_hdr, pe_details_sep] + l
        return l

    def show_transitions(self):
        if not self.prepare_source(no_live_update=self.prevent_live_update()):
            return []
        return ["%-30s  %-15s %-15s Tags" % ("Time", "Name", "Node")] + [t.description() for t in self.logparser.get_transitions()]

    def dotlist(self, a=None):
        l = [x.replace("bz2", "dot") for x in self.pelist(a)]
        return [x for x in l if os.path.isfile(x)]

    def find_pe_files(self, path):
        'Find a PE or dot file matching part of the path.'
        pe_l = path.endswith(".dot") and self.dotlist() or self.pelist()
        return [x for x in pe_l if x.find(path) >= 0]

    def pe2dot(self, f):
        f = f.replace("bz2", "dot")
        if os.path.isfile(f):
            return f
        return None

    def find_file(self, f):
        return utils.file_find_by_name(self.loc, f)

    def get_session_dir(self, name):
        try:
            return os.path.join(self.report_cache_dir, self.session_sub, name)
        except:
            return os.path.join(self.report_cache_dir, self.session_sub)
    state_file = 'history_state.cfg'
    rpt_section = 'report'

    def save_state(self, sdir):
        '''
        Save the current history state. It should include:
        - directory
        - timeframe
        - detail
        TODO
        '''
        p = configparser.ConfigParser()
        p.add_section(self.rpt_section)
        p.set(self.rpt_section, 'dir',
              self.source == "live" and sdir or self.source)
        p.set(self.rpt_section, 'from_time',
              self.from_dt and logtime.human_date(self.from_dt) or '')
        p.set(self.rpt_section, 'to_time',
              self.to_dt and logtime.human_date(self.to_dt) or '')
        p.set(self.rpt_section, 'detail', str(self.detail))
        self.manage_excludes("save", p)
        fname = os.path.join(sdir, self.state_file)
        try:
            f = open(fname, "wt")
        except IOError as msg:
            logger.error("Failed to save state: %s", msg)
            return False
        p.write(f)
        f.close()
        return True

    def load_state(self, sdir):
        '''
        Load the history state from a file.
        '''
        p = configparser.ConfigParser()
        fname = os.path.join(sdir, self.state_file)
        try:
            p.read(fname)
        except Exception as msg:
            logger.error("Failed to load state: %s", msg)
            return False
        rc = True
        try:
            for n, v in p.items(self.rpt_section):
                if n == 'dir':
                    self.set_source(v)
                    if not os.path.exists(v):
                        logger.error("session state file %s points to a non-existing directory: %s", fname, v)
                        rc = False
                elif n == 'from_time':
                    self.from_dt = v and utils.parse_time(v) or None
                elif n == 'to_time':
                    self.to_dt = v and utils.parse_time(v) or None
                elif n == 'detail':
                    self.set_detail(v)
                else:
                    logger.warning("unknown item %s in the session state file %s", n, fname)
            rc |= self.manage_excludes("load", p)
        except configparser.NoSectionError as msg:
            logger.error("session state file %s: %s", fname, msg)
            rc = False
        except Exception as msg:
            logger.error("%s: bad value '%s' for '%s' in session state file %s", msg, v, n, fname)
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
        session_dir = self.get_session_dir(name)
        if not utils.is_path_sane(session_dir):
            return False
        if subcmd == "save" and os.path.exists(session_dir):
            logger.error("history session %s exists", name)
            return False
        elif subcmd in ("load", "pack", "update", "delete") and not os.path.exists(session_dir):
            logger.error("history session %s does not exist", name)
            return False
        if subcmd == "save":
            utils.mkdirp(session_dir)
            if self.source == "live":
                rc = utils.pipe_cmd_nosudo("tar -C '%s' -c . | tar -C '%s' -x" %
                                           (self._live_loc(), session_dir))
                if rc != 0:
                    return False
            return self.save_state(session_dir)
        elif subcmd == "update":
            return self.save_state(session_dir)
        elif subcmd == "load":
            return self.load_state(session_dir)
        elif subcmd == "delete":
            utils.rmdir_r(session_dir)
        elif subcmd == "list":
            for l in self.session_list():
                print(l)
        elif subcmd == "pack":
            return mkarchive(session_dir)
        return True
    log_section = 'log'

    def manage_excludes(self, cmd, arg=None):
        '''Exclude messages from log files.
        arg: None (show, clear)
             regex (add)
             instance of ConfigParser.ConfigParser (load, save)
        '''
        if not self.prepare_source(no_live_update=True):
            return False
        rc = True
        if cmd == "show":
            print('\n'.join(self.log_filter_out))
        elif cmd == "clear":
            self.log_filter_out = []
            self.log_filter_out_re = []
        elif cmd == "add":
            try:
                regex = re.compile(arg)
                self.log_filter_out.append(arg)
                self.log_filter_out_re.append(regex)
            except Exception as msg:
                logger.error("bad regex %s: %s", arg, msg)
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
                        logger.warning("unknown item %s in the section %s", n, self.log_section)
            except configparser.NoSectionError:
                pass
        return rc

# vim:ts=4:sw=4:et:
