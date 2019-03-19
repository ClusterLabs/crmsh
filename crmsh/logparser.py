# Copyright (C) 2016 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import bz2
import gzip
import re
import os
import sys
import collections
import json
import time

from . import xmlutil
from . import logtime
from . import utils
from . import log_patterns
from . import log


logger = log.setup_logger(__name__)


_METADATA_FILENAME = "__meta.json"
_METADATA_CACHE_AGE = (60.0 * 60.0)
# Update this when changing the metadata format
_METADATA_VERSION = 1


def _open_logfile(logfile):
    """
    Open a file which may be gz|bz2 compressed.
    Uncompress based on extension.
    """
    try:
        if logfile.endswith(".bz2"):
            return bz2.BZ2File(logfile)
        if logfile.endswith(".gz"):
            return gzip.open(logfile)
        return open(logfile, "rb")
    except IOError as msg:
        logger.error("open %s: %s", logfile, msg)
        return None


def _transition_start_re():
    """
    Return regular expression matching transition start.
    number_re can be a specific transition or a regexp matching
    any transition number.
    The resulting RE has groups
    1: transition number
    2: full path of pe file
    3: pe file number
    """
    m1 = "pacemaker-controld.*Processing graph ([0-9]+).*derived from (.*/pe-[^-]+-([0-9]+)[.]bz2)"
    m2 = "pacemaker-schedulerd.*[Tt]ransition ([0-9]+).*([^ ]*/pe-[^-]+-([0-9]+)[.]bz2)"
    try:
        return re.compile("(?:%s)|(?:%s)" % (m1, m2))
    except re.error as e:
        logger.debug("RE compilation failed: %s", e)
        raise ValueError("Error in search expression")


def pefile_shortname(pe_file):
    return os.path.basename(pe_file).replace(".bz2", "")


def trans_str(node, pe_file):
    '''Convert node,pe_file to transition string.'''
    return "%s:%s" % (node, pefile_shortname(pe_file))


def _transition_end_re():
    """
    Return RE matching transition end.
    See transition_start_re for more details.

    1: trans_num
    2: pe_file
    3: pe_num
    4: state
    """
    try:
        return re.compile("pacemaker-controld.*Transition ([0-9]+).*Source=(.*/pe-[^-]+-([0-9]+)[.]bz2).:.*(Stopped|Complete|Terminated)")
    except re.error as e:
        logger.debug("RE compilation failed: %s", e)
        raise ValueError("Error in search expression")


_GRAPH_ACTIONS_RE = re.compile("([A-Z][a-z]+)=([0-9]+)")


def _run_graph_msg_actions(msg):
    '''
    crmd: [13667]: info: run_graph: Transition 399 (Complete=5,
    Pending=1, Fired=1, Skipped=0, Incomplete=3,
    Source=...
    Returns dict: d[Pending]=np, d[Fired]=nf, ...
    Only stores non-zero values.
    '''
    d = {}
    s = msg
    r = _GRAPH_ACTIONS_RE.search(s)
    while r:
        val = int(r.group(2))
        if val != 0:
            d[r.group(1)] = val
        s = s[r.end():]
        r = _GRAPH_ACTIONS_RE.search(s)
    return d


def mk_re_list(patt_l, repl):
    'Build a list of regular expressions, replace "%%" with repl'
    l = []
    for re_l in patt_l:
        l += [x.replace("%%", repl) for x in re_l]
    if not repl:
        l = [x.replace(".*.*", ".*") for x in l]
    return l


class Transition(object):
    __slots__ = ('loc', 'dc', 'start_ts', 'trans_num', 'pe_file', 'pe_num', 'end_ts', 'end_state', 'end_actions', 'tags')

    def __init__(self, loc, dc, start_ts, trans_num, pe_file, pe_num):
        self.loc = loc
        self.dc = dc
        self.start_ts = start_ts
        self.trans_num = trans_num
        self.pe_file = pe_file
        self.pe_num = pe_num
        self.end_ts = None
        self.end_state = None
        self.end_actions = None
        self.tags = set()

    def __str__(self):
        return trans_str(self.dc, self.pe_file)

    def shortname(self):
        return pefile_shortname(self.pe_file)

    def actions(self):
        return self.end_actions

    def actions_count(self):
        if self.end_actions is not None:
            return sum(self.end_actions.values())
        return -1

    def path(self):
        return os.path.join(self.loc, self.dc, "pengine", self.pe_file)

    def description(self):
        s = "%s %s - %s: %-15s %-15s %s" % (
            utils.shortdate(self.start_ts),
            utils.shorttime(self.start_ts),
            self.end_ts and utils.shorttime(self.end_ts) or "--:--:--",
            self.shortname(),
            self.dc,
            " ".join(sorted(self.tags))
        )
        return s

    def empty(self, prev):
        """
        True if this transition resulted in no actions and no CIB changes
        prev: previous transition
        """
        old_pe_l_file = prev.path()
        new_pe_l_file = self.path()
        no_actions = self.actions_count() == 0
        if not os.path.isfile(old_pe_l_file) or not os.path.isfile(new_pe_l_file):
            return no_actions
        old_cib = xmlutil.compressed_file_to_cib(old_pe_l_file)
        new_cib = xmlutil.compressed_file_to_cib(new_pe_l_file)
        if old_cib is None or new_cib is None:
            return no_actions
        prev_epoch = old_cib.attrib.get("epoch", "0")
        epoch = new_cib.attrib.get("epoch", "0")
        prev_admin_epoch = old_cib.attrib.get("admin_epoch", "0")
        admin_epoch = new_cib.attrib.get("admin_epoch", "0")
        return no_actions and epoch == prev_epoch and admin_epoch == prev_admin_epoch

    def transition_info(self):
        print("Transition %s (%s -" % (self, utils.shorttime(self.start_ts)), end=' ')
        if self.end_ts:
            print("%s):" % utils.shorttime(self.end_ts))
            act_d = self.actions()
            total = self.actions_count()
            s = ", ".join(["%d %s" % (act_d[x], x) for x in act_d if act_d[x]])
            print("\ttotal %d actions: %s" % (total, s))
        else:
            print("[unfinished])")

    def to_dict(self):
        """
        Serialize to dict (for cache)
        """
        o = {"tags": list(self.tags)}
        for k in self.__slots__:
            if k in ("loc", "tags"):
                continue
            o[k] = getattr(self, k)
        return o

    @classmethod
    def from_dict(cls, loc, obj):
        t = Transition(loc, None, None, None, None, None)
        for k, v in obj.items():
            setattr(t, k, set(v) if k == "tags" else v)
        return t


class CibInfo(object):
    def __init__(self, report_path):
        self.filename = utils.file_find_by_name(report_path, "cib.xml")
        self.nodes = []
        self.primitives = []
        self.groups = {}
        self.clones = {}
        self.cloned_resources = set()
        self.not_cloned_resources = set()

        cib_elem = None
        if self.filename:
            cib_elem = xmlutil.file2cib_elem(self.filename)

        if cib_elem is None:
            self.nodes = utils.list_cluster_nodes()
            return

        self.nodes = [x.get("uname") or x.get("id") for x in cib_elem.xpath("/cib/configuration/nodes/node")]

        self.primitives = [x.get("id") for x in cib_elem.xpath("/cib/configuration/resources//primitive")]

        for grp in cib_elem.xpath("/cib/configuration/resources/group"):
            self.groups[grp.get("id")] = xmlutil.get_rsc_children_ids(grp)

        for cln in cib_elem.xpath("/cib/configuration/resources/*[self::clone or self::master]"):
            self.clones[cln.get("id")] = xmlutil.get_prim_children_ids(cln)
            self.cloned_resources.union(self.clones[cln.get("id")])

        self.not_cloned_resources = set(x for x in self.primitives if x not in self.cloned_resources)

    def resources(self):
        return self.primitives + list(self.groups.keys()) + list(self.clones.keys())

    def match_resources(self):
        """
        list of regex expressions to match resources
        """
        rsc_l = list(self.not_cloned_resources)
        rsc_l += ["%s(?::[0-9]+)?" % x for x in self.cloned_resources]
        return rsc_l


class LogParser(object):
    """
    Used by the history explorer.
    Given a report directory, generates log metadata.

    TODO:

    This information is then written to a file called %(_METADATA_FILENAME),
    and the next time the history explorer is started, we skip the
    analysis and load the metadata directly.

    The analysis is done over the complete log: Timeframe narrowing happens elsewhere.
    """

    def __init__(self, loc, cib, logfiles, detail):
        """
        report_root: Base directory of the report
        """
        self.loc = loc
        self.cib = cib
        self.filenames = logfiles
        self.fileobjs = [_open_logfile(f) for f in logfiles]
        self.detail = detail

        self.events = {}
        self.transitions = []

        self.from_ts = None
        self.to_ts = None

    def __del__(self):
        for f in self.fileobjs:
            f.close()

    def scan(self, mode=None):
        """
        mode = 'refresh':
        Re-read logs that may have new data appended.
        Right now this re-scans all the log data.
        TODO: Only scan new data by tracking the previous
        end of each file and scanning from there. Retain
        previous data and just add new transitions / events.

        Returns list of pefiles missing from report. [(node, [pefile ...]) ...]

        mode = 'force':
        Completely re-parse (ignore cache)
        """
        with utils.nogc():
            return self._scan(mode=mode)

    def _scan(self, mode):
        """
        Scan logs and generate metadata for transitions,
        tags and events. (used when retreiving log lines later)

        Returns list of pefiles missing from report. [(node, [pefile ...]) ...]

        mode: None, 'refresh' or 'force'

        TODO: Load/save metadata when already generated.
        TODO: scan each logfile in a separate thread?
        """

        if mode not in ('refresh', 'force') and self._load_cache():
            return []

        missing_pefiles = []

        # {etype -> [(sortkey, msg)]}
        # TODO: store (sortkey, fileid, spos) instead?
        self.events = collections.defaultdict(list)

        self.transitions = []

        # trans_num:pe_num -> Transition()
        transitions_map = {}

        startre = _transition_start_re()
        endre = _transition_end_re()

        eventre = {}
        eventre["node"] = self._build_re("node", self.cib.nodes)
        eventre["resource"] = self._build_re("resource", self.cib.match_resources())
        eventre["quorum"] = self._build_re("quorum", [])
        eventre["events"] = self._build_re("events", [])

        DEFAULT, IN_TRANSITION = 0, 1
        state = DEFAULT
        transition = None

        for logidx, (filename, log) in enumerate(zip(self.filenames, self.fileobjs)):
            log.seek(0)
            logger.debug("parsing %s", filename)
            line = "a"
            while line != '':
                spos = log.tell()
                line = utils.to_ascii(log.readline())
                m = startre.search(line)
                if m:
                    # m.groups() is (transnum1, pefile1, penum1, transnum2, pefile2, penum2) where
                    # it matched either 1 or 2
                    t1, p1, n1, t2, p2, n2 = m.groups()
                    if t1 is not None:
                        trans_num, pe_file, pe_num = t1, p1, n1
                    else:
                        trans_num, pe_file, pe_num = t2, p2, n2
                    pe_orig = pe_file
                    pe_file = os.path.basename(pe_orig)
                    ts, dc = logtime.syslog_ts_node(line)
                    if ts is None or dc is None:
                        continue
                    id_ = trans_str(dc, pe_file)
                    transition = transitions_map.get(id_)
                    if transition is None:
                        transition = Transition(self.loc, dc, ts, trans_num, pe_file, pe_num)
                        self.transitions.append(transition)
                        transitions_map[id_] = transition
                        logger.debug("{Transition: %s", transition)

                        if not os.path.isfile(transition.path()):
                            missing_pefiles.append((dc, pe_orig))
                    else:
                        logger.debug("~Transition: %s old(%s, %s) new(%s, %s)", transition, transition.trans_num, transition.pe_file, trans_num, pe_file)
                    state = IN_TRANSITION
                    continue
                if state == IN_TRANSITION:
                    m = endre.search(line)
                    if m:
                        trans_num, pe_file, pe_num, state = m.groups()
                        pe_file = os.path.basename(pe_file)
                        ts, dc = logtime.syslog_ts_node(line)
                        if ts is None or dc is None:
                            continue
                        transition = transitions_map.get(trans_str(dc, pe_file))
                        if transition is None:
                            # transition end without previous begin...
                            logger.debug("Found transition end without start: %s: %s - %s:%s", ts, filename, trans_num, pe_file)
                        else:
                            transition.end_state = state
                            transition.end_ts = ts
                            transition.end_actions = _run_graph_msg_actions(line)
                            logger.debug("}Transition: %s %s", transition, state)
                        state = DEFAULT

                # events
                for etype, erx in eventre.items():
                    for rx in erx:
                        m = rx.search(line)
                        if m:
                            ts = logtime.syslog_ts(line)
                            if ts is None:
                                continue
                            logger.debug("+Event %s: %s: %s", etype, ", ".join(m.groups()), line.strip('\n'))
                            sk = (int(ts) << 32) + int(spos)
                            self.events[etype].append((sk, logidx, spos))
                            if transition is not None:
                                for t in m.groups():
                                    if t:
                                        transition.tags.add(t.lower())

                if state == DEFAULT:
                    transition = None

        self.transitions.sort(key=lambda t: t.start_ts)
        for etype, logs in self.events.items():
            logs.sort(key=lambda e: e[0])
        empties = []
        for i, t in enumerate(self.transitions):
            if i == 0:
                continue
            if t.empty(self.transitions[i - 1]):
                empties.append(t)
        self.transitions = [t for t in self.transitions if t not in empties]
        self._save_cache()
        if missing_pefiles:
            rdict = collections.defaultdict(list)
            for node, pe in missing_pefiles:
                rdict[node].append(pe)
            missing_pefiles = list(rdict.items())
        return missing_pefiles

    def set_timeframe(self, from_t, to_t):
        """
        from_t, to_t: timestamps or datetime objects
        """
        self.from_ts = logtime.make_time(from_t)
        self.to_ts = logtime.make_time(to_t)

    def get_logs(self, nodes=None):
        """
        Generator which yields a list of log messages limited by the
        list of nodes, or from all nodes.

        The log lines are printed in order, by reading from
        all files at once and always printing the line with
        the lowest timestamp
        """

        def include_log(logfile):
            return not nodes or os.path.basename(os.path.dirname(logfile)) in nodes

        for f in self.fileobjs:
            f.seek(0)

        lines = [[None, utils.to_ascii(f.readline()), f] for f in self.fileobjs]
        for i, line in enumerate(lines):
            if not line[1]:
                line[0], line[2] = sys.float_info.max, None
            else:
                line[0] = logtime.syslog_ts(line[1])

        while any(f is not None for _, _, f in lines):
            x = min(lines, key=lambda v: v[0])
            if x[0] is None or x[2] is None:
                break
            if self.to_ts and x[0] > self.to_ts:
                break
            if not (self.from_ts and x[0] < self.from_ts):
                yield x[1]
            x[1] = utils.to_ascii(x[2].readline())
            if not x[1]:
                x[0], x[2] = sys.float_info.max, None
            else:
                x[0] = logtime.syslog_ts(x[1])

    def get_events(self, event=None, nodes=None, resources=None):
        """
        Generator which outputs matching event lines
        event: optional node, resource, quorum
        nodes: optional list of nodes
        resources: optional list of resources

        TODO: ordering, time limits
        """
        if event is not None:
            eventlogs = [event]
        else:
            eventlogs = sorted(list(self.events.keys()))

        if nodes:
            rxes = self._build_re(event, nodes)
        elif resources:
            expanded_l = []
            for r in resources:
                if r in self.cib.groups:
                    expanded_l += self.cib.groups[r]
                elif r in self.cib.clones:
                    expanded_l += self.cib.clones[r]
                else:
                    expanded_l.append(r)

            def clonify(r):
                return r + "(?::[0-9]+)?" if r in self.cib.cloned_resources else r
            expanded_l = [clonify(r) for r in expanded_l]
            rxes = self._build_re(event, expanded_l)
        else:
            rxes = None

        if event == "resource" and resources is not None and rxes is not None:
            logger.debug("resource %s rxes: %s", ", ".join(resources), ", ".join(r.pattern for r in rxes))

        if rxes is not None:
            for log in eventlogs:
                for _, f, pos in self.events.get(log, []):
                    self.fileobjs[f].seek(pos)
                    msg = utils.to_ascii(self.fileobjs[f].readline())
                    if any(rx.search(msg) for rx in rxes):
                        ts = logtime.syslog_ts(msg)
                        if not (self.from_ts and ts < self.from_ts) and not (self.to_ts and ts > self.to_ts):
                            yield msg
        else:
            for log in eventlogs:
                for _, f, pos in self.events.get(log, []):
                    self.fileobjs[f].seek(pos)
                    msg = utils.to_ascii(self.fileobjs[f].readline())
                    ts = logtime.syslog_ts(msg)
                    if not (self.from_ts and ts < self.from_ts) and not (self.to_ts and ts > self.to_ts):
                        yield msg

    def get_transitions(self):
        """
        Yields transitions within the current timeframe
        """
        for t in self.transitions:
            if not (self.from_ts and t.end_ts and t.end_ts < self.from_ts) and not (self.to_ts and t.start_ts and t.start_ts > self.to_ts):
                yield t

    def _get_patt_l(self, etype):
        '''
        get the list of patterns for this type, up to and
        including current detail level
        '''
        patterns = log_patterns.patterns(cib_f=self.cib.filename)
        if etype not in patterns:
            logger.error("%s not featured in log patterns", etype)
            return None
        return patterns[etype][0:self.detail+1]

    def _build_re(self, etype, args):
        '''
        Prepare a regex string for the type and args.
        For instance, "resource" and rsc1, rsc2, ...
        '''
        patt_l = self._get_patt_l(etype)
        if not patt_l:
            return None
        if not args:
            re_l = mk_re_list(patt_l, "")
        else:
            re_l = mk_re_list(patt_l, r'(%s)' % "|".join(args))
        return [re.compile(r) for r in re_l]

    def to_dict(self):
        """
        Serialize self to dict (including transition objects)
        """
        o = {
            "version": _METADATA_VERSION,
            "events": self.events,
            "transitions": [t.to_dict() for t in self.transitions],
            "cib": {
                "nodes": self.cib.nodes,
                "primitives": self.cib.primitives,
                "groups": self.cib.groups,
                "clones": self.cib.clones
            }
        }
        return o

    def from_dict(self, obj):
        """
        Load from dict
        """
        if "version" not in obj or obj["version"] != _METADATA_VERSION:
            return False
        self.events = obj["events"]
        self.transitions = [Transition.from_dict(self.loc, t) for t in obj["transitions"]]
        return True

    def _metafile(self):
        return os.path.join(self.loc, _METADATA_FILENAME)

    def count(self):
        """
        Returns (num transitions, num events)
        """
        return len(self.transitions), sum(len(e) for e in list(self.events.values()))

    def _save_cache(self):
        """
        Save state to cache file
        """
        fn = self._metafile()
        try:
            with open(fn, 'wt') as f:
                json.dump(self.to_dict(), f, indent=2)
                logger.debug("Transition metadata saved to %s", fn)
        except IOError as e:
            logger.debug("Could not update metadata cache: %s", e)

    def _load_cache(self):
        """
        Load state from cache file
        """
        fn = self._metafile()
        if os.path.isfile(fn):
            meta_mtime = os.stat(fn).st_mtime
            logf_mtime = max([os.stat(f).st_mtime for f in self.filenames if os.path.isfile(f)])

            if meta_mtime >= logf_mtime and time.time() - meta_mtime < _METADATA_CACHE_AGE:
                try:
                    with open(fn, 'r') as f:
                        try:
                            if not self.from_dict(json.load(f)):
                                return False
                            logger.debug("Transition metadata loaded from %s", fn)
                            return True
                        except ValueError as e:
                            logger.debug("Failed to load metadata: %s", e)
                except IOError as e:
                    return False
        return False
