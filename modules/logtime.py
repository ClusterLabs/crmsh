# Copyright (C) 2013-2016 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

"""
Helpers for handling log timestamps.
"""

import re
import time
import datetime
from . import utils
from . import msg as crmlog


YEAR = None


def set_year(ts=None):
    '''
    ts: optional time in seconds
    '''
    global YEAR
    year = time.strftime("%Y", time.localtime(ts))
    if YEAR is not None:
        t = (" (ts: %s)" % (ts)) if ts is not None else ""
        crmlog.common_debug("history: setting year to %s%s" % (year, t))
    YEAR = year


def human_date(dt=None):
    '''
    Convert datetime argument into a presentational string.

    dt: Datetime (default: now)
    '''
    if dt is None:
        dt = utils.make_datetime_naive(datetime.datetime.now())
    # here, dt is in UTC. Convert to localtime:
    localdt = datetime.datetime.fromtimestamp(utils.datetime_to_timestamp(dt))
    # drop microseconds
    return re.sub("[.].*", "", "%s %s" % (localdt.date(), localdt.time()))


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
                        re.compile(r'^\d{4}-\d{2}-\d{2}T\S+\s+(?:\[\d+\])?\s*([\S]+)'),
                        re.compile(r'^\d{4}\/\d{2}\/\d{2}_\d{2}:\d{2}:\d{2}'))

_syslog_ts_prev = None


def syslog_ts(s):
    """
    Finds the timestamp in the given line
    Returns as floating point, seconds
    """
    global _syslog_ts_prev
    fmt1, fmt2, fmt3 = _syslog2node_formats
    m = fmt1.match(s)
    if m:
        if YEAR is None:
            set_year()
        tstr = ' '.join([YEAR] + s.split()[0:3])
        _syslog_ts_prev = utils.datetime_to_timestamp(utils.parse_time(tstr))
        return _syslog_ts_prev

    m = fmt2.match(s)
    if m:
        tstr = s.split()[0]
        _syslog_ts_prev = utils.datetime_to_timestamp(utils.parse_time(tstr))
        return _syslog_ts_prev

    m = fmt3.match(s)
    if m:
        tstr = s.split()[0].replace('_', ' ')
        _syslog_ts_prev = utils.datetime_to_timestamp(utils.parse_time(tstr))
        return _syslog_ts_prev

    crmlog.common_debug("malformed line: %s" % s)
    return _syslog_ts_prev


_syslog2node_formats = (re.compile(r'^[a-zA-Z]{2,4} \d{1,2} \d{2}:\d{2}:\d{2}\s+(?:\[\d+\])?\s*([\S]+)'),
                        re.compile(r'^\d{4}-\d{2}-\d{2}T\S+\s+(?:\[\d+\])?\s*([\S]+)'),
                        re.compile(r'^\d{4}\/\d{2}\/\d{2}_\d{2}:\d{2}:\d{2}'))


_syslog_node_prev = None


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
    global _syslog_node_prev

    fmt1, fmt2, _ = _syslog2node_formats
    m = fmt1.search(s)
    if m:
        _syslog_node_prev = m.group(1)
        return _syslog_node_prev

    m = fmt2.search(s)
    if m:
        _syslog_node_prev = m.group(1)
        return _syslog_node_prev

    try:
        # strptime defaults year to 1900 (sigh)
        time.strptime(' '.join(s.split()[0:3]),
                      "%b %d %H:%M:%S")
        _syslog_node_prev = s.split()[3]
        return _syslog_node_prev
    except Exception:  # try the rfc5424
        rfc5424 = s.split()[0]
        if 'T' in rfc5424:
            try:
                utils.parse_time(rfc5424)
                _syslog_node_prev = s.split()[1]
                return _syslog_node_prev
            except Exception:
                return _syslog_node_prev
        else:
            return _syslog_node_prev
