# Copyright (C) 2013-2016 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

"""
Helpers for handling log timestamps.
"""

import re
import time
import datetime
from . import utils
from . import log


logger = log.setup_logger(__name__)


YEAR = None


def set_year(ts=None):
    '''
    ts: optional time in seconds
    '''
    global YEAR
    year = time.strftime("%Y", time.localtime(ts))
    if YEAR is not None:
        t = (" (ts: %s)" % (ts)) if ts is not None else ""
        logger.debug("history: setting year to %s%s", year, t)
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
        return utils.datetime_to_timestamp(t)
    return t


# fmt1: group 11 is node
# fmt2: group 2 is node
# fmt3: group 2 is node
# fmt4: node not available?
_syslog2node_formats = (re.compile(r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:.(\d+))?([+-])(\d{2}):?(\d{2})\s+(?:\[\d+\])?\s*([\S]+)'),
                        re.compile(r'^(\d{4}-\d{2}-\d{2}T\S+)\s+(?:\[\d+\])?\s*([\S]+)'),
                        re.compile(r'^([a-zA-Z]{2,4}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?:\[\d+\])?\s*([\S]+)'),
                        re.compile(r'^(\d{4}\/\d{2}\/\d{2}_\d{2}:\d{2}:\d{2})'))

_syslog_ts_prev = None


def syslog_ts(s):
    """
    Finds the timestamp in the given line
    Returns as floating point, seconds
    """
    global _syslog_ts_prev
    fmt1, fmt2, fmt3, fmt4 = _syslog2node_formats

    # RFC3339
    m = fmt1.match(s)
    if m:
        year, month, day, hour, minute, second, ms, tzsgn, tzh, tzm, _ = m.groups()
        ts = time.mktime((int(year), int(month), int(day), int(hour), int(minute), int(second), 0, 0, -1))
        if tzsgn == '+':
            ts += (3600.0 * float(tzh) + 60.0 * float(tzm))
        else:
            ts -= (3600.0 * float(tzh) + 60.0 * float(tzm))
        if ms:
            ts += float("0.%s" % ms)
        _syslog_ts_prev = ts
        return _syslog_ts_prev

    m = fmt2.match(s)
    if m:
        _syslog_ts_prev = utils.parse_to_timestamp(m.group(1))
        return _syslog_ts_prev

    m = fmt3.match(s)
    if m:
        if YEAR is None:
            set_year()
        tstr = YEAR + ' ' + m.group(1)

        dt = datetime.datetime.strptime(tstr, '%Y %b %d %H:%M:%S')
        from dateutil import tz
        ts = utils.total_seconds(dt - tz.tzlocal().utcoffset(dt) - datetime.datetime(1970, 1, 1))
        _syslog_ts_prev = ts
        return _syslog_ts_prev

    m = fmt4.match(s)
    if m:
        tstr = m.group(1).replace('_', ' ')
        _syslog_ts_prev = utils.parse_to_timestamp(tstr)
        return _syslog_ts_prev

    logger.debug("malformed line: %s", s)
    return _syslog_ts_prev


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

    fmt1, fmt2, fmt3, _ = _syslog2node_formats
    m = fmt1.match(s)
    if m:
        _syslog_node_prev = m.group(11)
        return _syslog_node_prev

    m = fmt2.match(s)
    if m:
        _syslog_node_prev = m.group(2)
        return _syslog_node_prev

    m = fmt3.match(s)
    if m:
        _syslog_node_prev = m.group(2)
        return _syslog_node_prev

    try:
        # strptime defaults year to 1900 (sigh)
        time.strptime(' '.join(s.split()[0:3]),
                      "%b %d %H:%M:%S")
        _syslog_node_prev = s.split()[3]
        return _syslog_node_prev
    except ValueError:  # try the rfc5424
        ls = s.split()
        if not ls:
            return _syslog_node_prev
        rfc5424 = s.split()[0]
        if 'T' in rfc5424:
            try:
                utils.parse_to_timestamp(rfc5424)
                _syslog_node_prev = s.split()[1]
                return _syslog_node_prev
            except Exception:
                return _syslog_node_prev
        else:
            return _syslog_node_prev


def syslog_ts_node(s):
    """
    Returns (timestamp, node) from a syslog log line
    """
    global _syslog_ts_prev
    global _syslog_node_prev
    fmt1, fmt2, fmt3, fmt4 = _syslog2node_formats

    # RFC3339
    m = fmt1.match(s)
    if m:
        year, month, day, hour, minute, second, ms, tzsgn, tzh, tzm, node = m.groups()
        ts = time.mktime((int(year), int(month), int(day), int(hour), int(minute), int(second), 0, 0, -1))
        if tzsgn == '+':
            ts += (3600.0 * float(tzh) + 60.0 * float(tzm))
        else:
            ts -= (3600.0 * float(tzh) + 60.0 * float(tzm))
        _syslog_ts_prev = ts
        _syslog_node_prev = node
        return _syslog_ts_prev, node

    m = fmt2.match(s)
    if m:
        _syslog_ts_prev, _syslog_node_prev = utils.parse_to_timestamp(m.group(1)), m.group(2)
        return _syslog_ts_prev, _syslog_node_prev

    m = fmt3.match(s)
    if m:
        if YEAR is None:
            set_year()
        tstr = YEAR + ' ' + m.group(1)

        dt = datetime.datetime.strptime(tstr, '%Y %b %d %H:%M:%S')
        from dateutil import tz
        ts = utils.total_seconds(dt - tz.tzlocal().utcoffset(dt) - datetime.datetime(1970, 1, 1))
        _syslog_ts_prev, _syslog_node_prev = ts, m.group(2)
        return _syslog_ts_prev, _syslog_node_prev

    m = fmt4.match(s)
    if m:
        tstr = m.group(1).replace('_', ' ')
        _syslog_ts_prev = utils.parse_to_timestamp(tstr)
        return _syslog_ts_prev, _syslog_node_prev

    logger.debug("malformed line: %s", s)
    return _syslog_ts_prev, _syslog_node_prev
