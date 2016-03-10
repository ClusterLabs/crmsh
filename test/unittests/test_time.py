# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.


from crmsh import utils
from crmsh import logtime
from nose.tools import eq_
import time
import datetime
import dateutil.tz


def test_time_convert1():
    loctz = dateutil.tz.tzlocal()
    tm = time.localtime(utils.datetime_to_timestamp(utils.make_datetime_naive(datetime.datetime(2015, 6, 1, 10, 0, 0).replace(tzinfo=loctz))))
    dt = utils.parse_time('Jun 01, 2015 10:00:00')
    eq_(logtime.human_date(dt), time.strftime('%Y-%m-%d %H:%M:%S', tm))


def test_time_convert2():
    loctz = dateutil.tz.tzlocal()
    tm = time.localtime(utils.datetime_to_timestamp(utils.make_datetime_naive(datetime.datetime(2015, 6, 1, 10, 0, 0).replace(tzinfo=loctz))))
    ts = time.localtime(utils.parse_to_timestamp('Jun 01, 2015 10:00:00'))
    eq_(time.strftime('%Y-%m-%d %H:%M:%S', ts), time.strftime('%Y-%m-%d %H:%M:%S', tm))
