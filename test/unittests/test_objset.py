# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.


from crmsh import cibconfig
from nose.tools import eq_, with_setup

factory = cibconfig.cib_factory


def assert_in(needle, haystack):
    if needle not in haystack:
        message = "%s not in %s" % (needle, haystack)
        raise AssertionError(message)


def setup_func():
    "set up test fixtures"
    from crmsh import idmgmt
    idmgmt.clear()


def teardown_func():
    pass


@with_setup(setup_func, teardown_func)
def test_nodes_nocli():
    for n in factory.node_id_list():
        obj = factory.find_object(n)
        if obj is not None:
            assert obj.node is not None
            eq_(True, obj.cli_use_validate())
            eq_(False, obj.nocli)


@with_setup(setup_func, teardown_func)
def test_show():
    setobj = cibconfig.mkset_obj()
    s = setobj.repr_nopretty()
    sp = s.splitlines()
    assert_in("node ha-one", sp[0:3])
