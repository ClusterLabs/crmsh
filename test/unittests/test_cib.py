# Copyright (C) 2015 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
from crmsh import cibconfig
from lxml import etree
from nose.tools import eq_, with_setup
import copy

factory = cibconfig.cib_factory


def setup_func():
    "set up test fixtures"
    from crmsh import idmgmt
    idmgmt.clear()


def teardown_func():
    pass


@with_setup(setup_func, teardown_func)
def test_cib_schema_change():
    "Changing the validate-with CIB attribute"
    copy_of_cib = copy.copy(factory.cib_orig)
    print etree.tostring(copy_of_cib, pretty_print=True)
    tmp_cib_objects = factory.cib_objects
    factory.cib_objects = []
    factory.change_schema("pacemaker-1.1")
    factory.cib_objects = tmp_cib_objects
    factory._copy_cib_attributes(copy_of_cib, factory.cib_orig)
    eq_(factory.cib_attrs["validate-with"], "pacemaker-1.1")
    eq_(factory.cib_elem.get("validate-with"), "pacemaker-1.1")
