# Copyright (C) 2015 Kristoffer Gronlund <kgronlund@suse.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#
import cibconfig
from lxml import etree
from nose.tools import eq_, with_setup
import copy

factory = cibconfig.cib_factory


def setup_func():
    "set up test fixtures"
    import idmgmt
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
