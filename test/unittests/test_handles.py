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


from crmsh import handles
from nose.tools import eq_


def test_basic():
    t = """{{foo}}"""
    eq_("hello", handles.parse(t, {'foo': 'hello'}))
    t = """{{foo:bar}}"""
    eq_("hello", handles.parse(t, {'foo': {'bar': 'hello'}}))
    t = """{{wiz}}"""
    eq_("", handles.parse(t, {'foo': {'bar': 'hello'}}))
    t = """{{foo}}.{{wiz}}"""
    eq_("a.b", handles.parse(t, {'foo': "a", 'wiz': "b"}))



def test_conditional():
    t = """{{#foo}}!{{foo:bar}}!{{/foo}}"""
    eq_("!hello!", handles.parse(t, {'foo': {'bar': 'hello'}}))


def test_iteration():
    t = """{{#foo}}!{{foo:bar}}!{{/foo}}"""
    eq_("!hello!!there!", handles.parse(t, {'foo': [{'bar': 'hello'}, {'bar': 'there'}]}))
