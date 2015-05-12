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
    t = """Here's a line of text
    followed by another line
    followed by some {{foo}}.{{wiz}}
    and then some at the end"""
    eq_("""Here's a line of text
    followed by another line
    followed by some a.b
    and then some at the end""", handles.parse(t, {'foo': "a", 'wiz': "b"}))


def test_conditional():
    t = """{{#foo}}before{{foo:bar}}after{{/foo}}"""
    eq_("beforehelloafter", handles.parse(t, {'foo': {'bar': 'hello'}}))
    eq_("", handles.parse(t, {'faa': {'bar': 'hello'}}))


def test_iteration():
    t = """{{#foo}}!{{foo:bar}}!{{/foo}}"""
    eq_("!hello!!there!", handles.parse(t, {'foo': [{'bar': 'hello'}, {'bar': 'there'}]}))


def test_result():
    t = """{{obj}}
    group g1 {{obj:id}}
"""
    eq_("""primitive d0 Dummy
    group g1 d0
""", handles.parse(t, {'obj': handles.value({'id': 'd0'}, 'primitive d0 Dummy')}))
    eq_("\n    group g1 \n", handles.parse(t, {}))


def test_result2():
    t = """{{obj}}
    group g1 {{obj:id}}
{{#obj}}
{{obj}}
{{/obj}}
"""
    eq_("""primitive d0 Dummy
    group g1 d0
primitive d0 Dummy
""", handles.parse(t, {'obj': handles.value({'id': 'd0'}, 'primitive d0 Dummy')}))
    eq_("\n    group g1 \n", handles.parse(t, {}))


def test_mustasche():
    t = """Hello {{name}}
You have just won {{value}} dollars!
{{#in_ca}}
Well, {{taxed_value}} dollars, after taxes.
{{/in_ca}}
"""
    v = {
        "name": "Chris",
        "value": 10000,
        "taxed_value": 10000 - (10000 * 0.4),
        "in_ca": True
    }

    eq_("""Hello Chris
You have just won 10000 dollars!
Well, 6000.0 dollars, after taxes.
""", handles.parse(t, v))


def test_invert():
    t = """{{#repo}}
<b>{{name}}</b>
{{/repo}}
{{^repo}}
No repos :(
{{/repo}}
"""
    v = {
        "repo": []
    }

    eq_("""
No repos :(
""", handles.parse(t, v))


def test_invert_2():
    t = """foo
{{#repo}}
<b>{{name}}</b>
{{/repo}}
{{^repo}}
No repos :(
{{/repo}}
bar
"""
    v = {
        "repo": []
    }

    eq_("""foo
No repos :(
bar
""", handles.parse(t, v))
