# Copyright (C) 2015 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.


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


def test_weird_chars():
    t = "{{foo#_bar}}"
    eq_("hello", handles.parse(t, {'foo#_bar': 'hello'}))
    t = "{{_foo$bar_}}"
    eq_("hello", handles.parse(t, {'_foo$bar_': 'hello'}))


def test_conditional():
    t = """{{#foo}}before{{foo:bar}}after{{/foo}}"""
    eq_("beforehelloafter", handles.parse(t, {'foo': {'bar': 'hello'}}))
    eq_("", handles.parse(t, {'faa': {'bar': 'hello'}}))

    t = """{{#cond}}before{{foo:bar}}after{{/cond}}"""
    eq_("beforehelloafter", handles.parse(t, {'foo': {'bar': 'hello'}, 'cond': True}))
    eq_("", handles.parse(t, {'foo': {'bar': 'hello'}, 'cond': False}))


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


def test_cib():
    t = """{{filesystem}}
{{exportfs}}
{{rootfs}}
{{virtual-ip}}
clone c-{{rootfs:id}} {{rootfs:id}}
group g-nfs
  {{exportfs:id}}
  {{virtual-ip:id}}
order base-then-nfs inf: {{filesystem:id}} g-nfs
colocation nfs-with-base inf: g-nfs {{filesystem:id}}
order rootfs-before-nfs inf: c-{{rootfs:id}} g-nfs:start
colocation nfs-with-rootfs inf: g-nfs c-{{rootfs:id}}
"""
    r = """primitive fs1 Filesystem
primitive efs exportfs
primitive rfs rootfs
primitive vip IPaddr2
  params ip=192.168.0.2
clone c-rfs rfs
group g-nfs
  efs
  vip
order base-then-nfs inf: fs1 g-nfs
colocation nfs-with-base inf: g-nfs fs1
order rootfs-before-nfs inf: c-rfs g-nfs:start
colocation nfs-with-rootfs inf: g-nfs c-rfs
"""
    v = {
        'filesystem': handles.value({'id': 'fs1'}, 'primitive fs1 Filesystem'),
        'exportfs': handles.value({'id': 'efs'}, 'primitive efs exportfs'),
        'rootfs': handles.value({'id': 'rfs'}, 'primitive rfs rootfs'),
        'virtual-ip': handles.value({'id': 'vip'},
                                    'primitive vip IPaddr2\n  params ip=192.168.0.2'),
    }
    eq_(r, handles.parse(t, v))
