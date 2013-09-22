# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
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
# unit tests for parse.py

import parse
import unittest
import shlex
import itertools
from utils import olist


class MockValidation(parse.Validation):
    def __init__(self):
        parse.Validation.__init__(self, None)

    def resource_roles(self):
        return olist(['master', 'slave'])

    def resource_actions(self):
        return olist(['start', 'stop'])


class TestBaseParser(unittest.TestCase):
    def setUp(self):
        self.base = parse.BaseParser()

    def _reset(self, cmd):
        self.base._cmd = shlex.split(cmd)
        self.base._currtok = 0

    def test_err(self):
        self._reset('a:b:c:d')
        with self.assertRaises(parse.ParseError):
            self.base.match_split(order=(0, 1))

    def test_idspec(self):
        self._reset('$id=foo')
        self.base.match_idspec()
        self.assertEqual(self.base.matched(1), '$id')
        self.assertEqual(self.base.matched(2), 'foo')

        self._reset('$id-ref=foo')
        self.base.match_idspec()
        self.assertEqual(self.base.matched(1), '$id-ref')
        self.assertEqual(self.base.matched(2), 'foo')

        with self.assertRaises(parse.ParseError):
            self._reset('id=foo')
            self.base.match_idspec()

    def test_match_split(self):
        self._reset('resource:role')
        a, b = self.base.match_split(order=(1, 0))
        self.assertEqual(a, 'resource')
        self.assertEqual(b, 'role')

        self._reset('role')
        a, b = self.base.match_split(order=(1, 0))
        self.assertEqual(a, None)
        self.assertEqual(b, 'role')

        self._reset('class:provider:type')
        a, b, c = self.base.match_split(order=(1, 2, 0))
        self.assertEqual(a, 'class')
        self.assertEqual(b, 'provider')
        self.assertEqual(c, 'type')

        self._reset('class:type')
        a, b, c = self.base.match_split(order=(1, 2, 0))
        self.assertEqual(a, 'class')
        self.assertEqual(b, None)
        self.assertEqual(c, 'type')

    def test_description(self):
        self._reset('description="this is a description"')
        self.assertEqual(self.base.try_match_description(), 'this is a description')


class TestCliParser(unittest.TestCase):
    def setUp(self):
        self.parser = parse.CliParser()
        mockv = MockValidation()
        for n, p in self.parser.parsers.iteritems():
            p.validation = mockv

    def test_node(self):
        out = self.parser.parse('node node-1')
        self.assertEqual(out.uname, 'node-1')

        out = self.parser.parse('node $id=testid node-1')
        self.assertEqual(out.id, 'testid')
        self.assertEqual(out.uname, 'node-1')

        out = self.parser.parse('node $id=testid node-1:ping')
        self.assertEqual(out.id, 'testid')
        self.assertEqual(out.uname, 'node-1')
        self.assertEqual(out.type, 'ping')

        out = self.parser.parse('node node-1:unknown')
        self.assertFalse(out)

        out = self.parser.parse('node node-1 description="foo bar" attributes foo=bar')
        self.assertEqual(out.description, 'foo bar')
        self.assertTrue('foo' in out.attributes and out.attributes['foo'] == 'bar')

        out = self.parser.parse('node node-1 attributes foo=bar utilization wiz=bang')
        self.assertTrue('foo' in out.attributes)
        self.assertTrue('wiz' in out.utilization and out.utilization['wiz'] == 'bang')

    def test_resources(self):
        out = self.parser.parse('primitive www ocf:heartbeat:apache op monitor timeout=10s')
        self.assertEqual(out.id, 'www')
        self.assertEqual(out.ra_class, 'ocf')
        self.assertTrue(out.operations[0][0] == 'monitor')

        out = self.parser.parse('ms m0 resource params a=b')
        self.assertEqual(out.id, 'm0')
        self.assertEqual(out.children[0], 'resource')
        self.assertTrue('a' in out.params)

        out = self.parser.parse('master ma resource meta a=b')
        self.assertEqual(out.id, 'ma')
        self.assertEqual(out.children[0], 'resource')
        self.assertTrue('a' in out.meta)

        out = self.parser.parse('clone clone-1 resource meta a=b')
        self.assertEqual(out.id, 'clone-1')
        self.assertEqual(out.children[0], 'resource')
        self.assertTrue('a' in out.meta)

        out = self.parser.parse('group group-1 a')
        self.assertEqual(out.id, 'group-1')
        self.assertEqual(len(out.children), 1)

        out = self.parser.parse('group group-1 a b c')
        self.assertEqual(len(out.children), 3)

        out = self.parser.parse('group group-1')
        self.assertFalse(out)

        out = self.parser.parse('group group-1 params a=b')
        self.assertEqual(len(out.children), 0)
        self.assertTrue('a' in out.params)

    def test_constraints(self):
        out = self.parser.parse('location loc-1 resource inf: foo')
        self.assertEqual(out.id, 'loc-1')
        self.assertEqual(out.resource, 'resource')
        self.assertEqual(out.score[1], 'INFINITY')
        self.assertEqual(out.node, 'foo')

        out = self.parser.parse('colocation col-1 inf: foo:master ( bar wiz sequential=yes )')
        self.assertEqual(out.id, 'col-1')
        self.assertEqual(2, sum(1 for s in out.resources if s[0] == 'resource_set'))

        out = self.parser.parse(
            'colocation col-1 -20: foo:Master ( bar wiz ) ( zip zoo ) node-attribute="fiz"')
        self.assertEqual(out.id, 'col-1')
        self.assertEqual(out.score[1], '-20')
        self.assertEqual(out.node_attribute, 'fiz')
        self.assertEqual(3, sum(1 for s in out.resources if s[0] == 'resource_set'))

        out = self.parser.parse('colocation col-1 0: a:master b')
        print out.resources
        self.assertEqual(out.id, 'col-1')

        out = self.parser.parse('colocation col-1 10: ) bar wiz')
        self.assertFalse(out)

        out = self.parser.parse('colocation col-1 10: ( bar wiz')
        self.assertFalse(out)

        out = self.parser.parse('colocation col-1 10: ( bar wiz ]')
        self.assertFalse(out)

        out = self.parser.parse('order o1 Mandatory: [ A B sequential=true ] C')
        self.assertEqual(out.id, 'o1')

        out = self.parser.parse('order c_apache_1 Mandatory: apache:start ip_1')
        self.assertEqual(out.id, 'c_apache_1')

        out = self.parser.parse('order o1 Serialize: A ( B C )')
        self.assertEqual(out.id, 'o1')

        out = self.parser.parse('order order_2 Mandatory: [ A B ] C')
        self.assertEqual(out.id, 'order_2')

        out = self.parser.parse('rsc_ticket ticket-A_public-ip ticket-A: public-ip')
        self.assertEqual(out.id, 'ticket-A_public-ip')

        out = self.parser.parse('rsc_ticket ticket-A_bigdb ticket-A: bigdb loss-policy=fence')
        self.assertEqual(out.id, 'ticket-A_bigdb')

        out = self.parser.parse(
            'rsc_ticket ticket-B_storage ticket-B: drbd-a:Master drbd-b:Master')
        self.assertEqual(out.id, 'ticket-B_storage')

    def test_op(self):
        out = self.parser.parse('monitor apache:Master 10s:20s')
        self.assertEqual(out.resource, 'apache')
        self.assertEqual(out.role, 'Master')

        out = self.parser.parse('monitor apache 60m')
        self.assertEqual(out.resource, 'apache')
        self.assertEqual(out.role, None)
        self.assertEqual(out.interval, '60m')

    def test_acl(self):
        out = self.parser.parse('role user-1 error')
        self.assertFalse(out)
        out = self.parser.parse('user user-1 role:user-1')
        self.assertNotEqual(out, False)

        out = self.parser.parse("role bigdb_admin " +
                                "write meta:bigdb:target-role " +
                                "write meta:bigdb:is-managed " +
                                "write location:bigdb " +
                                "read ref:bigdb")
        self.assertEqual(4, len(out.rules))

    def test_xml(self):
        out = self.parser.parse('xml <node uname="foo-1"/>')
        self.assertEqual(out.raw, '<node uname="foo-1"/>')

    def test_property(self):
        out = self.parser.parse('property stonith-enabled=true')
        self.assertTrue(('stonith-enabled', 'true') in out.values)

        out = self.parser.parse('rsc_defaults failure-timeout=3m')
        self.assertTrue(('failure-timeout', '3m') in out.values)

    def test_fencing(self):
        out = self.parser.parse('fencing_topology poison-pill power')
        self.assertEqual(2, len(out.levels))

        out = self.parser.parse('fencing_topology node-a: poison-pill power node-b: ipmi serial')
        print out.levels
        self.assertEqual(4, len(out.levels))

