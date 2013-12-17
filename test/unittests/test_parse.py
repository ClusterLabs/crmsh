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
from utils import lines2cli
from pprint import pformat


class MockValidation(parse.Validation):
    def __init__(self):
        parse.Validation.__init__(self, None)

    def resource_roles(self):
        return ['Master', 'Slave', 'Started']

    def resource_actions(self):
        return ['start', 'stop', 'promote', 'demote']

    def date_ops(self):
        return ['lt', 'gt', 'in_range', 'date_spec']

    def expression_types(self):
        return ['normal', 'string', 'number']

    def rsc_order_kinds(self):
        return ['Mandatory', 'Optional', 'Serialize']


class TestBaseParser(unittest.TestCase):
    def setUp(self):
        self.base = parse.BaseParser()

    def _reset(self, cmd):
        self.base._cmd = shlex.split(cmd)
        self.base._currtok = 0

    def test_err(self):
        self._reset('a:b:c:d')

        def runner():
            self.base.match_split(order=(0, 1))
        self.assertRaises(parse.ParseError, runner)

    def test_idspec(self):
        self._reset('$id=foo')
        self.base.match_idspec()
        self.assertEqual(self.base.matched(1), '$id')
        self.assertEqual(self.base.matched(2), 'foo')

        self._reset('$id-ref=foo')
        self.base.match_idspec()
        self.assertEqual(self.base.matched(1), '$id-ref')
        self.assertEqual(self.base.matched(2), 'foo')

        def runner():
            self._reset('id=foo')
            self.base.match_idspec()
        self.assertRaises(parse.ParseError, runner)

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

        out = self.parser.parse('rsc_template public_vm ocf:heartbeat:Xen op start timeout=300s op stop timeout=300s op monitor interval=30s timeout=60s op migrate_from timeout=600s op migrate_to timeout=600s')
        self.assertEqual(out.id, 'public_vm')
        self.assertEqual(out.ra_class, 'ocf')
        #print out.to_list()

        out = self.parser.parse('primitive st stonith:ssh params hostlist=node1 meta target-role=Started op start requires=nothing timeout=60s op monitor interval=60m timeout=60s')
        self.assertEqual(out.id, 'st')

        out = self.parser.parse('primitive st stonith:null params hostlist=node1 meta description="some description here" op start requires=nothing op monitor interval=60m')
        self.assertEqual(out.id, 'st')

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

        out = self.parser.parse('location loc-1 /foo.*/ inf: bar')
        self.assertEqual(out.id, 'loc-1')
        self.assertEqual(out.rsc_pattern, 'foo.*')
        self.assertEqual(out.score[1], 'INFINITY')
        self.assertEqual(out.node, 'bar')
        #print out.to_list()

        out = self.parser.parse('location loc-1 // inf: bar')
        self.assertFalse(out)

        out = self.parser.parse('location loc-1 { one ( two three ) four } inf: bar')
        self.assertEqual(out.id, 'loc-1')
        self.assertEqual(3, sum(1 for s in out.rsc_set if s[0] == 'resource_set'))
        self.assertEqual(out.score[1], 'INFINITY')
        self.assertEqual(out.node, 'bar')
        #print out.to_list()

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
        #print out.resources
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
        self.assertEqual(out.to_list(), [['order', [['id', 'order_2'], ('kind', 'Mandatory')]], ['resource_set', [['require-all', 'false'], ['sequential', 'false'], ['resource_ref', ['id', 'A']], ['resource_ref', ['id', 'B']]]], ['resource_set', [['resource_ref', ['id', 'C']]]]])

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
        lf = out.to_list()
        self.assertNotEqual(lf, None)

        out = self.parser.parse('monitor apache 60m')
        self.assertEqual(out.resource, 'apache')
        self.assertEqual(out.role, None)
        self.assertEqual(out.interval, '60m')
        lf = out.to_list()
        self.assertNotEqual(lf, None)

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
        self.assertEqual(4, len(out.levels))

        out = self.parser.parse('fencing_topology vbox4: stonith-vbox3-1-off,stonith-vbox3-2-off,stonith-vbox3-1-on,stonith-vbox3-2-on')
        self.assertEqual(1, len(out.levels))

    def _parse_lines(self, lines):
        out = []
        for line in lines2cli(lines):
            if line:
                tmp = self.parser.parse(line.strip())
                self.assertNotEqual(tmp, False)
                if tmp:
                    out.append(tmp.to_list())
        return out

    def test_comments(self):
        outp = self._parse_lines('''
        # comment
        node n1
        ''')
        self.assertNotEqual(-1, repr(outp).find('# comment'))

    def test_configs(self):
        outp = self._parse_lines('''
        primitive rsc_dummy ocf:heartbeat:Dummy
        monitor rsc_dummy 30
        ''')
        #print outp
        self.assertEqual(2, len(outp))

        outp = self._parse_lines('''
        primitive testfs ocf:heartbeat:Filesystem \
          params directory="/mnt" fstype="ocfs2" device="/dev/sda1"
        clone testfs-clone testfs \
          meta ordered="true" interleave="true"
        ''')
        #print outp
        self.assertEqual(2, len(outp))

        inp = '''
        node node1 \
          attributes mem=16G
        node node2 utilization cpu=4
        primitive st stonith:ssh \
          params hostlist='node1 node2' \
          meta target-role="Started" \
          op start requires=nothing timeout=60s \
          op monitor interval=60m timeout=60s
        primitive st2 stonith:ssh \
          params hostlist='node1 node2'
        primitive d1 ocf:pacemaker:Dummy \
          operations $id=d1-ops \
          op monitor interval=60m \
          op monitor interval=120m OCF_CHECK_LEVEL=10
        monitor d1 60s:30s
        primitive d2 ocf:heartbeat:Delay \
          params mondelay=60 \
          op start timeout=60s \
          op stop timeout=60s
        monitor d2:Started 60s:30s
        group g1 d1 d2
        primitive d3 ocf:pacemaker:Dummy
        clone c d3 \
          meta clone-max=1
        primitive d4 ocf:pacemaker:Dummy
        ms m d4
        primitive s5 ocf:pacemaker:Stateful \
        operations $id-ref=d1-ops
        primitive s6 ocf:pacemaker:Stateful \
          operations $id-ref=d1
        ms m5 s5
        ms m6 s6
        location l1 g1 100: node1
        location l2 c \
          rule $id=l2-rule1 100: #uname eq node1
        location l3 m5 \
          rule inf: #uname eq node1 and pingd gt 0
        location l4 m5 \
          rule -inf: not_defined pingd or pingd lte 0
        location l5 m5 \
          rule -inf: not_defined pingd or pingd lte 0 \
          rule inf: #uname eq node1 and pingd gt 0 \
          rule inf: date lt "2009-05-26" and \
          date in_range start="2009-05-26" end="2009-07-26" and \
          date in_range start="2009-05-26" years="2009" and \
          date date_spec years="2009" hours="09-17"
        location l6 m5 \
          rule $id-ref=l2-rule1
        location l7 m5 \
          rule $id-ref=l2
        collocation c1 inf: m6 m5
        collocation c2 inf: m5:Master d1:Started
        order o1 Mandatory: m5 m6
        order o2 Optional: d1:start m5:promote
        order o3 Serialize: m5 m6
        order o4 inf: m5 m6
        rsc_ticket ticket-A_m6 ticket-A: m6
        rsc_ticket ticket-B_m6_m5 ticket-B: m6 m5 loss-policy=fence
        rsc_ticket ticket-C_master ticket-C: m6 m5:Master loss-policy=fence
        fencing_topology st st2
        property stonith-enabled=true
        property $id=cpset2 maintenance-mode=true
        rsc_defaults failure-timeout=10m
        op_defaults $id=opsdef2 record-pending=true
        '''

        old_parser_output = '''[[['node', [['uname', 'node1'], ['id', 'node1']]],
  ['attributes', [['mem', '16G']]]],
 [['node', [['uname', 'node2'], ['id', 'node2']]],
  ['utilization', [['cpu', '4']]]],
 [['primitive', [['id', 'st'], ['class', 'stonith'], ['type', 'ssh']]],
  ['params', [['hostlist', 'node1 node2']]],
  ['meta', [['target-role', 'Started']]],
  ['op',
   [['name', 'start'],
    ['requires', 'nothing'],
    ['timeout', '60s'],
    ['interval', '0']]],
  ['op', [['name', 'monitor'], ['interval', '60m'], ['timeout', '60s']]]],
 [['primitive', [['id', 'st2'], ['class', 'stonith'], ['type', 'ssh']]],
  ['params', [['hostlist', 'node1 node2']]]],
 [['primitive',
   [['id', 'd1'],
    ['class', 'ocf'],
    ['provider', 'pacemaker'],
    ['type', 'Dummy']]],
  ['operations', [['$id', 'd1-ops']]],
  ['op', [['name', 'monitor'], ['interval', '60m']]],
  ['op',
   [['name', 'monitor'], ['interval', '120m'], ['OCF_CHECK_LEVEL', '10']]]],
 [['op',
   [['rsc', 'd1'],
    ['interval', '60s'],
    ['timeout', '30s'],
    ['name', 'monitor']]]],
 [['primitive',
   [['id', 'd2'],
    ['class', 'ocf'],
    ['provider', 'heartbeat'],
    ['type', 'Delay']]],
  ['params', [['mondelay', '60']]],
  ['op', [['name', 'start'], ['timeout', '60s'], ['interval', '0']]],
  ['op', [['name', 'stop'], ['timeout', '60s'], ['interval', '0']]]],
 [['op',
   [['rsc', 'd2'],
    ['role', 'Started'],
    ['interval', '60s'],
    ['timeout', '30s'],
    ['name', 'monitor']]]],
 [['group', [['id', 'g1'], ['$children', ['d1', 'd2']]]]],
 [['primitive',
   [['id', 'd3'],
    ['class', 'ocf'],
    ['provider', 'pacemaker'],
    ['type', 'Dummy']]]],
 [['clone', [['id', 'c'], ['$children', ['d3']]]],
  ['meta', [['clone-max', '1']]]],
 [['primitive',
   [['id', 'd4'],
    ['class', 'ocf'],
    ['provider', 'pacemaker'],
    ['type', 'Dummy']]]],
 [['ms', [['id', 'm'], ['$children', ['d4']]]]],
 [['primitive',
   [['id', 's5'],
    ['class', 'ocf'],
    ['provider', 'pacemaker'],
    ['type', 'Stateful']]],
  ['operations', [['$id-ref', 'd1-ops']]]],
 [['primitive',
   [['id', 's6'],
    ['class', 'ocf'],
    ['provider', 'pacemaker'],
    ['type', 'Stateful']]],
  ['operations', [['$id-ref', 'd1']]]],
 [['ms', [['id', 'm5'], ['$children', ['s5']]]]],
 [['ms', [['id', 'm6'], ['$children', ['s6']]]]],
 [['location',
   [['id', 'l1'], ['rsc', 'g1'], ['score', '100'], ['node', 'node1']]]],
 [['location', [['id', 'l2'], ['rsc', 'c']]],
  ['rule', [['$id', 'l2-rule1'], ['score', '100']]],
  ['expression',
   [['attribute', '#uname'], ['operation', 'eq'], ['value', 'node1']]]],
 [['location', [['id', 'l3'], ['rsc', 'm5']]],
  ['rule', [['score', 'INFINITY']]],
  ['expression',
   [['attribute', '#uname'], ['operation', 'eq'], ['value', 'node1']]],
  ['expression',
   [['attribute', 'pingd'], ['operation', 'gt'], ['value', '0']]]],
 [['location', [['id', 'l4'], ['rsc', 'm5']]],
  ['rule', [['score', '-INFINITY'], ['boolean-op', 'or']]],
  ['expression', [['operation', 'not_defined'], ['attribute', 'pingd']]],
  ['expression',
   [['attribute', 'pingd'], ['operation', 'lte'], ['value', '0']]]],
 [['location', [['id', 'l5'], ['rsc', 'm5']]],
  ['rule', [['score', '-INFINITY'], ['boolean-op', 'or']]],
  ['expression', [['operation', 'not_defined'], ['attribute', 'pingd']]],
  ['expression',
   [['attribute', 'pingd'], ['operation', 'lte'], ['value', '0']]],
  ['rule', [['score', 'INFINITY']]],
  ['expression',
   [['attribute', '#uname'], ['operation', 'eq'], ['value', 'node1']]],
  ['expression',
   [['attribute', 'pingd'], ['operation', 'gt'], ['value', '0']]],
  ['rule', [['score', 'INFINITY']]],
  ['date_expression', [['operation', 'lt'], ['end', '2009-05-26']]],
  ['date_expression',
   [['operation', 'in_range'],
    ['start', '2009-05-26'],
    ['end', '2009-07-26']]],
  ['date_expression',
   [['operation', 'in_range'], ['start', '2009-05-26'], ['years', '2009']]],
  ['date_expression',
   [['operation', 'date_spec'], ['years', '2009'], ['hours', '09-17']]]],
 [['location', [['id', 'l6'], ['rsc', 'm5']]],
  ['rule', [['$id-ref', 'l2-rule1']]]],
 [['location', [['id', 'l7'], ['rsc', 'm5']]], ['rule', [['$id-ref', 'l2']]]],
 [['colocation',
   [['id', 'c1'], ['score', 'INFINITY'], ['rsc', 'm6'], ['with-rsc', 'm5']]]],
 [['colocation',
   [['id', 'c2'],
    ['score', 'INFINITY'],
    ['rsc', 'm5'],
    ['rsc-role', 'Master'],
    ['with-rsc', 'd1'],
    ['with-rsc-role', 'Started']]]],
 [['order',
   [['id', 'o1'], ['kind', 'Mandatory'], ['first', 'm5'], ['then', 'm6']]]],
 [['order',
   [['id', 'o2'],
    ['kind', 'Optional'],
    ['first', 'd1'],
    ['first-action', 'start'],
    ['then', 'm5'],
    ['then-action', 'promote']]]],
 [['order',
   [['id', 'o3'], ['kind', 'Serialize'], ['first', 'm5'], ['then', 'm6']]]],
 [['order',
   [['id', 'o4'], ['score', 'INFINITY'], ['first', 'm5'], ['then', 'm6']]]],
 [['rsc_ticket',
   [['id', 'ticket-A_m6'], ['ticket', 'ticket-A'], ['rsc', 'm6']]]],
 [['rsc_ticket',
   [['id', 'ticket-B_m6_m5'],
    ['ticket', 'ticket-B'],
    ['loss-policy', 'fence']]],
  ['resource_set',
   [['resource_ref', ['id', 'm6']], ['resource_ref', ['id', 'm5']]]]],
 [['rsc_ticket',
   [['id', 'ticket-C_master'],
    ['ticket', 'ticket-C'],
    ['loss-policy', 'fence']]],
  ['resource_set', [['resource_ref', ['id', 'm6']]]],
  ['resource_set', [['role', 'Master'], ['resource_ref', ['id', 'm5']]]]],
 [['fencing_topology',
   [['fencing-level', [['target', '@@'], ['devices', 'st']]],
    ['fencing-level', [['target', '@@'], ['devices', 'st2']]]]]],
 [['property', [['stonith-enabled', 'true']]]],
 [['property', [['$id', 'cpset2'], ['maintenance-mode', 'true']]]],
 [['rsc_defaults', [['failure-timeout', '10m']]]],
 [['op_defaults', [['$id', 'opsdef2'], ['record-pending', 'true']]]]]'''

        outp = self._parse_lines(inp)
        a = pformat(outp).replace('(', '[').replace(')', ']')
        b = old_parser_output
        if a != b:
            f = open('failed-diff-new.txt', 'w')
            f.write(a)
            f.close()
            f = open('failed-diff-old.txt', 'w')
            f.write(b)
            f.close()
        self.assertEqual(a, b)

if __name__ == '__main__':
    unittest.main()
