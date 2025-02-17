from __future__ import print_function
from __future__ import unicode_literals
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
#
# unit tests for parse.py
try:
    from unittest import mock
except ImportError:
    import mock

from builtins import zip
from crmsh import parse
import unittest
import shlex
from crmsh.utils import lines2cli
from crmsh.xmlutil import xml_tostring
from lxml import etree


def test_score_to_kind():
    assert parse.score_to_kind("0") == "Optional"
    assert parse.score_to_kind("INFINITY") == "Mandatory"
    assert parse.score_to_kind("200") == "Mandatory"


class MockValidation(parse.Validation):
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

    def op_attributes(self):
        return ['id', 'name', 'interval', 'timeout', 'description',
                'start-delay', 'interval-origin', 'timeout', 'enabled',
                'record-pending', 'role', 'requires', 'on-fail']

    def acl_2_0(self):
        return True


class TestBaseParser(unittest.TestCase):
    def setUp(self):
        self.base = parse.BaseParser()

    def _reset(self, cmd):
        self.base._cmd = shlex.split(cmd)
        self.base._currtok = 0

    @mock.patch('logging.Logger.error')
    def test_err(self, mock_err):
        self._reset('a:b:c:d')

        def runner():
            self.base.match_split()
        self.assertRaises(parse.ParseError, runner)

    @mock.patch('logging.Logger.error')
    def test_idspec(self, mock_error):
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
        a, b = self.base.match_split()
        self.assertEqual(a, 'resource')
        self.assertEqual(b, 'role')

        self._reset('role')
        a, b = self.base.match_split()
        self.assertEqual(a, 'role')
        self.assertEqual(b, None)

    def test_description(self):
        self._reset('description="this is a description"')
        self.assertEqual(self.base.try_match_description(), 'this is a description')

    def test_nvpairs(self):
        self._reset('foo=bar wiz="fizz buzz" bug= bug2=')
        ret = self.base.match_nvpairs()
        self.assertEqual(len(ret), 4)
        retdict = dict([(r.get('name'), r.get('value')) for r in ret])
        self.assertEqual(retdict['foo'], 'bar')
        self.assertEqual(retdict['bug'], '')
        self.assertEqual(retdict['wiz'], 'fizz buzz')


class TestCliParser(unittest.TestCase):
    def setUp(self):
        parse.validator = MockValidation()
        self.comments = []

    def _parse(self, s):
        return parse.parse(s, comments=self.comments)

    @mock.patch('logging.Logger.error')
    def test_node(self, mock_error):
        out = self._parse('node node-1')
        self.assertEqual(out.get('uname'), 'node-1')

        out = self._parse('node $id=testid node-1')
        self.assertEqual(out.get('id'), 'testid')
        self.assertEqual(out.get('uname'), 'node-1')

        out = self._parse('node 1: node-1')
        self.assertEqual(out.get('id'), '1')
        self.assertEqual(out.get('uname'), 'node-1')

        out = self._parse('node testid: node-1')
        self.assertEqual(out.get('id'), 'testid')
        self.assertEqual(out.get('uname'), 'node-1')

        out = self._parse('node $id=testid node-1:ping')
        self.assertEqual(out.get('id'), 'testid')
        self.assertEqual(out.get('uname'), 'node-1')
        self.assertEqual(out.get('type'), 'ping')

        out = self._parse('node node-1:unknown')
        self.assertFalse(out)

        out = self._parse('node node-1 description="foo bar" attributes foo=bar')
        self.assertEqual(out.get('description'), 'foo bar')
        self.assertEqual(['bar'], out.xpath('instance_attributes/nvpair[@name="foo"]/@value'))

        out = self._parse('node node-1 attributes foo=bar utilization wiz=bang')
        self.assertEqual(['bar'], out.xpath('instance_attributes/nvpair[@name="foo"]/@value'))
        self.assertEqual(['bang'], out.xpath('utilization/nvpair[@name="wiz"]/@value'))

    @mock.patch('logging.Logger.error')
    def test_resources(self, mock_error):
        out = self._parse('primitive www ocf:heartbeat:apache op monitor timeout=10s')
        self.assertEqual(out.get('id'), 'www')
        self.assertEqual(out.get('class'), 'ocf')
        self.assertEqual(['monitor'], out.xpath('//op/@name'))

        out = self._parse('rsc_template public_vm ocf:heartbeat:Xen op start timeout=300s op stop timeout=300s op monitor interval=30s timeout=60s op migrate_from timeout=600s op migrate_to timeout=600s')
        self.assertEqual(out.get('id'), 'public_vm')
        self.assertEqual(out.get('class'), 'ocf')
        #print out

        out = self._parse('primitive st stonith:fence_sbd meta target-role=Started requires=nothing op start timeout=60s op monitor interval=60m timeout=60s')
        self.assertEqual(out.get('id'), 'st')

        out2 = self._parse('primitive st stonith:fence_sbd meta target-role=Started requires=nothing op start timeout=60s op monitor interval=60m timeout=60s')
        self.assertEqual(out2.get('id'), 'st')

        self.assertEqual(xml_tostring(out), xml_tostring(out2))

        out = self._parse('primitive st stonith:fence_sbd meta')
        self.assertEqual(out.get('id'), 'st')

        out = self._parse('ms m0 resource params a=b')
        self.assertEqual(out.get('id'), 'm0')
        print(xml_tostring(out))
        self.assertEqual(['resource'], out.xpath('./crmsh-ref/@id'))
        self.assertEqual(['b'], out.xpath('instance_attributes/nvpair[@name="a"]/@value'))

        out2 = self._parse('ms m0 resource a=b')
        self.assertEqual(out.get('id'), 'm0')
        self.assertEqual(xml_tostring(out), xml_tostring(out2))

        out = self._parse('master ma resource meta a=b')
        self.assertEqual(out.get('id'), 'ma')
        self.assertEqual(['resource'], out.xpath('./crmsh-ref/@id'))
        self.assertEqual(['b'], out.xpath('meta_attributes/nvpair[@name="a"]/@value'))

        out = self._parse('clone clone-1 resource meta a=b')
        self.assertEqual(out.get('id'), 'clone-1')
        self.assertEqual(['resource'], out.xpath('./crmsh-ref/@id'))
        self.assertEqual(['b'], out.xpath('meta_attributes/nvpair[@name="a"]/@value'))

        out = self._parse('group group-1 a')
        self.assertEqual(out.get('id'), 'group-1')
        self.assertEqual(len(out), 1)

        out = self._parse('group group-1 a b c')
        self.assertEqual(len(out), 3)

        out = self._parse('group group-1')
        self.assertFalse(out)

        out = self._parse('group group-1 params a=b')
        self.assertEqual(len(out), 1)
        self.assertEqual(['b'], out.xpath('/group/instance_attributes/nvpair[@name="a"]/@value'))

    def test_heartbeat_class(self):
        out = self._parse('primitive p_node-activate heartbeat:node-activate')
        self.assertEqual(out.get('id'), 'p_node-activate')
        self.assertEqual(out.get('class'), 'heartbeat')
        self.assertEqual(out.get('provider'), None)
        self.assertEqual(out.get('type'), 'node-activate')


    def test_nvpair_ref(self):
        out = self._parse('primitive dummy-0 Dummy params @foo')
        self.assertEqual(out.get('id'), 'dummy-0')
        self.assertEqual(out.get('class'), 'ocf')
        self.assertEqual(['foo'], out.xpath('.//nvpair/@id-ref'))

        out = self._parse('primitive dummy-0 Dummy params @fiz')
        self.assertEqual(out.get('id'), 'dummy-0')
        self.assertEqual(out.get('class'), 'ocf')
        self.assertEqual(['fiz'], out.xpath('.//nvpair/@id-ref'))

    @mock.patch('logging.Logger.error')
    def test_location(self, mock_error):
        out = self._parse('location loc-1 resource inf: foo')
        self.assertEqual(out.get('id'), 'loc-1')
        self.assertEqual(out.get('rsc'), 'resource')
        self.assertEqual(out.get('score'), 'INFINITY')
        self.assertEqual(out.get('node'), 'foo')

        out = self._parse('location loc-1 /foo.*/ inf: bar')
        self.assertEqual(out.get('id'), 'loc-1')
        self.assertEqual(out.get('rsc-pattern'), 'foo.*')
        self.assertEqual(out.get('score'), 'INFINITY')
        self.assertEqual(out.get('node'), 'bar')
        #print out

        out = self._parse('location loc-1 // inf: bar')
        self.assertFalse(out)

        out = self._parse('location loc-1 { one ( two three ) four } inf: bar')
        self.assertEqual(out.get('id'), 'loc-1')
        self.assertEqual(['one', 'two', 'three', 'four'], out.xpath('//resource_ref/@id'))
        self.assertEqual(out.get('score'), 'INFINITY')
        self.assertEqual(out.get('node'), 'bar')
        #print out

        out = self._parse('location loc-1 thing rule role=slave -inf: #uname eq madrid')
        self.assertEqual(out.get('id'), 'loc-1')
        self.assertEqual(out.get('rsc'), 'thing')
        self.assertEqual(out.get('score'), None)

        out = self._parse('location l { a:foo b:bar }')
        self.assertFalse(out)

    @mock.patch('logging.Logger.error')
    def test_colocation(self, mock_error):
        out = self._parse('colocation col-1 inf: foo:master ( bar wiz sequential=yes )')
        self.assertEqual(out.get('id'), 'col-1')
        self.assertEqual(['foo', 'bar', 'wiz'], out.xpath('//resource_ref/@id'))
        self.assertEqual([], out.xpath('//resource_set[@name="sequential"]/@value'))

        out = self._parse(
            'colocation col-1 -20: foo:Master ( bar wiz ) ( zip zoo ) node-attribute="fiz"')
        self.assertEqual(out.get('id'), 'col-1')
        self.assertEqual(out.get('score'), '-20')
        self.assertEqual(['foo', 'bar', 'wiz', 'zip', 'zoo'], out.xpath('//resource_ref/@id'))
        self.assertEqual(['fiz'], out.xpath('//@node-attribute'))

        out = self._parse('colocation col-1 0: a:master b')
        self.assertEqual(out.get('id'), 'col-1')

        out = self._parse('colocation col-1 10: ) bar wiz')
        self.assertFalse(out)

        out = self._parse('colocation col-1 10: ( bar wiz')
        self.assertFalse(out)

        out = self._parse('colocation col-1 10: ( bar wiz ]')
        self.assertFalse(out)

    def test_order(self):
        out = self._parse('order o1 Mandatory: [ A B sequential=true ] C')
        print(xml_tostring(out))
        self.assertEqual(['Mandatory'], out.xpath('/rsc_order/@kind'))
        self.assertEqual(2, len(out.xpath('/rsc_order/resource_set')))
        self.assertEqual(['false'], out.xpath('/rsc_order/resource_set/@require-all'))
        self.assertEqual(['A', 'B', 'C'], out.xpath('//resource_ref/@id'))

        out = self._parse('order o1 Mandatory: [ A B sequential=false ] C')
        self.assertEqual(2, len(out.xpath('/rsc_order/resource_set')))
        #self.assertTrue(['require-all', 'false'] in out.resources[0][1])
        #self.assertTrue(['sequential', 'false'] in out.resources[0][1])
        self.assertEqual(out.get('id'), 'o1')

        out = self._parse('order o1 Mandatory: A B C sequential=false')
        self.assertEqual(1, len(out.xpath('/rsc_order/resource_set')))
        #self.assertTrue(['sequential', 'false'] in out.resources[0][1])
        self.assertEqual(out.get('id'), 'o1')

        out = self._parse('order o1 Mandatory: A B C sequential=true')
        self.assertEqual(1, len(out.xpath('/rsc_order/resource_set')))
        #self.assertTrue(['sequential', 'true'] not in out.resources[0][1])
        self.assertEqual(out.get('id'), 'o1')

        out = self._parse('order c_apache_1 Mandatory: apache:start ip_1')
        self.assertEqual(out.get('id'), 'c_apache_1')

        out = self._parse('order c_apache_2 Mandatory: apache:start ip_1 ip_2 ip_3')
        self.assertEqual(2, len(out.xpath('/rsc_order/resource_set')))
        self.assertEqual(out.get('id'), 'c_apache_2')

        out = self._parse('order o1 Serialize: A ( B C )')
        self.assertEqual(2, len(out.xpath('/rsc_order/resource_set')))
        self.assertEqual(out.get('id'), 'o1')

        out = self._parse('order o1 Serialize: A ( B C ) symmetrical=false')
        self.assertEqual(2, len(out.xpath('/rsc_order/resource_set')))
        self.assertEqual(out.get('id'), 'o1')
        self.assertEqual(['false'], out.xpath('//@symmetrical'))

        out = self._parse('order o1 Serialize: A ( B C ) symmetrical=true')
        self.assertEqual(2, len(out.xpath('/rsc_order/resource_set')))
        self.assertEqual(out.get('id'), 'o1')
        self.assertEqual(['true'], out.xpath('//@symmetrical'))

        inp = 'colocation rsc_colocation-master INFINITY: [ vip-master vip-rep sequential=true ] [ msPostgresql:Master sequential=true ]'
        out = self._parse(inp)
        self.assertEqual(2, len(out.xpath('/rsc_colocation/resource_set')))
        self.assertEqual(out.get('id'), 'rsc_colocation-master')

        out = self._parse('order order_2 Mandatory: [ A B ] C')
        self.assertEqual(2, len(out.xpath('/rsc_order/resource_set')))
        self.assertEqual(out.get('id'), 'order_2')
        self.assertEqual(['Mandatory'], out.xpath('/rsc_order/@kind'))
        self.assertEqual(['false'], out.xpath('//resource_set/@sequential'))

        out = self._parse('order order-1 Optional: group1:stop group2:start')
        self.assertEqual(out.get('id'), 'order-1')
        self.assertEqual(['Optional'], out.xpath('/rsc_order/@kind'))
        self.assertEqual(['group1'], out.xpath('/rsc_order/@first'))
        self.assertEqual(['stop'], out.xpath('/rsc_order/@first-action'))
        self.assertEqual(['group2'], out.xpath('/rsc_order/@then'))
        self.assertEqual(['start'], out.xpath('/rsc_order/@then-action'))

    def test_ticket(self):
        out = self._parse('rsc_ticket ticket-A_public-ip ticket-A: public-ip')
        self.assertEqual(out.get('id'), 'ticket-A_public-ip')

        out = self._parse('rsc_ticket ticket-A_bigdb ticket-A: bigdb loss-policy=fence')
        self.assertEqual(out.get('id'), 'ticket-A_bigdb')

        out = self._parse(
            'rsc_ticket ticket-B_storage ticket-B: drbd-a:Master drbd-b:Master')
        self.assertEqual(out.get('id'), 'ticket-B_storage')

    @mock.patch('logging.Logger.error')
    def test_bundle(self, mock_error):
        out = self._parse('bundle httpd docker image=pcmk:httpd replicas=3 network ip-range-start=10.10.10.123 host-netmask=24 port-mapping port=80 storage storage-mapping target-dir=/var/www/html source-dir=/srv/www options=rw primitive httpd-apache')
        self.assertEqual(out.get('id'), 'httpd')
        self.assertEqual(['pcmk:httpd'], out.xpath('/bundle/docker/@image'))
        self.assertEqual(['httpd-apache'], out.xpath('/bundle/crmsh-ref/@id'))

        out = self._parse('bundle httpd docker image=pcmk:httpd primitive httpd-apache apache')
        self.assertFalse(out)

    @mock.patch('logging.Logger.error')
    def test_op(self, mock_error):
        out = self._parse('monitor apache:Master 10s:20s')
        self.assertEqual(out.get('rsc'), 'apache')
        self.assertEqual(out.get('role'), 'Master')
        self.assertEqual(out.get('interval'), '10s')
        self.assertEqual(out.get('timeout'), '20s')

        out = self._parse('monitor apache 60m')
        self.assertEqual(out.get('rsc'), 'apache')
        self.assertEqual(out.get('role'), None)
        self.assertEqual(out.get('interval'), '60m')

        out = self._parse('primitive rsc_dummy1 Dummy op monitor interval=10 OCF_CHECK_LEVEL=10 timeout=60')
        # incorrect ordering of attributes
        self.assertFalse(out)

    @mock.patch('logging.Logger.error')
    def test_acl(self, mock_error):
        out = self._parse('role user-1 error')
        self.assertFalse(out)
        out = self._parse('user user-1 role:user-1')
        self.assertNotEqual(out, False)

        out = self._parse("role bigdb_admin " +
                          "write meta:bigdb:target-role " +
                          "write meta:bigdb:is-managed " +
                          "write location:bigdb " +
                          "read ref:bigdb")
        self.assertEqual(4, len(out))

        # new type of acls

        out = self._parse("acl_target foo a")
        self.assertEqual('acl_target', out.tag)
        self.assertEqual('foo', out.get('id'))
        self.assertEqual(['a'], out.xpath('./role/@id'))

        out = self._parse("acl_target foo a b")
        self.assertEqual('acl_target', out.tag)
        self.assertEqual('foo', out.get('id'))
        self.assertEqual(['a', 'b'], out.xpath('./role/@id'))

        out = self._parse("acl_target foo a b c")
        self.assertEqual('acl_target', out.tag)
        self.assertEqual('foo', out.get('id'))
        self.assertEqual(['a', 'b', 'c'], out.xpath('./role/@id'))
        out = self._parse("acl_group fee a b c")
        self.assertEqual('acl_group', out.tag)
        self.assertEqual('fee', out.get('id'))
        self.assertEqual(['a', 'b', 'c'], out.xpath('./role/@id'))
        out = self._parse('role fum description="test" read a: description="test2" xpath:*[@name=\\"karl\\"]')
        self.assertEqual(['*[@name="karl"]'], out.xpath('/acl_role/acl_permission/@xpath'))

    def test_xml(self):
        out = self._parse('xml <node uname="foo-1"/>')
        self.assertEqual('node', out.tag)
        self.assertEqual('foo-1', out.get('uname'))

    @mock.patch('logging.Logger.error')
    def test_property(self, mock_error):
        out = self._parse('property stonith-enabled=true')
        self.assertEqual(['true'], out.xpath('//nvpair[@name="stonith-enabled"]/@value'))

        # missing score
        out = self._parse('property rule #uname eq node1 stonith-enabled=no')
        self.assertEqual(['INFINITY'], out.xpath('//@score'))

        out = self._parse('property rule 10: #uname eq node1 stonith-enabled=no')
        self.assertEqual(['no'], out.xpath('//nvpair[@name="stonith-enabled"]/@value'))
        self.assertEqual(['node1'], out.xpath('//expression[@attribute="#uname"]/@value'))

        out = self._parse('property rule +inf: date spec years=2014 stonith-enabled=no')
        self.assertEqual(['no'], out.xpath('//nvpair[@name="stonith-enabled"]/@value'))
        self.assertEqual(['2014'], out.xpath('//date_spec/@years'))

        out = self._parse('rsc_defaults failure-timeout=3m')
        self.assertEqual(['3m'], out.xpath('//nvpair[@name="failure-timeout"]/@value'))

        out = self._parse('rsc_defaults foo: failure-timeout=3m')
        self.assertEqual('foo', out[0].get('id'))
        self.assertEqual(['3m'], out.xpath('//nvpair[@name="failure-timeout"]/@value'))

        out = self._parse('rsc_defaults failure-timeout=3m foo:')
        self.assertEqual(False, out)

    def test_empty_property_sets(self):
        out = self._parse('rsc_defaults defaults:')
        self.assertEqual('<rsc_defaults><meta_attributes id="defaults"/></rsc_defaults>',
                         xml_tostring(out))

        out = self._parse('op_defaults defaults:')
        self.assertEqual('<op_defaults><meta_attributes id="defaults"/></op_defaults>',
                         xml_tostring(out))

    def test_fencing(self):
        # num test nodes are 3

        out = self._parse('fencing_topology')
        expect = '<fencing-topology/>'
        self.assertEqual(expect, xml_tostring(out))

        out = self._parse('fencing_topology poison-pill power')
        expect = '<fencing-topology><fencing-level target="ha-one" index="1" devices="poison-pill"/><fencing-level target="ha-one" index="2" devices="power"/><fencing-level target="ha-three" index="1" devices="poison-pill"/><fencing-level target="ha-three" index="2" devices="power"/><fencing-level target="ha-two" index="1" devices="poison-pill"/><fencing-level target="ha-two" index="2" devices="power"/></fencing-topology>'
        self.assertEqual(expect, xml_tostring(out))

        out = self._parse('fencing_topology node-a: poison-pill power node-b: ipmi serial')
        self.assertEqual(4, len(out))

        devs = ['stonith-vbox3-1-off', 'stonith-vbox3-2-off',
                'stonith-vbox3-1-on', 'stonith-vbox3-2-on']
        out = self._parse('fencing_topology vbox4: %s' % ','.join(devs))
        print(xml_tostring(out))
        self.assertEqual(1, len(out))

    def test_fencing_1114(self):
        """
        Test node attribute fence target assignment
        """
        out = self._parse('fencing_topology attr:rack=1 poison-pill power')
        expect = """<fencing-topology><fencing-level index="1" devices="poison-pill" target-attribute="rack" target-value="1"/><fencing-level index="2" devices="power" target-attribute="rack" target-value="1"/></fencing-topology>"""
        self.assertEqual(expect, xml_tostring(out))

        out = self._parse('fencing_topology attr:rack=1 poison-pill,power')
        expect = '<fencing-topology><fencing-level index="1" devices="poison-pill,power" target-attribute="rack" target-value="1"/></fencing-topology>'
        self.assertEqual(expect, xml_tostring(out))

    @mock.patch('logging.Logger.error')
    def test_tag(self, mock_error):
        out = self._parse('tag tag1: one two three')
        self.assertEqual(out.get('id'), 'tag1')
        self.assertEqual(['one', 'two', 'three'], out.xpath('/tag/obj_ref/@id'))

        out = self._parse('tag tag1:')
        self.assertFalse(out)

        out = self._parse('tag tag1:: foo')
        self.assertFalse(out)

        out = self._parse('tag tag1 foo bar')
        self.assertEqual(out.get('id'), 'tag1')
        self.assertEqual(['foo', 'bar'], out.xpath('/tag/obj_ref/@id'))

    def test_alerts(self):
        "Test alerts (1.1.15+)"
        out = self._parse('alert alert1 /tmp/foo.sh to /tmp/bar.log')
        self.assertEqual(out.get('id'), 'alert1')
        self.assertEqual(['/tmp/foo.sh'],
                         out.xpath('/alert/@path'))
        self.assertEqual(['/tmp/bar.log'],
                         out.xpath('/alert/recipient/@value'))

    def test_alerts_brackets(self):
        "Test alerts w/ brackets (1.1.15+)"
        out = self._parse('alert alert2 /tmp/foo.sh to { /tmp/bar.log meta timeout=10s }')
        self.assertEqual(out.get('id'), 'alert2')
        self.assertEqual(['/tmp/foo.sh'],
                         out.xpath('/alert/@path'))
        self.assertEqual(['/tmp/bar.log'],
                         out.xpath('/alert/recipient/@value'))
        self.assertEqual(['10s'],
                         out.xpath('/alert/recipient/meta_attributes/nvpair[@name="timeout"]/@value'))

    def test_alerts_selectors(self):
        "Test alerts w/ selectors (1.1.17+)"
        out = self._parse('alert alert3 /tmp/foo.sh select nodes fencing attributes { standby shutdown } to { /tmp/bar.log meta timeout=10s }')
        self.assertEqual(out.get('id'), 'alert3')
        self.assertEqual(1, len(out.xpath('/alert/select/select_nodes')))
        self.assertEqual(1, len(out.xpath('/alert/select/select_fencing')))
        self.assertEqual(['standby', 'shutdown'],
                         out.xpath('/alert/select/select_attributes/attribute/@name'))


    def _parse_lines(self, lines):
        out = []
        for line in lines2cli(lines):
            if line is not None:
                tmp = self._parse(line.strip())
                self.assertNotEqual(tmp, False)
                if tmp is not None:
                    out.append(tmp)
        return out

    def test_comments(self):
        outp = self._parse_lines('''
        # comment
        node n1
        ''')
        self.assertNotEqual(-1, xml_tostring(outp[0]).find('# comment'))

    def test_uppercase(self):
        outp = self._parse_lines('''
        PRIMITIVE rsc_dummy ocf:heartbeat:Dummy
        MONITOR rsc_dummy 30
        ''')
        #print outp
        self.assertEqual('primitive', outp[0].tag)
        self.assertEqual('op', outp[1].tag)

        outp = self._parse_lines('''
        PRIMITIVE testfs ocf:heartbeat:Filesystem \
          PARAMS directory="/mnt" fstype="ocfs2" device="/dev/sda1"
        CLONE testfs-clone testfs \
          META ordered="true" interleave="true"
        ''')
        #print outp
        self.assertEqual('primitive', outp[0].tag)
        self.assertEqual('clone', outp[1].tag)

        out = self._parse('LOCATION loc-1 resource INF: foo')
        self.assertEqual(out.get('id'), 'loc-1')
        self.assertEqual(out.get('rsc'), 'resource')
        self.assertEqual(out.get('score'), 'INFINITY')
        self.assertEqual(out.get('node'), 'foo')

        out = self._parse('NODE node-1 ATTRIBUTES foo=bar UTILIZATION wiz=bang')
        self.assertEqual('node-1', out.get('uname'))
        self.assertEqual(['bar'], out.xpath('/node/instance_attributes/nvpair[@name="foo"]/@value'))
        self.assertEqual(['bang'], out.xpath('/node/utilization/nvpair[@name="wiz"]/@value'))

        out = self._parse('PRIMITIVE virtual-ip ocf:heartbeat:IPaddr2 PARAMS ip=192.168.122.13 lvs_support=false OP start timeout=20 interval=0 OP stop timeout=20 interval=0 OP monitor interval=10 timeout=20')
        self.assertEqual(['192.168.122.13'], out.xpath('//instance_attributes/nvpair[@name="ip"]/@value'))

        out = self._parse('GROUP web-server virtual-ip apache META target-role=Started')
        self.assertEqual(out.get('id'), 'web-server')

    def test_nvpair_novalue(self):
        inp = """primitive stonith_ipmi-karl stonith:fence_ipmilan \
        params pcmk_host_list=karl verbose action=reboot \
        ipaddr=10.43.242.221 login=root passwd=dummy method=onoff \
        op start interval=0 timeout=60 \
        op stop interval=0 timeout=60 \
        op monitor interval=600 timeout=60 \
        meta target-role=Started"""

        outp = self._parse_lines(inp)
        self.assertEqual(len(outp), 1)
        self.assertEqual('primitive', outp[0].tag)
        # print xml_tostring(outp[0])
        verbose = outp[0].xpath('//nvpair[@name="verbose"]')
        self.assertEqual(len(verbose), 1)
        self.assertTrue('value' not in verbose[0].attrib)

    @mock.patch('logging.Logger.error')
    def test_configs(self, mock_error):
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

        inp = [
            """node node1 attributes mem=16G""",
            """node node2 utilization cpu=4""",
            """primitive d1 ocf:pacemaker:Dummy \
            operations $id=d1-ops \
            op monitor interval=60m \
            op monitor interval=120m OCF_CHECK_LEVEL=10""",
            """monitor d1 60s:30s""",
            """primitive d2 ocf:heartbeat:Delay \
            params mondelay=60 \
            op start timeout=60s \
            op stop timeout=60s""",
            """monitor d2:Started 60s:30s""",
            """group g1 d1 d2""",
            """primitive d3 ocf:pacemaker:Dummy""",
            """clone c d3 \
            meta clone-max=1""",
            """primitive d4 ocf:pacemaker:Dummy""",
            """ms m d4""",
            """primitive s5 ocf:pacemaker:Stateful \
            operations $id-ref=d1-ops""",
            """primitive s6 ocf:pacemaker:Stateful \
            operations $id-ref=d1""",
            """ms m5 s5""",
            """ms m6 s6""",
            """location l1 g1 100: node1""",
            """location l2 c \
            rule $id=l2-rule1 100: #uname eq node1""",
            """location l3 m5 \
            rule inf: #uname eq node1 and pingd gt 0""",
            """location l4 m5 \
            rule -inf: not_defined pingd or pingd lte 0""",
            """location l5 m5 \
            rule -inf: not_defined pingd or pingd lte 0 \
            rule inf: #uname eq node1 and pingd gt 0 \
            rule inf: date lt "2009-05-26" and \
            date in start="2009-05-26" end="2009-07-26" and \
            date in start="2009-05-26" years="2009" and \
            date date_spec years="2009" hours=09-17""",
            """location l6 m5 \
            rule $id-ref=l2-rule1""",
            """location l7 m5 \
            rule $id-ref=l2""",
            """collocation c1 inf: m6 m5""",
            """collocation c2 inf: m5:Master d1:Started""",
            """order o1 Mandatory: m5 m6""",
            """order o2 Optional: d1:start m5:promote""",
            """order o3 Serialize: m5 m6""",
            """order o4 inf: m5 m6""",
            """rsc_ticket ticket-A_m6 ticket-A: m6""",
            """rsc_ticket ticket-B_m6_m5 ticket-B: m6 m5 loss-policy=fence""",
            """rsc_ticket ticket-C_master ticket-C: m6 m5:Master loss-policy=fence""",
            """fencing_topology st st2""",
            """property stonith-enabled=true""",
            """property $id=cpset2 maintenance-mode=true""",
            """rsc_defaults failure-timeout=10m""",
            """op_defaults $id=opsdef2 record-pending=true"""]

        outp = self._parse_lines('\n'.join(inp))
        a = [xml_tostring(x) for x in outp]
        b = [
            '<node uname="node1"><instance_attributes><nvpair name="mem" value="16G"/></instance_attributes></node>',
            '<node uname="node2"><utilization><nvpair name="cpu" value="4"/></utilization></node>',
            '<primitive id="d1" class="ocf" provider="pacemaker" type="Dummy"><operations id="d1-ops"><op name="monitor" interval="60m"/><op name="monitor" interval="120m"><instance_attributes><nvpair name="OCF_CHECK_LEVEL" value="10"/></instance_attributes></op></operations></primitive>',
            '<op name="monitor" rsc="d1" interval="60s" timeout="30s"/>',
            '<primitive id="d2" class="ocf" provider="heartbeat" type="Delay"><instance_attributes><nvpair name="mondelay" value="60"/></instance_attributes><operations><op name="start" timeout="60s" interval="0s"/><op name="stop" timeout="60s" interval="0s"/></operations></primitive>',
            '<op name="monitor" role="Started" rsc="d2" interval="60s" timeout="30s"/>',
            '<group id="g1"><crmsh-ref id="d1"/><crmsh-ref id="d2"/></group>',
            '<primitive id="d3" class="ocf" provider="pacemaker" type="Dummy"/>',
            '<clone id="c"><meta_attributes><nvpair name="clone-max" value="1"/></meta_attributes><crmsh-ref id="d3"/></clone>',
            '<primitive id="d4" class="ocf" provider="pacemaker" type="Dummy"/>',
            '<master id="m"><crmsh-ref id="d4"/></master>',
            '<primitive id="s5" class="ocf" provider="pacemaker" type="Stateful"><operations id-ref="d1-ops"/></primitive>',
            '<primitive id="s6" class="ocf" provider="pacemaker" type="Stateful"><operations id-ref="d1"/></primitive>',
            '<master id="m5"><crmsh-ref id="s5"/></master>',
            '<master id="m6"><crmsh-ref id="s6"/></master>',
            '<rsc_location id="l1" rsc="g1" score="100" node="node1"/>',
            '<rsc_location id="l2" rsc="c"><rule id="l2-rule1" score="100"><expression operation="eq" attribute="#uname" value="node1"/></rule></rsc_location>',
            '<rsc_location id="l3" rsc="m5"><rule score="INFINITY"><expression operation="eq" attribute="#uname" value="node1"/><expression operation="gt" attribute="pingd" value="0"/></rule></rsc_location>',
            '<rsc_location id="l4" rsc="m5"><rule score="-INFINITY" boolean-op="or"><expression operation="not_defined" attribute="pingd"/><expression operation="lte" attribute="pingd" value="0"/></rule></rsc_location>',
            '<rsc_location id="l5" rsc="m5"><rule score="-INFINITY" boolean-op="or"><expression operation="not_defined" attribute="pingd"/><expression operation="lte" attribute="pingd" value="0"/></rule><rule score="INFINITY"><expression operation="eq" attribute="#uname" value="node1"/><expression operation="gt" attribute="pingd" value="0"/></rule><rule score="INFINITY"><date_expression operation="lt" end="2009-05-26"/><date_expression operation="in_range" start="2009-05-26" end="2009-07-26"/><date_expression operation="in_range" start="2009-05-26"><duration years="2009"/></date_expression><date_expression operation="date_spec"><date_spec years="2009" hours="09-17"/></date_expression></rule></rsc_location>',
            '<rsc_location id="l6" rsc="m5"><rule id-ref="l2-rule1"/></rsc_location>',
            '<rsc_location id="l7" rsc="m5"><rule id-ref="l2"/></rsc_location>',
            '<rsc_colocation id="c1" score="INFINITY" rsc="m6" with-rsc="m5"/>',
            '<rsc_colocation id="c2" score="INFINITY" rsc="m5" rsc-role="Master" with-rsc="d1" with-rsc-role="Started"/>',
            '<rsc_order id="o1" kind="Mandatory" first="m5" then="m6"/>',
            '<rsc_order id="o2" kind="Optional" first="d1" first-action="start" then="m5" then-action="promote"/>',
            '<rsc_order id="o3" kind="Serialize" first="m5" then="m6"/>',
            '<rsc_order id="o4" kind="Mandatory" first="m5" then="m6"/>',
            '<rsc_ticket id="ticket-A_m6" ticket="ticket-A" rsc="m6"/>',
            '<rsc_ticket id="ticket-B_m6_m5" ticket="ticket-B" loss-policy="fence"><resource_set><resource_ref id="m6"/><resource_ref id="m5"/></resource_set></rsc_ticket>',
            '<rsc_ticket id="ticket-C_master" ticket="ticket-C" loss-policy="fence"><resource_set><resource_ref id="m6"/></resource_set><resource_set role="Master"><resource_ref id="m5"/></resource_set></rsc_ticket>',
            '<fencing-topology><fencing-level target="ha-one" index="1" devices="st"/><fencing-level target="ha-one" index="2" devices="st2"/><fencing-level target="ha-three" index="1" devices="st"/><fencing-level target="ha-three" index="2" devices="st2"/><fencing-level target="ha-two" index="1" devices="st"/><fencing-level target="ha-two" index="2" devices="st2"/></fencing-topology>',
            '<cluster_property_set><nvpair name="stonith-enabled" value="true"/></cluster_property_set>',
            '<cluster_property_set id="cpset2"><nvpair name="maintenance-mode" value="true"/></cluster_property_set>',
            '<rsc_defaults><meta_attributes><nvpair name="failure-timeout" value="10m"/></meta_attributes></rsc_defaults>',
            '<op_defaults><meta_attributes id="opsdef2"><nvpair name="record-pending" value="true"/></meta_attributes></op_defaults>',
            ]

        for result, expected in zip(a, b):
            self.maxDiff = None
            self.assertEqual(expected, result)

if __name__ == '__main__':
    unittest.main()
