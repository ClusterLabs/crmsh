# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
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
# unit tests for cliformat.py

import utils
import parse
import cibconfig
from lxml import etree
from test_parse import MockValidation

factory = cibconfig.cib_factory


def mk_cli_list(cli):
    'Sometimes we get a string and sometimes a list.'
    if isinstance(cli, basestring):
        cp = parse.CliParser()
        mv = MockValidation()
        for p in cp.parsers.values():
            p.validation = mv
        # what follows looks strange, but the last string actually matters
        # the previous ones may be comments and are collected by the parser
        for s in utils.lines2cli(cli):
            cli_list = cp.parse2(s)
        return cli_list
    else:
        return cli


def roundtrip(type, name, cli, debug=False):
    obj = factory.new_object(type, name)
    assert obj is not None
    cli_list = mk_cli_list(cli)
    node = obj.cli2node(cli_list)
    assert node is not None
    obj.node = node
    obj.set_id()
    obj.nocli = True
    xml = obj.repr_cli(format=-1)
    print xml
    obj.nocli = False
    s = obj.repr_cli(format=-1)
    if s != cli:
        print "GOT:", s
        print "EXP:", cli
    if debug:
        print s
        print cli
    assert obj.cli_use_validate()
    assert s == cli
    if debug:
        assert False


def setup_func():
    "set up test fixtures"
    import idmgmt
    idmgmt.IdMgmt.getInstance().clear()


def teardown_func():
    "tear down test fixtures"


def test_rscset():
    roundtrip('colocation', 'foo', 'colocation foo inf: a b')
    roundtrip('order', 'order_2', 'order order_2 Mandatory: [ A B ] C')
    roundtrip('rsc_template', 'public_vm', 'rsc_template public_vm Xen')


def test_bnc863736():
    roundtrip('order', 'order_3', 'order order_3 Mandatory: [ A B ] C symmetrical=true')


def test_sequential():
    roundtrip('colocation', 'rsc_colocation-master',
              'colocation rsc_colocation-master inf: [ vip-master vip-rep sequential=true ] [ msPostgresql:Master sequential=true ]')

def test_broken_colo():
    xml = """<rsc_colocation id="colo-2" score="INFINITY">
  <resource_set id="colo-2-0" require-all="false">
    <resource_ref id="vip1"/>
    <resource_ref id="vip2"/>
  </resource_set>
  <resource_set id="colo-2-1" require-all="false" role="Master">
    <resource_ref id="apache"/>
  </resource_set>
</rsc_colocation>"""
    data = etree.fromstring(xml)
    obj = factory.new_object('colocation', 'colo-2')
    assert obj is not None
    obj.node = data
    obj.set_id()
    data = obj.repr_cli(format=-1)
    print data
    assert data == 'colocation colo-2 inf: [ vip1 vip2 sequential=true ] [ apache:Master sequential=true ]'
    assert obj.cli_use_validate()


def test_comment():
    roundtrip('primitive', 'd0', "# comment 1\nprimitive d0 ocf:pacemaker:Dummy")


def test_ordering():
    xml = """<primitive id="dummy" class="ocf" provider="pacemaker" type="Dummy"> \
  <operations> \
    <op name="start" timeout="60" interval="0" id="dummy-start-0"/> \
    <op name="stop" timeout="60" interval="0" id="dummy-stop-0"/> \
    <op name="monitor" interval="60" timeout="30" id="dummy-monitor-60"/> \
  </operations> \
  <meta_attributes id="dummy-meta_attributes"> \
    <nvpair id="dummy-meta_attributes-target-role" name="target-role"
value="Stopped"/> \
  </meta_attributes> \
</primitive>"""
    data = etree.fromstring(xml)
    obj = factory.new_object('primitive', 'dummy')
    assert obj is not None
    obj.node = data
    obj.set_id()
    data = obj.repr_cli(format=-1)
    print data
    exp = 'primitive dummy ocf:pacemaker:Dummy op start timeout=60 interval=0 op stop timeout=60 interval=0 op monitor interval=60 timeout=30 meta target-role=Stopped'
    assert data == exp
    assert obj.cli_use_validate()


def test_ordering2():
    xml = """<primitive id="dummy2" class="ocf" provider="pacemaker" type="Dummy"> \
  <meta_attributes id="dummy2-meta_attributes"> \
    <nvpair id="dummy2-meta_attributes-target-role" name="target-role"
value="Stopped"/> \
  </meta_attributes> \
  <operations> \
    <op name="start" timeout="60" interval="0" id="dummy2-start-0"/> \
    <op name="stop" timeout="60" interval="0" id="dummy2-stop-0"/> \
    <op name="monitor" interval="60" timeout="30" id="dummy2-monitor-60"/> \
  </operations> \
</primitive>"""
    data = etree.fromstring(xml)
    obj = factory.new_object('primitive', 'dummy2')
    assert obj is not None
    obj.node = data
    obj.set_id()
    data = obj.repr_cli(format=-1)
    print data
    exp = 'primitive dummy2 ocf:pacemaker:Dummy meta target-role=Stopped op start timeout=60 interval=0 op stop timeout=60 interval=0 op monitor interval=60 timeout=30'
    assert data == exp
    assert obj.cli_use_validate()

def test_fencing():
    xml = """<fencing-topology>
    <fencing-level devices="st1" id="fencing" index="1"
target="ha-three"></fencing-level>
    <fencing-level devices="st1" id="fencing-0" index="1"
target="ha-two"></fencing-level>
    <fencing-level devices="st1" id="fencing-1" index="1"
target="ha-one"></fencing-level>
  </fencing-topology>"""
    data = etree.fromstring(xml)
    obj = factory.new_object('fencing_topology', 'st1')
    assert obj is not None
    obj.node = data
    obj.set_id()
    data = obj.repr_cli(format=-1)
    print data
    exp = 'fencing_topology st1'
    assert data == exp
    assert obj.cli_use_validate()


def test_degenerate_set():
    xml = """<rsc_colocation id="colo-3" score="INFINITY">
  <resource_set id="colo-3-0">
    <resource_ref id="vip1"/>
    <resource_ref id="vip2"/>
  </resource_set>
</rsc_colocation>"""
    data = etree.fromstring(xml)
    obj = factory.new_object('colocation', 'colo-3')
    assert obj is not None
    obj.node = data
    obj.set_id()
    data = obj.repr_cli(format=-1)
    print data
    assert data == 'colocation colo-3 inf: ( vip1 vip2 sequential=true )'
    assert obj.cli_use_validate()

