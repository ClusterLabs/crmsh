from __future__ import print_function
from __future__ import unicode_literals
# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
#
# unit tests for cliformat.py

from crmsh import cibconfig
from crmsh import parse
from lxml import etree
from .test_parse import MockValidation

factory = cibconfig.cib_factory


def assert_is_not_none(thing):
    assert thing is not None, "Expected non-None value"


def roundtrip(cli, debug=False, expected=None, format_mode=-1, strip_color=False):
    parse.validator = MockValidation()
    node, _, _ = cibconfig.parse_cli_to_xml(cli)
    assert_is_not_none(node)
    obj = factory.find_object(node.get("id"))
    if obj:
        factory.delete(node.get("id"))
    obj = factory.create_from_node(node)
    assert_is_not_none(obj)
    obj.nocli = True
    xml = obj.repr_cli(format_mode=format_mode)
    print(xml)
    obj.nocli = False
    s = obj.repr_cli(format_mode=format_mode)
    if strip_color:
        import re
        s = re.sub(r"\$\{[^}]+\}", "", s)
    if (s != cli) or debug:
        print("GOT:", s)
        print("EXP:", cli)
    assert obj.cli_use_validate()
    if expected is not None:
        assert expected == s
    else:
        assert cli == s
    assert not debug


def setup_function():
    "set up test fixtures"
    from crmsh import idmgmt
    idmgmt.clear()


def teardown_function():
    "tear down test fixtures"


def test_rscset():
    roundtrip('colocation foo inf: a b')
    roundtrip('order order_2 Mandatory: [ A B ] C')
    roundtrip('rsc_template public_vm Xen')


''' Seems rely on cluster env, should be in functional test
def test_normalize():
    """
    Test automatic normalization of parameter names:
    "shutdown_timeout" is a parameter name, but
    "shutdown-timeout" is not.
    """
    roundtrip('primitive vm1 Xen params shutdown-timeout=0',
              expected='primitive vm1 Xen params shutdown_timeout=0')
'''


def test_group():
    factory.create_from_cli('primitive p1 Dummy')
    roundtrip('group g1 p1 params target-role=Stopped')


def test_bnc863736():
    roundtrip('order order_3 Mandatory: [ A B ] C symmetrical=true')


def test_sequential():
    roundtrip('colocation rsc_colocation-master inf: [ vip-master vip-rep sequential=true ] [ msPostgresql:Master sequential=true ]')


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
    obj = factory.create_from_node(data)
    assert_is_not_none(obj)
    data = obj.repr_cli(format_mode=-1)
    assert 'colocation colo-2 inf: [ vip1 vip2 sequential=true ] [ apache:Master sequential=true ]' == data
    assert obj.cli_use_validate()


def test_comment():
    roundtrip("# comment 1\nprimitive d0 ocf:pacemaker:Dummy", format_mode=0, strip_color=True)


def test_comment2():
    roundtrip("# comment 1\n# comment 2\n# comment 3\nprimitive d0 ocf:pacemaker:Dummy", format_mode=0, strip_color=True)


def test_nvpair_ref1():
    factory.create_from_cli("primitive dummy-0 Dummy params $fiz:buz=bin")
    roundtrip('primitive dummy-1 Dummy params @fiz')


def test_idresolve():
    factory.create_from_cli("primitive dummy-5 Dummy params buz=bin")
    roundtrip('primitive dummy-1 Dummy params @dummy-5-instance_attributes-buz')


def test_ordering():
    xml = """<primitive id="dummy" class="ocf" provider="pacemaker" type="Dummy"> \
  <operations> \
    <op name="start" timeout="60s" interval="0s" id="dummy-start-0s"/> \
    <op name="stop" timeout="60s" interval="0s" id="dummy-stop-0s"/> \
    <op name="monitor" interval="60s" timeout="30s" id="dummy-monitor-60s"/> \
  </operations> \
  <meta_attributes id="dummy-meta_attributes"> \
    <nvpair id="dummy-meta_attributes-target-role" name="target-role"
value="Stopped"/> \
  </meta_attributes> \
</primitive>"""
    data = etree.fromstring(xml)
    obj = factory.create_from_node(data)
    assert_is_not_none(obj)
    data = obj.repr_cli(format_mode=-1)
    print(data)
    exp = 'primitive dummy ocf:pacemaker:Dummy op start timeout=60s interval=0s op stop timeout=60s interval=0s op monitor interval=60s timeout=30s meta target-role=Stopped'
    assert exp == data
    assert obj.cli_use_validate()


def test_ordering2():
    xml = """<primitive id="dummy2" class="ocf" provider="pacemaker" type="Dummy"> \
  <meta_attributes id="dummy2-meta_attributes"> \
    <nvpair id="dummy2-meta_attributes-target-role" name="target-role"
value="Stopped"/> \
  </meta_attributes> \
  <operations> \
    <op name="start" timeout="60s" interval="0s" id="dummy2-start-0s"/> \
    <op name="stop" timeout="60s" interval="0s" id="dummy2-stop-0s"/> \
    <op name="monitor" interval="60s" timeout="30s" id="dummy2-monitor-60s"/> \
  </operations> \
</primitive>"""
    data = etree.fromstring(xml)
    obj = factory.create_from_node(data)
    assert_is_not_none(obj)
    data = obj.repr_cli(format_mode=-1)
    print(data)
    exp = 'primitive dummy2 ocf:pacemaker:Dummy meta target-role=Stopped ' \
          'op start timeout=60s interval=0s op stop timeout=60s interval=0s ' \
          'op monitor interval=60s timeout=30s'
    assert exp == data
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
    obj = factory.create_from_node(data)
    assert_is_not_none(obj)
    data = obj.repr_cli(format_mode=-1)
    print(data)
    exp = 'fencing_topology st1'
    assert exp == data
    assert obj.cli_use_validate()


def test_fencing2():
    xml = """<fencing-topology>
    <fencing-level devices="apple" id="fencing" index="1"
target-pattern="green.*"></fencing-level>
    <fencing-level devices="pear" id="fencing" index="2"
target-pattern="green.*"></fencing-level>
    <fencing-level devices="pear" id="fencing" index="1"
target-pattern="red.*"></fencing-level>
    <fencing-level devices="apple" id="fencing" index="2"
target-pattern="red.*"></fencing-level>
  </fencing-topology>"""
    data = etree.fromstring(xml)
    obj = factory.create_from_node(data)
    assert_is_not_none(obj)
    data = obj.repr_cli(format_mode=-1)
    print(data)
    exp = 'fencing_topology pattern:green.* apple pear pattern:red.* pear apple'
    assert exp == data
    assert obj.cli_use_validate()


def test_master():
    xml = """<master id="ms-1">
    <crmsh-ref id="dummy3" />
    </master>
    """
    data = etree.fromstring(xml)
    factory.create_from_cli("primitive dummy3 ocf:pacemaker:Dummy")
    data, _, _ = cibconfig.postprocess_cli(data)
    print("after postprocess:", etree.tostring(data))
    obj = factory.create_from_node(data)
    assert_is_not_none(obj)
    assert obj.cli_use_validate()


def test_param_rules():
    roundtrip('primitive foo Dummy ' +
              'params rule #uname eq wizbang laser=yes ' +
              'params rule #uname eq gandalf staff=yes')

    roundtrip('primitive mySpecialRsc me:Special ' +
              'params 3: rule #uname eq node1 interface=eth1 ' +
              'params 2: rule #uname eq node2 interface=eth2 port=8888 ' +
              'params 1: interface=eth0 port=9999')


def test_operation_rules():
    roundtrip('primitive test Dummy ' +
              'op start interval=0s '
              'op_params 2: rule #uname eq node1 fake=fake ' +
              'op_params 1: fake=real ' +
              'op_meta 2: rule #ra-version version:gt 1.0 timeout=120s ' +
              'op_meta 1: timeout=60s')


def test_multiple_attrsets():
    roundtrip('primitive mySpecialRsc me:Special ' +
              'params 3: interface=eth1 ' +
              'params 2: port=8888')
    roundtrip('primitive mySpecialRsc me:Special ' +
              'meta 3: interface=eth1 ' +
              'meta 2: port=8888')


def test_new_acls():
    roundtrip('role fum description=test read description=test2 xpath:"*[@name=karl]"')


def test_acls_reftype():
    roundtrip('role boo deny ref:d0 type:nvpair',
              expected='role boo deny ref:d0 deny type:nvpair')


def test_acls_oldsyntax():
    roundtrip('role boo deny ref:d0 tag:nvpair',
              expected='role boo deny ref:d0 deny type:nvpair')


def test_rules():
    roundtrip('primitive p1 Dummy params ' +
              'rule $role=Started date in start=2009-05-26 end=2010-05-26 ' +
              'or date gt 2014-01-01 state=2')


def test_new_role():
    roundtrip('role silly-role-2 read xpath:"//nodes//attributes" ' +
              'deny type:nvpair deny ref:d0 deny type:nvpair')


def test_topology_1114():
    roundtrip('fencing_topology attr:rack=1 node1,node2')


def test_topology_1114_pattern():
    roundtrip('fencing_topology pattern:.* network disk')


def test_locrule():
    roundtrip('location loc-testfs-with-eth1 testfs rule ethmonitor-eth1 eq 1')


def test_is_value_sane():
    roundtrip('''primitive p1 Dummy params state="bo'o"''')


def test_is_value_sane_2():
    roundtrip('primitive p1 Dummy params state="bo\\"o"')


def test_alerts_1():
    roundtrip('alert alert1 "/tmp/foo.sh" to "/tmp/bar.log"')


def test_alerts_2():
    roundtrip('alert alert2 "/tmp/foo.sh" attributes foo=bar to "/tmp/bar.log"')


def test_alerts_3():
    roundtrip('alert alert3 "a path here" meta baby to "/tmp/bar.log"')


def test_alerts_4():
    roundtrip('alert alert4 "/also/a/path"')


def test_alerts_5():
    roundtrip('alert alert5 "/a/path" to { "/another/path" } meta timeout=30s')


def test_alerts_6():
    roundtrip('alert alert6 "/a/path" select fencing attributes { standby } to { "/another/path" } meta timeout=30s')


def test_alerts_7():
    roundtrip('alert alert7 "/a/path" select fencing attributes foo=bar to { "/another/path" } meta timeout=30s')
