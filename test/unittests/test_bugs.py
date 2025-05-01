from __future__ import print_function
from __future__ import unicode_literals
# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
try:
    from unittest import mock
except ImportError:
    import mock

from crmsh import cibconfig
from lxml import etree
from crmsh import xmlutil, utils

factory = cibconfig.cib_factory


def setup_function():
    "set up test fixtures"
    from crmsh import idmgmt
    idmgmt.clear()
    factory._push_state()


def teardown_function():
    factory._pop_state()


def test_bug41660_1():
    xml = """<primitive id="bug41660" class="ocf" provider="pacemaker" type="Dummy"> \
    <meta_attributes id="bug41660-meta"> \
    <nvpair id="bug41660-meta-target-role" name="target-role" value="Stopped"/> \
    </meta_attributes> \
    </primitive>
"""
    data = etree.fromstring(xml)
    obj = factory.create_from_node(data)
    print(etree.tostring(obj.node))
    data = obj.repr_cli(format_mode=-1)
    print(data)
    exp = 'primitive bug41660 ocf:pacemaker:Dummy meta target-role=Stopped'
    assert data == exp
    assert obj.cli_use_validate()

    commit_holder = factory.commit
    try:
        factory.commit = lambda *args: True
        from crmsh.ui_resource import set_deep_meta_attr
        set_deep_meta_attr("bug41660", "target-role", "Started")
        assert ['Started'] == obj.node.xpath('.//nvpair[@name="target-role"]/@value')
    finally:
        factory.commit = commit_holder


def test_bug41660_2():
    xml = """
<clone id="libvirtd-clone">
 <primitive class="lsb" id="libvirtd" type="libvirtd">
  <operations>
   <op id="libvirtd-monitor-interval-15" interval="15" name="monitor" start-delay="15" timeout="15"/>
   <op id="libvirtd-start-interval-0" interval="0" name="start" on-fail="restart" timeout="15"/>
   <op id="libvirtd-stop-interval-0" interval="0" name="stop" on-fail="ignore" timeout="15"/>
  </operations>
  <meta_attributes id="libvirtd-meta_attributes"/>
 </primitive>
 <meta_attributes id="libvirtd-clone-meta">
  <nvpair id="libvirtd-interleave" name="interleave" value="true"/>
  <nvpair id="libvirtd-ordered" name="ordered" value="true"/>
  <nvpair id="libvirtd-clone-meta-target-role" name="target-role" value="Stopped"/>
 </meta_attributes>
</clone>
"""
    data = etree.fromstring(xml)
    obj = factory.create_from_node(data)
    assert obj is not None
    #data = obj.repr_cli(format_mode=-1)
    #print data
    #exp = 'clone libvirtd-clone libvirtd meta interleave=true ordered=true target-role=Stopped'
    #assert data == exp
    #assert obj.cli_use_validate()

    print(etree.tostring(obj.node))

    commit_holder = factory.commit
    try:
        factory.commit = lambda *args: True
        from crmsh.ui_resource import set_deep_meta_attr
        print("PRE", etree.tostring(obj.node))
        set_deep_meta_attr("libvirtd-clone", "target-role", "Started")
        print("POST", etree.tostring(obj.node))
        assert ['Started'] == obj.node.xpath('.//nvpair[@name="target-role"]/@value')
    finally:
        factory.commit = commit_holder


def test_bug41660_3():
    xml = """
<clone id="libvirtd-clone">
 <primitive class="lsb" id="libvirtd" type="libvirtd">
  <operations>
   <op id="libvirtd-monitor-interval-15" interval="15" name="monitor" start-delay="15" timeout="15"/>
   <op id="libvirtd-start-interval-0" interval="0" name="start" on-fail="restart" timeout="15"/>
   <op id="libvirtd-stop-interval-0" interval="0" name="stop" on-fail="ignore" timeout="15"/>
  </operations>
  <meta_attributes id="libvirtd-meta_attributes"/>
 </primitive>
 <meta_attributes id="libvirtd-clone-meta_attributes">
 <nvpair id="libvirtd-clone-meta_attributes-target-role" name="target-role" value="Stopped"/>
 </meta_attributes>
</clone>
"""
    data = etree.fromstring(xml)
    obj = factory.create_from_node(data)
    assert obj is not None
    data = obj.repr_cli(format_mode=-1)
    print(data)
    exp = 'clone libvirtd-clone libvirtd meta target-role=Stopped'
    assert data == exp
    assert obj.cli_use_validate()

    commit_holder = factory.commit
    try:
        factory.commit = lambda *args: True
        from crmsh.ui_resource import set_deep_meta_attr
        set_deep_meta_attr("libvirtd-clone", "target-role", "Started")
        assert ['Started'] == obj.node.xpath('.//nvpair[@name="target-role"]/@value')
    finally:
        factory.commit = commit_holder


def test_comments():
    xml = """<cib epoch="25" num_updates="1" admin_epoch="0" validate-with="pacemaker-1.2" cib-last-written="Thu Mar  6 15:53:49 2014" update-origin="beta1" update-client="cibadmin" update-user="root" crm_feature_set="3.0.8" have-quorum="1" dc-uuid="1">
  <configuration>
    <crm_config>
      <cluster_property_set id="cib-bootstrap-options">
        <nvpair id="cib-bootstrap-options-dc-version" name="dc-version" value="1.1.11-3.3-3ca8c3b"/>
        <nvpair id="cib-bootstrap-options-cluster-infrastructure" name="cluster-infrastructure" value="corosync"/>
        <!--# COMMENT TEXT 1 -->
      </cluster_property_set>
    </crm_config>
    <nodes>
      <node uname="beta1" id="1">
        <!--# COMMENT TEXT 2 -->
      </node>
    </nodes>
    <resources/>
    <constraints/>
    <rsc_defaults>
      <meta_attributes id="rsc-options">
        <nvpair name="resource-stickiness" value="1" id="rsc-options-resource-stickiness"/>
        <!--# COMMENT TEXT 3 -->
      </meta_attributes>
    </rsc_defaults>
  </configuration>
  <status>
    <node_state id="1" uname="beta1" in_ccm="true" crmd="online" crm-debug-origin="do_state_transition" join="member" expected="member">
      <lrm id="1">
        <lrm_resources/>
      </lrm>
      <transient_attributes id="1">
        <instance_attributes id="status-1">
          <nvpair id="status-1-shutdown" name="shutdown" value="0"/>
          <nvpair id="status-1-probe_complete" name="probe_complete" value="true"/>
        </instance_attributes>
      </transient_attributes>
    </node_state>
  </status>
</cib>"""
    elems = etree.fromstring(xml)
    xmlutil.sanitize_cib(elems)
    assert xmlutil.xml_tostring(elems).count("COMMENT TEXT") == 3


def test_eq1():
    xml1 = """<cluster_property_set id="cib-bootstrap-options">
    <nvpair id="cib-bootstrap-options-stonith-enabled" name="stonith-enabled" value="true"></nvpair>
    <nvpair id="cib-bootstrap-options-stonith-timeout" name="stonith-timeout" value="180"></nvpair>
    <nvpair id="cib-bootstrap-options-symmetric-cluster" name="symmetric-cluster" value="false"></nvpair>
    <nvpair id="cib-bootstrap-options-no-quorum-policy" name="no-quorum-policy" value="freeze"></nvpair>
    <nvpair id="cib-bootstrap-options-batch-limit" name="batch-limit" value="20"></nvpair>
    <nvpair id="cib-bootstrap-options-dc-version" name="dc-version" value="1.1.10-c1a326d"></nvpair>
    <nvpair id="cib-bootstrap-options-cluster-infrastructure" name="cluster-infrastructure" value="corosync"></nvpair>
    <nvpair id="cib-bootstrap-options-last-lrm-refresh" name="last-lrm-refresh" value="1391433789"></nvpair>
    <nvpair id="cib-bootstrap-options-is-managed-default" name="is-managed-default" value="true"></nvpair>
  </cluster_property_set>
  """
    xml2 = """<cluster_property_set id="cib-bootstrap-options">
    <nvpair id="cib-bootstrap-options-stonith-enabled" name="stonith-enabled" value="true"></nvpair>
    <nvpair id="cib-bootstrap-options-stonith-timeout" name="stonith-timeout" value="180"></nvpair>
    <nvpair id="cib-bootstrap-options-symmetric-cluster" name="symmetric-cluster" value="false"></nvpair>
    <nvpair id="cib-bootstrap-options-no-quorum-policy" name="no-quorum-policy" value="freeze"></nvpair>
    <nvpair id="cib-bootstrap-options-batch-limit" name="batch-limit" value="20"></nvpair>
    <nvpair id="cib-bootstrap-options-dc-version" name="dc-version" value="1.1.10-c1a326d"></nvpair>
    <nvpair id="cib-bootstrap-options-cluster-infrastructure" name="cluster-infrastructure" value="corosync"></nvpair>
    <nvpair id="cib-bootstrap-options-last-lrm-refresh" name="last-lrm-refresh" value="1391433789"></nvpair>
    <nvpair id="cib-bootstrap-options-is-managed-default" name="is-managed-default" value="true"></nvpair>
  </cluster_property_set>
    """
    e1 = etree.fromstring(xml1)
    e2 = etree.fromstring(xml2)
    assert xmlutil.xml_equals(e1, e2, show=True)


def test_pcs_interop_1():
    """
    pcs<>crmsh interop bug
    """

    xml = """<clone id="dummies">
        <meta_attributes id="dummies-meta">
          <nvpair name="globally-unique" value="false" id="dummies-meta-globally-unique"/>
        </meta_attributes>
        <meta_attributes id="dummies-meta_attributes">
          <nvpair id="dummies-meta_attributes-target-role" name="target-role" value="Stopped"/>
        </meta_attributes>
        <primitive id="dummy-1" class="ocf" provider="heartbeat" type="Dummy"/>
      </clone>"""
    elem = etree.fromstring(xml)
    from crmsh.ui_resource import set_deep_meta_attr_node

    assert len(elem.xpath(".//meta_attributes/nvpair[@name='target-role']")) == 1

    print("BEFORE:", etree.tostring(elem))

    set_deep_meta_attr_node(elem, 'target-role', 'Stopped')

    print("AFTER:", etree.tostring(elem))

    assert len(elem.xpath(".//meta_attributes/nvpair[@name='target-role']")) == 1


def test_bnc878128():
    """
    L3: "crm configure show" displays XML information instead of typical crm output.
    """
    xml = """<rsc_location id="cli-prefer-dummy-resource" rsc="dummy-resource"
role="Started">
  <rule id="cli-prefer-rule-dummy-resource" score="INFINITY">
    <expression id="cli-prefer-expr-dummy-resource" attribute="#uname"
operation="eq" value="x64-4"/>
    <date_expression id="cli-prefer-lifetime-end-dummy-resource" operation="lt"
end="2014-05-17 17:56:11Z"/>
  </rule>
</rsc_location>"""
    data = etree.fromstring(xml)
    obj = factory.create_from_node(data)
    assert obj is not None
    data = obj.repr_cli(format_mode=-1)
    print("OUTPUT:", data)
    exp = 'location cli-prefer-dummy-resource dummy-resource role=Started rule #uname eq x64-4 and date lt "2014-05-17 17:56:11Z"'
    assert data == exp
    assert obj.cli_use_validate()


def test_order_without_score_kind():
    """
    Spec says order doesn't require score or kind to be set
    """
    xml = '<rsc_order first="a" first-action="promote" id="order-a-b" then="b" then-action="start"/>'
    data = etree.fromstring(xml)
    obj = factory.create_from_node(data)
    assert obj is not None
    data = obj.repr_cli(format_mode=-1)
    print("OUTPUT:", data)
    exp = 'order order-a-b a:promote b:start'
    assert data == exp
    assert obj.cli_use_validate()



def test_bnc878112():
    """
    crm configure group can hijack a cloned primitive (and then crash)
    """
    obj1 = factory.create_object('primitive', 'p1', 'Dummy')
    assert obj1 is True
    obj2 = factory.create_object('group', 'g1', 'p1')
    assert obj2 is True
    obj3 = factory.create_object('group', 'g2', 'p1')
    print(obj3)
    assert obj3 is False


def test_copy_nvpairs():
    from crmsh.cibconfig import copy_nvpairs

    to = etree.fromstring('''
    <node>
    <nvpair name="stonith-enabled" value="true"/>
    </node>
    ''')
    copy_nvpairs(to, etree.fromstring('''
    <node>
    <nvpair name="stonith-enabled" value="false"/>
    </node>
    '''))

    assert ['stonith-enabled'] == to.xpath('./nvpair/@name')
    assert ['false'] == to.xpath('./nvpair/@value')

    copy_nvpairs(to, etree.fromstring('''
    <node>
    <nvpair name="stonith-enabled" value="true"/>
    </node>
    '''))

    assert ['stonith-enabled'] == to.xpath('./nvpair/@name')
    assert ['true'] == to.xpath('./nvpair/@value')


def test_pengine_test():
    xml = '''<primitive class="ocf" id="rsc1" provider="pacemaker" type="Dummy">
        <instance_attributes id="rsc1-instance_attributes-1">
          <nvpair id="rsc1-instance_attributes-1-state" name="state" value="/var/run/Dummy-rsc1-clusterA"/>
          <rule id="rsc1-instance_attributes-1-rule-1" score="0">
            <expression id="rsc1-instance_attributes-1-rule-1-expr-1" attribute="#cluster-name" operation="eq" value="clusterA"/>
          </rule>
        </instance_attributes>
        <instance_attributes id="rsc1-instance_attributes-2">
          <nvpair id="rsc1-instance_attributes-2-state" name="state" value="/var/run/Dummy-rsc1-clusterB"/>
          <rule id="rsc1-instance_attributes-2-rule-1" score="0">
            <expression id="rsc1-instance_attributes-2-rule-1-expr-1" attribute="#cluster-name" operation="eq" value="clusterB"/>
          </rule>
        </instance_attributes>
        <operations>
          <op id="rsc1-monitor-10s" interval="10s" name="monitor"/>
        </operations>
      </primitive>'''
    data = etree.fromstring(xml)
    obj = factory.create_from_node(data)
    assert obj is not None
    data = obj.repr_cli(format_mode=-1)
    print("OUTPUT:", data)
    exp = 'primitive rsc1 ocf:pacemaker:Dummy params rule 0: #cluster-name eq clusterA state="/var/run/Dummy-rsc1-clusterA" params rule 0: #cluster-name eq clusterB state="/var/run/Dummy-rsc1-clusterB" op monitor interval=10s'
    assert data == exp
    assert obj.cli_use_validate()


def test_tagset():
    xml = '''<primitive class="ocf" id="%s" provider="pacemaker" type="Dummy"/>'''
    tag = '''<tag id="t0"><obj_ref id="r1"/><obj_ref id="r2"/></tag>'''
    factory.create_from_node(etree.fromstring(xml % ('r1')))
    factory.create_from_node(etree.fromstring(xml % ('r2')))
    factory.create_from_node(etree.fromstring(xml % ('r3')))
    factory.create_from_node(etree.fromstring(tag))
    elems = factory.get_elems_on_tag("tag:t0")
    assert set(x.obj_id for x in elems) == set(['r1', 'r2'])


def test_op_role():
    xml = '''<primitive class="ocf" id="rsc2" provider="pacemaker" type="Dummy">
        <operations>
          <op id="rsc2-monitor-10s" interval="10s" name="monitor" role="Stopped"/>
        </operations>
      </primitive>'''
    data = etree.fromstring(xml)
    obj = factory.create_from_node(data)
    assert obj is not None
    data = obj.repr_cli(format_mode=-1)
    print("OUTPUT:", data)
    exp = 'primitive rsc2 ocf:pacemaker:Dummy op monitor interval=10s role=Stopped'
    assert data == exp
    assert obj.cli_use_validate()


def test_nvpair_no_value():
    xml = '''<primitive class="ocf" id="rsc3" provider="heartbeat" type="Dummy">
        <instance_attributes id="rsc3-instance_attributes-1">
          <nvpair id="rsc3-instance_attributes-1-verbose" name="verbose"/>
          <nvpair id="rsc3-instance_attributes-1-verbase" name="verbase" value=""/>
          <nvpair id="rsc3-instance_attributes-1-verbese" name="verbese" value=" "/>
        </instance_attributes>
      </primitive>'''
    data = etree.fromstring(xml)
    obj = factory.create_from_node(data)
    assert obj is not None
    data = obj.repr_cli(format_mode=-1)
    print("OUTPUT:", data)
    exp = 'primitive rsc3 Dummy params verbose verbase="" verbese=" "'
    assert data == exp
    assert obj.cli_use_validate()


def test_delete_ticket():
    xml0 = '<primitive id="daa0" class="ocf" provider="heartbeat" type="Dummy"/>'
    xml1 = '<primitive id="daa1" class="ocf" provider="heartbeat" type="Dummy"/>'
    xml2 = '''<rsc_ticket id="taa0" ticket="taaA">
        <resource_set id="taa0-0">
          <resource_ref id="daa0"/>
          <resource_ref id="daa1"/>
        </resource_set>
      </rsc_ticket>'''
    for x in (xml0, xml1, xml2):
        data = etree.fromstring(x)
        obj = factory.create_from_node(data)
        assert obj is not None
        data = obj.repr_cli(format_mode=-1)

    factory.delete('daa0')
    assert factory.find_object('daa0') is None
    assert factory.find_object('taa0') is not None


def test_quotes():
    """
    Parsing escaped quotes
    """
    xml = '''<primitive class="ocf" id="q1" provider="pacemaker" type="Dummy">
        <instance_attributes id="q1-instance_attributes-1">
          <nvpair id="q1-instance_attributes-1-state" name="state" value="foo&quot;foo&quot;"/>
        </instance_attributes>
    </primitive>
    '''
    data = etree.fromstring(xml)
    obj = factory.create_from_node(data)
    assert obj is not None
    data = obj.repr_cli(format_mode=-1)
    print("OUTPUT:", data)
    exp = 'primitive q1 ocf:pacemaker:Dummy params state="foo\\"foo\\""'
    assert data == exp
    assert obj.cli_use_validate()


def test_nodeattrs():
    """
    bug with parsing node attrs
    """
    xml = '''<node id="1" uname="dell71"> \
  <instance_attributes id="dell71-instance_attributes"> \
    <nvpair name="staging-0-0-placement" value="true" id="dell71-instance_attributes-staging-0-0-placement"/> \
    <nvpair name="meta-0-0-placement" value="true" id="dell71-instance_attributes-meta-0-0-placement"/> \
  </instance_attributes> \
  <instance_attributes id="nodes-1"> \
    <nvpair id="nodes-1-standby" name="standby" value="off"/> \
  </instance_attributes> \
</node>'''

    data = etree.fromstring(xml)
    obj = factory.create_from_node(data)
    assert obj is not None
    data = obj.repr_cli(format_mode=-1)
    exp = 'node 1: dell71 attributes staging-0-0-placement=true meta-0-0-placement=true attributes standby=off'
    assert data == exp
    assert obj.cli_use_validate()


def test_nodeattrs2():
    xml = """<node id="h04" uname="h04"> \
 <utilization id="h04-utilization"> \
   <nvpair id="h04-utilization-utl_ram" name="utl_ram" value="1200"/> \
   <nvpair id="h04-utilization-utl_cpu" name="utl_cpu" value="200"/> \
 </utilization> \
 <instance_attributes id="nodes-h04"> \
   <nvpair id="nodes-h04-standby" name="standby" value="off"/> \
 </instance_attributes> \
</node>"""
    data = etree.fromstring(xml)
    obj = factory.create_from_node(data)
    assert obj is not None
    data = obj.repr_cli(format_mode=-1)
    exp = 'node h04 utilization utl_ram=1200 utl_cpu=200 attributes standby=off'
    assert data == exp
    assert obj.cli_use_validate()


def test_group_constraint_location():
    """
    configuring a location constraint on a grouped resource is OK
    """
    factory.create_object('node', 'node1')
    factory.create_object('primitive', 'p1', 'Dummy')
    factory.create_object('primitive', 'p2', 'Dummy')
    factory.create_object('group', 'g1', 'p1', 'p2')
    factory.create_object('location', 'loc-p1', 'p1', 'inf:', 'node1')
    c = factory.find_object('loc-p1')
    assert c and c.check_sanity() == utils.VerifyResult.SUCCESS


def test_group_constraint_colocation():
    """
    configuring a colocation constraint on a grouped resource is bad
    """
    factory.create_object('primitive', 'p1', 'Dummy')
    factory.create_object('primitive', 'p2', 'Dummy')
    factory.create_object('group', 'g1', 'p1', 'p2')
    factory.create_object('colocation', 'coloc-p1-p2', 'inf:', 'p1', 'p2')
    c = factory.find_object('coloc-p1-p2')
    rc = c.check_sanity()
    assert c and bool(rc) is True and utils.VerifyResult.WARNING in rc


def test_group_constraint_colocation_rscset():
    """
    configuring a constraint on a grouped resource is bad
    """
    factory.create_object('primitive', 'p1', 'Dummy')
    factory.create_object('primitive', 'p2', 'Dummy')
    factory.create_object('primitive', 'p3', 'Dummy')
    factory.create_object('group', 'g1', 'p1', 'p2')
    factory.create_object('colocation', 'coloc-p1-p2-p3', 'inf:', 'p1', 'p2', 'p3')
    c = factory.find_object('coloc-p1-p2-p3')
    rc = c.check_sanity()
    assert c and bool(rc) is True and utils.VerifyResult.WARNING in rc


def test_clone_constraint_colocation_rscset():
    """
    configuring a constraint on a cloned resource is bad
    """
    factory.create_object('primitive', 'p1', 'Dummy')
    factory.create_object('primitive', 'p2', 'Dummy')
    factory.create_object('primitive', 'p3', 'Dummy')
    factory.create_object('clone', 'c1', 'p1')
    factory.create_object('colocation', 'coloc-p1-p2-p3', 'inf:', 'p1', 'p2', 'p3')
    c = factory.find_object('coloc-p1-p2-p3')
    rc = c.check_sanity()
    assert c and bool(rc) is True and utils.VerifyResult.WARNING in rc


def test_existing_node_resource():
    factory.create_object('primitive', 'ha-one', 'Dummy')

    n = factory.find_node('ha-one')
    assert factory.test_element(n)

    r = factory.find_resource('ha-one')
    assert factory.test_element(r)

    assert n != r

    assert factory.check_structure()
    factory.cli_use_validate_all()

    ok, s = factory.mkobj_set('ha-one')
    assert ok


@mock.patch("crmsh.log.LoggerUtils.line_number")
@mock.patch("crmsh.log.LoggerUtils.incr_lineno")
def test_existing_node_resource_2(mock_incr, mock_line_num):
    obj = cibconfig.mkset_obj()
    assert obj is not None

    from crmsh import clidisplay
    with clidisplay.nopretty():
        text = obj.repr()
    text += "\nprimitive ha-one Dummy"
    ok = obj.save(text)
    assert ok

    obj = cibconfig.mkset_obj()
    assert obj is not None
    with clidisplay.nopretty():
        text2 = obj.repr()

    assert sorted(text.split('\n')) == sorted(text2.split('\n'))


@mock.patch("crmsh.log.LoggerUtils.line_number")
@mock.patch("crmsh.log.LoggerUtils.incr_lineno")
def test_id_collision_breakage_1(mock_incr, mock_line_num):
    from crmsh import clidisplay

    obj = cibconfig.mkset_obj()
    assert obj is not None
    with clidisplay.nopretty():
        original_cib = obj.repr()
    print(original_cib)

    obj = cibconfig.mkset_obj()
    assert obj is not None

    ok = obj.save("""node node1
primitive p0 ocf:pacemaker:Dummy
primitive p1 ocf:pacemaker:Dummy
primitive p2 ocf:heartbeat:Delay \
    params startdelay=2 mondelay=2 stopdelay=2
primitive p3 ocf:pacemaker:Dummy
clone c1 p1
op_defaults timeout=60s
""")
    assert ok

    obj = cibconfig.mkset_obj()
    assert obj is not None
    ok = obj.save("""op_defaults timeout=2m
node node1 \
    attributes mem=16G
primitive p1 ocf:heartbeat:Dummy \
    op monitor interval=60m \
    op monitor interval=120m OCF_CHECK_LEVEL=10
""")
    assert ok

    obj = cibconfig.mkset_obj()
    with clidisplay.nopretty():
        text = obj.repr()
    text = text + "\nprimitive p2 ocf:heartbeat:Dummy"
    ok = obj.save(text)
    assert ok

    obj = cibconfig.mkset_obj()
    with clidisplay.nopretty():
        text = obj.repr()
    text = text + "\ngroup g1 p1 p2"
    ok = obj.save(text)
    assert ok

    obj = cibconfig.mkset_obj("g1")
    with clidisplay.nopretty():
        text = obj.repr()
    text = text.replace("group g1 p1 p2", "group g1 p1 p3")
    text = text + "\nprimitive p3 ocf:heartbeat:Dummy"
    ok = obj.save(text)
    assert ok

    obj = cibconfig.mkset_obj("g1")
    with clidisplay.nopretty():
        print(obj.repr().strip())
        assert obj.repr().strip() == "group g1 p1 p3"

    obj = cibconfig.mkset_obj()
    assert obj is not None
    ok = obj.save(original_cib)
    assert ok
    obj = cibconfig.mkset_obj()
    with clidisplay.nopretty():
        print("*** ORIGINAL")
        print(original_cib)
        print("*** NOW")
        print(obj.repr())
        assert original_cib == obj.repr()


@mock.patch("crmsh.log.LoggerUtils.line_number")
@mock.patch("crmsh.log.LoggerUtils.incr_lineno")
def test_id_collision_breakage_3(mock_incr, mock_line_num):
    from crmsh import clidisplay

    obj = cibconfig.mkset_obj()
    assert obj is not None
    with clidisplay.nopretty():
        original_cib = obj.repr()
    print(original_cib)

    obj = cibconfig.mkset_obj()
    assert obj is not None
    ok = obj.save("""node node1
primitive node1 Dummy params fake=something
    """)
    assert ok

    print("** baseline")
    obj = cibconfig.mkset_obj()
    assert obj is not None
    with clidisplay.nopretty():
        print(obj.repr())

    obj = cibconfig.mkset_obj()
    assert obj is not None
    ok = obj.save("""primitive node1 Dummy params fake=something-else
    """, remove=False, method='update')
    assert ok

    print("** end")

    obj = cibconfig.mkset_obj()
    assert obj is not None
    ok = obj.save(original_cib, remove=True, method='replace')
    assert ok
    obj = cibconfig.mkset_obj()
    with clidisplay.nopretty():
        print("*** ORIGINAL")
        print(original_cib)
        print("*** NOW")
        print(obj.repr())
        assert original_cib == obj.repr()


@mock.patch("crmsh.log.LoggerUtils.line_number")
@mock.patch("crmsh.log.LoggerUtils.incr_lineno")
def test_id_collision_breakage_2(mock_incr, mock_line_num):
    from crmsh import clidisplay

    obj = cibconfig.mkset_obj()
    assert obj is not None
    with clidisplay.nopretty():
        original_cib = obj.repr()
    print(original_cib)

    obj = cibconfig.mkset_obj()
    assert obj is not None

    ok = obj.save("""node 168633610: webui
node 168633611: node1
rsc_template web-server apache \
	params port=8000 \
	op monitor interval=10s
primitive d0 Dummy \
	meta target-role=Started
primitive d1 Dummy
primitive d2 Dummy
# Never use this STONITH agent in production!
primitive proxy systemd:haproxy \
	op monitor interval=10s
primitive proxy-vip IPaddr2 \
	params ip=10.13.37.20
primitive srv1 @web-server
primitive srv2 @web-server
primitive vip1 IPaddr2 \
	params ip=10.13.37.21 \
	op monitor interval=20s
primitive vip2 IPaddr2 \
	params ip=10.13.37.22 \
	op monitor interval=20s
primitive virtual-ip IPaddr2 \
	params ip=10.13.37.77 lvs_support=false \
	op start timeout=20 interval=0 \
	op stop timeout=20 interval=0 \
	op monitor interval=10 timeout=20
primitive yet-another-virtual-ip IPaddr2 \
	params ip=10.13.37.72 cidr_netmask=24 \
	op start interval=0 timeout=20 \
	op stop interval=0 timeout=20 \
	op monitor interval=10 timeout=20 \
	meta target-role=Started
group dovip d0 virtual-ip \
	meta target-role=Stopped
group g-proxy proxy-vip proxy
group g-serv1 vip1 srv1
group g-serv2 vip2 srv2
clone d2-clone d2 \
	meta target-role=Started
tag dummytag d0 d1 d1-on-node1 d2 d2-clone
# Never put the two web servers on the same node
colocation co-serv -inf: g-serv1 g-serv2
location d1-on-node1 d1 inf: node1
# Never put any web server or haproxy on webui
location l-avoid-webui { g-proxy g-serv1 g-serv2 } -inf: webui
# Prever to spread groups across nodes
location l-proxy g-proxy 200: node1
location l-serv1 g-serv1 200: node2
location l-serv2 g-serv2 200: node3
property cib-bootstrap-options: \
	have-watchdog=false \
	dc-version="1.1.13+git20150917.20c2178-224.2-1.1.13+git20150917.20c2178" \
	cluster-infrastructure=corosync \
	cluster-name=hacluster \
	stonith-enabled=true \
	no-quorum-policy=ignore
rsc_defaults rsc-options: \
	resource-stickiness=1 \
	migration-threshold=3
op_defaults op-options: \
	timeout=600 \
	record-pending=true
""")
    assert ok

    obj = cibconfig.mkset_obj()
    assert obj is not None
    ok = obj.save(original_cib)
    assert ok
    obj = cibconfig.mkset_obj()
    with clidisplay.nopretty():
        print("*** ORIGINAL")
        print(original_cib)
        print("*** NOW")
        print(obj.repr())
        assert original_cib == obj.repr()


def test_bug_110():
    """
    configuring attribute-based fencing-topology
    """
    factory.create_object(*"primitive stonith-libvirt stonith:fence_sbd".split())
    factory.create_object(*"primitive fence-nova stonith:fence_sbd".split())
    cmd = "fencing_topology attr:OpenStack-role=compute stonith-libvirt,fence-nova".split()
    ok = factory.create_object(*cmd)
    assert ok
    obj = cibconfig.mkset_obj()
    assert obj is not None

    for o in obj.obj_set:
        if o.node.tag == 'fencing-topology':
            assert o.check_sanity() == utils.VerifyResult.SUCCESS


@mock.patch("crmsh.log.LoggerUtils.line_number")
@mock.patch("crmsh.log.LoggerUtils.incr_lineno")
def test_reordering_resource_sets(mock_incr, mock_line_num):
    """
    Can we reorder resource sets?
    """
    from crmsh import clidisplay
    obj1 = factory.create_object('primitive', 'p1', 'Dummy')
    assert obj1 is True
    obj2 = factory.create_object('primitive', 'p2', 'Dummy')
    assert obj2 is True
    obj3 = factory.create_object('primitive', 'p3', 'Dummy')
    assert obj3 is True
    obj4 = factory.create_object('primitive', 'p4', 'Dummy')
    assert obj4 is True
    o1 = factory.create_object('order', 'o1', 'p1', 'p2', 'p3', 'p4')
    assert o1 is True

    obj = cibconfig.mkset_obj('o1')
    assert obj is not None
    rc = obj.save('order o1 p4 p3 p2 p1')
    assert rc == True

    obj2 = cibconfig.mkset_obj('o1')
    with clidisplay.nopretty():
        assert "order o1 p4 p3 p2 p1" == obj2.repr().strip()


def test_bug959895():
    """
    Allow importing XML with cloned groups
    """
    xml = """<clone id="c-bug959895">
    <group id="g-bug959895">
    <primitive id="p-bug959895-a" class="ocf" provider="pacemaker" type="Dummy" />
    <primitive id="p-bug959895-b" class="ocf" provider="pacemaker" type="Dummy" />
    </group>
</clone>
"""
    data = etree.fromstring(xml)
    obj = factory.create_from_node(data)
    print(etree.tostring(obj.node))
    data = obj.repr_cli(format_mode=-1)
    print(data)
    exp = 'clone c-bug959895 g-bug959895'
    assert data == exp
    assert obj.cli_use_validate()

    commit_holder = factory.commit
    try:
        factory.commit = lambda *args: True
        from crmsh.ui_resource import set_deep_meta_attr
        set_deep_meta_attr("c-bug959895", "target-role", "Started")
        assert ['Started'] == obj.node.xpath('.//nvpair[@name="target-role"]/@value')
    finally:
        factory.commit = commit_holder


def test_node_util_attr():
    """
    Handle node with utitilization before attributes correctly
    """
    xml = """<node id="aberfeldy" uname="aberfeldy">
  <utilization id="nodes-aberfeldy-utilization">
    <nvpair id="nodes-aberfeldy-utilization-cpu" name="cpu" value="2"/>
    <nvpair id="nodes-aberfeldy-utilization-memory" name="memory" value="500"/>
  </utilization>
  <instance_attributes id="nodes-aberfeldy">
    <nvpair id="nodes-aberfeldy-standby" name="standby" value="on"/>
  </instance_attributes>
</node>"""

    data = etree.fromstring(xml)
    obj = factory.create_from_node(data)
    print(etree.tostring(obj.node))
    data = obj.repr_cli(format_mode=-1)
    print(data)
    exp = 'node aberfeldy utilization cpu=2 memory=500 attributes standby=on'
    assert data == exp
    assert obj.cli_use_validate()


def test_dup_create_same_name():
    """
    Creating two objects with the same name
    """
    ok = factory.create_object(*"primitive dup1 Dummy".split())
    assert ok
    ok = factory.create_object(*"primitive dup1 Dummy".split())
    assert not ok


def test_dup_create():
    """
    Creating property sets with unknown properties
    """
    ok = factory.create_object(*"property hana_test1: hana_attribute_1=5 hana_attribute_2=mohican".split())
    assert ok
    ok = factory.create_object(*"property hana_test2: hana_attribute_1=5s a-b-c-d=e-f-g".split())
    assert ok
