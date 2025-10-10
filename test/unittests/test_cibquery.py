import unittest

import lxml.etree

from crmsh import cibquery
from crmsh.cibquery import ResourceAgent


class TestDataObjectResourceAgent(unittest.TestCase):
    def test_eq(self):
        self.assertEqual(ResourceAgent('foo', None, 'bar'), ResourceAgent('foo', None, 'bar'))

    def test_set_eq(self):
        self.assertSetEqual({ResourceAgent('foo', None, 'bar')}, {ResourceAgent('foo', None, 'bar')})


class TestCibQuery(unittest.TestCase):
    _TEST_DATA = """<?xml version="1.0" ?>
<cib crm_feature_set="3.16.1" validate-with="pacemaker-3.9" epoch="11" num_updates="3" admin_epoch="0" cib-last-written="Tue Dec 31 17:02:43 2024" update-origin="ha-1-1" update-client="cibadmin" update-user="root" have-quorum="1" dc-uuid="1">
  <configuration>
    <crm_config>
      <cluster_property_set id="cib-bootstrap-options">
        <nvpair id="cib-bootstrap-options-have-watchdog" name="have-watchdog" value="false"/>
        <nvpair id="cib-bootstrap-options-dc-version" name="dc-version" value="2.1.5+20221208.a3f44794f-150500.4.9-2.1.5+20221208.a3f44794f"/>
        <nvpair id="cib-bootstrap-options-cluster-infrastructure" name="cluster-infrastructure" value="corosync"/>
        <nvpair id="cib-bootstrap-options-cluster-name" name="cluster-name" value="hacluster"/>
        <nvpair name="stonith-enabled" value="true" id="cib-bootstrap-options-stonith-enabled"/>
        <nvpair id="cib-bootstrap-options-stonith-timeout" name="stonith-timeout" value="71"/>
      </cluster_property_set>
    </crm_config>
    <nodes>
      <node id="1" uname="ha-1-1"/>
    </nodes>
    <resources>
      <primitive id="admin-ip" class="ocf" provider="heartbeat" type="IPaddr2">
        <instance_attributes id="admin-ip-instance_attributes">
          <nvpair name="ip" value="192.168.122.17" id="admin-ip-instance_attributes-ip"/>
        </instance_attributes>
        <operations>
          <op name="monitor" interval="10" timeout="20" id="admin-ip-monitor-10"/>
        </operations>
      </primitive>
      <primitive id="stonith-sbd" class="stonith" type="external/sbd">
        <operations>
          <op name="monitor" timeout="20" interval="3600" id="stonith-sbd-monitor-3600"/>
          <op name="start" timeout="20" interval="0s" id="stonith-sbd-start-0s"/>
          <op name="stop" timeout="15" interval="0s" id="stonith-sbd-stop-0s"/>
        </operations>
      </primitive>
      <clone id="ocfs2-clone">
        <meta_attributes id="ocfs2-clone-meta_attributes">
          <nvpair name="interleave" value="true" id="ocfs2-clone-meta_attributes-interleave"/>
        </meta_attributes>
        <group id="ocfs2-group">
          <primitive id="ocfs2-dlm" class="ocf" provider="pacemaker" type="controld">
            <operations>
              <op name="start" timeout="90" interval="0s" id="ocfs2-dlm-start-0s"/>
              <op name="stop" timeout="100" interval="0s" id="ocfs2-dlm-stop-0s"/>
              <op name="monitor" interval="60" timeout="60" id="ocfs2-dlm-monitor-60"/>
            </operations>
          </primitive>
          <primitive id="ocfs2-clusterfs" class="ocf" provider="heartbeat" type="Filesystem">
            <instance_attributes id="ocfs2-clusterfs-instance_attributes">
              <nvpair name="directory" value="/srv/clusterfs" id="ocfs2-clusterfs-instance_attributes-directory"/>
              <nvpair name="fstype" value="ocfs2" id="ocfs2-clusterfs-instance_attributes-fstype"/>
              <nvpair name="device" value="/dev/disk/by-partlabel/ocfs2-157" id="ocfs2-clusterfs-instance_attributes-device"/>
            </instance_attributes>
            <operations>
              <op name="monitor" interval="20" timeout="40" id="ocfs2-clusterfs-monitor-20"/>
              <op name="start" timeout="60" interval="0s" id="ocfs2-clusterfs-start-0s"/>
              <op name="stop" timeout="60" interval="0s" id="ocfs2-clusterfs-stop-0s"/>
            </operations>
          </primitive>
        </group>
      </clone>
    </resources>
    <constraints/>
    <rsc_defaults>
      <meta_attributes id="build-resource-defaults">
        <nvpair id="build-resource-stickiness" name="resource-stickiness" value="1"/>
        <nvpair name="migration-threshold" value="3" id="rsc-options-migration-threshold"/>
        <nvpair name="priority" value="0" id="rsc-options-priority"/>
      </meta_attributes>
    </rsc_defaults>
    <op_defaults>
      <meta_attributes id="op-options">
        <nvpair name="timeout" value="600" id="op-options-timeout"/>
        <nvpair name="record-pending" value="true" id="op-options-record-pending"/>
      </meta_attributes>
    </op_defaults>
  </configuration>
</cib>"""

    def setUp(self) -> None:
        self.cib = lxml.etree.fromstring(self._TEST_DATA)
    
    def test_get_resource_agents(self):
        self.assertSetEqual(
            {
                ResourceAgent('ocf', 'heartbeat', 'IPaddr2'),
                ResourceAgent('stonith', None, 'external/sbd'),
                ResourceAgent('ocf', 'heartbeat', 'Filesystem'),
                ResourceAgent('ocf', 'pacemaker', 'controld'),
            },
            cibquery.get_configured_resource_agents(self.cib),
        )

    def test_has_primitive_filesystem_with_fstype(self):
        self.assertTrue(cibquery.has_primitive_filesystem_with_fstype(self.cib, 'ocfs2'))
        self.assertFalse(cibquery.has_primitive_filesystem_with_fstype(self.cib, 'foo'))

    def test_get_node_name_by_id(self):
        self.assertEqual(cibquery.get_node_name_by_id(self.cib, 1), "ha-1-1")
        self.assertIsNone(cibquery.get_node_name_by_id(self.cib, 2))
