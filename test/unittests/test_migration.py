import re
import unittest
from unittest import mock

import lxml.etree

from crmsh import migration, cibquery


class TestCheckRemovedResourceAgents(unittest.TestCase):
    def setUp(self):
        self._handler = mock.Mock(migration.CheckResultHandler)

    def test_load_unsupported_resource_agents(self):
        s = migration.UnsupportedResourceAgentDetector()
        self.assertEqual(
            migration.UnsupportedResourceAgentDetector.UnsupportedState(
                cibquery.ResourceAgent('ocf', 'heartbeat', 'IPaddr2'),
                False,
            ),
            s.get_unsupported_state(cibquery.ResourceAgent('ocf', 'heartbeat', 'IPaddr'))
        )
        self.assertEqual(
            migration.UnsupportedResourceAgentDetector.UnsupportedState(
                cibquery.ResourceAgent('stonith', None, 'fence_sbd'),
                False,
            ),
            s.get_unsupported_state(cibquery.ResourceAgent('stonith', None, 'external/sbd'))
        )
        self.assertEqual(
            migration.UnsupportedResourceAgentDetector.UnsupportedState(
                None,
                False,
            ),
            s.get_unsupported_state(cibquery.ResourceAgent('ocf', 'heartbeat', 'rkt'))
        )
        self.assertEqual(
            migration.UnsupportedResourceAgentDetector.UnsupportedState(
                cibquery.ResourceAgent('ocf', 'heartbeat', 'LVM-activate'),
                True,
            ),
            s.get_unsupported_state(cibquery.ResourceAgent('ocf', 'heartbeat', 'LVM'))
        )

    def test_check_version_range(self):
        def check_fn(x):
            migration._check_version_range(
                self._handler,
                'foo',
                (0, 2,),
                (1,),
                re.compile(r'^foo\s+(\d+(?:.\d+)*)'),
                x,
            )
        check_fn('foo 0.2')
        self._handler.handle_problem.assert_not_called()
        check_fn('foo 0.2.1')
        self._handler.handle_problem.assert_not_called()
        check_fn('foo 0.9')
        self._handler.handle_problem.assert_not_called()
        check_fn('foo 0.9.99')
        self._handler.handle_problem.assert_not_called()
        check_fn('foo 1')
        self._handler.handle_problem.assert_called()
        self._handler.handle_problem.reset_mock()
        check_fn('foo 1.0')
        self._handler.handle_problem.assert_called()
        self._handler.handle_problem.reset_mock()
        check_fn('foo 1.0.0')
        self._handler.handle_problem.assert_called()


class TestCheckObsoletedSapAscsErsMount(unittest.TestCase):
    XML_DATA = '''<?xml version="1.0" ?>
<cib crm_feature_set="3.16.1" validate-with="pacemaker-3.9" epoch="9" num_updates="0" admin_epoch="0" cib-last-written="Fri Sep 26 15:02:50 2025" update-origin="ha-1-1" update-client="cibadmin" update-user="root" have-quorum="1" dc-uuid="1">
  <configuration>
    <crm_config>
      <cluster_property_set id="cib-bootstrap-options">
        <nvpair id="cib-bootstrap-options-have-watchdog" name="have-watchdog" value="false"/>
        <nvpair id="cib-bootstrap-options-dc-version" name="dc-version" value="2.1.5+20221208.a3f44794f-150500.4.9-2.1.5+20221208.a3f44794f"/>
        <nvpair id="cib-bootstrap-options-cluster-infrastructure" name="cluster-infrastructure" value="corosync"/>
        <nvpair id="cib-bootstrap-options-cluster-name" name="cluster-name" value="hacluster"/>
        <nvpair name="stonith-enabled" value="false" id="cib-bootstrap-options-stonith-enabled"/>
      </cluster_property_set>
    </crm_config>
    <nodes>
      <node id="1" uname="ha-1-1"/>
    </nodes>
    <resources>
      <group id="ers_group">
        <primitive id="fs_ers" class="ocf" provider="heartbeat" type="Filesystem">
          <instance_attributes id="fs_ers-instance_attributes">
            <nvpair name="device" value="tmpfs" id="fs_ers-instance_attributes-device"/>
            <nvpair name="directory" value="/mnt/dummy" id="fs_ers-instance_attributes-directory"/>
            <nvpair name="fstype" value="tmpfs" id="fs_ers-instance_attributes-fstype"/>
          </instance_attributes>
        </primitive>
        <primitive id="ers_instance" class="ocf" provider="heartbeat" type="SAPInstance">
          <instance_attributes id="ers_instance-instance_attributes">
            <nvpair name="IS_ERS" value="true" id="ers_instance-instance_attributes-IS_ERS"/>
          </instance_attributes>
        </primitive>
      </group>
    </resources>
    <rsc_defaults>
      <meta_attributes id="build-resource-defaults">
        <nvpair id="build-resource-stickiness" name="resource-stickiness" value="1"/>
        <nvpair name="migration-threshold" value="3" id="rsc-options-migration-threshold"/>
      </meta_attributes>
    </rsc_defaults>
    <op_defaults>
      <meta_attributes id="op-options">
        <nvpair name="timeout" value="600" id="op-options-timeout"/>
        <nvpair name="record-pending" value="true" id="op-options-record-pending"/>
      </meta_attributes>
    </op_defaults>
  </configuration>
</cib>
'''

    def setUp(self):
        self.handler = mock.Mock(migration.CheckResultHandler)
        self.cib = lxml.etree.fromstring(self.XML_DATA)

    def test_check_obseleted_sap_ascs_ers_mount(self):
        migration._check_obseleted_sap_ascs_ers_mount(self.handler, self.cib)
        self.handler.handle_problem.assert_called_once_with(
            False,
            "Cluster-controlled filesystem setup for SAP ENSA2 is not supported in SLES 16. Please migrate to simple-mount setup.",
            ['* Filesystem resource "fs_ers" is ordered to start before SAPInstance ERS resource "ers_instance" in group "ers_group".']
        )

    def test_nvpair_boolean_value_case_insensitive(self):
        for val in ("True", "TRUE", "tRUE"):
            self.handler.handle_problem.reset_mock()
            xml_data = self.XML_DATA.replace('value="true"', f'value="{val}"')
            cib = lxml.etree.fromstring(xml_data)
            migration._check_obseleted_sap_ascs_ers_mount(self.handler, cib)
            self.handler.handle_problem.assert_called_once()


class TestCheckObsoleteSapAscsErsEnsa1(unittest.TestCase):
    XML_DATA = '''<?xml version="1.0" ?>
<cib crm_feature_set="3.16.1" validate-with="pacemaker-3.9" epoch="9" num_updates="0" admin_epoch="0" cib-last-written="Fri Sep 26 15:02:50 2025" update-origin="ha-1-1" update-client="cibadmin" update-user="root" have-quorum="1" dc-uuid="1">
  <configuration>
    <crm_config>
      <cluster_property_set id="cib-bootstrap-options">
        <nvpair id="cib-bootstrap-options-have-watchdog" name="have-watchdog" value="false"/>
        <nvpair id="cib-bootstrap-options-dc-version" name="dc-version" value="2.1.5+20221208.a3f44794f-150500.4.9-2.1.5+20221208.a3f44794f"/>
        <nvpair id="cib-bootstrap-options-cluster-infrastructure" name="cluster-infrastructure" value="corosync"/>
        <nvpair id="cib-bootstrap-options-cluster-name" name="cluster-name" value="hacluster"/>
        <nvpair name="stonith-enabled" value="false" id="cib-bootstrap-options-stonith-enabled"/>
      </cluster_property_set>
    </crm_config>
    <nodes>
      <node id="1" uname="ha-1-1"/>
    </nodes>
    <resources>
      <primitive id="ascs_instance" class="ocf" provider="heartbeat" type="SAPInstance" />
      <primitive id="ers_instance" class="ocf" provider="heartbeat" type="SAPInstance">
        <instance_attributes id="ers_instance-instance_attributes">
          <nvpair name="IS_ERS" value="true" id="ers_instance-instance_attributes-IS_ERS"/>
        </instance_attributes>
      </primitive>
    </resources>
    <constraints>
        <rsc_location id="loc_failover_to_ers" rsc="ascs_instance">
            <rule score="1000" id="loc_failover_to_ers-rule">
                <expression operation="eq" attribute="runs_ers_ers_instance" value="1" id="loc_failover_to_ers-rule-expression"/>
            </rule>
        </rsc_location>
    </constraints>
  </configuration>
</cib>
'''

    def setUp(self):
        self.handler = mock.Mock(migration.CheckResultHandler)
        self.cib = lxml.etree.fromstring(self.XML_DATA)

    def test_check_obsolete_sap_ascs_ers_ensa1(self):
        migration._check_obsolete_sap_ascs_ers_ensa1(self.handler, self.cib)
        self.handler.handle_problem.assert_called_once_with(
            False,
            "SAP ASCS/ERS ENSA1 is obsolete and not supported in SLES 16. Please migrate to ENSA2.",
            ['* SAPInstance resource "ascs_instance" has a location constraint with a rule matching the ENSA1 pattern (attribute "runs_ers_ers_instance").']
        )

    def test_score_zero_or_less_not_triggered(self):
        for score in ("0", "-100"):
            self.handler.handle_problem.reset_mock()
            xml_data = self.XML_DATA.replace('score="1000"', f'score="{score}"')
            cib = lxml.etree.fromstring(xml_data)
            migration._check_obsolete_sap_ascs_ers_ensa1(self.handler, cib)
            self.handler.handle_problem.assert_not_called()

    def test_nvpair_boolean_value_case_insensitive(self):
        for val in ("True", "TRUE", "tRUE"):
            self.handler.handle_problem.reset_mock()
            xml_data = self.XML_DATA.replace('value="true"', f'value="{val}"')
            cib = lxml.etree.fromstring(xml_data)
            migration._check_obsolete_sap_ascs_ers_ensa1(self.handler, cib)
            self.handler.handle_problem.assert_called_once()
