from __future__ import unicode_literals
import os
import sys

try:
    import crmsh
except ImportError as e:
    pass

from crmsh import config
from crmsh import options
config.core.debug = True
options.regression_tests = True
_here = os.path.dirname(__file__)
config.path.sharedir = os.path.join(_here, "../../doc")
config.path.crm_dtd_dir = os.path.join(_here, "schemas")

os.environ["CIB_file"] = "test"


# install a basic CIB
from crmsh import cibconfig

_CIB = """
<cib epoch="0" num_updates="0" admin_epoch="0" validate-with="pacemaker-1.2" cib-last-written="Mon Mar  3 23:58:36 2014" update-origin="ha-one" update-client="crmd" update-user="hacluster" crm_feature_set="3.0.9" have-quorum="1" dc-uuid="1">
  <configuration>
    <crm_config>
      <cluster_property_set id="cib-bootstrap-options">
        <nvpair name="stonith-enabled" value="false" id="cib-bootstrap-options-stonith-enabled"/>
        <nvpair name="no-quorum-policy" value="ignore" id="cib-bootstrap-options-no-quorum-policy"/>
        <nvpair name="dc-version" value="1.1.11+git20140221.0b7d85a-115.1-1.1.11+git20140221.0b7d85a" id="cib-bootstrap-options-dc-version"/>
        <nvpair name="cluster-infrastructure" value="corosync" id="cib-bootstrap-options-cluster-infrastructure"/>
        <nvpair name="symmetric-cluster" value="true" id="cib-bootstrap-options-symmetric-cluster"/>
      </cluster_property_set>
    </crm_config>
    <nodes>
      <node id="ha-one" uname="ha-one"/>
      <node id="ha-two" uname="ha-two"/>
      <node id="ha-three" uname="ha-three"/>
    </nodes>
    <resources>
    </resources>
    <constraints>
    </constraints>
    <rsc_defaults>
      <meta_attributes id="rsc-options">
        <nvpair name="resource-stickiness" value="1" id="rsc-options-resource-stickiness"/>
        <nvpair name="migration-threshold" value="0" id="rsc-options-migration-threshold"/>
      </meta_attributes>
    </rsc_defaults>
    <op_defaults>
      <meta_attributes id="op-options">
        <nvpair name="timeout" value="200" id="op-options-timeout"/>
        <nvpair name="record-pending" value="true" id="op-options-record-pending"/>
      </meta_attributes>
    </op_defaults>
  </configuration>
  <status>
  </status>
</cib>
"""

cibconfig.cib_factory.initialize(cib=_CIB)

