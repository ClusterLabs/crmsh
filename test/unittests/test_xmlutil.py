from lxml import etree
import unittest

try:
    from unittest import mock
except ImportError:
    import mock

from crmsh import xmlutil, constants

FAKE_XML = '''
<data>
  <nodes>
    <node name="tbw-1" id="1084783148" online="true" standby="true" standby_onfail="false" maintenance="false" pending="false" unclean="false" shutdown="false" expected_up="true" is_dc="true" resources_running="3" type="member"/>
    <node name="tbw-2" id="1084783312" online="false" standby="false" standby_onfail="false" maintenance="false" pending="false" unclean="false" shutdown="false" expected_up="true" is_dc="false" resources_running="2" type="member"/>
    <node name="tbw-3" id="alp-2" online="true" standby="false" standby_onfail="false" maintenance="true" pending="false" unclean="false" health="green" shutdown="false" expected_up="false" is_dc="false" resources_running="0" type="remote"/>
  </nodes>
  <resources>
    <resource id="ocfs2-dlm" resource_agent="ocf:pacemaker:controld" role="Started" active="true" orphaned="false" blocked="false" managed="true" failed="false" failure_ignored="false" nodes_running_on="1">
      <node name="tbw-2" id="1084783312" cached="true"/>
    </resource>
    <resource id="ocfs2-clusterfs" resource_agent="ocf:heartbeat:Filesystem" role="Started" active="true" orphaned="false" blocked="false" managed="true" failed="false" failure_ignored="false" nodes_running_on="1">
      <node name="tbw-2" id="1084783312" cached="true"/>
    </resource>
  </resources>
</data>
'''


class TestCrmMonXmlParser(unittest.TestCase):
    """
    Unitary tests for crmsh.xmlutil.CrmMonXmlParser
    """
    @mock.patch('crmsh.sh.cluster_shell')
    def setUp(self, mock_cluster_shell):
        """
        Test setUp.
        """
        mock_cluster_shell().get_rc_stdout_stderr_without_input.return_value = (0, FAKE_XML, '')
        self.parser_inst = xmlutil.CrmMonXmlParser()

    def test_is_node_online(self):
        assert self.parser_inst.is_node_online("tbw-1") is True
        assert self.parser_inst.is_node_online("tbw-2") is False

    def test_is_node_maintenance(self):
        assert self.parser_inst.is_node_maintenance("tbw-1") is False
        assert self.parser_inst.is_node_maintenance("tbw-3") is True

    def test_is_node_remote(self):
        assert self.parser_inst.is_node_remote("tbw-1") is False
        assert self.parser_inst.is_node_remote("tbw-3") is True

    def test_is_resource_configured(self):
        assert self.parser_inst.is_resource_configured("test") is False
        assert self.parser_inst.is_resource_configured("ocf:heartbeat:Filesystem") is True

    def test_is_any_resource_running(self):
        assert self.parser_inst.is_any_resource_running() is True

    def test_is_resource_started(self):
        assert self.parser_inst.is_resource_started("test") is False
        assert self.parser_inst.is_resource_started("ocfs2-clusterfs") is True
        assert self.parser_inst.is_resource_started("ocf:pacemaker:controld") is True

    def test_get_resource_id_list_via_type(self):
        assert self.parser_inst.get_resource_id_list_via_type("test") == []
        assert self.parser_inst.get_resource_id_list_via_type("ocf:pacemaker:controld")[0] == "ocfs2-dlm"

    def test_get_node_list(self):
        assert self.parser_inst.get_node_list() == ['tbw-1', 'tbw-2', 'tbw-3']
        assert self.parser_inst.get_node_list(online=True) == ['tbw-1', 'tbw-3']
        assert self.parser_inst.get_node_list(maintenance=True) == ['tbw-3']
        assert self.parser_inst.get_node_list(node_type="remote") == ['tbw-3']
        assert self.parser_inst.get_node_list(node_type="member") == ['tbw-1', 'tbw-2']
