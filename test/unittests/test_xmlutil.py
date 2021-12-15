import unittest

try:
    from unittest import mock
except ImportError:
    import mock

from crmsh import xmlutil, constants


class TestCrmMonXmlParser(unittest.TestCase):
    """
    Unitary tests for crmsh.xmlutil.CrmMonXmlParser
    """

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """
        self.parser_inst = xmlutil.CrmMonXmlParser()
        self.nodes_xml = """
  <nodes>
    <node name="tbw-1" id="1084783148" online="true" standby="false" standby_onfail="false" maintenance="false" pending="false" unclean="false" shutdown="false" expected_up="true" is_dc="true" resources_running="3" type="member"/>
    <node name="tbw-2" id="1084783312" online="true" standby="false" standby_onfail="false" maintenance="false" pending="false" unclean="false" shutdown="false" expected_up="true" is_dc="false" resources_running="2" type="member"/>
  </nodes>
        """
        self.resources_xml = """
      <resources>
        <resource id="ocfs2-dlm" resource_agent="ocf::pacemaker:controld" role="Started" active="true" orphaned="false" blocked="false" managed="true" failed="false" failure_ignored="false" nodes_running_on="1">
          <node name="tbw-2" id="1084783312" cached="true"/>
        </resource>
        <resource id="ocfs2-clusterfs" resource_agent="ocf::heartbeat:Filesystem" role="Started" active="true" orphaned="false" blocked="false" managed="true" failed="false" failure_ignored="false" nodes_running_on="1">
          <node name="tbw-2" id="1084783312" cached="true"/>
        </resource>
      </resources>
        """

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('crmsh.xmlutil.text2elem')
    @mock.patch('crmsh.xmlutil.get_stdout_or_raise_error')
    def test_load(self, mock_run, mock_text2elem):
        mock_run.return_value = "data"
        mock_text2elem.return_value = mock.Mock()
        self.parser_inst._load()
        mock_run.assert_called_once_with(constants.CRM_MON_XML_OUTPUT, remote=None, no_raise=True)
        mock_text2elem.assert_called_once_with("data")

    @mock.patch('crmsh.xmlutil.get_stdout_or_raise_error')
    def test_is_node_online(self, mock_run):
        mock_run.return_value = self.nodes_xml
        assert xmlutil.CrmMonXmlParser.is_node_online("node1") is False
        assert xmlutil.CrmMonXmlParser.is_node_online("tbw-2") is True

    @mock.patch('crmsh.xmlutil.get_stdout_or_raise_error')
    def test_is_resource_configured(self, mock_run):
        mock_run.return_value = self.resources_xml
        assert xmlutil.CrmMonXmlParser.is_resource_configured("test") is False
        assert xmlutil.CrmMonXmlParser.is_resource_configured("ocf::heartbeat:Filesystem") is True

    @mock.patch('crmsh.xmlutil.get_stdout_or_raise_error')
    def test_is_any_resource_running(self, mock_run):
        mock_run.return_value = self.resources_xml
        assert xmlutil.CrmMonXmlParser.is_any_resource_running() is True

    @mock.patch('crmsh.xmlutil.get_stdout_or_raise_error')
    def test_is_resource_started(self, mock_run):
        mock_run.return_value = self.resources_xml
        assert xmlutil.CrmMonXmlParser.is_resource_started("test") is False
        assert xmlutil.CrmMonXmlParser.is_resource_started("ocfs2-clusterfs") is True
        assert xmlutil.CrmMonXmlParser.is_resource_started("ocf::pacemaker:controld") is True
