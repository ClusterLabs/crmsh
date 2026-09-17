import unittest
from types import SimpleNamespace
from lxml import etree
try:
    from unittest import mock
except ImportError:
    import mock
from crmsh import cibconfig, ra
from crmsh.ui_context import Context
from crmsh.ui_resource import RscMgmt
from crmsh.ui_root import Root


class TestRATrace(unittest.TestCase):
    """Unit tests for enabling/disabling RA tracing."""

    context = Context(Root())
    factory = cibconfig.cib_factory

    def setUp(self):
        self.factory._push_state()

    def tearDown(self):
        self.factory._pop_state()

    @mock.patch('logging.Logger.error')
    def test_ratrace_resource(self, mock_error):
        """Check setting RA tracing for a resource."""
        xml = '''<primitive class="ocf" id="r1" provider="pacemaker" type="Dummy"/>'''
        obj = self.factory.create_from_node(etree.fromstring(xml))

        # Trace the resource.
        RscMgmt()._trace_resource(self.context, obj.obj_id, obj, '/var/lib/heartbeat/trace_ra')
        self.assertEqual(obj.node.xpath('operations/op/@id'), ['r1-start-0', 'r1-stop-0'])
        self.assertEqual(obj.node.xpath('operations/op[@id="r1-start-0"]/instance_attributes/nvpair[@name="trace_ra"]/@value'), ['1'])
        self.assertEqual(obj.node.xpath('operations/op[@id="r1-stop-0"]/instance_attributes/nvpair[@name="trace_ra"]/@value'), ['1'])

        # Untrace the resource.
        RscMgmt()._untrace_resource(self.context, obj.obj_id, obj)
        self.assertEqual(obj.node.xpath('operations/op/@id'), [])
        self.assertEqual(obj.node.xpath('.//*[@name="trace_ra"]'), [])

    @mock.patch('logging.Logger.error')
    def test_ratrace_op(self, mock_error):
        """Check setting RA tracing for a specific operation."""
        xml = '''<primitive class="ocf" id="r1" provider="pacemaker" type="Dummy">
            <operations>
              <op id="r1-monitor-10" interval="10" name="monitor"/>
            </operations>
          </primitive>'''
        obj = self.factory.create_from_node(etree.fromstring(xml))

        # Trace the operation.
        RscMgmt()._trace_op(self.context, obj.obj_id, obj, 'monitor', '/var/lib/heartbeat/trace_ra')
        self.assertEqual(obj.node.xpath('operations/op/@id'), ['r1-monitor-10'])
        self.assertEqual(obj.node.xpath('operations/op[@id="r1-monitor-10"]/instance_attributes/nvpair[@name="trace_ra"]/@value'), ['1'])

        # Untrace the operation.
        RscMgmt()._untrace_op(self.context, obj.obj_id, obj, 'monitor')
        self.assertEqual(obj.node.xpath('operations/op/@id'), ['r1-monitor-10'])
        self.assertEqual(obj.node.xpath('.//*[@name="trace_ra"]'), [])

        # Try untracing a non-existent operation.
        with self.assertRaises(ValueError) as err:
            RscMgmt()._untrace_op(self.context, obj.obj_id, obj, 'invalid-op')
        self.assertEqual(str(err.exception), "Operation invalid-op not found in r1")

    @mock.patch('logging.Logger.error')
    def test_ratrace_new(self, mock_error):
        """Check setting RA tracing for an operation that is not in CIB."""
        xml = '''<primitive class="ocf" id="r1" provider="pacemaker" type="Dummy">
          </primitive>'''
        obj = self.factory.create_from_node(etree.fromstring(xml))

        # Trace a regular operation that is not yet defined in CIB. The request
        # should succeed and introduce an op node for the operation.
        RscMgmt()._trace_op(self.context, obj.obj_id, obj, 'start', '/var/lib/heartbeat/trace_ra')
        self.assertEqual(obj.node.xpath('operations/op/@id'), ['r1-start-0'])
        self.assertEqual(obj.node.xpath('operations/op[@id="r1-start-0"]/instance_attributes/nvpair[@name="trace_ra"]/@value'), ['1'])

        # Try tracing the monitor operation in the same way. The request should
        # get rejected because no explicit interval is specified.
        with self.assertRaises(ValueError) as err:
            RscMgmt()._trace_op(self.context, obj.obj_id, obj, 'monitor', '/var/lib/heartbeat/trace_ra')
        self.assertEqual(str(err.exception), "No monitor operation configured for r1")

    @mock.patch('logging.Logger.error')
    def test_ratrace_op_stateful(self, mock_error):
        """Check setting RA tracing for an operation on a stateful resource."""
        xml = '''<primitive class="ocf" id="r1" provider="pacemaker" type="Dummy">
            <operations>
              <op id="r1-monitor-10" interval="10" name="monitor" role="Master"/>
              <op id="r1-monitor-11" interval="11" name="monitor" role="Slave"/>
            </operations>
          </primitive>'''
        obj = self.factory.create_from_node(etree.fromstring(xml))

        # Trace the operation.
        RscMgmt()._trace_op(self.context, obj.obj_id, obj, 'monitor', '/var/lib/heartbeat/trace_ra')
        self.assertEqual(obj.node.xpath('operations/op/@id'), ['r1-monitor-10', 'r1-monitor-11'])
        self.assertEqual(obj.node.xpath('operations/op[@id="r1-monitor-10"]/instance_attributes/nvpair[@name="trace_ra"]/@value'), ['1'])
        self.assertEqual(obj.node.xpath('operations/op[@id="r1-monitor-11"]/instance_attributes/nvpair[@name="trace_ra"]/@value'), ['1'])

        # Untrace the operation.
        RscMgmt()._untrace_op(self.context, obj.obj_id, obj, 'monitor')
        self.assertEqual(obj.node.xpath('operations/op/@id'), ['r1-monitor-10', 'r1-monitor-11'])
        self.assertEqual(obj.node.xpath('.//*[@name="trace_ra"]'), [])

    @mock.patch('logging.Logger.error')
    @mock.patch.object(RscMgmt, '_get_trace_rsc')
    def test_ratrace_unknown_op(self, mock_get_rsc, mock_error):
        """Check that do_trace rejects an unknown operation name."""
        xml = '''<primitive class="ocf" id="r1" provider="pacemaker" type="Dummy"/>'''
        obj = self.factory.create_from_node(etree.fromstring(xml))
        mock_get_rsc.return_value = obj

        with self.assertRaises(ValueError) as err:
            RscMgmt().do_trace(self.context, obj.obj_id, 'xxx')
        self.assertEqual(str(err.exception), "Unknown operation: xxx")

    @mock.patch('logging.Logger.error')
    @mock.patch.object(RscMgmt, '_get_trace_rsc')
    def test_ratrace_interval_with_unit(self, mock_get_rsc, mock_error):
        """Check that do_trace accepts an interval expressed with a time unit."""
        xml = '''<primitive class="ocf" id="r1" provider="pacemaker" type="Dummy">
            <operations>
              <op id="r1-monitor-10s" interval="10s" name="monitor"/>
            </operations>
          </primitive>'''
        obj = self.factory.create_from_node(etree.fromstring(xml))
        mock_get_rsc.return_value = obj

        RscMgmt().do_trace(self.context, obj.obj_id, 'monitor', '10s')
        self.assertEqual(obj.node.xpath('operations/op/@id'), ['r1-monitor-10s'])
        self.assertEqual(obj.node.xpath('operations/op[@id="r1-monitor-10s"]/instance_attributes/nvpair[@name="trace_ra"]/@value'), ['1'])

    @mock.patch('logging.Logger.error')
    def test_ratrace_op_interval(self, mock_error):
        """Check setting RA tracing for an operation+interval."""
        xml = '''<primitive class="ocf" id="r1" provider="pacemaker" type="Dummy">
            <operations>
              <op id="r1-monitor-10" interval="10" name="monitor"/>
            </operations>
          </primitive>'''
        obj = self.factory.create_from_node(etree.fromstring(xml))

        # Trace the operation.
        RscMgmt()._trace_op_interval(self.context, obj.obj_id, obj, 'monitor', '10', '/var/lib/heartbeat/trace_ra')
        self.assertEqual(obj.node.xpath('operations/op/@id'), ['r1-monitor-10'])
        self.assertEqual(obj.node.xpath('operations/op[@id="r1-monitor-10"]/instance_attributes/nvpair[@name="trace_ra"]/@value'), ['1'])

        # Untrace the operation.
        RscMgmt()._untrace_op_interval(self.context, obj.obj_id, obj, 'monitor', '10')
        self.assertEqual(obj.node.xpath('operations/op/@id'), ['r1-monitor-10'])
        self.assertEqual(obj.node.xpath('.//*[@name="trace_ra"]'), [])

        # Try untracing a non-existent operation.
        with self.assertRaises(ValueError) as err:
            RscMgmt()._untrace_op_interval(self.context, obj.obj_id, obj, 'invalid-op', '10')
        self.assertEqual(str(err.exception), "Operation invalid-op with interval 10 not found in r1")


def _fake_rsc(ra_class, ra_type, ra_provider=None):
    attrs = {"class": ra_class, "type": ra_type}
    if ra_provider is not None:
        attrs["provider"] = ra_provider
    return SimpleNamespace(node=attrs)


class TestIsShellAgent(unittest.TestCase):
    """Unit tests for detecting non-shell resource agents."""

    @mock.patch('os.path.isfile')
    @mock.patch('builtins.open', new_callable=mock.mock_open, read_data=b'#!/bin/sh\n')
    def test_shell_agent(self, mock_open, mock_isfile):
        mock_isfile.return_value = True
        self.assertTrue(ra.is_shell_agent(_fake_rsc('ocf', 'Dummy', 'heartbeat')))

    @mock.patch('os.path.isfile')
    @mock.patch('builtins.open', new_callable=mock.mock_open, read_data=b'#!/usr/bin/env bash\n')
    def test_shell_agent_env(self, mock_open, mock_isfile):
        mock_isfile.return_value = True
        self.assertTrue(ra.is_shell_agent(_fake_rsc('ocf', 'Dummy', 'heartbeat')))

    @mock.patch('os.path.isfile')
    @mock.patch('builtins.open', new_callable=mock.mock_open, read_data=b'#!/usr/bin/env -S bash\n')
    def test_shell_agent_env_with_flag(self, mock_open, mock_isfile):
        mock_isfile.return_value = True
        self.assertTrue(ra.is_shell_agent(_fake_rsc('ocf', 'Dummy', 'heartbeat')))

    @mock.patch('os.path.isfile')
    @mock.patch('builtins.open', new_callable=mock.mock_open, read_data=b'#!/usr/bin/python3\n')
    def test_recognized_shebang_non_shell_interpreter_is_unknown(self, mock_open, mock_isfile):
        """A script with a valid shebang whose interpreter is not in
        SHELL_INTERPRETERS is reported as indeterminate: we cannot tell
        shell-like interpreters we don't know about from genuinely
        non-shell ones without an explicit deny-list."""
        mock_isfile.return_value = True
        self.assertIsNone(ra.is_shell_agent(_fake_rsc('stonith', 'fence_sbd')))

    @mock.patch('os.path.isfile')
    @mock.patch('builtins.open', new_callable=mock.mock_open, read_data=b'\x7fELF\x02\x01\x01\x00binary-garbage')
    def test_binary_agent(self, mock_open, mock_isfile):
        """A file with no shebang is confidently not a shell script."""
        mock_isfile.return_value = True
        self.assertFalse(ra.is_shell_agent(_fake_rsc('stonith', 'fence_compiled')))

    @mock.patch('os.path.isfile')
    @mock.patch('builtins.open', new_callable=mock.mock_open, read_data=b'#!/usr/bin/fish\n')
    def test_unrecognized_interpreter_is_unknown(self, mock_open, mock_isfile):
        """An interpreter that is neither a known shell nor a known
        non-shell scripting language is reported as indeterminate,
        rather than guessed at."""
        mock_isfile.return_value = True
        self.assertIsNone(ra.is_shell_agent(_fake_rsc('ocf', 'Dummy', 'heartbeat')))

    @mock.patch('os.path.isfile')
    def test_unknown_agent(self, mock_isfile):
        mock_isfile.return_value = False
        self.assertIsNone(ra.is_shell_agent(_fake_rsc('ocf', 'Dummy', 'heartbeat')))


class TestTraceNonShellWarning(unittest.TestCase):
    """Unit tests for the non-shell agent warning emitted by `trace`."""

    context = Context(Root())
    factory = cibconfig.cib_factory

    def setUp(self):
        self.factory._push_state()

    def tearDown(self):
        self.factory._pop_state()

    @mock.patch('crmsh.xmlutil.CrmMonXMLParser.get_resource_running_nodes', return_value=[])
    @mock.patch('crmsh.ra.is_shell_agent')
    @mock.patch('logging.Logger.warning')
    def test_trace_warns_for_non_shell_agent(self, mock_warning, mock_is_shell_agent, mock_running_nodes):
        """do_trace should warn when the RA is known not to be a shell script."""
        mock_is_shell_agent.return_value = False
        xml = '''<primitive class="stonith" id="fencing-sbd" type="fence_sbd"/>'''
        obj = self.factory.create_from_node(etree.fromstring(xml))

        with mock.patch.object(RscMgmt, '_get_trace_rsc', return_value=obj), \
                mock.patch.object(self.factory, 'commit', return_value=True):
            RscMgmt().do_trace(self.context, obj.obj_id)

        mock_is_shell_agent.assert_called_with(obj)
        self.assertTrue(any(
            "trace supports shell-based resource agents" in call.args[0]
            for call in mock_warning.call_args_list
        ))

    @mock.patch('crmsh.xmlutil.CrmMonXMLParser.get_resource_running_nodes', return_value=[])
    @mock.patch('crmsh.ra.is_shell_agent')
    @mock.patch('logging.Logger.warning')
    def test_trace_no_warning_for_shell_agent(self, mock_warning, mock_is_shell_agent, mock_running_nodes):
        """do_trace should not warn when the RA is a shell script."""
        mock_is_shell_agent.return_value = True
        xml = '''<primitive class="ocf" id="r1" provider="heartbeat" type="Dummy"/>'''
        obj = self.factory.create_from_node(etree.fromstring(xml))

        with mock.patch.object(RscMgmt, '_get_trace_rsc', return_value=obj), \
                mock.patch.object(self.factory, 'commit', return_value=True):
            RscMgmt().do_trace(self.context, obj.obj_id)

        self.assertFalse(any(
            "trace supports shell-based resource agents" in call.args[0]
            for call in mock_warning.call_args_list
        ))

    @mock.patch('crmsh.xmlutil.CrmMonXMLParser.get_resource_running_nodes', return_value=[])
    @mock.patch('crmsh.ra.is_shell_agent')
    @mock.patch('logging.Logger.warning')
    def test_untrace_warns_for_non_shell_agent(self, mock_warning, mock_is_shell_agent, mock_running_nodes):
        """do_untrace should warn when the RA is known not to be a shell script."""
        mock_is_shell_agent.return_value = False
        xml = '''<primitive class="stonith" id="fencing-sbd" type="fence_sbd"/>'''
        obj = self.factory.create_from_node(etree.fromstring(xml))

        with mock.patch.object(RscMgmt, '_get_trace_rsc', return_value=obj), \
                mock.patch.object(self.factory, 'commit', return_value=True):
            RscMgmt().do_untrace(self.context, obj.obj_id)

        mock_is_shell_agent.assert_called_with(obj)
        self.assertTrue(any(
            "untrace supports shell-based resource agents" in call.args[0]
            for call in mock_warning.call_args_list
        ))
