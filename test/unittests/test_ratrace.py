import unittest
from lxml import etree

from crmsh import cibconfig
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

    def test_ratrace_resource(self):
        """Check setting RA tracing for a resource."""
        xml = '''<primitive class="ocf" id="r1" provider="pacemaker" type="Dummy"/>'''
        obj = self.factory.create_from_node(etree.fromstring(xml))

        # Trace the resource.
        RscMgmt()._trace_resource(self.context, obj.obj_id, obj)
        self.assertEqual(obj.node.xpath('operations/op/@id'), ['r1-start-0', 'r1-stop-0'])
        self.assertEqual(obj.node.xpath('operations/op[@id="r1-start-0"]/instance_attributes/nvpair[@name="trace_ra"]/@value'), ['1'])
        self.assertEqual(obj.node.xpath('operations/op[@id="r1-stop-0"]/instance_attributes/nvpair[@name="trace_ra"]/@value'), ['1'])

        # Untrace the resource.
        RscMgmt()._untrace_resource(self.context, obj.obj_id, obj)
        self.assertEqual(obj.node.xpath('operations/op/@id'), [])
        self.assertEqual(obj.node.xpath('.//*[@name="trace_ra"]'), [])

    def test_ratrace_op(self):
        """Check setting RA tracing for a specific operation."""
        xml = '''<primitive class="ocf" id="r1" provider="pacemaker" type="Dummy">
            <operations>
              <op id="r1-monitor-10" interval="10" name="monitor"/>
            </operations>
          </primitive>'''
        obj = self.factory.create_from_node(etree.fromstring(xml))

        # Trace the operation.
        RscMgmt()._trace_op(self.context, obj.obj_id, obj, 'monitor')
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

    def test_ratrace_new(self):
        """Check setting RA tracing for an operation that is not in CIB."""
        xml = '''<primitive class="ocf" id="r1" provider="pacemaker" type="Dummy">
          </primitive>'''
        obj = self.factory.create_from_node(etree.fromstring(xml))

        # Trace a regular operation that is not yet defined in CIB. The request
        # should succeed and introduce an op node for the operation.
        RscMgmt()._trace_op(self.context, obj.obj_id, obj, 'start')
        self.assertEqual(obj.node.xpath('operations/op/@id'), ['r1-start-0'])
        self.assertEqual(obj.node.xpath('operations/op[@id="r1-start-0"]/instance_attributes/nvpair[@name="trace_ra"]/@value'), ['1'])

        # Try tracing the monitor operation in the same way. The request should
        # get rejected because no explicit interval is specified.
        with self.assertRaises(ValueError) as err:
            RscMgmt()._trace_op(self.context, obj.obj_id, obj, 'monitor')
        self.assertEqual(str(err.exception), "No monitor operation configured for r1")

    def test_ratrace_op_stateful(self):
        """Check setting RA tracing for an operation on a stateful resource."""
        xml = '''<primitive class="ocf" id="r1" provider="pacemaker" type="Dummy">
            <operations>
              <op id="r1-monitor-10" interval="10" name="monitor" role="Master"/>
              <op id="r1-monitor-11" interval="11" name="monitor" role="Slave"/>
            </operations>
          </primitive>'''
        obj = self.factory.create_from_node(etree.fromstring(xml))

        # Trace the operation.
        RscMgmt()._trace_op(self.context, obj.obj_id, obj, 'monitor')
        self.assertEqual(obj.node.xpath('operations/op/@id'), ['r1-monitor-10', 'r1-monitor-11'])
        self.assertEqual(obj.node.xpath('operations/op[@id="r1-monitor-10"]/instance_attributes/nvpair[@name="trace_ra"]/@value'), ['1'])
        self.assertEqual(obj.node.xpath('operations/op[@id="r1-monitor-11"]/instance_attributes/nvpair[@name="trace_ra"]/@value'), ['1'])

        # Untrace the operation.
        RscMgmt()._untrace_op(self.context, obj.obj_id, obj, 'monitor')
        self.assertEqual(obj.node.xpath('operations/op/@id'), ['r1-monitor-10', 'r1-monitor-11'])
        self.assertEqual(obj.node.xpath('.//*[@name="trace_ra"]'), [])

    def test_ratrace_op_interval(self):
        """Check setting RA tracing for an operation+interval."""
        xml = '''<primitive class="ocf" id="r1" provider="pacemaker" type="Dummy">
            <operations>
              <op id="r1-monitor-10" interval="10" name="monitor"/>
            </operations>
          </primitive>'''
        obj = self.factory.create_from_node(etree.fromstring(xml))

        # Trace the operation.
        RscMgmt()._trace_op_interval(self.context, obj.obj_id, obj, 'monitor', '10')
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
