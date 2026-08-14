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

    def test_check_removed_resource_agents(self):
        mock_detector = mock.Mock(migration.UnsupportedResourceAgentDetector)
        mock_detector.get_unsupported_state.side_effect = [
            migration.UnsupportedResourceAgentDetector.UnsupportedState(cibquery.ResourceAgent('foo', 'bar', 'qux2'), True),
            migration.UnsupportedResourceAgentDetector.UnsupportedState(None, False),
        ]
        migration._check_removed_resource_agents(
            self._handler,
            'msg',
            mock_detector,
            [
                cibquery.ResourceAgent('foo', 'bar', 'qux'),
                cibquery.ResourceAgent('a', 'b', 'c'),
            ]
        )
        self._handler.handle_problem.assert_called()

    def test_check_version_range(self):
        def check_fn(x):
            migration._check_version_range(
                self._handler,
                'foo',
                (1, 1,),
                re.compile(r'^foo\s+(\d+(?:.\d+)*)'),
                x,
            )
        check_fn('foo 0')
        self._handler.handle_problem.assert_called()
        self._handler.handle_problem.reset_mock()
        check_fn('foo 0.9')
        self._handler.handle_problem.assert_called()
        self._handler.handle_problem.reset_mock()
        check_fn('foo 0.9.99')
        self._handler.handle_problem.assert_called()
        self._handler.handle_problem.reset_mock()
        check_fn('foo 1')
        self._handler.handle_problem.assert_called()
        self._handler.handle_problem.reset_mock()
        check_fn('foo 1.1')
        self._handler.handle_problem.assert_not_called()
        check_fn('foo 1.1.0')
        self._handler.handle_problem.assert_not_called()
        check_fn('foo 1.1.1')
        self._handler.handle_problem.assert_not_called()
        check_fn('foo 1.2')
        self._handler.handle_problem.assert_not_called()
        check_fn('foo 2')
        self._handler.handle_problem.assert_not_called()
        check_fn('foo 2.0')
        self._handler.handle_problem.assert_not_called()

    @mock.patch('glob.iglob')
    def test_get_latest_cib_schema_version(self, mock_iglob: mock.MagicMock):
        mock_iglob.return_value = iter([
            'pacemaker-0.1.rng', 'pacemaker-1.9.rng', 'pacemaker-1.11.rng', 'pacemaker-next.rng',
        ])
        self.assertEqual((1, 11), migration._get_latest_cib_schema_version())

    @mock.patch('crmsh.migration._get_latest_cib_schema_version')
    def test_check_cib_schema_version(self, mock_get_latest_cib_schema_version):
        cib = lxml.etree.fromstring('<cib crm_feature_set="3.16.1" validate-with="pacemaker-3.9" epoch="7" num_updates="0" admin_epoch="0" cib-last-written="Fri Jan  3 13:35:49 2025" update-origin="ha-1-2" update-client="cibadmin" update-user="root" have-quorum="1" dc-uuid="1"/>')
        mock_get_latest_cib_schema_version.return_value = (3, 10)
        handler = mock.Mock(migration.CheckResultHandler)
        migration.check_cib_schema_version(handler, cib)
        handler.handle_problem.assert_called_with(
            False, False, handler.LEVEL_WARN,
            "The CIB is not validated with the latest schema version.", [
                '* Latest version:  3.10',
                '* Current version: 3.9',
                'Please run "crm configure upgrade force" to upgrade to the latest version.',
            ]
        )


class TestDeprecatedCibProperties(unittest.TestCase):
    @mock.patch('crmsh.utils.get_all_configured_deprecated_properties')
    @mock.patch('crmsh.utils.DeprecatedTermTranslator._get_maps')
    def test_check_deprecated_cib_properties_found(self, mock_get_maps, mock_get_dep_properties):
        mock_get_dep_properties.return_value = ['stonith-timeout']
        mock_get_maps.return_value = ({'stonith-timeout': 'fencing-timeout'}, {})
        cib = lxml.etree.fromstring('''
            <cib>
              <configuration>
                <crm_config>
                  <cluster_property_set id="cib-bootstrap-options">
                    <nvpair name="stonith-timeout" value="120s"/>
                  </cluster_property_set>
                </crm_config>
              </configuration>
            </cib>
        ''')
        handler = mock.Mock(migration.CheckResultHandler)
        migration.check_deprecated_cib_properties(handler, cib)
        handler.handle_problem.assert_called_with(
            True, False, handler.LEVEL_WARN,
            'Deprecated CIB properties found',
            ['The following properties are deprecated: stonith-timeout. Please run "crm cluster health sles16 --fix" when cluster is running to migrate them.']
        )

    @mock.patch('crmsh.utils.get_all_configured_deprecated_properties')
    @mock.patch('crmsh.utils.DeprecatedTermTranslator._get_maps')
    def test_check_deprecated_cib_properties_not_found(self, mock_get_maps, mock_get_dep_properties):
        mock_get_dep_properties.return_value = []
        mock_get_maps.return_value = ({'stonith-timeout': 'fencing-timeout'}, {})
        cib = lxml.etree.fromstring('''
            <cib>
              <configuration>
                <crm_config>
                  <cluster_property_set id="cib-bootstrap-options">
                    <nvpair name="fencing-timeout" value="120s"/>
                  </cluster_property_set>
                </crm_config>
              </configuration>
            </cib>
        ''')
        handler = mock.Mock(migration.CheckResultHandler)
        migration.check_deprecated_cib_properties(handler, cib)
        handler.handle_problem.assert_not_called()

    @mock.patch('crmsh.utils.get_all_configured_deprecated_properties')
    @mock.patch('crmsh.utils.DeprecatedTermTranslator._get_maps')
    @mock.patch('crmsh.utils.ra.get_properties_meta')
    def test_check_deprecated_cib_properties_without_replacement_not_found(self, mock_get_properties_meta, mock_get_maps, mock_get_dep_properties):
        mock_get_dep_properties.return_value = ['stonith-timeout']
        mock_get_maps.return_value = ({'stonith-timeout': None}, {})
        mock_get_properties_meta.return_value.param_default.return_value = 'true'
        cib = lxml.etree.fromstring('''
            <cib>
              <configuration>
                <crm_config>
                  <cluster_property_set id="cib-bootstrap-options">
                    <nvpair name="stonith-timeout" value="false"/>
                  </cluster_property_set>
                </crm_config>
              </configuration>
            </cib>
        ''')
        handler = mock.Mock(migration.CheckResultHandler)
        migration.check_deprecated_cib_properties(handler, cib)
        handler.handle_problem.assert_not_called()

    @mock.patch('crmsh.utils.get_all_configured_deprecated_properties')
    @mock.patch('crmsh.utils.DeprecatedTermTranslator')
    @mock.patch('crmsh.sh.LocalShell.get_stdout_or_raise_error')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    def test_migrate_deprecated_cib_properties_active(self, mock_service_is_active, mock_get_stdout, mock_translator, mock_get_dep_properties):
        mock_service_is_active.return_value = True
        mock_get_dep_properties.return_value = ['stonith-timeout']
        mock_get_stdout.return_value = '''
            <cib>
              <configuration>
                <crm_config>
                  <cluster_property_set id="cib-bootstrap-options">
                    <nvpair name="stonith-timeout" value="120s"/>
                  </cluster_property_set>
                </crm_config>
              </configuration>
            </cib>
        '''
        mock_trans_inst = mock.Mock()
        mock_trans_inst.check.return_value = False
        mock_translator.return_value = mock_trans_inst

        migration.migrate_deprecated_cib_properties()

        mock_translator.assert_called_with('stonith-timeout', existing_xml_node=mock.ANY, quiet=True)
        mock_trans_inst.fix.assert_called_once()

    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    @mock.patch('crmsh.utils.DeprecatedTermTranslator')
    def test_migrate_deprecated_cib_properties_inactive(self, mock_translator, mock_service_is_active):
        mock_service_is_active.return_value = False
        migration.migrate_deprecated_cib_properties()
        mock_translator.assert_not_called()
