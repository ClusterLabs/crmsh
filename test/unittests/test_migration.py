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
            ]
        )
