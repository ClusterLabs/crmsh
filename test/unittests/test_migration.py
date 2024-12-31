import unittest
from unittest import mock

from crmsh import migration, cibquery


class TestCheckRemovedResourceAgents(unittest.TestCase):
    def setUp(self):
        self._handler = mock.Mock(migration.CheckResultHandler)

    def test_load_supported_resource_agents(self):
        s = migration._load_supported_resource_agents()
        self.assertIn(cibquery.ResourceAgent('ocf', 'heartbeat', 'IPaddr2'), s)
        self.assertIn(cibquery.ResourceAgent('stonith', None, 'fence_sbd'), s)
        self.assertNotIn(cibquery.ResourceAgent('foo', None, 'bar'), s)

    def test_check_removed_resource_agents(self):
        migration._check_removed_resource_agents(
            self._handler,
            {cibquery.ResourceAgent('foo', None, 'bar')},
            [cibquery.ResourceAgent('foo', 'bar', 'qux')]
        )
        self._handler.handle_problem.assert_called()
