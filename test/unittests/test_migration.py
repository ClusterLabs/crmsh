import re
import unittest
from unittest import mock

from crmsh import migration, cibquery


class TestCheckRemovedResourceAgents(unittest.TestCase):
    def setUp(self):
        self._handler = mock.Mock(migration.CheckResultHandler)

    def test_load_unsupported_resource_agents(self):
        s = migration._load_unsupported_resource_agents()
        self.assertIn((
                cibquery.ResourceAgent('ocf', 'heartbeat', 'IPaddr'),
                cibquery.ResourceAgent('ocf', 'heartbeat', 'IPaddr2'),
            ),
            s.items(),
        )
        self.assertIn((
                cibquery.ResourceAgent('stonith', None, 'external/sbd'),
                cibquery.ResourceAgent('stonith', None, 'fence_sbd'),
            ),
            s.items(),
        )
        self.assertIn((
                cibquery.ResourceAgent('ocf', 'heartbeat', 'rkt'),
                None,
            ),
            s.items(),
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
