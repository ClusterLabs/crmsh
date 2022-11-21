import unittest
from unittest import mock
import sys

from crmsh import healthcheck


class _Py37MockCallShim:
    def __init__(self, mock_call):
        self._mock_call = mock_call

    def __getattr__(self, item):
        f = getattr(self._mock_call, item)

        def g(*args, **kwargs):
            return f(*((self._mock_call, ) + args[1:]), **kwargs)
        return g

    @property
    def args(self):
        if sys.version_info.major == 3 and sys.version_info.major < 8:
            return self._mock_call[0]
        else:
            return self._mock_call.args

    @property
    def kwargs(self):
        def args(self):
            if sys.version_info.major == 3 and sys.version_info.major < 8:
                return self._mock_call[1]
            else:
                return self._mock_call.kwargs


class TestPasswordlessHaclusterAuthenticationFeature(unittest.TestCase):
    @mock.patch('crmsh.parallax.parallax_call')
    @mock.patch('crmsh.utils.ask')
    @mock.patch('crmsh.healthcheck._parallax_run')
    def test_upgrade_partially_initialized(self, mock_parallax_run, mock_ask, mock_parallax_call: mock.MagicMock):
        nodes = ['node-{}'.format(i) for i in range(1, 6)]
        return_value = {'node-{}'.format(i): (0, b'', b'') for i in range(1, 4)}
        return_value.update({'node-{}'.format(i): (1, b'', b'') for i in range(4, 6)})
        mock_parallax_run.return_value = return_value
        mock_ask.return_value = True
        healthcheck.feature_fix(healthcheck.PasswordlessHaclusterAuthenticationFeature(), nodes, mock_ask)
        self.assertFalse(any(_Py37MockCallShim(call_args).args[1].startswith('crm cluster init ssh') for call_args in mock_parallax_call.call_args_list))
        self.assertEqual(
            {'node-{}'.format(i) for i in range(4, 6)},
            set(
                _Py37MockCallShim(call_args).args[0][0] for call_args in mock_parallax_call.call_args_list
                if _Py37MockCallShim(call_args).args[1].startswith('crm cluster join ssh')
            ),
        )

    @mock.patch('crmsh.parallax.parallax_call')
    @mock.patch('crmsh.utils.ask')
    @mock.patch('crmsh.healthcheck._parallax_run')
    def test_upgrade_clean(self, mock_parallax_run, mock_ask, mock_parallax_call: mock.MagicMock):
        nodes = ['node-{}'.format(i) for i in range(1, 6)]
        mock_parallax_run.return_value = {node: (1, b'', b'') for node in nodes}
        mock_ask.return_value = True
        healthcheck.feature_fix(healthcheck.PasswordlessHaclusterAuthenticationFeature(), nodes, mock_ask)
        self.assertEqual(
            1, len([
                True for call_args in mock_parallax_call.call_args_list
                if _Py37MockCallShim(call_args).args[1].startswith('crm cluster init ssh')
            ])
        )
        self.assertEqual(
            len(nodes) - 1,
            len([
                True for call_args in mock_parallax_call.call_args_list
                if _Py37MockCallShim(call_args).args[1].startswith('crm cluster join ssh')
            ]),
            )
