import os
import sys
import unittest
from unittest import mock

from crmsh import upgradeutil


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


class TestUpgradeCondition(unittest.TestCase):
    @mock.patch('crmsh.upgradeutil._get_file_content')
    @mock.patch('os.stat')
    def test_is_upgrade_needed_by_force_upgrade(self, mock_stat: mock.MagicMock, mock_get_file_content):
        mock_stat.return_value = mock.Mock(os.stat_result)
        mock_get_file_content.return_value = b''
        self.assertTrue(upgradeutil._is_upgrade_needed(['node-1', 'node-2']))

    @mock.patch('crmsh.upgradeutil._get_file_content')
    @mock.patch('os.stat')
    def test_is_upgrade_needed_by_non_existent_seq(
            self,
            mock_stat: mock.MagicMock,
            mock_get_file_content: mock.MagicMock,
    ):
        mock_stat.side_effect = FileNotFoundError()
        mock_get_file_content.return_value = b''
        self.assertTrue(upgradeutil._is_upgrade_needed(['node-1', 'node-2']))

    @mock.patch('crmsh.upgradeutil.CURRENT_UPGRADE_SEQ')
    @mock.patch('crmsh.upgradeutil._get_file_content')
    @mock.patch('os.stat')
    def test_is_upgrade_needed_by_seq_less_than_expected(
            self,
            mock_stat,
            mock_get_file_content,
            mock_current_upgrade_seq: mock.MagicMock,
    ):
        mock_stat.side_effect = FileNotFoundError()
        mock_get_file_content.return_value = b'0\n'
        mock_current_upgrade_seq.__gt__.return_value = True
        self.assertTrue(upgradeutil._is_upgrade_needed(['node-1', 'node-2']))

    @mock.patch('crmsh.upgradeutil.CURRENT_UPGRADE_SEQ')
    @mock.patch('crmsh.upgradeutil._get_file_content')
    @mock.patch('os.stat')
    def test_is_upgrade_needed_by_seq_not_less_than_expected(
            self,
            mock_stat,
            mock_get_file_content,
            mock_current_upgrade_seq: mock.MagicMock,
    ):
        mock_stat.side_effect = FileNotFoundError()
        mock_get_file_content.return_value = b'1\n'
        mock_current_upgrade_seq.__gt__.return_value = False
        self.assertFalse(upgradeutil._is_upgrade_needed(['node-1', 'node-2']))


class TestSeq0UpgradeHaclusterPasswordless(unittest.TestCase):
    @mock.patch('crmsh.parallax.parallax_call')
    @mock.patch('crmsh.utils.ask')
    @mock.patch('crmsh.upgradeutil._parallax_run')
    def test_upgrade_partially_initialized(self, mock_parallax_run, mock_ask, mock_parallax_call: mock.MagicMock):
        nodes = ['node-{}'.format(i) for i in range(1, 6)]
        return_value = {'node-{}'.format(i): (0, b'', b'') for i in range(1, 4)}
        return_value.update({'node-{}'.format(i): (1, b'', b'') for i in range(4, 6)})
        mock_parallax_run.return_value = return_value
        mock_ask.return_value = True
        upgradeutil.seq_0_setup_hacluster_passwordless(nodes)
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
    @mock.patch('crmsh.upgradeutil._parallax_run')
    def test_upgrade_clean(self, mock_parallax_run, mock_ask, mock_parallax_call: mock.MagicMock):
        nodes = ['node-{}'.format(i) for i in range(1, 6)]
        mock_parallax_run.return_value = {node: (1, b'', b'') for node in nodes}
        mock_ask.return_value = True
        upgradeutil.seq_0_setup_hacluster_passwordless(nodes)
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
