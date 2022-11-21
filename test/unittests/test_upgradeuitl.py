import os
import sys
import unittest
from unittest import mock

from crmsh import upgradeutil


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
