"""
Unitary tests for crmsh/bootstrap.py

:author: xinliang
:organization: SUSE Linux GmbH
:contact: XLiang@suse.de

:since: 2019-10-21
"""

# pylint:disable=C0103,C0111,W0212,W0611

import os
import unittest

try:
    from unittest import mock
except ImportError:
    import mock

from crmsh import bootstrap


class TestBootstrap(unittest.TestCase):
    """
    Unitary tests for crmsh/bootstrap.py
    """

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    #@mock.patch('crmsh.bootstrap.Context')
    def setUp(self):
        """
        Test setUp.
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

    @mock.patch('crmsh.bootstrap.append')
    @mock.patch('crmsh.bootstrap.status')
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.bootstrap.start_service')
    @mock.patch('crmsh.bootstrap.invoke')
    def test_init_ssh_no_exist_keys(self, mock_invoke, mock_start_service,
                                    mock_exists, mock_status, mock_append):
        mock_exists.return_value = False

        bootstrap.init_ssh()

        mock_start_service.assert_called_once_with("sshd.service")
        mock_invoke.assert_has_calls([
            mock.call("mkdir -m 700 -p /root/.ssh"),
            mock.call("ssh-keygen -q -f /root/.ssh/id_rsa -C 'Cluster Internal' -N ''")
        ])
        mock_exists.assert_called_once_with("/root/.ssh/id_rsa")
        mock_status.assert_called_once_with("Generating SSH key")
        mock_append.assert_called_once_with("/root/.ssh/id_rsa.pub", "/root/.ssh/authorized_keys")

    @mock.patch('crmsh.bootstrap.append')
    @mock.patch('crmsh.bootstrap.status')
    @mock.patch('crmsh.bootstrap.rmfile')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.bootstrap.start_service')
    @mock.patch('crmsh.bootstrap.invoke')
    def test_init_ssh_exits_keys_yes_to_all_confirm(self, mock_invoke, mock_start_service,
                         mock_exists, mock_confirm, mock_rmfile, mock_status, mock_append):
        mock_exists.return_value = True
        bootstrap._context = mock.Mock(yes_to_all=True, no_overwrite_sshkey=False)
        mock_confirm.return_value = True

        bootstrap.init_ssh()

        mock_start_service.assert_called_once_with("sshd.service")
        mock_invoke.assert_has_calls([
            mock.call("mkdir -m 700 -p /root/.ssh"),
            mock.call("ssh-keygen -q -f /root/.ssh/id_rsa -C 'Cluster Internal' -N ''")
        ])
        mock_exists.assert_called_once_with("/root/.ssh/id_rsa")
        mock_confirm.assert_called_once_with("/root/.ssh/id_rsa already exists - overwrite?")
        mock_rmfile.assert_called_once_with("/root/.ssh/id_rsa")
        mock_status.assert_called_once_with("Generating SSH key")
        mock_append.assert_called_once_with("/root/.ssh/id_rsa.pub", "/root/.ssh/authorized_keys")

    @mock.patch('crmsh.bootstrap.rmfile')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.bootstrap.start_service')
    @mock.patch('crmsh.bootstrap.invoke')
    def test_init_ssh_exits_keys_no_overwrite(self, mock_invoke, mock_start_service,
                                              mock_exists, mock_confirm, mock_rmfile):
        mock_exists.return_value = True
        bootstrap._context = mock.Mock(yes_to_all=True, no_overwrite_sshkey=True)

        bootstrap.init_ssh()

        mock_start_service.assert_called_once_with("sshd.service")
        mock_invoke.assert_called_once_with("mkdir -m 700 -p /root/.ssh")
        mock_exists.assert_called_once_with("/root/.ssh/id_rsa")
        mock_confirm.assert_not_called()
        mock_rmfile.assert_not_called()

    @mock.patch('builtins.open')
    @mock.patch('crmsh.bootstrap.append')
    @mock.patch('os.path.join')
    @mock.patch('os.path.exists')
    def test_init_ssh_remote_no_sshkey(self, mock_exists, mock_join, mock_append, mock_open_file):
        mock_exists.side_effect = [False, True, False, False, False]
        mock_join.side_effect = ["/root/.ssh/id_rsa",
                                 "/root/.ssh/id_dsa",
                                 "/root/.ssh/id_ecdsa",
                                 "/root/.ssh/id_ed25519"]
        mock_open_file.side_effect = [
            mock.mock_open().return_value,
            mock.mock_open(read_data="data1 data2").return_value,
            mock.mock_open(read_data="data1111").return_value
        ]

        bootstrap.init_ssh_remote()

        mock_open_file.assert_has_calls([
            mock.call("/root/.ssh/authorized_keys", 'w'),
            mock.call("/root/.ssh/authorized_keys", "r+"),
            mock.call("/root/.ssh/id_rsa.pub")
        ])
        mock_exists.assert_has_calls([
            mock.call("/root/.ssh/authorized_keys"),
            mock.call("/root/.ssh/id_rsa"),
            mock.call("/root/.ssh/id_dsa"),
            mock.call("/root/.ssh/id_ecdsa"),
            mock.call("/root/.ssh/id_ed25519"),
        ])
        mock_append.assert_called_once_with("/root/.ssh/id_rsa.pub", "/root/.ssh/authorized_keys")
