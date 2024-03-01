"""
Unitary tests for crmsh/bootstrap.py

:author: xinliang
:organization: SUSE Linux GmbH
:contact: XLiang@suse.de

:since: 2019-10-21
"""

# pylint:disable=C0103,C0111,W0212,W0611

import subprocess
import unittest
import yaml
import socket

import crmsh.sh
import crmsh.ssh_key
import crmsh.user_of_host
import crmsh.utils
from crmsh.ui_node import NodeMgmt

try:
    from unittest import mock
except ImportError:
    import mock

from crmsh import bootstrap
from crmsh import constants
from crmsh import qdevice


class TestContext(unittest.TestCase):
    """
    Unitary tests for crmsh.bootstrap.Context
    """

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """
        self.ctx_inst = bootstrap.Context()

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('crmsh.bootstrap.Validation.valid_admin_ip')
    @mock.patch('crmsh.utils.fatal')
    def test_validate_network_options_one_link(self, mock_error, valid_ip):
        self.ctx_inst.admin_ip = "10.10.10.123"
        self.ctx_inst.type = "init"
        self.ctx_inst.transport = "udpu"
        self.ctx_inst.nic_addr_list = ["eth1", "eth2"]
        mock_error.side_effect = SystemExit
        with self.assertRaises(SystemExit):
            self.ctx_inst._validate_network_options()
        mock_error.assert_called_once_with("Only one link is allowed for the 'udpu' transport type")

    @mock.patch('crmsh.utils.fatal')
    def test_validate_network_options_max_link(self, mock_error):
        self.ctx_inst.admin_ip = None
        self.ctx_inst.type = "init"
        self.ctx_inst.transport = "knet"
        self.ctx_inst.nic_addr_list = [f"eth{x}" for x in range(10)]
        mock_error.side_effect = SystemExit
        with self.assertRaises(SystemExit):
            self.ctx_inst._validate_network_options()
        mock_error.assert_called_once_with("Maximum number of interfaces is 8")

    @mock.patch('crmsh.utils.detect_cloud')
    @mock.patch('crmsh.utils.fatal')
    def test_validate_network_options_udp_cloud(self, mock_error, mock_cloud):
        mock_cloud.return_value = "aws"
        self.ctx_inst.admin_ip = None
        self.ctx_inst.type = "init"
        self.ctx_inst.transport = "udp"
        self.ctx_inst.nic_addr_list = ["eth1"]
        mock_error.side_effect = SystemExit
        with self.assertRaises(SystemExit):
            self.ctx_inst._validate_network_options()
        mock_error.assert_called_once_with("Transport udp(multicast) cannot be used in aws platform")

    @mock.patch('crmsh.bootstrap.Context.initialize_user')
    def test_set_context(self, mock_initialize_user: mock.MagicMock):
        options = mock.Mock(yes_to_all=True, ipv6=False)
        ctx = self.ctx_inst.set_context(options)
        self.assertEqual(ctx.yes_to_all, True)
        self.assertEqual(ctx.ipv6, False)
        mock_initialize_user.assert_called_once()

    @mock.patch('crmsh.qdevice.QDevice')
    def test_initialize_qdevice_return(self, mock_qdevice):
        self.ctx_inst.initialize_qdevice()
        mock_qdevice.assert_not_called()

    @mock.patch('crmsh.qdevice.QDevice')
    def test_initialize_qdevice(self, mock_qdevice):
        ctx = crmsh.bootstrap.Context()
        ctx.qnetd_addr = "node3"
        ctx.qdevice_port = 123
        ctx.stage = ""
        ctx.initialize_qdevice()
        mock_qdevice.assert_called_once_with('node3', port=123, ssh_user=None, algo=None, tie_breaker=None, tls=None, cmds=None, mode=None, is_stage=False)

    @mock.patch('crmsh.qdevice.QDevice')
    def test_initialize_qdevice_with_user(self, mock_qdevice):
        ctx = crmsh.bootstrap.Context()
        ctx.qnetd_addr = "alice@node3"
        ctx.qdevice_port = 123
        ctx.stage = ""
        ctx.initialize_qdevice()
        mock_qdevice.assert_called_once_with('node3', port=123, ssh_user='alice', algo=None, tie_breaker=None, tls=None, cmds=None, mode=None, is_stage=False)

    @mock.patch('crmsh.utils.fatal')
    def test_validate_sbd_option_error_together(self, mock_error):
        mock_error.side_effect = SystemExit
        ctx = crmsh.bootstrap.Context()
        ctx.sbd_devices = ["/dev/sda1"]
        ctx.diskless_sbd = True
        with self.assertRaises(SystemExit):
            ctx._validate_sbd_option()
        mock_error.assert_called_once_with("Can't use -s and -S options together")

    @mock.patch('crmsh.utils.fatal')
    def test_validate_sbd_option_error_sbd_stage_no_option(self, mock_error):
        mock_error.side_effect = SystemExit
        ctx = crmsh.bootstrap.Context()
        ctx.stage = "sbd"
        ctx.yes_to_all = True
        with self.assertRaises(SystemExit):
            ctx._validate_sbd_option()
        mock_error.assert_called_once_with("Stage sbd should specify sbd device by -s or diskless sbd by -S option")

    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    def test_validate_sbd_option_error_sbd_stage_service(self, mock_active, mock_error):
        mock_error.side_effect = SystemExit
        ctx = crmsh.bootstrap.Context()
        ctx.stage = "sbd"
        ctx.diskless_sbd = True
        mock_active.return_value = True
        with self.assertRaises(SystemExit):
            ctx._validate_sbd_option()
        mock_error.assert_called_once_with("Can't configure stage sbd: sbd.service already running! Please use crm option '-F' if need to redeploy")
        mock_active.assert_called_once_with("sbd.service")

    @mock.patch('crmsh.utils.check_all_nodes_reachable')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    def test_validate_sbd_option_error_sbd_stage(self, mock_active, mock_check_all):
        options = mock.Mock(stage="sbd", diskless_sbd=True, cluster_is_running=True)
        ctx = crmsh.bootstrap.Context()
        ctx.stage = "sbd"
        ctx.diskless_sbd = True
        ctx.cluster_is_running = True
        mock_active.return_value = False
        ctx._validate_sbd_option()
        mock_active.assert_called_once_with("sbd.service")
        mock_check_all.assert_called_once_with()

    @mock.patch('crmsh.utils.fatal')
    @mock.patch('socket.gethostbyname')
    @mock.patch('crmsh.utils.InterfacesInfo.ip_in_local')
    def test_validate_cluster_node_same_name(self, mock_ip_in_local, mock_gethost, mock_fatal):
        options = mock.Mock(cluster_node="me", type="join")
        ctx = crmsh.bootstrap.Context()
        ctx.cluster_node = "me"
        ctx.type = "join"
        mock_fatal.side_effect = SystemExit
        mock_gethost.return_value = ("10.10.10.41", None)
        mock_ip_in_local.return_value = True
        with self.assertRaises(SystemExit):
            ctx._validate_cluster_node()
        mock_fatal.assert_called_once_with("Please specify peer node's hostname or IP address")

    @mock.patch('crmsh.utils.fatal')
    @mock.patch('socket.gethostbyname')
    def test_validate_cluster_node_unknown_name(self, mock_gethost, mock_fatal):
        ctx = crmsh.bootstrap.Context()
        ctx.cluster_node = "xxxx"
        ctx.type = "join"
        mock_fatal.side_effect = SystemExit
        mock_gethost.side_effect = socket.gaierror("gethostbyname error")
        with self.assertRaises(SystemExit):
            ctx._validate_cluster_node()
        mock_fatal.assert_called_once_with('"xxxx": gethostbyname error')

    @mock.patch('logging.Logger.warning')
    @mock.patch('crmsh.bootstrap.Validation.valid_admin_ip')
    def test_validate_option(self, mock_admin_ip, mock_warn):
        ctx = crmsh.bootstrap.Context()
        ctx.admin_ip = "10.10.10.123"
        ctx.qdevice_inst = mock.Mock()
        ctx._validate_sbd_option = mock.Mock()
        ctx._validate_nodes_option = mock.Mock()
        ctx.validate_option()
        mock_admin_ip.assert_called_once_with("10.10.10.123")
        ctx.qdevice_inst.valid_qdevice_options.assert_called_once_with()
        ctx._validate_sbd_option.assert_called_once_with()

    @mock.patch('logging.Logger.info')
    def test_load_specific_profile_return(self, mock_status):
        res = self.ctx_inst.load_specific_profile(None)
        assert res == {}
        mock_status.assert_not_called()

    @mock.patch('logging.Logger.info')
    def test_load_specific_profile_not_exist(self, mock_status):
        self.ctx_inst.profiles_data = {"name": "test"}
        res = self.ctx_inst.load_specific_profile("newname")
        assert res == {}
        mock_status.assert_called_once_with("\"newname\" profile does not exist in {}".format(bootstrap.PROFILES_FILE))

    @mock.patch('logging.Logger.info')
    def test_load_specific_profile(self, mock_status):
        self.ctx_inst.profiles_data = {"name": "test"}
        res = self.ctx_inst.load_specific_profile("name")
        assert res == "test"
        mock_status.assert_called_once_with("Loading \"name\" profile from {}".format(bootstrap.PROFILES_FILE))

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.utils.detect_cloud')
    @mock.patch('os.uname')
    def test_detect_platform_s390(self, mock_uname, mock_cloud, mock_status):
        mock_uname.return_value = mock.Mock(machine="s390")
        res = self.ctx_inst.detect_platform()
        self.assertEqual(res, bootstrap.Context.S390_PROFILE_NAME)
        mock_uname.assert_called_once_with()
        mock_cloud.assert_not_called()
        mock_status.assert_called_once_with("Detected \"{}\" platform".format(res))

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.utils.detect_cloud')
    @mock.patch('os.uname')
    def test_detect_platform(self, mock_uname, mock_cloud, mock_status):
        mock_uname.return_value = mock.Mock(machine="xxx")
        mock_cloud.return_value = "azure"
        res = self.ctx_inst.detect_platform()
        self.assertEqual(res, "azure")
        mock_uname.assert_called_once_with()
        mock_cloud.assert_called_once_with()
        mock_status.assert_called_once_with("Detected \"{}\" platform".format(res))

    @mock.patch('os.path.exists')
    @mock.patch('crmsh.bootstrap.Context.detect_platform')
    def test_load_profiles_file_not_exist(self, mock_platform, mock_exists):
        mock_platform.return_value = "s390"
        mock_exists.return_value = False
        self.ctx_inst.load_profiles()
        mock_platform.assert_called_once_with()
        mock_exists.assert_called_once_with(bootstrap.PROFILES_FILE)

    @mock.patch('yaml.load')
    @mock.patch('builtins.open', new_callable=mock.mock_open, read_data="")
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.bootstrap.Context.detect_platform')
    def test_load_profiles_file_empty(self, mock_platform, mock_exists, mock_open_file, mock_load):
        mock_platform.return_value = "s390"
        mock_exists.return_value = True
        mock_load.return_value = ""
        self.ctx_inst.load_profiles()
        mock_platform.assert_called_once_with()
        mock_exists.assert_called_once_with(bootstrap.PROFILES_FILE)
        mock_open_file.assert_called_once_with(bootstrap.PROFILES_FILE)
        mock_load.assert_called_once_with(mock_open_file.return_value, Loader=yaml.SafeLoader)

    @mock.patch('crmsh.bootstrap.Context.load_specific_profile')
    @mock.patch('yaml.load')
    @mock.patch('builtins.open', new_callable=mock.mock_open, read_data="")
    @mock.patch('os.path.exists')
    @mock.patch('crmsh.bootstrap.Context.detect_platform')
    def test_load_profiles_file(self, mock_platform, mock_exists, mock_open_file, mock_load, mock_load_specific):
        mock_platform.return_value = "s390"
        mock_exists.return_value = True
        mock_load.return_value = "data"
        mock_load_specific.side_effect = [
                {"name": "xin", "age": 18},
                {"name": "wang"}
                ]

        self.ctx_inst.load_profiles()
        assert self.ctx_inst.profiles_dict == {"name": "wang", "age": 18}

        mock_platform.assert_called_once_with()
        mock_exists.assert_called_once_with(bootstrap.PROFILES_FILE)
        mock_open_file.assert_called_once_with(bootstrap.PROFILES_FILE)
        mock_load.assert_called_once_with(mock_open_file.return_value, Loader=yaml.SafeLoader)
        mock_load_specific.assert_has_calls([
            mock.call(bootstrap.Context.DEFAULT_PROFILE_NAME),
            mock.call("s390")
            ])

    @mock.patch('crmsh.userdir.get_sudoer')
    @mock.patch('crmsh.userdir.getuser')
    def test_initialize_user_without_args_without_sudoer(self, mock_getuser: mock.MagicMock, mock_get_sudoer: mock.MagicMock):
        mock_getuser.return_value = 'root'
        mock_get_sudoer.return_value = None
        context = bootstrap.Context()
        context.cluster_node = None
        context.user_at_node_list = None
        context.initialize_user()
        self.assertEqual('root', context.current_user)

    @mock.patch('crmsh.userdir.get_sudoer')
    @mock.patch('crmsh.userdir.getuser')
    def test_initialize_user_without_args_with_sudoer(self, mock_getuser: mock.MagicMock, mock_get_sudoer: mock.MagicMock):
        mock_getuser.return_value = 'root'
        mock_get_sudoer.return_value = 'alice'
        context = bootstrap.Context()
        context.cluster_node = None
        context.user_at_node_list = None
        context.initialize_user()
        self.assertEqual('root', context.current_user)

    @mock.patch('crmsh.userdir.get_sudoer')
    @mock.patch('crmsh.userdir.getuser')
    def test_initialize_user_cluster_node_without_user_without_sudoer(self, mock_getuser: mock.MagicMock, mock_get_sudoer: mock.MagicMock):
        mock_getuser.return_value = 'root'
        mock_get_sudoer.return_value = None
        context = bootstrap.Context()
        context.cluster_node = 'node1'
        context.user_at_node_list = None
        context.initialize_user()
        self.assertEqual('root', context.current_user)

    @mock.patch('crmsh.userdir.get_sudoer')
    @mock.patch('crmsh.userdir.getuser')
    def test_initialize_user_cluster_node_with_user_without_sudoer(self, mock_getuser: mock.MagicMock, mock_get_sudoer: mock.MagicMock):
        mock_getuser.return_value = 'root'
        mock_get_sudoer.return_value = None
        context = bootstrap.Context()
        context.cluster_node = 'alice@node1'
        context.user_at_node_list = None
        with self.assertRaises(ValueError):
            context.initialize_user()

    @mock.patch('crmsh.userdir.get_sudoer')
    @mock.patch('crmsh.userdir.getuser')
    def test_initialize_user_cluster_node_without_user_with_sudoer(self, mock_getuser: mock.MagicMock, mock_get_sudoer: mock.MagicMock):
        mock_getuser.return_value = 'root'
        mock_get_sudoer.return_value = 'bob'
        context = bootstrap.Context()
        context.cluster_node = 'node1'
        context.user_at_node_list = None
        context.initialize_user()
        self.assertEqual('root', context.current_user)

    @mock.patch('crmsh.userdir.get_sudoer')
    @mock.patch('crmsh.userdir.getuser')
    def test_initialize_user_cluster_node_with_user_with_sudoer(self, mock_getuser: mock.MagicMock, mock_get_sudoer: mock.MagicMock):
        mock_getuser.return_value = 'root'
        mock_get_sudoer.return_value = 'bob'
        context = bootstrap.Context()
        context.cluster_node = 'alice@node1'
        context.user_at_node_list = None
        context.initialize_user()
        self.assertEqual('bob', context.current_user)

    @mock.patch('crmsh.userdir.get_sudoer')
    @mock.patch('crmsh.userdir.getuser')
    def test_initialize_user_node_list_without_user_without_sudoer(self, mock_getuser: mock.MagicMock, mock_get_sudoer: mock.MagicMock):
        mock_getuser.return_value = 'root'
        mock_get_sudoer.return_value = None
        context = bootstrap.Context()
        context.user_at_node_list = ['node1', 'node2']
        context.cluster_node = None
        context.initialize_user()
        self.assertEqual('root', context.current_user)

    @mock.patch('crmsh.userdir.get_sudoer')
    @mock.patch('crmsh.userdir.getuser')
    def test_initialize_user_node_list_with_user_without_sudoer(self, mock_getuser: mock.MagicMock, mock_get_sudoer: mock.MagicMock):
        mock_getuser.return_value = 'root'
        mock_get_sudoer.return_value = None
        context = bootstrap.Context()
        context.user_at_node_list = ['alice@node1', 'alice@node2']
        context.cluster_node = None
        with self.assertRaises(ValueError):
            context.initialize_user()

    @mock.patch('crmsh.userdir.get_sudoer')
    @mock.patch('crmsh.userdir.getuser')
    def test_initialize_user_node_list_without_user_with_sudoer(self, mock_getuser: mock.MagicMock, mock_get_sudoer: mock.MagicMock):
        mock_getuser.return_value = 'root'
        mock_get_sudoer.return_value = 'bob'
        context = bootstrap.Context()
        context.user_at_node_list = ['node1', 'node2']
        context.cluster_node = None
        context.initialize_user()
        self.assertEqual('root', context.current_user)

    @mock.patch('crmsh.userdir.get_sudoer')
    @mock.patch('crmsh.userdir.getuser')
    def test_initialize_user_node_list_with_user_with_sudoer(self, mock_getuser: mock.MagicMock, mock_get_sudoer: mock.MagicMock):
        mock_getuser.return_value = 'root'
        mock_get_sudoer.return_value = 'bob'
        context = bootstrap.Context()
        context.user_at_node_list = ['alice@node1', 'alice@node2']
        context.cluster_node = None
        context.initialize_user()
        self.assertEqual('bob', context.current_user)


class TestBootstrap(unittest.TestCase):
    """
    Unitary tests for crmsh/bootstrap.py
    """

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """
        self.qdevice_with_ip = qdevice.QDevice("10.10.10.123")

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('crmsh.parallax.parallax_call')
    @mock.patch('crmsh.service_manager.ServiceManager.start_service')
    @mock.patch('crmsh.sbd.SBDTimeout.is_sbd_delay_start')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_enabled')
    @mock.patch('crmsh.utils.package_is_installed')
    def test_start_pacemaker(self, mock_installed, mock_enabled, mock_delay_start, mock_start, mock_parallax_call):
        bootstrap._context = None
        mock_installed.return_value = True
        mock_enabled.return_value = True
        mock_delay_start.return_value = True
        node_list = ["node1", "node2", "node3", "node4", "node5", "node6"]
        bootstrap.start_pacemaker(node_list)
        mock_start.assert_has_calls([
            mock.call("corosync.service", remote_addr="node1"),
            mock.call("corosync.service", remote_addr="node2"),
            mock.call("corosync.service", remote_addr="node3"),
            mock.call("corosync.service", remote_addr="node4"),
            mock.call("corosync.service", remote_addr="node5"),
            mock.call("corosync.service", remote_addr="node6"),
            mock.call("pacemaker.service", enable=False, node_list=node_list)
            ])
        mock_parallax_call.assert_has_calls([
            mock.call(node_list, 'mkdir -p /run/systemd/system/sbd.service.d/'),
            mock.call(node_list, "echo -e '[Service]\nUnsetEnvironment=SBD_DELAY_START' > /run/systemd/system/sbd.service.d/sbd_delay_start_disabled.conf"),
            mock.call(node_list, "systemctl daemon-reload"),
            ])

    @mock.patch('crmsh.bootstrap.configure_ssh_key')
    @mock.patch('crmsh.service_manager.ServiceManager.start_service')
    def test_init_ssh(self, mock_start_service, mock_config_ssh):
        bootstrap._context = mock.Mock(current_user="alice", user_at_node_list=[], use_ssh_agent=False)
        bootstrap.init_ssh()
        mock_start_service.assert_called_once_with("sshd.service", enable=True)
        mock_config_ssh.assert_has_calls([
            mock.call("alice")
            ])

    @mock.patch('crmsh.userdir.gethomedir')
    def test_key_files(self, mock_gethome):
        mock_gethome.return_value = "/root"
        expected_res = {"private": "/root/.ssh/id_rsa", "public": "/root/.ssh/id_rsa.pub", "authorized": "/root/.ssh/authorized_keys"}
        self.assertEqual(bootstrap.key_files("root"), expected_res)
        mock_gethome.assert_called_once_with("root")

    @mock.patch('builtins.open')
    def test_is_nologin(self, mock_open_file):
        data = "hacluster:x:90:90:heartbeat processes:/var/lib/heartbeat/cores/hacluster:/sbin/nologin"
        mock_open_file.return_value = mock.mock_open(read_data=data).return_value
        assert bootstrap.is_nologin("hacluster") is not None
        mock_open_file.assert_called_once_with("/etc/passwd")

    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.bootstrap.is_nologin')
    def test_change_user_shell_return(self, mock_nologin, mock_status, mock_confirm):
        bootstrap._context = mock.Mock(yes_to_all=False)
        mock_nologin.return_value = True
        mock_confirm.return_value = False

        bootstrap.change_user_shell("hacluster")

        mock_nologin.assert_called_once_with("hacluster", None)
        mock_confirm.assert_called_once_with("Continue?")

    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    @mock.patch('crmsh.bootstrap.is_nologin')
    def test_change_user_shell(self, mock_nologin, mock_invoke):
        bootstrap._context = mock.Mock(yes_to_all=True)
        mock_nologin.return_value = True

        bootstrap.change_user_shell("hacluster")

        mock_nologin.assert_called_once_with("hacluster", None)
        mock_invoke.assert_called_once_with("usermod -s /bin/bash hacluster", None)

    @mock.patch('crmsh.sh.LocalShell.su_subprocess_run')
    def test_generate_ssh_key_pair_on_remote(self, mock_su: mock.MagicMock):
        mock_su.return_value = mock.Mock(returncode=0, stdout=b'')
        bootstrap.generate_ssh_key_pair_on_remote('local_sudoer', 'remote_host', 'remote_sudoer', 'remote_user')
        mock_su.assert_has_calls([
            mock.call(
                'local_sudoer',
                'ssh -o StrictHostKeyChecking=no remote_sudoer@remote_host sudo -H -u remote_user /bin/sh',
                input='''
[ -f ~/.ssh/id_rsa ] || ssh-keygen -q -t rsa -f ~/.ssh/id_rsa -C "Cluster internal on $(hostname)" -N ''
[ -f ~/.ssh/id_rsa.pub ] || ssh-keygen -y -f ~/.ssh/id_rsa > ~/.ssh/id_rsa.pub
'''.encode('utf-8'),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            ),
            mock.call(
                'local_sudoer',
                'ssh -o StrictHostKeyChecking=no remote_sudoer@remote_host sudo -H -u remote_user /bin/sh',
                input='cat ~/.ssh/id_rsa.pub'.encode('utf-8'),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ),
        ])

    @mock.patch('crmsh.bootstrap.append_unique')
    @mock.patch('crmsh.sh.LocalShell.get_stdout_or_raise_error')
    @mock.patch('crmsh.utils.detect_file')
    @mock.patch('crmsh.bootstrap.key_files')
    @mock.patch('crmsh.bootstrap.change_user_shell')
    def _test_configure_ssh_key(self, mock_change_shell, mock_key_files, mock_detect, mock_su, mock_append_unique):
        mock_key_files.return_value = {"private": "/test/.ssh/id_rsa", "public": "/test/.ssh/id_rsa.pub", "authorized": "/test/.ssh/authorized_keys"}
        mock_detect.side_effect = [True, True, False]

        bootstrap.configure_ssh_key("test")

        mock_change_shell.assert_called_once_with("test")
        mock_key_files.assert_called_once_with("test")
        mock_detect.assert_has_calls([
            mock.call("/test/.ssh/id_rsa"),
            mock.call("/test/.ssh/id_rsa.pub"),
            mock.call("/test/.ssh/authorized_keys")
            ])
        mock_append_unique.assert_called_once_with("/test/.ssh/id_rsa.pub", "/test/.ssh/authorized_keys", "test")
        mock_su.assert_called_once_with('test', 'touch /test/.ssh/authorized_keys')

    @mock.patch('crmsh.ssh_key.AuthorizedKeyManager.add')
    @mock.patch('crmsh.ssh_key.KeyFileManager.ensure_key_pair_exists_for_user')
    def test_configure_ssh_key(self, mock_ensure_key_pair, mock_add):
        public_key = crmsh.ssh_key.InMemoryPublicKey('foo')
        mock_ensure_key_pair.return_value = (True, [public_key])
        bootstrap.configure_ssh_key('alice')
        mock_ensure_key_pair.assert_called_once_with(None, 'alice')
        mock_add.assert_called_once_with(None, 'alice', public_key)

    @mock.patch('crmsh.bootstrap.append_to_remote_file')
    @mock.patch('crmsh.utils.check_file_content_included')
    def test_append_unique_remote(self, mock_check, mock_append):
        mock_check.return_value = False
        bootstrap.append_unique("fromfile", "tofile", user="root", remote="node1", from_local=True)
        mock_check.assert_called_once_with("fromfile", "tofile", remote="node1", source_local=True)
        mock_append.assert_called_once_with("fromfile", "root", "node1", "tofile")

    @mock.patch('crmsh.bootstrap.append')
    @mock.patch('crmsh.utils.check_file_content_included')
    def test_append_unique(self, mock_check, mock_append):
        mock_check.return_value = False
        bootstrap.append_unique("fromfile", "tofile")
        mock_check.assert_called_once_with("fromfile", "tofile", remote=None, source_local=False)
        mock_append.assert_called_once_with("fromfile", "tofile", remote=None)

    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    def test_append_to_remote_file(self, mock_run):
        bootstrap.append_to_remote_file("fromfile", "root", "node1", "tofile")
        cmd = "cat fromfile | ssh {} root@node1 'cat >> tofile'".format(constants.SSH_OPTION)
        mock_run.assert_called_once_with(cmd)

    @mock.patch('crmsh.utils.fatal')
    def test_join_ssh_no_seed_host(self, mock_error):
        mock_error.side_effect = ValueError
        with self.assertRaises(ValueError):
            bootstrap.join_ssh(None, None)
        mock_error.assert_called_once_with("No existing IP/hostname specified (use -c option)")

    @mock.patch('crmsh.bootstrap.get_node_canonical_hostname')
    @mock.patch('crmsh.bootstrap.swap_public_ssh_key_for_secondary_user')
    @mock.patch('crmsh.bootstrap.change_user_shell')
    @mock.patch('crmsh.sh.LocalShell.get_stdout_or_raise_error')
    @mock.patch('crmsh.bootstrap.swap_public_ssh_key')
    @mock.patch('crmsh.utils.ssh_copy_id_no_raise')
    @mock.patch('crmsh.bootstrap.configure_ssh_key')
    @mock.patch('crmsh.service_manager.ServiceManager.start_service')
    def test_join_ssh(
            self,
            mock_start_service, mock_config_ssh, mock_ssh_copy_id, mock_swap, mock_invoke, mock_change, mock_swap_2,
            mock_get_node_cononical_hostname,
    ):
        bootstrap._context = mock.Mock(current_user="bob", default_nic="eth1", use_ssh_agent=False)
        mock_invoke.return_value = ''
        mock_swap.return_value = None
        mock_ssh_copy_id.return_value = 0
        mock_get_node_cononical_hostname.return_value='node1'

        bootstrap.join_ssh("node1", "alice")

        mock_start_service.assert_called_once_with("sshd.service", enable=True)
        mock_config_ssh.assert_has_calls([
                mock.call("bob"),
                mock.call("hacluster"),
            ])
        mock_ssh_copy_id.assert_called_once_with("bob", "alice", "node1")
        mock_swap.assert_called_once_with("node1", "bob", "alice", "bob", "alice", add=True)
        mock_invoke.assert_called_once_with(
            "bob",
            "ssh {} alice@node1 sudo crm cluster init -i eth1 ssh_remote".format(constants.SSH_OPTION),
        )
        mock_swap_2.assert_called_once()
        args, kwargs = mock_swap_2.call_args
        self.assertEqual(3, len(args))
        self.assertEqual('node1', args[1])
        self.assertEqual('hacluster', args[2])

    @mock.patch('crmsh.ssh_key.AuthorizedKeyManager.add')
    @mock.patch('crmsh.ssh_key.KeyFile.public_key')
    @mock.patch('crmsh.ssh_key.KeyFileManager.ensure_key_pair_exists_for_user')
    @mock.patch('crmsh.ssh_key.KeyFileManager.list_public_key_for_user')
    @mock.patch('logging.Logger.info')
    def test_swap_public_ssh_key_for_secondary_user(
            self,
            mock_log_info,
            mock_list_public_key_for_user,
            mock_ensure_key_pair_exists_for_user,
            mock_public_key,
            mock_authorized_key_manager_add,
    ):
        mock_shell = mock.Mock(
            crmsh.sh.ClusterShell,
            local_shell=mock.Mock(crmsh.sh.LocalShell),
            user_of_host=mock.Mock(crmsh.user_of_host.UserOfHost),
        )
        mock_list_public_key_for_user.return_value = ['~/.ssh/id_rsa', '~/.ssh/id_ed25519']
        mock_ensure_key_pair_exists_for_user.return_value = (True, [
            crmsh.ssh_key.InMemoryPublicKey('foo'),
            crmsh.ssh_key.InMemoryPublicKey('bar'),
        ])
        mock_public_key.return_value = 'public_key'
        crmsh.bootstrap.swap_public_ssh_key_for_secondary_user(mock_shell, 'node1', 'alice')
        mock_list_public_key_for_user.assert_called_once_with(None, 'alice')
        mock_ensure_key_pair_exists_for_user.assert_called_once_with('node1', 'alice')
        mock_authorized_key_manager_add.assert_has_calls([
            mock.call(None, 'alice', crmsh.ssh_key.InMemoryPublicKey('foo')),
            mock.call('node1', 'alice', crmsh.ssh_key.KeyFile('~/.ssh/id_rsa')),
        ])
        mock_log_info.assert_called_with("A new ssh keypair is generated for user %s@%s.", 'alice', 'node1')

    @mock.patch('crmsh.bootstrap.change_user_shell')
    @mock.patch('crmsh.sh.LocalShell.get_stdout_or_raise_error')
    @mock.patch('crmsh.bootstrap.swap_public_ssh_key')
    @mock.patch('crmsh.utils.ssh_copy_id_no_raise')
    @mock.patch('crmsh.bootstrap.configure_ssh_key')
    @mock.patch('crmsh.service_manager.ServiceManager.start_service')
    def test_join_ssh_bad_credential(self, mock_start_service, mock_config_ssh, mock_ssh_copy_id, mock_swap, mock_invoke, mock_change):
        bootstrap._context = mock.Mock(current_user="bob", default_nic="eth1", use_ssh_agent=False)
        mock_invoke.return_value = ''
        mock_swap.return_value = None
        mock_ssh_copy_id.return_value = 255

        with self.assertRaises(ValueError):
            bootstrap.join_ssh("node1", "alice")

        mock_start_service.assert_called_once_with("sshd.service", enable=True)
        mock_config_ssh.assert_has_calls([
            mock.call("bob"),
        ])
        mock_ssh_copy_id.assert_called_once_with("bob", "alice", "node1")
        mock_swap.assert_not_called()
        mock_invoke.assert_not_called()


    @mock.patch('crmsh.bootstrap.import_ssh_key')
    @mock.patch('crmsh.bootstrap.export_ssh_key_non_interactive')
    @mock.patch('logging.Logger.warning')
    @mock.patch('crmsh.utils.check_ssh_passwd_need')
    def test_swap_public_ssh_key_exception(self, mock_check_passwd, mock_warn, mock_export_ssh_key, mock_import_ssh):
        mock_check_passwd.return_value = False
        mock_import_ssh.side_effect = ValueError("Can't get the remote id_rsa.pub from {}: {}")

        bootstrap.swap_public_ssh_key("node1", "bob", "bob", "alice", "alice")

        mock_check_passwd.assert_called_once_with("bob", "bob", "node1")
        mock_import_ssh.assert_called_once_with("bob", "bob", "alice", "node1", "alice")
        mock_warn.assert_called_once_with(mock_import_ssh.side_effect)

    @mock.patch('crmsh.bootstrap.import_ssh_key')
    @mock.patch('crmsh.bootstrap.export_ssh_key_non_interactive')
    @mock.patch('crmsh.utils.check_ssh_passwd_need')
    def test_swap_public_ssh_key(self, mock_check_passwd, mock_export_ssh, mock_import_ssh):
        mock_check_passwd.return_value = True

        bootstrap.swap_public_ssh_key("node1", "bob", "bob", "alice", "alice")

        mock_check_passwd.assert_called_once_with("bob", "bob", "node1")
        mock_export_ssh.assert_called_once_with("bob", "bob", "node1", "alice", "alice")
        mock_import_ssh.assert_called_once_with("bob", "bob", "alice", "node1", "alice")

    @mock.patch('crmsh.utils.this_node')
    def test_bootstrap_add_return(self, mock_this_node):
        ctx = mock.Mock(user_at_node_list=[], use_ssh_agent=False)
        bootstrap.bootstrap_add(ctx)
        mock_this_node.assert_not_called()

    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.utils.this_node')
    def test_bootstrap_add(self, mock_this_node, mock_info, mock_run):
        mock_interfaces_inst = mock.Mock(input_nic_list=["eth1", "eth2"])
        ctx = mock.Mock(current_user="alice", user_at_node_list=["bob@node2", "carol@node3"], nic_list=["eth1"], use_ssh_agent=False, interfaces_inst=mock_interfaces_inst)
        mock_this_node.return_value = "node1"
        bootstrap.bootstrap_add(ctx)
        mock_info.assert_has_calls([
            mock.call("Adding node node2 to cluster"),
            mock.call("Running command on node2: crm cluster join -y  -i eth1 -i eth2 -c alice@node1"),
            mock.call("Adding node node3 to cluster"),
            mock.call("Running command on node3: crm cluster join -y  -i eth1 -i eth2 -c alice@node1")
            ])

    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.sh.ClusterShell.get_rc_stdout_stderr_without_input')
    def test_setup_passwordless_with_other_nodes_failed_fetch_nodelist(self, mock_run, mock_error):
        bootstrap._context = mock.Mock(current_user="carol", use_ssh_agent=False)
        mock_run.return_value = (1, None, None)
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap.setup_passwordless_with_other_nodes("node1", "alice")

        mock_run.assert_called_once_with('node1', 'crm_node -l')
        mock_error.assert_called_once_with("Can't fetch cluster nodes list from node1: None")

    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.utils.HostUserConfig')
    @mock.patch('crmsh.bootstrap._fetch_core_hosts')
    @mock.patch('crmsh.sh.ClusterShell.get_rc_stdout_stderr_without_input')
    def test_setup_passwordless_with_other_nodes_failed_fetch_hostname(
            self,
            mock_run,
            mock_fetch_core_hosts,
            mock_host_user_config_class,
            mock_error,
    ):
        bootstrap._context = mock.Mock(current_user="carol", use_ssh_agent=False)
        out_node_list = """1 node1 member
        2 node2 member"""
        mock_run.side_effect = [
                (0, out_node_list, None),
                (1, None, None)
                ]
        mock_fetch_core_hosts.return_value = (["alice", "bob"], ["node1", "node2"])
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap.setup_passwordless_with_other_nodes("node1", "alice")

        mock_run.assert_has_calls([
            mock.call('node1', 'crm_node -l'),
            mock.call('node1', 'hostname'),
        ])
        mock_error.assert_called_once_with("Can't fetch hostname of node1: None")

    @mock.patch('crmsh.bootstrap.swap_key_for_hacluster')
    @mock.patch('crmsh.bootstrap.change_user_shell')
    @mock.patch('crmsh.utils.HostUserConfig')
    @mock.patch('crmsh.bootstrap._fetch_core_hosts')
    @mock.patch('crmsh.utils.ssh_copy_id')
    @mock.patch('crmsh.utils.user_of')
    @mock.patch('crmsh.bootstrap.swap_public_ssh_key')
    @mock.patch('crmsh.sh.ClusterShell.get_rc_stdout_stderr_without_input')
    def test_setup_passwordless_with_other_nodes(
            self,
            mock_run,
            mock_swap,
            mock_userof,
            mock_ssh_copy_id: mock.MagicMock,
            mock_fetch_core_hosts,
            mock_host_user_config_class,
            mock_change_shell,
            mock_swap_hacluster
    ):
        bootstrap._context = mock.Mock(current_user="carol", use_ssh_agent=False)
        mock_fetch_core_hosts.return_value = (["alice", "bob"], ["node1", "node2"])
        mock_userof.return_value = "bob"
        out_node_list = """1 node1 member
        2 node2 member"""
        mock_run.side_effect = [
                (0, out_node_list, None),
                (0, "node1", None)
                ]

        bootstrap.setup_passwordless_with_other_nodes("node1", "alice")

        mock_run.assert_has_calls([
            mock.call('node1', 'crm_node -l'),
            mock.call('node1', 'hostname'),
        ])
        mock_userof.assert_called_once_with("node2")
        mock_ssh_copy_id.assert_has_calls([
            mock.call('carol', 'bob', 'node2')
        ])
        mock_swap.assert_has_calls([
            mock.call('node2', "carol", "bob", "carol", "bob"),
            mock.call('node2', 'hacluster', 'hacluster', 'carol', 'bob', add=True)
            ])

    @mock.patch('crmsh.userdir.getuser')
    @mock.patch('crmsh.bootstrap.key_files')
    @mock.patch('builtins.open')
    @mock.patch('crmsh.bootstrap.append')
    @mock.patch('os.path.join')
    @mock.patch('os.path.exists')
    def test_init_ssh_remote_no_sshkey(self, mock_exists, mock_join, mock_append, mock_open_file, mock_key_files, mock_getuser):
        mock_getuser.return_value = "alice"
        mock_key_files.return_value = {"private": "/home/alice/.ssh/id_rsa", "public": "/home/alice/.ssh/id_rsa.pub", "authorized": "/home/alice/.ssh/authorized_keys"}
        mock_exists.side_effect = [False, True, False, False, False]
        mock_join.side_effect = ["/home/alice/.ssh/id_rsa",
                                 "/home/alice/.ssh/id_dsa",
                                 "/home/alice/.ssh/id_ecdsa",
                                 "/home/alice/.ssh/id_ed25519"]
        mock_open_file.side_effect = [
            mock.mock_open().return_value,
            mock.mock_open(read_data="data1 data2").return_value,
            mock.mock_open(read_data="data1111").return_value
        ]

        bootstrap.init_ssh_remote()

        mock_getuser.assert_called_once_with()
        mock_key_files.assert_called_once_with("alice")

        mock_open_file.assert_has_calls([
            mock.call("/home/alice/.ssh/authorized_keys", 'w'),
            mock.call("/home/alice/.ssh/authorized_keys", "r+"),
            mock.call("/home/alice/.ssh/id_rsa.pub")
        ])
        mock_exists.assert_has_calls([
            mock.call("/home/alice/.ssh/authorized_keys"),
            mock.call("/home/alice/.ssh/id_rsa"),
            mock.call("/home/alice/.ssh/id_dsa"),
            mock.call("/home/alice/.ssh/id_ecdsa"),
            mock.call("/home/alice/.ssh/id_ed25519"),
        ])
        mock_append.assert_called_once_with("/home/alice/.ssh/id_rsa.pub", "/home/alice/.ssh/authorized_keys")

    @mock.patch('crmsh.sh.ClusterShell.get_rc_stdout_stderr_without_input')
    def test_get_node_canonical_hostname(self, mock_run):
        mock_run.return_value = (0, "Node1", None)

        peer_node = bootstrap.get_node_canonical_hostname('node1')
        self.assertEqual('Node1', peer_node)
        mock_run.assert_called_once_with('node1', 'crm_node --name')

    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.sh.ClusterShell.get_rc_stdout_stderr_without_input')
    def test_get_node_canonical_hostname_error(self, mock_run, mock_error):
        mock_run.return_value = (1, None, "error")
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap.get_node_canonical_hostname('node1')

        mock_run.assert_called_once_with("node1", "crm_node --name")
        mock_error.assert_called_once_with("error")

    @mock.patch('crmsh.utils.this_node')
    @mock.patch('crmsh.bootstrap.get_node_canonical_hostname')
    @mock.patch('crmsh.xmlutil.CrmMonXmlParser.is_node_online')
    def test_is_online_local_offline(self, mock_is_online, mock_get_hostname, mock_this_node):
        bootstrap._context = mock.Mock(cluster_node='node2')
        mock_this_node.return_value = "node1"
        mock_is_online.return_value = False

        assert bootstrap.is_online() is False

        mock_this_node.assert_called_once_with()
        mock_get_hostname.assert_not_called()
        mock_is_online.assert_called_once_with("node1")

    @mock.patch('crmsh.utils.this_node')
    @mock.patch('crmsh.bootstrap.get_node_canonical_hostname')
    @mock.patch('crmsh.xmlutil.CrmMonXmlParser.is_node_online')
    def test_is_online_on_init_node(self, mock_is_online, mock_get_hostname, mock_this_node):
        bootstrap._context = mock.Mock(cluster_node=None)
        mock_this_node.return_value = "node1"
        mock_is_online.return_value = True

        assert bootstrap.is_online() is True

        mock_this_node.assert_called_once_with()
        mock_get_hostname.assert_not_called()
        mock_is_online.assert_called_once_with("node1")

    @mock.patch('crmsh.sh.cluster_shell')
    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.service_manager.ServiceManager.stop_service')
    @mock.patch('crmsh.bootstrap.sync_file')
    @mock.patch('crmsh.corosync.conf')
    @mock.patch('shutil.copy')
    @mock.patch('crmsh.utils.this_node')
    @mock.patch('crmsh.bootstrap.get_node_canonical_hostname')
    @mock.patch('crmsh.xmlutil.CrmMonXmlParser')
    def test_is_online_peer_offline(self, mock_parser, mock_get_hostname, mock_this_node,
            mock_copy, mock_corosync_conf, mock_csync2, mock_stop_service, mock_error, mock_cluster_shell):
        bootstrap._context = mock.Mock(cluster_node='node1')
        mock_parser_inst = mock.Mock()
        mock_parser.return_value = mock_parser_inst
        mock_parser_inst.is_node_online.side_effect = [True, False]
        bootstrap.COROSYNC_CONF_ORIG = "/tmp/crmsh_tmpfile"
        mock_this_node.return_value = "node2"
        mock_get_hostname.return_value = "node1"
        mock_corosync_conf.side_effect = [ "/etc/corosync/corosync.conf",
                "/etc/corosync/corosync.conf"]

        bootstrap.is_online()

        mock_this_node.assert_called_once_with()
        mock_get_hostname.assert_called_once_with('node1')
        mock_corosync_conf.assert_has_calls([
            mock.call(),
            mock.call()
            ])
        mock_copy.assert_called_once_with(bootstrap.COROSYNC_CONF_ORIG, "/etc/corosync/corosync.conf")
        mock_csync2.assert_called_once_with("/etc/corosync/corosync.conf")
        mock_stop_service.assert_called_once_with("corosync")
        mock_error.assert_called_once_with("Cannot see peer node \"node1\", please check the communication IP")

    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.service_manager.ServiceManager.stop_service')
    @mock.patch('crmsh.bootstrap.sync_file')
    @mock.patch('crmsh.corosync.conf')
    @mock.patch('shutil.copy')
    @mock.patch('crmsh.utils.this_node')
    @mock.patch('crmsh.bootstrap.get_node_canonical_hostname')
    @mock.patch('crmsh.xmlutil.CrmMonXmlParser.is_node_online')
    def test_is_online_both_online(self, mock_is_online, mock_get_hostname, mock_this_node,
            mock_copy, mock_corosync_conf, mock_csync2, mock_stop_service, mock_error):
        bootstrap._context = mock.Mock(cluster_node='node2')
        mock_is_online.side_effect = [True, True]
        mock_this_node.return_value = "node2"
        mock_get_hostname.return_value = "node2"

        assert bootstrap.is_online() is True

        mock_this_node.assert_called_once_with()
        mock_get_hostname.assert_called_once_with('node2')
        mock_corosync_conf.assert_not_called()
        mock_copy.assert_not_called()
        mock_csync2.assert_not_called()
        mock_stop_service.assert_not_called()
        mock_error.assert_not_called()

    @mock.patch('crmsh.bootstrap.invokerc')
    @mock.patch('crmsh.bootstrap.invoke')
    def test_csync2_update_no_conflicts(self, mock_invoke, mock_invokerc):
        mock_invokerc.return_value = True
        bootstrap.csync2_update("/etc/corosync.conf")
        mock_invoke.assert_called_once_with("csync2 -rm /etc/corosync.conf")
        mock_invokerc.assert_called_once_with("csync2 -rxv /etc/corosync.conf")

    @mock.patch('logging.Logger.warning')
    @mock.patch('crmsh.bootstrap.invokerc')
    @mock.patch('crmsh.bootstrap.invoke')
    def test_csync2_update(self, mock_invoke, mock_invokerc, mock_warn):
        mock_invokerc.side_effect = [False, False]
        bootstrap.csync2_update("/etc/corosync.conf")
        mock_invoke.assert_has_calls([
            mock.call("csync2 -rm /etc/corosync.conf"),
            mock.call("csync2 -rf /etc/corosync.conf")
            ])
        mock_invokerc.assert_has_calls([
            mock.call("csync2 -rxv /etc/corosync.conf"),
            mock.call("csync2 -rxv /etc/corosync.conf")
            ])
        mock_warn.assert_called_once_with("/etc/corosync.conf was not synced")

    @mock.patch('crmsh.utils.InterfacesInfo')
    def test_init_network_input_nic_list(self, mock_interface_info):
        bootstrap._context = mock.Mock(ipv6=None, nic_addr_list=["eth1", "eth2"])
        mock_interface_info_inst = mock.Mock()
        mock_interface_info.return_value = mock_interface_info_inst
        mock_interface_info_inst.input_nic_list = ["eth1", "eth2"]
        mock_interface_info_inst.input_addr_list = ["10.10.10.1", "20.20.20.1"]

        bootstrap.init_network()

        self.assertEqual(bootstrap._context.default_nic, "eth1")
        self.assertEqual(bootstrap._context.default_ip_list, mock_interface_info_inst.input_addr_list)

    @mock.patch('crmsh.utils.InterfacesInfo')
    def test_init_network_input(self, mock_interface_info):
        bootstrap._context = mock.Mock(ipv6=None, nic_addr_list=[])
        bootstrap.init_network()

    @mock.patch('crmsh.service_manager.ServiceManager.disable_service')
    @mock.patch('logging.Logger.info')
    def test_init_qdevice_no_config(self, mock_status, mock_disable):
        bootstrap._context = mock.Mock(qdevice_inst=None)
        bootstrap.init_qdevice()
        mock_status.assert_not_called()
        mock_disable.assert_called_once_with("corosync-qdevice.service")

    @mock.patch('crmsh.utils.HostUserConfig')
    @mock.patch('crmsh.user_of_host.UserOfHost.instance')
    @mock.patch('crmsh.utils.list_cluster_nodes')
    @mock.patch('crmsh.utils.ssh_copy_id_no_raise')
    @mock.patch('crmsh.bootstrap.configure_ssh_key')
    @mock.patch('crmsh.utils.check_ssh_passwd_need')
    @mock.patch('logging.Logger.info')
    def test_init_qdevice_copy_ssh_key_failed(
            self,
            mock_status, mock_check_ssh_passwd_need,
            mock_configure_ssh_key, mock_ssh_copy_id, mock_list_nodes, mock_user_of_host,
            mock_host_user_config_class,
    ):
        mock_list_nodes.return_value = []
        bootstrap._context = mock.Mock(qdevice_inst=self.qdevice_with_ip, current_user="bob")
        mock_check_ssh_passwd_need.return_value = True
        mock_ssh_copy_id.return_value = 255
        mock_user_of_host.return_value = mock.MagicMock(crmsh.user_of_host.UserOfHost)
        mock_user_of_host.return_value.user_pair_for_ssh.return_value = "bob", "bob"
        mock_user_of_host.return_value.use_ssh_agent.return_value = False

        with self.assertRaises(ValueError):
            bootstrap.init_qdevice()

        mock_status.assert_has_calls([
            mock.call("Configure Qdevice/Qnetd:"),
        ])
        mock_check_ssh_passwd_need.assert_called_once_with("bob", "bob", "10.10.10.123")
        mock_configure_ssh_key.assert_called_once_with('bob')
        mock_ssh_copy_id.assert_called_once_with('bob', 'bob', '10.10.10.123')

    @mock.patch('crmsh.utils.HostUserConfig')
    @mock.patch('crmsh.user_of_host.UserOfHost.instance')
    @mock.patch('crmsh.utils.list_cluster_nodes')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.corosync.is_qdevice_configured')
    @mock.patch('crmsh.bootstrap.configure_ssh_key')
    @mock.patch('crmsh.utils.check_ssh_passwd_need')
    @mock.patch('logging.Logger.info')
    def test_init_qdevice_already_configured(
            self,
            mock_status, mock_ssh, mock_configure_ssh_key,
            mock_qdevice_configured, mock_confirm, mock_list_nodes, mock_user_of_host,
            mock_host_user_config_class,
    ):
        mock_list_nodes.return_value = []
        bootstrap._context = mock.Mock(qdevice_inst=self.qdevice_with_ip, current_user="bob")
        mock_ssh.return_value = False
        mock_user_of_host.return_value = mock.MagicMock(crmsh.user_of_host.UserOfHost)
        mock_user_of_host.return_value.user_pair_for_ssh.return_value = "bob", "bob"
        mock_user_of_host.return_value.use_ssh_agent.return_value = False
        mock_qdevice_configured.return_value = True
        mock_confirm.return_value = False
        self.qdevice_with_ip.start_qdevice_service = mock.Mock()

        bootstrap.init_qdevice()

        mock_status.assert_called_once_with("Configure Qdevice/Qnetd:")
        mock_ssh.assert_called_once_with("bob", "bob", "10.10.10.123")
        mock_configure_ssh_key.assert_not_called()
        mock_host_user_config_class.return_value.save_remote.assert_called_once_with(mock_list_nodes.return_value)
        mock_qdevice_configured.assert_called_once_with()
        mock_confirm.assert_called_once_with("Qdevice is already configured - overwrite?")
        self.qdevice_with_ip.start_qdevice_service.assert_called_once_with()

    @mock.patch('crmsh.utils.HostUserConfig')
    @mock.patch('crmsh.user_of_host.UserOfHost.instance')
    @mock.patch('crmsh.bootstrap.adjust_priority_fencing_delay')
    @mock.patch('crmsh.bootstrap.adjust_priority_in_rsc_defaults')
    @mock.patch('crmsh.utils.list_cluster_nodes')
    @mock.patch('crmsh.utils.this_node')
    @mock.patch('crmsh.corosync.is_qdevice_configured')
    @mock.patch('crmsh.bootstrap.configure_ssh_key')
    @mock.patch('crmsh.utils.check_ssh_passwd_need')
    @mock.patch('logging.Logger.info')
    def test_init_qdevice(self, mock_info, mock_ssh, mock_configure_ssh_key, mock_qdevice_configured,
                          mock_this_node, mock_list_nodes, mock_adjust_priority, mock_adjust_fence_delay,
                          mock_user_of_host, mock_host_user_config_class):
        bootstrap._context = mock.Mock(qdevice_inst=self.qdevice_with_ip, current_user="bob")
        mock_this_node.return_value = "192.0.2.100"
        mock_list_nodes.return_value = []
        mock_ssh.return_value = False
        mock_user_of_host.return_value = mock.MagicMock(crmsh.user_of_host.UserOfHost)
        mock_user_of_host.return_value.user_pair_for_ssh.return_value = "bob", "bob"
        mock_user_of_host.return_value.use_ssh_agent.return_value = False
        mock_qdevice_configured.return_value = False
        self.qdevice_with_ip.set_cluster_name = mock.Mock()
        self.qdevice_with_ip.valid_qnetd = mock.Mock()
        self.qdevice_with_ip.config_and_start_qdevice = mock.Mock()

        bootstrap.init_qdevice()

        mock_info.assert_called_once_with("Configure Qdevice/Qnetd:")
        mock_ssh.assert_called_once_with("bob", "bob", "10.10.10.123")
        mock_host_user_config_class.return_value.add.assert_has_calls([
            mock.call('bob', '192.0.2.100'),
            mock.call('bob', '10.10.10.123'),
        ])
        mock_host_user_config_class.return_value.save_remote.assert_called_once_with(mock_list_nodes.return_value)
        mock_qdevice_configured.assert_called_once_with()
        self.qdevice_with_ip.set_cluster_name.assert_called_once_with()
        self.qdevice_with_ip.valid_qnetd.assert_called_once_with()
        self.qdevice_with_ip.config_and_start_qdevice.assert_called_once_with()

    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.utils.HostUserConfig')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_available')
    @mock.patch('crmsh.utils.list_cluster_nodes')
    @mock.patch('logging.Logger.info')
    def test_init_qdevice_service_not_available(
            self,
            mock_info, mock_list_nodes, mock_available,
            mock_host_user_config_class,
            mock_fatal,
    ):
        bootstrap._context = mock.Mock(qdevice_inst=self.qdevice_with_ip)
        mock_list_nodes.return_value = ["node1"]
        mock_available.return_value = False
        mock_fatal.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap.init_qdevice()

        mock_host_user_config_class.return_value.save_local.assert_not_called()
        mock_host_user_config_class.return_value.save_remote.assert_not_called()
        mock_fatal.assert_called_once_with("corosync-qdevice.service is not available on node1")
        mock_available.assert_called_once_with("corosync-qdevice.service", "node1")
        mock_info.assert_called_once_with("Configure Qdevice/Qnetd:")

    @mock.patch('crmsh.bootstrap.prompt_for_string')
    def test_configure_qdevice_interactive_return(self, mock_prompt):
        bootstrap._context = mock.Mock(yes_to_all=True)
        bootstrap.configure_qdevice_interactive()
        mock_prompt.assert_not_called()

    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.bootstrap.confirm')
    def test_configure_qdevice_interactive_not_confirm(self, mock_confirm, mock_info):
        bootstrap._context = mock.Mock(yes_to_all=False)
        mock_confirm.return_value = False
        bootstrap.configure_qdevice_interactive()
        mock_confirm.assert_called_once_with("Do you want to configure QDevice?")

    @mock.patch('logging.Logger.error')
    @mock.patch('crmsh.qdevice.QDevice.check_package_installed')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.bootstrap.confirm')
    def test_configure_qdevice_interactive_not_installed(self, mock_confirm, mock_info, mock_installed, mock_error):
        bootstrap._context = mock.Mock(yes_to_all=False)
        mock_confirm.side_effect = [True, False]
        mock_installed.side_effect = ValueError("corosync-qdevice not installed")
        bootstrap.configure_qdevice_interactive()
        mock_confirm.assert_has_calls([
            mock.call("Do you want to configure QDevice?"),
            mock.call("Please install the package manually and press 'y' to continue")
            ])

    @mock.patch('crmsh.qdevice.QDevice')
    @mock.patch('crmsh.bootstrap.prompt_for_string')
    @mock.patch('crmsh.qdevice.QDevice.check_package_installed')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.bootstrap.confirm')
    def test_configure_qdevice_interactive(self, mock_confirm, mock_info, mock_installed, mock_prompt, mock_qdevice):
        bootstrap._context = mock.Mock(yes_to_all=False)
        mock_confirm.return_value = True
        mock_prompt.side_effect = ["alice@qnetd-node", 5403, "ffsplit", "lowest", "on", None]
        mock_qdevice_inst = mock.Mock()
        mock_qdevice.return_value = mock_qdevice_inst

        bootstrap.configure_qdevice_interactive()
        mock_confirm.assert_called_once_with("Do you want to configure QDevice?")
        mock_prompt.assert_has_calls([
            mock.call("HOST or IP of the QNetd server to be used",
                valid_func=qdevice.QDevice.check_qnetd_addr),
            mock.call("TCP PORT of QNetd server", default=5403,
                valid_func=qdevice.QDevice.check_qdevice_port),
            mock.call("QNetd decision ALGORITHM (ffsplit/lms)", default="ffsplit",
                valid_func=qdevice.QDevice.check_qdevice_algo),
            mock.call("QNetd TIE_BREAKER (lowest/highest/valid node id)", default="lowest",
                valid_func=qdevice.QDevice.check_qdevice_tie_breaker),
            mock.call("Whether using TLS on QDevice/QNetd (on/off/required)", default="on",
                valid_func=qdevice.QDevice.check_qdevice_tls),
            mock.call("Heuristics COMMAND to run with absolute path; For multiple commands, use \";\" to separate",
                valid_func=qdevice.QDevice.check_qdevice_heuristics,
                allow_empty=True)
            ])
        mock_qdevice.assert_called_once_with('qnetd-node', port=5403, ssh_user='alice', algo='ffsplit', tie_breaker='lowest', tls='on', cmds=None, mode=None, is_stage=False)

    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.corosync.is_qdevice_configured')
    def test_remove_qdevice_no_configured(self, mock_qdevice_configured, mock_error):
        mock_qdevice_configured.return_value = False
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap.remove_qdevice()

        mock_qdevice_configured.assert_called_once_with()
        mock_error.assert_called_once_with("No QDevice configuration in this cluster")

    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.corosync.is_qdevice_configured')
    def test_remove_qdevice_not_confirmed(self, mock_qdevice_configured, mock_confirm):
        mock_qdevice_configured.return_value = True
        mock_confirm.return_value = False

        bootstrap.remove_qdevice()

        mock_qdevice_configured.assert_called_once_with()
        mock_confirm.assert_called_once_with("Removing QDevice service and configuration from cluster: Are you sure?")

    @mock.patch('crmsh.bootstrap.adjust_properties')
    @mock.patch('crmsh.bootstrap.sync_file')
    @mock.patch('crmsh.corosync.configure_two_node')
    @mock.patch('crmsh.qdevice.QDevice.remove_certification_files_on_qnetd')
    @mock.patch('crmsh.qdevice.QDevice.remove_qdevice_db')
    @mock.patch('crmsh.qdevice.QDevice.remove_qdevice_config')
    @mock.patch('crmsh.log.LoggerUtils.status_long')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.qdevice.evaluate_qdevice_quorum_effect')
    @mock.patch('crmsh.utils.check_all_nodes_reachable')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.corosync.is_qdevice_configured')
    def test_remove_qdevice_reload(self, mock_qdevice_configured, mock_confirm, mock_reachable, mock_evaluate,
            mock_status, mock_invoke, mock_status_long, mock_remove_config, mock_remove_db,
            mock_remove_files, mock_config_two_node, mock_sync, mock_adjust_priority):
        mock_qdevice_configured.return_value = True
        mock_confirm.return_value = True
        mock_evaluate.return_value = qdevice.QdevicePolicy.QDEVICE_RELOAD

        bootstrap.remove_qdevice()

        mock_qdevice_configured.assert_called_once_with()
        mock_confirm.assert_called_once_with("Removing QDevice service and configuration from cluster: Are you sure?")
        mock_reachable.assert_called_once_with()
        mock_evaluate.assert_called_once_with(qdevice.QDEVICE_REMOVE)
        mock_status.assert_has_calls([
            mock.call("Disable corosync-qdevice.service"),
            mock.call("Stopping corosync-qdevice.service")
            ])
        mock_invoke.assert_has_calls([
            mock.call("crm cluster run 'systemctl disable corosync-qdevice'"),
            mock.call("crm cluster run 'systemctl stop corosync-qdevice'"),
            mock.call("crm cluster run 'crm corosync reload'")
            ] )
        mock_status_long.assert_called_once_with("Removing QDevice configuration from cluster")
        mock_remove_config.assert_called_once_with()
        mock_remove_db.assert_called_once_with()

    @mock.patch('crmsh.service_manager.ServiceManager.start_service')
    @mock.patch('crmsh.qdevice.QDevice')
    @mock.patch('crmsh.corosync.get_value')
    @mock.patch('crmsh.corosync.is_qdevice_tls_on')
    @mock.patch('crmsh.log.LoggerUtils.status_long')
    def test_start_qdevice_on_join_node(self, mock_status_long, mock_qdevice_tls, mock_get_value, mock_qdevice, mock_start_service):
        mock_qdevice_tls.return_value = True
        mock_get_value.return_value = "10.10.10.123"
        mock_qdevice_inst = mock.Mock()
        mock_qdevice.return_value = mock_qdevice_inst
        mock_qdevice_inst.certificate_process_on_join = mock.Mock()

        bootstrap.start_qdevice_on_join_node("node2")

        mock_status_long.assert_called_once_with("Starting corosync-qdevice.service")
        mock_qdevice_tls.assert_called_once_with()
        mock_get_value.assert_called_once_with("quorum.device.net.host")
        mock_qdevice.assert_called_once_with("10.10.10.123", cluster_node="node2")
        mock_qdevice_inst.certificate_process_on_join.assert_called_once_with()
        mock_start_service.assert_called_once_with("corosync-qdevice.service", enable=True)

    @mock.patch('crmsh.sh.ShellUtils.get_stdout_stderr')
    @mock.patch('crmsh.log.LoggerUtils.log_only_to_file')
    def test_invoke(self, mock_log, mock_run):
        mock_run.return_value = (0, "output", "error")
        res = bootstrap.invoke("cmd --option")
        self.assertEqual(res, (True, "output", "error"))
        mock_log.assert_has_calls([
            mock.call('invoke: cmd --option'),
            mock.call('stdout: output'),
            mock.call('stderr: error')
            ])

    @mock.patch('crmsh.bootstrap.invoke')
    def test_invokerc(self, mock_invoke):
        mock_invoke.return_value = (True, None, None)
        res = bootstrap.invokerc("cmd")
        self.assertEqual(res, True)
        mock_invoke.assert_called_once_with("cmd")

    @mock.patch('crmsh.utils.cluster_run_cmd')
    @mock.patch('os.path.isfile')
    def test_sync_files_to_disk(self, mock_isfile, mock_cluster_cmd):
        bootstrap.FILES_TO_SYNC = ("file1", "file2")
        mock_isfile.side_effect = [True, True]
        bootstrap.sync_files_to_disk()
        mock_isfile.assert_has_calls([mock.call("file1"), mock.call("file2")])
        mock_cluster_cmd.assert_called_once_with("sync file1 file2")

    @mock.patch('logging.Logger.debug')
    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    @mock.patch('crmsh.bootstrap.cib_factory')
    def test_adjust_pcmk_delay_2node(self, mock_cib_factory, mock_run, mock_debug):
        mock_cib_factory.refresh = mock.Mock()
        mock_cib_factory.fence_id_list_without_pcmk_delay = mock.Mock()
        mock_cib_factory.fence_id_list_without_pcmk_delay.return_value = ["res_1"]
        bootstrap.adjust_pcmk_delay_max(True)
        mock_run.assert_called_once_with("crm resource param res_1 set pcmk_delay_max {}s".format(constants.PCMK_DELAY_MAX))

    @mock.patch('logging.Logger.debug')
    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    @mock.patch('crmsh.bootstrap.cib_factory')
    def test_adjust_pcmk_delay(self, mock_cib_factory, mock_run, mock_debug):
        mock_cib_factory.refresh = mock.Mock()
        mock_cib_factory.fence_id_list_with_pcmk_delay = mock.Mock()
        mock_cib_factory.fence_id_list_with_pcmk_delay.return_value = ["res_1"]
        bootstrap.adjust_pcmk_delay_max(False)
        mock_run.assert_called_once_with("crm resource param res_1 delete pcmk_delay_max")

    @mock.patch('crmsh.sbd.SBDTimeout')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    def test_adjust_stonith_timeout_sbd(self, mock_is_active, mock_sbd_timeout):
        mock_is_active.return_value = True
        mock_sbd_timeout.adjust_sbd_timeout_related_cluster_configuration = mock.Mock()
        bootstrap.adjust_stonith_timeout()
        mock_sbd_timeout.adjust_sbd_timeout_related_cluster_configuration.assert_called_once_with()

    @mock.patch('crmsh.utils.set_property')
    @mock.patch('crmsh.bootstrap.get_stonith_timeout_generally_expected')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    def test_adjust_stonith_timeout(self, mock_is_active, mock_get_timeout, mock_set):
        mock_is_active.return_value = False
        mock_get_timeout.return_value = 30
        bootstrap.adjust_stonith_timeout()
        mock_set.assert_called_once_with("stonith-timeout", 30, conditional=True)

    @mock.patch('crmsh.utils.set_property')
    def test_adjust_priority_in_rsc_defaults_2node(self, mock_set):
        bootstrap.adjust_priority_in_rsc_defaults(True)
        mock_set.assert_called_once_with('priority', 1, property_type='rsc_defaults', conditional=True)

    @mock.patch('crmsh.utils.set_property')
    def test_adjust_priority_in_rsc_defaults(self, mock_set):
        bootstrap.adjust_priority_in_rsc_defaults(False)
        mock_set.assert_called_once_with('priority', 0, property_type='rsc_defaults')

    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    def test_adjust_priority_fencing_delay_no_fence_agent(self, mock_run):
        mock_run.return_value = None
        bootstrap.adjust_priority_fencing_delay(False)
        mock_run.assert_called_once_with("crm configure show related:stonith")

    @mock.patch('crmsh.utils.set_property')
    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    def test_adjust_priority_fencing_delay_no_pcmk_delay(self, mock_run, mock_set):
        mock_run.return_value = "data"
        bootstrap.adjust_priority_fencing_delay(False)
        mock_run.assert_called_once_with("crm configure show related:stonith")
        mock_set.assert_called_once_with("priority-fencing-delay", 0)

    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    def test_adjust_properties_no_service(self, mock_is_active):
        mock_is_active.return_value = False
        bootstrap.adjust_properties()
        mock_is_active.assert_called_once_with("pacemaker.service")

    @mock.patch('crmsh.bootstrap.adjust_priority_fencing_delay')
    @mock.patch('crmsh.bootstrap.adjust_priority_in_rsc_defaults')
    @mock.patch('crmsh.bootstrap.adjust_stonith_timeout')
    @mock.patch('crmsh.bootstrap.adjust_pcmk_delay_max')
    @mock.patch('crmsh.utils.is_2node_cluster_without_qdevice')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    def test_adjust_properties(self, mock_is_active, mock_2node_qdevice, mock_adj_pcmk, mock_adj_stonith, mock_adj_priority, mock_adj_fence):
        mock_is_active.return_value = True
        mock_2node_qdevice.return_value = True
        bootstrap.adjust_properties()
        mock_is_active.assert_called_once_with("pacemaker.service")
        mock_adj_pcmk.assert_called_once_with(True)
        mock_adj_stonith.assert_called_once_with()
        mock_adj_priority.assert_called_once_with(True)
        mock_adj_fence.assert_called_once_with(True)

    @mock.patch('crmsh.utils.cluster_copy_file')
    def test_sync_file_skip_csync2(self, mock_copy):
        bootstrap._context = mock.Mock(skip_csync2=True, node_list_in_cluster=["node1", "node2"])
        bootstrap.sync_file("/file1")
        mock_copy.assert_called_once_with("/file1", nodes=["node1", "node2"], output=False)

    @mock.patch('crmsh.bootstrap.csync2_update')
    def test_sync_file(self, mock_csync2_update):
        bootstrap._context = mock.Mock(skip_csync2=False)
        bootstrap.sync_file("/file1")
        mock_csync2_update.assert_called_once_with("/file1")


class TestValidation(unittest.TestCase):
    """
    Unitary tests for class bootstrap.Validation
    """
    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """
        self.validate_inst = bootstrap.Validation("10.10.10.1")
        self.validate_port_inst_in_use = bootstrap.Validation("4567", ["4568"])
        self.validate_port_inst_out_of_range = bootstrap.Validation("456766")

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('crmsh.utils.IP.is_mcast')
    def test_is_mcast_addr(self, mock_mcast):
        mock_mcast.return_value = False
        with self.assertRaises(ValueError) as err:
            self.validate_inst._is_mcast_addr()
        self.assertEqual("10.10.10.1 is not multicast address", str(err.exception))
        mock_mcast.assert_called_once_with("10.10.10.1")

    def test_is_local_addr(self):
        with self.assertRaises(ValueError) as err:
            self.validate_inst._is_local_addr(["20.20.20.1", "20.20.20.2"])
        self.assertEqual("Address must be a local address (one of ['20.20.20.1', '20.20.20.2'])", str(err.exception))

    def test_is_valid_port_in_use(self):
        with self.assertRaises(ValueError) as err:
            self.validate_port_inst_in_use._is_valid_port()
        self.assertEqual("Port 4567 is already in use by corosync. Leave a gap between multiple rings.", str(err.exception))

    def test_is_valid_port_out_of_range(self):
        with self.assertRaises(ValueError) as err:
            self.validate_port_inst_out_of_range._is_valid_port()
        self.assertEqual("Valid port range should be 1025-65535", str(err.exception))

    @mock.patch('crmsh.bootstrap.Validation._is_mcast_addr')
    def test_valid_mcast_address(self, mock_mcast):
        bootstrap.Validation.valid_mcast_address("10.10.10.1")
        mock_mcast.assert_called_once_with()

    @mock.patch('crmsh.bootstrap.Validation._is_local_addr')
    def test_valid_ucast_ip(self, mock_local_addr):
        interfaces_inst = mock.Mock(ip_list=["10.10.10.2", "10.10.10.3"])
        bootstrap._context = mock.Mock(interfaces_inst=interfaces_inst)
        bootstrap.Validation.valid_ucast_ip("10.10.10.1")
        mock_local_addr.assert_called_once_with(["10.10.10.2", "10.10.10.3"])

    @mock.patch('crmsh.bootstrap.Validation._is_local_addr')
    def test_valid_mcast_ip(self, mock_local_addr):
        interfaces_inst = mock.Mock(ip_list=["10.10.10.2", "10.10.10.3"], network_list=["10.10.10.0"])
        bootstrap._context = mock.Mock(interfaces_inst=interfaces_inst)
        bootstrap.Validation.valid_mcast_ip("10.10.10.1")
        mock_local_addr.assert_called_once_with(["10.10.10.2", "10.10.10.3", "10.10.10.0"])

    @mock.patch('crmsh.bootstrap.Validation._is_valid_port')
    def test_valid_port(self, mock_port):
        bootstrap.Validation.valid_port("10.10.10.1")
        mock_port.assert_called_once_with()

    @mock.patch('crmsh.bootstrap.invokerc')
    @mock.patch('crmsh.utils.IP.is_ipv6')
    def test_valid_admin_ip_in_use(self, mock_ipv6, mock_invoke):
        mock_ipv6.return_value = False
        mock_invoke.return_value = True

        with self.assertRaises(ValueError) as err:
            self.validate_inst.valid_admin_ip("10.10.10.1")
        self.assertEqual("Address already in use: 10.10.10.1", str(err.exception))

        mock_ipv6.assert_called_once_with("10.10.10.1")
        mock_invoke.assert_called_once_with("ping -c 1 10.10.10.1")

    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    @mock.patch('crmsh.bootstrap.init')
    @mock.patch('crmsh.bootstrap.Context')
    def test_bootstrap_remove_cluster_is_active(self, mock_context, mock_init, mock_active,
            mock_error):
        mock_context_inst = mock.Mock()
        mock_context.return_value = mock_context_inst
        mock_active.return_value = False
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
             bootstrap.bootstrap_remove(mock_context_inst)

        mock_init.assert_called_once_with()
        mock_active.assert_called_once_with("corosync.service")
        mock_error.assert_called_once_with("Cluster is not active - can't execute removing action")

    @mock.patch('crmsh.bootstrap.remove_qdevice')
    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    @mock.patch('crmsh.bootstrap.init')
    @mock.patch('crmsh.bootstrap.Context')
    def test_bootstrap_remove_qdevice(self, mock_context, mock_init, mock_active,
            mock_error, mock_qdevice):
        mock_context_inst = mock.Mock(qdevice=True, cluster_node=None)
        mock_context.return_value = mock_context_inst
        mock_active.return_value = [True, True]

        bootstrap.bootstrap_remove(mock_context_inst)

        mock_init.assert_called_once_with()
        mock_active.assert_has_calls([
            mock.call("corosync.service"),
            mock.call("csync2.socket")
            ])
        mock_error.assert_not_called()
        mock_qdevice.assert_called_once_with()

    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    @mock.patch('crmsh.bootstrap.init')
    @mock.patch('crmsh.bootstrap.Context')
    def test_bootstrap_remove_qdevice_cluster_node(self, mock_context, mock_init, mock_active, mock_error):
        mock_context_inst = mock.Mock(qdevice=True, cluster_node="node1")
        mock_context.return_value = mock_context_inst
        mock_active.return_value = True
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap.bootstrap_remove(mock_context_inst)

        mock_init.assert_called_once_with()
        mock_active.assert_called_once_with("corosync.service")
        mock_error.assert_called_once_with("Either remove node or qdevice")

    @mock.patch('crmsh.bootstrap.prompt_for_string')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.bootstrap.remove_qdevice')
    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    @mock.patch('crmsh.bootstrap.init')
    @mock.patch('crmsh.bootstrap.Context')
    def test_bootstrap_remove_no_cluster_node(self, mock_context, mock_init, mock_active,
            mock_error, mock_qdevice, mock_status, mock_prompt):
        mock_context_inst = mock.Mock(yes_to_all=False, cluster_node=None, qdevice_rm_flag=None)
        mock_context.return_value = mock_context_inst
        mock_active.return_value = [True, True]
        mock_prompt.return_value = None
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap.bootstrap_remove(mock_context_inst)

        mock_init.assert_called_once_with()
        mock_active.assert_has_calls([
            mock.call("corosync.service"),
            mock.call("csync2.socket")
            ])
        mock_qdevice.assert_not_called()
        mock_status.assert_called_once_with('Remove This Node from Cluster:\n  You will be asked for the IP address or name of an existing node,\n  which will be removed from the cluster. This command must be\n  executed from a different node in the cluster.\n')
        mock_prompt.assert_called_once_with("IP address or hostname of cluster node (e.g.: 192.168.1.1)", ".+")
        mock_error.assert_called_once_with("No existing IP/hostname specified (use -c option)")

    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.bootstrap.get_node_canonical_hostname')
    @mock.patch('crmsh.bootstrap.remove_qdevice')
    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    @mock.patch('crmsh.bootstrap.init')
    @mock.patch('crmsh.bootstrap.Context')
    def test_bootstrap_remove_no_confirm(self, mock_context, mock_init, mock_active,
            mock_error, mock_qdevice, mock_hostname, mock_confirm):
        mock_context_inst = mock.Mock(cluster_node="node1", force=False, qdevice_rm_flag=None)
        mock_context.return_value = mock_context_inst
        mock_active.return_value = [True, True]
        mock_hostname.return_value = "node1"
        mock_confirm.return_value = False

        bootstrap.bootstrap_remove(mock_context_inst)

        mock_init.assert_called_once_with()
        mock_active.assert_has_calls([
            mock.call("corosync.service"),
            mock.call("csync2.socket")
            ])
        mock_qdevice.assert_not_called()
        mock_error.assert_not_called()
        mock_hostname.assert_called_once_with('node1')
        mock_confirm.assert_called_once_with('Removing node "node1" from the cluster: Are you sure?')

    @mock.patch('crmsh.utils.this_node')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.bootstrap.get_node_canonical_hostname')
    @mock.patch('crmsh.bootstrap.remove_qdevice')
    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    @mock.patch('crmsh.bootstrap.init')
    @mock.patch('crmsh.bootstrap.Context')
    def test_bootstrap_remove_self_need_force(self, mock_context, mock_init, mock_active,
            mock_error, mock_qdevice, mock_hostname, mock_confirm, mock_this_node):
        mock_context_inst = mock.Mock(cluster_node="node1", force=False, qdevice_rm_flag=None)
        mock_context.return_value = mock_context_inst
        mock_active.return_value = [True, True]
        mock_hostname.return_value = "node1"
        mock_confirm.return_value = True
        mock_this_node.return_value = "node1"
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap.bootstrap_remove(mock_context_inst)

        mock_init.assert_called_once_with()
        mock_active.assert_has_calls([
            mock.call("corosync.service"),
            mock.call("csync2.socket")
            ])
        mock_qdevice.assert_not_called()
        mock_hostname.assert_called_once_with('node1')
        mock_confirm.assert_called_once_with('Removing node "node1" from the cluster: Are you sure?')
        mock_this_node.assert_called_once_with()
        mock_error.assert_called_once_with("Removing self requires --force")

    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    @mock.patch('crmsh.bootstrap.remove_self')
    @mock.patch('crmsh.utils.this_node')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.bootstrap.get_node_canonical_hostname')
    @mock.patch('crmsh.bootstrap.remove_qdevice')
    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    @mock.patch('crmsh.bootstrap.init')
    @mock.patch('crmsh.bootstrap.Context')
    def test_bootstrap_remove_self(self, mock_context, mock_init, mock_active,
            mock_error, mock_qdevice, mock_hostname, mock_confirm, mock_this_node, mock_self, mock_run):
        mock_context_inst = mock.Mock(cluster_node="node1", force=True, qdevice_rm_flag=None)
        mock_context.return_value = mock_context_inst
        mock_active.return_value = [True, True]
        mock_hostname.return_value = "node1"
        mock_this_node.return_value = "node1"

        bootstrap.bootstrap_remove(mock_context_inst)

        mock_init.assert_called_once_with()
        mock_active.assert_has_calls([
            mock.call("corosync.service"),
            mock.call("csync2.socket")
            ])
        mock_qdevice.assert_not_called()
        mock_hostname.assert_called_once_with('node1')
        mock_confirm.assert_not_called()
        mock_this_node.assert_called_once_with()
        mock_error.assert_not_called()
        mock_self.assert_called_once_with(True)
        mock_run.assert_called_once_with('rm -rf /var/lib/crmsh', 'node1')

    @mock.patch('crmsh.xmlutil.listnodes')
    @mock.patch('crmsh.utils.this_node')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.bootstrap.get_node_canonical_hostname')
    @mock.patch('crmsh.bootstrap.remove_qdevice')
    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    @mock.patch('crmsh.bootstrap.init')
    @mock.patch('crmsh.bootstrap.Context')
    def test_bootstrap_remove_not_in_cluster(self, mock_context, mock_init, mock_active,
            mock_error, mock_qdevice, mock_hostname, mock_confirm, mock_this_node, mock_list):
        mock_context_inst = mock.Mock(cluster_node="node2", force=True, qdevice_rm_flag=None)
        mock_context.return_value = mock_context_inst
        mock_active.return_value = [True, True]
        mock_hostname.return_value = "node2"
        mock_this_node.return_value = "node1"
        mock_list.return_value = ["node1", "node3"]
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap.bootstrap_remove(mock_context_inst)

        mock_init.assert_called_once_with()
        mock_active.assert_has_calls([
            mock.call("corosync.service"),
            mock.call("csync2.socket")
            ])
        mock_qdevice.assert_not_called()
        mock_hostname.assert_called_once_with('node2')
        mock_confirm.assert_not_called()
        mock_this_node.assert_called_once_with()
        mock_error.assert_called_once_with("Specified node node2 is not configured in cluster! Unable to remove.")

    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    @mock.patch('crmsh.utils.fetch_cluster_node_list_from_node')
    @mock.patch('crmsh.bootstrap.remove_node_from_cluster')
    @mock.patch('crmsh.xmlutil.listnodes')
    @mock.patch('crmsh.utils.this_node')
    @mock.patch('crmsh.bootstrap.confirm')
    @mock.patch('crmsh.bootstrap.get_node_canonical_hostname')
    @mock.patch('crmsh.bootstrap.remove_qdevice')
    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    @mock.patch('crmsh.bootstrap.init')
    @mock.patch('crmsh.bootstrap.Context')
    def test_bootstrap_remove(self, mock_context, mock_init, mock_active,
            mock_error, mock_qdevice, mock_hostname, mock_confirm, mock_this_node,
            mock_list, mock_remove, mock_fetch, mock_run):
        mock_context_inst = mock.Mock(cluster_node="node2", qdevice_rm_flag=None, force=True)
        mock_context.return_value = mock_context_inst
        mock_active.side_effect = [True, False]
        mock_hostname.return_value = "node2"
        mock_this_node.return_value = "node1"
        mock_list.return_value = ["node1", "node2"]
        mock_fetch.return_value = ["node1", "node2"]

        bootstrap.bootstrap_remove(mock_context_inst)

        mock_init.assert_called_once_with()
        mock_active.assert_has_calls([
            mock.call("corosync.service"),
            mock.call("csync2.socket")
            ])
        mock_qdevice.assert_not_called()
        mock_hostname.assert_called_once_with('node2')
        mock_confirm.assert_not_called()
        mock_error.assert_not_called()
        mock_remove.assert_called_once_with('node2')
        mock_run.assert_called_once_with('rm -rf /var/lib/crmsh', 'node2')

    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.sh.ClusterShell.get_rc_stdout_stderr_without_input')
    @mock.patch('crmsh.xmlutil.listnodes')
    @mock.patch('crmsh.utils.this_node')
    def test_remove_self_other_nodes(self, mock_this_node, mock_list, mock_run, mock_error):
        mock_this_node.return_value = 'node1'
        mock_list.return_value = ["node1", "node2"]
        mock_run.return_value = (1, '', 'err')
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap._context = mock.Mock(cluster_node="node1", yes_to_all=True)
            bootstrap.remove_self()

        mock_list.assert_called_once_with(include_remote_nodes=False)
        mock_run.assert_called_once_with("node2", "crm cluster remove -y -c node1")
        mock_error.assert_called_once_with("Failed to remove this node from node2")

    @mock.patch('crmsh.utils.package_is_installed')
    @mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
    def test_rm_configuration_files(self, mock_run, mock_installed):
        bootstrap._context = mock.Mock(rm_list=["file1", "file2"])
        mock_installed.return_value = True
        bootstrap.rm_configuration_files()
        mock_run.assert_has_calls([
            mock.call('rm -f file1 file2', None),
            mock.call('cp /usr/share/fillup-templates/sysconfig.sbd /etc/sysconfig/sbd', None)
            ])

    @mock.patch('crmsh.utils.get_iplist_from_name')
    @mock.patch('crmsh.corosync.get_values')
    def test_get_cluster_node_ip_host(self, mock_get_values, mock_get_iplist):
        mock_get_values.return_value = ["node1", "node2"]
        self.assertIsNone(bootstrap.get_cluster_node_ip('node1'))
        mock_get_values.assert_called_once_with("nodelist.node.ring0_addr")
        mock_get_iplist.assert_not_called()

    @mock.patch('crmsh.utils.get_iplist_from_name')
    @mock.patch('crmsh.corosync.get_values')
    def test_get_cluster_node_ip(self, mock_get_values, mock_get_iplist):
        mock_get_values.return_value = ["10.10.10.1", "10.10.10.2"]
        mock_get_iplist.return_value = ["10.10.10.1"]
        self.assertEqual("10.10.10.1", bootstrap.get_cluster_node_ip('node1'))
        mock_get_values.assert_called_once_with("nodelist.node.ring0_addr")
        mock_get_iplist.assert_called_once_with('node1')

    @mock.patch('crmsh.service_manager.ServiceManager.stop_service')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    def test_stop_services(self, mock_active, mock_status, mock_stop):
        mock_active.side_effect = [True, True, True, True]
        bootstrap.stop_services(bootstrap.SERVICES_STOP_LIST)
        mock_active.assert_has_calls([
            mock.call("corosync-qdevice.service", remote_addr=None),
            mock.call("corosync.service", remote_addr=None),
            mock.call("hawk.service", remote_addr=None),
            mock.call("csync2.socket", remote_addr=None)
            ])
        mock_status.assert_has_calls([
            mock.call('Stopping the %s%s', 'corosync-qdevice.service', ''),
            mock.call('Stopping the %s%s', 'corosync.service', ''),
            mock.call('Stopping the %s%s', 'hawk.service', ''),
            mock.call('Stopping the %s%s', 'csync2.socket', '')
            ])
        mock_stop.assert_has_calls([
            mock.call("corosync-qdevice.service", disable=True, remote_addr=None),
            mock.call("corosync.service", disable=True, remote_addr=None),
            mock.call("hawk.service", disable=True, remote_addr=None),
            mock.call("csync2.socket", disable=True, remote_addr=None)
            ])

    @mock.patch.object(NodeMgmt, 'call_delnode')
    @mock.patch('crmsh.bootstrap.rm_configuration_files')
    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.bootstrap.stop_services')
    @mock.patch('crmsh.bootstrap.get_cluster_node_ip')
    def test_remove_node_from_cluster_rm_node_failed(self, mock_get_ip, mock_stop, mock_status, mock_invoke, mock_error, mock_rm_conf_files, mock_call_delnode):
        mock_get_ip.return_value = '192.0.2.100'
        mock_call_delnode.return_value = False
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap._context = mock.Mock(rm_list=["file1", "file2"])
            bootstrap.remove_node_from_cluster('node1')

        mock_get_ip.assert_called_once_with('node1')
        mock_status.assert_called_once_with("Removing the node node1")
        mock_stop.assert_called_once_with(bootstrap.SERVICES_STOP_LIST, remote_addr="node1")
        mock_invoke.assert_not_called()
        mock_call_delnode.assert_called_once_with("node1")
        mock_error.assert_called_once_with("Failed to remove node1.")

    @mock.patch.object(NodeMgmt, 'call_delnode')
    @mock.patch('crmsh.bootstrap.rm_configuration_files')
    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.bootstrap.invokerc')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.bootstrap.stop_services')
    @mock.patch('crmsh.bootstrap.get_cluster_node_ip')
    def test_remove_node_from_cluster_rm_csync_failed(self, mock_get_ip, mock_stop, mock_status, mock_invoke, mock_invokerc, mock_error, mock_rm_conf_files, mock_call_delnode):
        mock_get_ip.return_value = '192.0.2.100'
        mock_call_delnode.return_value = True
        mock_invokerc.return_value = False
        mock_error.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            bootstrap._context = mock.Mock(rm_list=["file1", "file2"])
            bootstrap.remove_node_from_cluster('node1')

        mock_get_ip.assert_called_once_with('node1')
        mock_status.assert_called_once_with("Removing the node node1")
        mock_stop.assert_called_once_with(bootstrap.SERVICES_STOP_LIST, remote_addr="node1")
        mock_invoke.assert_not_called()
        mock_call_delnode.assert_called_once_with("node1")
        mock_invokerc.assert_has_calls([
            mock.call("sed -i /node1/d {}".format(bootstrap.CSYNC2_CFG))
            ])
        mock_error.assert_called_once_with("Removing the node node1 from {} failed".format(bootstrap.CSYNC2_CFG))

    @mock.patch.object(NodeMgmt, 'call_delnode')
    @mock.patch('crmsh.service_manager.ServiceManager.service_is_active')
    @mock.patch('crmsh.bootstrap.rm_configuration_files')
    @mock.patch('crmsh.corosync.configure_two_node')
    @mock.patch('crmsh.bootstrap.adjust_properties')
    @mock.patch('crmsh.bootstrap.sync_file')
    @mock.patch('crmsh.corosync.del_node')
    @mock.patch('crmsh.corosync.get_values')
    @mock.patch('crmsh.utils.fatal')
    @mock.patch('crmsh.bootstrap.invokerc')
    @mock.patch('crmsh.bootstrap.invoke')
    @mock.patch('logging.Logger.info')
    @mock.patch('crmsh.bootstrap.stop_services')
    @mock.patch('crmsh.bootstrap.get_cluster_node_ip')
    def test_remove_node_from_cluster_hostname(self, mock_get_ip, mock_stop, mock_status,
            mock_invoke, mock_invokerc, mock_error, mock_get_values, mock_del, mock_csync2,
            mock_adjust_priority, mock_adjust_fence_delay, mock_rm_conf_files, mock_is_active, mock_cal_delnode):
        mock_get_ip.return_value = "10.10.10.1"
        mock_cal_delnode.return_value = True
        mock_invoke.side_effect = [(True, None, None)]
        mock_invokerc.return_value = True
        mock_get_values.return_value = ["10.10.10.1"]
        mock_is_active.return_value = False

        bootstrap._context = mock.Mock(cluster_node="node1", rm_list=["file1", "file2"])
        bootstrap.remove_node_from_cluster('node1')

        mock_get_ip.assert_called_once_with('node1')
        mock_status.assert_has_calls([
            mock.call("Removing the node node1"),
            mock.call("Propagating configuration changes across the remaining nodes")
            ])
        mock_stop.assert_called_once_with(bootstrap.SERVICES_STOP_LIST, remote_addr="node1")
        mock_cal_delnode.assert_called_once_with("node1")
        mock_invoke.assert_has_calls([
            mock.call("corosync-cfgtool -R")
            ])
        mock_invokerc.assert_called_once_with("sed -i /node1/d {}".format(bootstrap.CSYNC2_CFG))
        mock_error.assert_not_called()
        mock_get_values.assert_called_once_with("nodelist.node.ring0_addr")
        mock_del.assert_called_once_with("10.10.10.1")
        mock_csync2.assert_has_calls([
            mock.call(bootstrap.CSYNC2_CFG),
            mock.call("/etc/corosync/corosync.conf")
            ])
