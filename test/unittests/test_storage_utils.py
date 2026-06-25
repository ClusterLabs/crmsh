# Copyright (C) 2026 SUSE LLC
# See COPYING for license information.
#
# unit tests for storage_utils.py

import unittest
import pytest
from pathlib import Path
from unittest import mock

from crmsh import storage_utils, constants


@mock.patch('crmsh.storage_utils.get_dev_info')
def test_has_dev_partitioned(mock_get_dev_info):
    mock_get_dev_info.return_value = """
disk
part
    """
    res = storage_utils.has_dev_partitioned("/dev/sda1")
    assert res is True
    mock_get_dev_info.assert_called_once_with("/dev/sda1", "NAME", peer=None)


@mock.patch('crmsh.storage_utils.get_dev_uuid')
def test_compare_uuid_with_peer_dev_cannot_find_local(mock_get_dev_uuid):
    mock_get_dev_uuid.return_value = ""
    with pytest.raises(ValueError) as err:
        storage_utils.compare_uuid_with_peer_dev(["/dev/sdb1"], "node2")
    assert str(err.value) == "Cannot find UUID for /dev/sdb1 on local"
    mock_get_dev_uuid.assert_called_once_with("/dev/sdb1")


@mock.patch('crmsh.storage_utils.get_dev_uuid')
def test_compare_uuid_with_peer_dev_cannot_find_peer(mock_get_dev_uuid):
    mock_get_dev_uuid.side_effect = ["1234", ""]
    with pytest.raises(ValueError) as err:
        storage_utils.compare_uuid_with_peer_dev(["/dev/sdb1"], "node2")
    assert str(err.value) == "Cannot find UUID for /dev/sdb1 on node2"
    mock_get_dev_uuid.assert_has_calls([
        mock.call("/dev/sdb1"),
        mock.call("/dev/sdb1", "node2")
        ])


@mock.patch('crmsh.storage_utils.get_dev_uuid')
def test_compare_uuid_with_peer_dev(mock_get_dev_uuid):
    mock_get_dev_uuid.side_effect = ["1234", "5678"]
    with pytest.raises(ValueError) as err:
        storage_utils.compare_uuid_with_peer_dev(["/dev/sdb1"], "node2")
    assert str(err.value) == "UUID of /dev/sdb1 not same with peer node2"
    mock_get_dev_uuid.assert_has_calls([
        mock.call("/dev/sdb1"),
        mock.call("/dev/sdb1", "node2")
        ])


@mock.patch('crmsh.storage_utils.get_dev_info')
def test_is_dev_used_for_lvm(mock_dev_info):
    mock_dev_info.return_value = "lvm"
    res = storage_utils.is_dev_used_for_lvm("/dev/sda1")
    assert res is True
    mock_dev_info.assert_called_once_with("/dev/sda1", "TYPE", peer=None)


@mock.patch('crmsh.storage_utils.get_dev_info')
def test_is_dev_a_plain_raw_disk_or_partition(mock_dev_info):
    mock_dev_info.return_value = "raid1\nlvm"
    res = storage_utils.is_dev_a_plain_raw_disk_or_partition("/dev/md127")
    assert res is False
    mock_dev_info.assert_called_once_with("/dev/md127", "TYPE", peer=None)


@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
def test_get_dev_info(mock_run):
    mock_run.return_value = "data"
    res = storage_utils.get_dev_info("/dev/sda1", "TYPE")
    assert res == "data"
    mock_run.assert_called_once_with("lsblk -fno TYPE /dev/sda1", None)


@mock.patch('crmsh.storage_utils.get_dev_info')
def test_get_dev_fs_type(mock_get_info):
    mock_get_info.return_value = "data"
    res = storage_utils.get_dev_fs_type("/dev/sda1")
    assert res == "data"
    mock_get_info.assert_called_once_with("/dev/sda1", "FSTYPE", peer=None)


@mock.patch('crmsh.storage_utils.get_dev_info')
def test_get_dev_uuid(mock_get_info):
    mock_get_info.return_value = "uuid"
    res = storage_utils.get_dev_uuid("/dev/sda1")
    assert res == "uuid"
    mock_get_info.assert_called_once_with("/dev/sda1", "UUID", peer=None)


@mock.patch('crmsh.storage_utils.get_dev_uuid_by_blkid')
@mock.patch('crmsh.storage_utils.get_dev_info')
def test_get_dev_uuid_falls_back_to_blkid(mock_get_info, mock_blkid):
    mock_get_info.return_value = ""
    mock_blkid.return_value = "blkid-uuid"
    res = storage_utils.get_dev_uuid("/dev/sda1")
    assert res == "blkid-uuid"
    mock_get_info.assert_called_once_with("/dev/sda1", "UUID", peer=None)
    mock_blkid.assert_called_once_with("/dev/sda1", None)


@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
def test_get_dev_uuid_by_blkid(mock_run):
    mock_run.return_value = '/dev/sda1: UUID="abc-123" TYPE="ext4"'
    res = storage_utils.get_dev_uuid_by_blkid("/dev/sda1")
    assert res == "abc-123"
    mock_run.assert_called_once_with("blkid /dev/sda1", None)


@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
def test_get_dev_uuid_by_blkid_no_uuid(mock_run):
    mock_run.return_value = "/dev/sda1: TYPE=\"swap\""
    res = storage_utils.get_dev_uuid_by_blkid("/dev/sda1")
    assert res is None


@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
def test_get_pe_number_except(mock_run):
    mock_run.return_value = "data"
    with pytest.raises(ValueError) as err:
        storage_utils.get_pe_number("vg1")
    assert str(err.value) == "Cannot find PE on VG(vg1)"
    mock_run.assert_called_once_with("vgdisplay vg1")


@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
def test_get_pe_number(mock_run):
    mock_run.return_value = """
PE Size               4.00 MiB
Total PE              1534
Alloc PE / Size       1534 / 5.99 GiB
    """
    res = storage_utils.get_pe_number("vg1")
    assert res == 1534
    mock_run.assert_called_once_with("vgdisplay vg1")


@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
def test_get_all_vg_name(mock_run):
    mock_run.return_value = """
--- Volume group ---
  VG Name               ocfs2-vg
  System ID
    """
    res = storage_utils.get_all_vg_name()
    assert res == ["ocfs2-vg"]
    mock_run.assert_called_once_with("vgdisplay")


@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
def test_has_mount_point_used(mock_run):
    mock_run.return_value = """
/dev/vda2 on /usr/local type btrfs (rw,relatime,space_cache,subvolid=259,subvol=/@/usr/local)
/dev/vda2 on /opt type btrfs (rw,relatime,space_cache,subvolid=263,subvol=/@/opt)
/dev/vda2 on /var/lib/docker/btrfs type btrfs (rw,relatime,space_cache,subvolid=258,subvol=/@/var)
    """
    res = storage_utils.has_mount_point_used("/opt")
    assert res is True
    mock_run.assert_called_once_with("mount")


@mock.patch('crmsh.sh.ClusterShell.get_stdout_or_raise_error')
def test_has_disk_mounted(mock_run):
    mock_run.return_value = """
/dev/vda2 on /usr/local type btrfs (rw,relatime,space_cache,subvolid=259,subvol=/@/usr/local)
/dev/vda2 on /opt type btrfs (rw,relatime,space_cache,subvolid=263,subvol=/@/opt)
/dev/vda2 on /var/lib/docker/btrfs type btrfs (rw,relatime,space_cache,subvolid=258,subvol=/@/var)
    """
    res = storage_utils.has_disk_mounted("/dev/vda2")
    assert res is True
    mock_run.assert_called_once_with("mount")


@mock.patch('crmsh.sh.cluster_shell')
def test_get_non_block_device_nodes(mock_cluster_shell):
    mock_cluster_shell_inst = mock.Mock()
    mock_cluster_shell.return_value = mock_cluster_shell_inst
    mock_cluster_shell_inst.get_rc_stdout_stderr_without_input.return_value = (1, None, None)
    res = storage_utils.get_non_block_device_nodes("/dev/sda1", ["node1"])
    assert res == ["node1"]
    mock_cluster_shell_inst.get_rc_stdout_stderr_without_input.assert_called_once_with("node1", "test -b /dev/sda1")


def test_detect_duplicate_device_path_no_duplicate():
    storage_utils.detect_duplicate_device_path(["/dev/sda1", "/dev/sdb1"])


@mock.patch('pathlib.Path.resolve')
def test_detect_duplicate_device_path_raises(mock_resolve):
    mock_resolve.return_value = Path("/dev/sda1")
    with pytest.raises(ValueError) as err:
        storage_utils.detect_duplicate_device_path(["/dev/sda1", "/dev/disk/by-id/sda1"])
    assert "Duplicated device path detected" in str(err.value)
    assert "/dev/sda1" in str(err.value)


@mock.patch('crmsh.sh.cluster_shell')
def test_get_dlm_option_dict(mock_run):
    mock_run_inst = mock.Mock()
    mock_run.return_value = mock_run_inst
    mock_run_inst.get_stdout_or_raise_error.return_value = """
key1=value1
key2=value2
    """
    res_dict = storage_utils.get_dlm_option_dict()
    assert res_dict == {
            "key1": "value1",
            "key2": "value2"
            }
    mock_run_inst.get_stdout_or_raise_error.assert_called_once_with("dlm_tool dump_config", None)


@mock.patch('crmsh.storage_utils.get_dlm_option_dict')
def test_set_dlm_option_exception(mock_get_dict):
    mock_get_dict.return_value = {
            "key1": "value1",
            "key2": "value2"
            }
    with pytest.raises(ValueError) as err:
        storage_utils.set_dlm_option(name="xin")
    assert str(err.value) == '"name" is not dlm config option'


@mock.patch('crmsh.sh.cluster_shell')
@mock.patch('crmsh.storage_utils.get_dlm_option_dict')
def test_set_dlm_option(mock_get_dict, mock_run):
    mock_run_inst = mock.Mock()
    mock_run.return_value = mock_run_inst
    mock_get_dict.return_value = {
            "key1": "value1",
            "key2": "value2"
            }
    storage_utils.set_dlm_option(key2="test")
    mock_run_inst.get_stdout_or_raise_error.assert_called_once_with('dlm_tool set_config "key2=test"', None)


@mock.patch('crmsh.xmlutil.CrmMonXmlParser')
def test_is_dlm_configured(mock_crmmon):
    mock_crmmon_inst = mock.Mock()
    mock_crmmon.return_value = mock_crmmon_inst
    mock_crmmon_inst.is_resource_configured.return_value = True
    assert storage_utils.is_dlm_configured() is True
    mock_crmmon_inst.is_resource_configured.assert_called_once_with(constants.DLM_CONTROLD_RA)


@mock.patch('crmsh.xmlutil.CrmMonXmlParser')
def test_is_dlm_running(mock_crmmon):
    mock_crmmon_inst = mock.Mock()
    mock_crmmon.return_value = mock_crmmon_inst
    mock_crmmon_inst.is_resource_started.return_value = True
    assert storage_utils.is_dlm_running() is True
    mock_crmmon_inst.is_resource_started.assert_called_once_with(constants.DLM_CONTROLD_RA, node=None)


@mock.patch('crmsh.xmlutil.CrmMonXmlParser')
def test_is_dlm_running_on_node(mock_crmmon):
    mock_crmmon_inst = mock.Mock()
    mock_crmmon.return_value = mock_crmmon_inst
    mock_crmmon_inst.is_resource_started.return_value = False
    assert storage_utils.is_dlm_running(on_node="node1") is False
    mock_crmmon_inst.is_resource_started.assert_called_once_with(constants.DLM_CONTROLD_RA, node="node1")


@mock.patch('crmsh.storage_utils.is_dlm_configured')
def test_check_no_quorum_policy_with_dlm_return(mock_dlm):
    mock_dlm.return_value = False
    storage_utils.check_no_quorum_policy_with_dlm()
    mock_dlm.assert_called_once_with()


@mock.patch('logging.Logger.warning')
@mock.patch('crmsh.utils.get_property')
@mock.patch('crmsh.storage_utils.is_dlm_configured')
def test_check_no_quorum_policy_with_dlm(mock_dlm, mock_get_property, mock_warn):
    mock_dlm.return_value = True
    mock_get_property.return_value = "stop"
    storage_utils.check_no_quorum_policy_with_dlm()
    mock_dlm.assert_called_once_with()
    mock_get_property.assert_called_once_with("no-quorum-policy")
    mock_warn.assert_called_once_with('The DLM cluster best practice suggests to set the cluster property "no-quorum-policy=freeze"')


class TestMultipathInspector(unittest.TestCase):

    @mock.patch('crmsh.sh.cluster_shell')
    def test_init(self, mock_cluster_shell):
        """Test MultipathInspector initialization"""
        mock_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_shell_inst
        mock_shell_inst.get_rc_stdout_stderr_without_input.side_effect = [
            (0, "sda", ""),  # lsblk output for parent device
            (0, "dev multipath\nsda mpatha", "")  # multipathd show paths output
        ]

        inspector = storage_utils.MultipathInspector("/dev/sda1")

        assert inspector._shell == mock_shell_inst
        assert inspector._device_info.device == "/dev/sda1"
        assert inspector._device_info.parent_device == "sda"
        assert inspector._device_info.under_multipath is True

    @mock.patch('crmsh.sh.cluster_shell')
    def test_get_parent_device(self, mock_cluster_shell):
        """Test _get_parent_device method"""
        mock_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_shell_inst
        mock_shell_inst.get_rc_stdout_stderr_without_input.side_effect = [
            (0, "sda", ""),  # lsblk output for __init__
            (0, "", ""),  # multipathd show paths output for __init__
            (0, "sda", "")  # lsblk output for test call
        ]

        inspector = storage_utils.MultipathInspector("/dev/sda1")
        parent = inspector._get_parent_device("/dev/sda1")

        assert parent == "sda"

    @mock.patch('crmsh.sh.cluster_shell')
    def test_get_multipath_mapping(self, mock_cluster_shell):
        """Test _get_multipath_mapping method with valid output"""
        mock_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_shell_inst
        multipathd_output = """dev multipath
sda mpatha
sdb mpatha
sdc mpathb"""
        mock_shell_inst.get_rc_stdout_stderr_without_input.side_effect = [
            (0, "sda", ""),  # lsblk for __init__
            (0, multipathd_output, ""),  # multipathd for __init__
            (0, multipathd_output, "")  # multipathd for test call
        ]

        inspector = storage_utils.MultipathInspector("/dev/sda1")
        mapping = inspector._get_multipath_mapping()

        assert mapping == {"sda": "mpatha", "sdb": "mpatha", "sdc": "mpathb"}

    @mock.patch('crmsh.sh.cluster_shell')
    def test_inspect_device_under_multipath(self, mock_cluster_shell):
        """Test _inspect method when device is under multipath"""
        mock_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_shell_inst
        mock_shell_inst.get_rc_stdout_stderr_without_input.side_effect = [
            (0, "sda", ""),
            (0, "dev multipath\nsda mpatha", "")
        ]

        inspector = storage_utils.MultipathInspector("/dev/sda1")
        device_info = inspector._device_info

        assert device_info.device == "/dev/sda1"
        assert device_info.parent_device == "sda"
        assert device_info.under_multipath is True

    @mock.patch('crmsh.sh.cluster_shell')
    def test_is_under_multipath_true(self, mock_cluster_shell):
        """Test _is_under_multipath returns True"""
        mock_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_shell_inst
        mock_shell_inst.get_rc_stdout_stderr_without_input.side_effect = [
            (0, "sda", ""),
            (0, "dev multipath\nsda mpatha", "")
        ]

        inspector = storage_utils.MultipathInspector("/dev/sda1")

        assert inspector._is_under_multipath() is True

    @mock.patch('crmsh.sh.cluster_shell')
    def test_check_device_under_multipath_raises_error(self, mock_cluster_shell):
        """Test check_device_under_multipath raises ValueError when device is under multipath"""
        mock_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_shell_inst
        mock_shell_inst.get_rc_stdout_stderr_without_input.side_effect = [
            (0, "sda", ""),
            (0, "dev multipath\nsda mpatha", "")
        ]

        with pytest.raises(ValueError) as exc_info:
            storage_utils.MultipathInspector.check_device_under_multipath("/dev/sda1")

        assert str(exc_info.value) == "Device /dev/sda1 is under multipath, please provide the multipath device instead"
