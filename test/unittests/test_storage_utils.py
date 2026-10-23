# Copyright (C) 2026 SUSE LLC
# See COPYING for license information.
#
# unit tests for storage_utils.py

import tempfile
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


@mock.patch('crmsh.xmlutil.CrmMonXMLParser')
def test_is_dlm_configured(mock_crmmon):
    mock_crmmon_inst = mock.Mock()
    mock_crmmon.return_value = mock_crmmon_inst
    mock_crmmon_inst.is_resource_configured.return_value = True
    assert storage_utils.is_dlm_configured() is True
    mock_crmmon_inst.is_resource_configured.assert_called_once_with(constants.DLM_CONTROLD_RA)


@mock.patch('crmsh.xmlutil.CrmMonXMLParser')
def test_is_dlm_running(mock_crmmon):
    mock_crmmon_inst = mock.Mock()
    mock_crmmon.return_value = mock_crmmon_inst
    mock_crmmon_inst.is_resource_started.return_value = True
    assert storage_utils.is_dlm_running() is True
    mock_crmmon_inst.is_resource_started.assert_called_once_with(constants.DLM_CONTROLD_RA, node=None)


@mock.patch('crmsh.xmlutil.CrmMonXMLParser')
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

    def setUp(self):
        self._real_get_root = storage_utils.MultipathInspector._get_root_backing_device
        patcher = mock.patch.object(
            storage_utils.MultipathInspector, "_get_root_backing_device", return_value="sda"
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    @mock.patch('crmsh.sh.cluster_shell')
    def test_init(self, mock_cluster_shell):
        """Test MultipathInspector initialization"""
        mock_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_shell_inst
        mock_shell_inst.get_rc_stdout_stderr_without_input.side_effect = [
            (0, "dev multipath\nsda mpatha", "")  # multipathd show paths output
        ]

        inspector = storage_utils.MultipathInspector("/dev/sda1")

        assert inspector._shell == mock_shell_inst
        assert inspector._device_info.device == "/dev/sda1"
        assert inspector._device_info.root_backing_device == "sda"
        assert inspector._device_info.under_multipath is True

    def test_get_root_backing_device(self):
        """Test _get_root_backing_device walks partitions and nested slaves down to sdX"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sda" / "sda1").mkdir(parents=True)
            (root / "sda" / "sda1" / "partition").write_text("1")
            (root / "sda1").symlink_to(root / "sda" / "sda1")
            (root / "sdb").mkdir()
            (root / "dm-3" / "slaves").mkdir(parents=True)
            (root / "dm-3" / "slaves" / "sdb").mkdir()
            (root / "dm-48" / "slaves").mkdir(parents=True)
            (root / "dm-48" / "slaves" / "dm-3").mkdir()
            with mock.patch.object(storage_utils.MultipathInspector, "SYSFS_BLOCK", root):
                get = self._real_get_root
                assert get("/dev/sda1") == "sda"
                assert get("/dev/sdb") == "sdb"
                assert get("/dev/dm-48") == "sdb"

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
            (0, "dev multipath\nsda mpatha", "")
        ]

        inspector = storage_utils.MultipathInspector("/dev/sda1")
        device_info = inspector._device_info

        assert device_info.device == "/dev/sda1"
        assert device_info.root_backing_device == "sda"
        assert device_info.under_multipath is True

    @mock.patch('crmsh.sh.cluster_shell')
    def test_is_under_multipath_true(self, mock_cluster_shell):
        """Test _is_under_multipath returns True"""
        mock_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_shell_inst
        mock_shell_inst.get_rc_stdout_stderr_without_input.side_effect = [
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
            (0, "dev multipath\nsda mpatha", "")
        ]

        with pytest.raises(ValueError) as exc_info:
            storage_utils.MultipathInspector.check_device_under_multipath("/dev/sda1")

        assert str(exc_info.value) == "Device /dev/sda1 is under multipath, please provide the multipath device instead"

    @mock.patch("crmsh.sh.cluster_shell")
    def test_check_device_under_multipath_accepts_multipath_device(self, mock_cluster_shell):
        """Test check_device_under_multipath accepts a multipath device alias"""
        mock_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_shell_inst
        mock_shell_inst.get_rc_stdout_stderr_without_input.side_effect = [
            (0, "dev multipath\nsda mpatha", ""),
            (0, "dev multipath\nsda mpatha", "")
        ]

        storage_utils.MultipathInspector.check_device_under_multipath("/dev/mapper/mpatha")

    @mock.patch("crmsh.sh.cluster_shell")
    def test_check_device_under_multipath_accepts_multipath_partition(self, mock_cluster_shell):
        """Test check_device_under_multipath accepts a multipath partition alias"""
        mock_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_shell_inst
        mock_shell_inst.get_rc_stdout_stderr_without_input.side_effect = [
            (0, "dev multipath\nsda shared_iscsi_lun1", ""),
            (0, "dev multipath\nsda shared_iscsi_lun1", "")
        ]

        storage_utils.MultipathInspector.check_device_under_multipath("/dev/mapper/shared_iscsi_lun1-part5")

    @mock.patch("crmsh.sh.cluster_shell")
    def test_get_scsi_timeout_non_multipath(self, mock_cluster_shell):
        """Test get_scsi_timeout for a non-multipath device"""
        mock_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_shell_inst
        mock_shell_inst.get_rc_stdout_stderr_without_input.side_effect = [
            (0, "", ""),
            (0, "", "")
        ]
        mock_shell_inst.get_stdout_or_raise_error.return_value = "30\n"

        timeout = storage_utils.get_scsi_timeout("/dev/sda1")

        assert timeout == 30
        mock_shell_inst.get_stdout_or_raise_error.assert_called_once_with("cat /sys/block/sda/device/timeout")

    @mock.patch("crmsh.sh.cluster_shell")
    def test_get_scsi_timeout_multipath_device(self, mock_cluster_shell):
        """Test get_scsi_timeout resolves multipath devices to a backing path"""
        mock_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_shell_inst
        mock_shell_inst.get_rc_stdout_stderr_without_input.side_effect = [
            (0, "dev multipath\nsda mpatha\nsdb mpatha", ""),
            (0, "dev multipath\nsda mpatha\nsdb mpatha", ""),
            (0, "dev multipath\nsda mpatha\nsdb mpatha", "")
        ]
        mock_shell_inst.get_stdout_or_raise_error.return_value = "60\n"

        timeout = storage_utils.get_scsi_timeout("/dev/mapper/mpatha")

        assert timeout == 60
        mock_shell_inst.get_stdout_or_raise_error.assert_called_once_with("cat /sys/block/sda/device/timeout")

    @mock.patch("crmsh.sh.cluster_shell")
    def test_get_scsi_timeout_multipath_partition_device(self, mock_cluster_shell):
        """Test get_scsi_timeout resolves multipath partition aliases"""
        mock_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_shell_inst
        mock_shell_inst.get_rc_stdout_stderr_without_input.side_effect = [
            (0, "dev multipath\nsda shared_iscsi_lun1\nsdb shared_iscsi_lun1", ""),
            (0, "dev multipath\nsda shared_iscsi_lun1\nsdb shared_iscsi_lun1", ""),
            (0, "dev multipath\nsda shared_iscsi_lun1\nsdb shared_iscsi_lun1", "")
        ]
        mock_shell_inst.get_stdout_or_raise_error.return_value = "30\n"

        timeout = storage_utils.get_scsi_timeout("/dev/mapper/shared_iscsi_lun1-part5")

        assert timeout == 30
        mock_shell_inst.get_stdout_or_raise_error.assert_called_once_with("cat /sys/block/sda/device/timeout")

    @mock.patch("crmsh.sh.cluster_shell")
    def test_get_scsi_timeout_under_multipath_path(self, mock_cluster_shell):
        """Test get_scsi_timeout accepts an underlying path directly"""
        mock_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_shell_inst
        mock_shell_inst.get_rc_stdout_stderr_without_input.side_effect = [
            (0, "dev multipath\nsda mpatha", ""),
            (0, "dev multipath\nsda mpatha", "")
        ]
        mock_shell_inst.get_stdout_or_raise_error.return_value = "60\n"

        timeout = storage_utils.get_scsi_timeout("/dev/sda1")

        assert timeout == 60
        mock_shell_inst.get_stdout_or_raise_error.assert_called_once_with("cat /sys/block/sda/device/timeout")

    @mock.patch("crmsh.sh.cluster_shell")
    def test_get_multipath_runtime_timeouts(self, mock_cluster_shell):
        """Test multipath runtime timeout values are parsed from effective config"""
        mock_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_shell_inst
        mock_shell_inst.get_rc_stdout_stderr_without_input.side_effect = [
            (0, "dev multipath\nsda mpatha", ""),
            (0, "defaults {\n    max_polling_interval 20\n    checker_timeout 30\n}", ""),
            (0, "defaults {\n    max_polling_interval 20\n    checker_timeout 30\n}", "")
        ]

        inspector = storage_utils.MultipathInspector("/dev/mapper/mpatha")

        assert inspector.get_max_polling_interval() == 20
        assert inspector.get_checker_timeout() == 30

    @mock.patch("crmsh.sh.cluster_shell")
    def test_get_checker_timeout_defaults_to_scsi_timeout(self, mock_cluster_shell):
        """Test checker_timeout defaults to SCSI timeout when absent"""
        mock_shell_inst = mock.Mock()
        mock_cluster_shell.return_value = mock_shell_inst
        mock_shell_inst.get_rc_stdout_stderr_without_input.side_effect = [
            (0, "", ""),
            (0, "defaults {\n    max_polling_interval 20\n}", ""),
            (0, "", "")
        ]
        mock_shell_inst.get_stdout_or_raise_error.return_value = "30\n"

        timeout = storage_utils.get_multipath_checker_timeout("/dev/sda1")

        assert timeout == 30
        mock_shell_inst.get_stdout_or_raise_error.assert_called_once_with("cat /sys/block/sda/device/timeout")


@mock.patch("crmsh.storage_utils.is_multipath_device")
def test_pick_backstore_device(mock_is_mp):
    mock_is_mp.side_effect = lambda d: d.startswith("/dev/mapper")
    assert storage_utils.pick_backstore_device(["/dev/sdc7", "/dev/mapper/m-part5"]) == "/dev/mapper/m-part5"
    assert storage_utils.pick_backstore_device(["/dev/sdc7", "/dev/sdd1"]) == "/dev/sdc7"
    assert storage_utils.pick_backstore_device([]) is None


def test_parse_multipath_config():
    out = """
defaults {
    no_path_retry fail
    path_grouping_policy failover
    path_checker tur
    detect_checker yes
}
blacklist {
    devnode "^(ram|raw|loop|fd|md|dm-|sr|scd|st)[0-9]*"
}
devices {
    device {
        vendor "IBM"
        product "2145"
        path_checker directio
        detect_checker no
    }
}
overrides {
    checker_timeout 30
}
multipaths {
    multipath {
        wwid "360050768018081c9c00000000000c9b2"
        alias mpatha
        no_path_retry 0
    }
}
"""
    parsed = storage_utils._parse_multipath_config(out)
    assert parsed["defaults"]["no_path_retry"] == "fail"
    assert parsed["defaults"]["path_checker"] == "tur"
    assert parsed["overrides"]["checker_timeout"] == "30"
    assert parsed["devices"][0]["vendor"] == "IBM"
    assert parsed["devices"][0]["product"] == "2145"
    assert parsed["devices"][0]["attrs"]["path_checker"] == "directio"
    assert parsed["multipaths"][0]["wwid"] == "360050768018081c9c00000000000c9b2"
    assert parsed["multipaths"][0]["attrs"]["no_path_retry"] == "0"


def test_resolve_multipath_value_precedence():
    parsed = {
        "defaults": {"no_path_retry": "fail", "path_grouping_policy": "failover"},
        "overrides": {"path_checker": "directio"},
        "devices": [{"vendor": "IBM", "product": "2145", "attrs": {"detect_checker": "no"}}],
        "multipaths": [{"wwid": "3600", "attrs": {"no_path_retry": "0"}}],
    }
    # multipaths section takes precedence over defaults
    assert storage_utils._resolve_multipath_value(parsed, "no_path_retry", "3600", "IBM", "2145") == "0"
    # overrides section takes precedence over devices
    assert storage_utils._resolve_multipath_value(parsed, "path_checker", "3600", "IBM", "2145") == "directio"
    # devices section takes precedence over defaults
    assert storage_utils._resolve_multipath_value(parsed, "detect_checker", "3600", "IBM", "2145") == "no"
    # falls back to defaults
    assert storage_utils._resolve_multipath_value(parsed, "path_grouping_policy", "3600", "IBM", "2145") == "failover"
    # not configured anywhere
    assert storage_utils._resolve_multipath_value(parsed, "checker_timeout", "3600", "IBM", "2145") is None
    # device vendor/product not matching
    assert storage_utils._resolve_multipath_value(parsed, "detect_checker", "3600", "VENDOR", "PRODUCT") is None


@mock.patch.object(storage_utils.MultipathInspector, "_get_root_backing_device", return_value="sda")
@mock.patch('crmsh.sh.cluster_shell')
def test_get_multipath_config_values(mock_cluster_shell, mock_get_root):
    mock_shell_inst = mock.Mock()
    mock_cluster_shell.return_value = mock_shell_inst
    mock_shell_inst.get_rc_stdout_stderr_without_input.side_effect = [
        (0, "dev multipath\nsda mpatha", ""),  # multipathd show paths
        (0, "mpatha 360050768018081c9c00000000000c9b2", ""),  # multipathd show maps
        (0, "IBM    ", ""),  # cat vendor
        (0, "2145   ", ""),  # cat model
        (0, "defaults {\n no_path_retry fail\n path_checker tur\n}\n", ""),  # multipath -T
    ]

    inspector = storage_utils.MultipathInspector("/dev/mapper/mpatha")
    config = inspector.get_multipath_config_values()

    assert config["no_path_retry"] == "fail"
    assert config["path_checker"] == "tur"
    assert config["path_grouping_policy"] is None
    assert config["checker_timeout"] is None


@mock.patch.object(storage_utils.MultipathInspector, "_get_root_backing_device", return_value="sda")
@mock.patch('crmsh.sh.cluster_shell')
def test_get_multipath_config_not_multipath(mock_cluster_shell, mock_get_root):
    mock_shell_inst = mock.Mock()
    mock_cluster_shell.return_value = mock_shell_inst
    mock_shell_inst.get_rc_stdout_stderr_without_input.side_effect = [
        (0, "", ""),  # multipathd show paths (empty)
    ]

    assert storage_utils.get_multipath_config("/dev/sda1") is None
