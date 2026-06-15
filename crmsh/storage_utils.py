import logging
import os
import re
import shlex
import typing
from collections import defaultdict
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from . import constants, sh, xmlutil, utils


logger = logging.getLogger(__name__)


def get_non_block_device_nodes(dev, node_list=None) -> list[str]:
    """
    Return a list of nodes where the device is not a block device or does not exist
    """
    shell = sh.cluster_shell()
    cluster_nodes = node_list or [utils.this_node()]
    failed_nodes = []
    for node in cluster_nodes:
        rc, _, _ = shell.get_rc_stdout_stderr_without_input(
            node,
            f"test -b {shlex.quote(dev)}"
        )
        if rc != 0:
            failed_nodes.append(node)
    return failed_nodes


def detect_duplicate_device_path(device_list: typing.List[str]):
    """
    Resolve device path and check if there are duplicated device path
    """
    path_dict = defaultdict(list)
    for dev in device_list:
        resolved_path = Path(dev).resolve()
        path_dict[resolved_path].append(dev)
    for path, dev_list in path_dict.items():
        if len(dev_list) > 1:
            raise ValueError(f"Duplicated device path detected: {','.join(dev_list)}. They are all pointing to {path}")


def has_disk_mounted(dev):
    """
    Check if device already mounted
    """
    out = sh.cluster_shell().get_stdout_or_raise_error("mount")
    return re.search("\n{} on ".format(dev), out) is not None


def has_mount_point_used(directory):
    """
    Check if mount directory already mounted
    """
    out = sh.cluster_shell().get_stdout_or_raise_error("mount")
    return re.search(" on {}".format(directory), out) is not None


def get_all_vg_name():
    """
    Get all available VGs
    """
    out = sh.cluster_shell().get_stdout_or_raise_error("vgdisplay")
    return re.findall(r"VG Name\s+(.*)", out)


def get_pe_number(vg_id):
    """
    Get pe number
    """
    output = sh.cluster_shell().get_stdout_or_raise_error("vgdisplay {}".format(vg_id))
    res = re.search(r"Total PE\s+(\d+)", output)
    if not res:
        raise ValueError("Cannot find PE on VG({})".format(vg_id))
    return int(res.group(1))


def has_dev_partitioned(dev, peer=None):
    """
    Check if device has partitions
    """
    return len(get_dev_info(dev, "NAME", peer=peer).splitlines()) > 1


def get_dev_uuid(dev, peer=None):
    """
    Get UUID of device on local or peer node
    """
    out = get_dev_info(dev, "UUID", peer=peer).splitlines()
    return out[0] if out else get_dev_uuid_2(dev, peer)


def get_dev_uuid_2(dev, peer=None):
    """
    Get UUID of device using blkid
    """
    out = sh.cluster_shell().get_stdout_or_raise_error("blkid {}".format(dev), peer)
    res = re.search("UUID=\"(.*?)\"", out)
    return res.group(1) if res else None


def get_dev_fs_type(dev, peer=None):
    """
    Get filesystem type of device
    """
    return get_dev_info(dev, "FSTYPE", peer=peer)


def get_dev_info(dev, *_type, peer=None):
    """
    Get device info using lsblk
    """
    cmd = "lsblk -fno {} {}".format(','.join(_type), dev)
    return sh.cluster_shell().get_stdout_or_raise_error(cmd, peer)


def is_dev_used_for_lvm(dev, peer=None):
    """
    Check if device is LV
    """
    return "lvm" in get_dev_info(dev, "TYPE", peer=peer)


def is_dev_a_plain_raw_disk_or_partition(dev, peer=None):
    """
    Check if device is a raw disk or partition
    """
    out = get_dev_info(dev, "TYPE", peer=peer)
    return re.search("(disk|part)", out) is not None


def compare_uuid_with_peer_dev(dev_list, peer):
    """
    Check if device UUID is the same with peer's device
    """
    for dev in dev_list:
        local_uuid = get_dev_uuid(dev)
        if not local_uuid:
            raise ValueError("Cannot find UUID for {} on local".format(dev))
        peer_uuid = get_dev_uuid(dev, peer)
        if not peer_uuid:
            raise ValueError("Cannot find UUID for {} on {}".format(dev, peer))
        if local_uuid != peer_uuid:
            raise ValueError("UUID of {} not same with peer {}".format(dev, peer))


def get_dlm_option_dict(peer=None):
    """
    Get dlm config option dictionary
    """
    out = sh.cluster_shell().get_stdout_or_raise_error("dlm_tool dump_config", peer)
    return dict(re.findall(r"(\w+)=(\w+)", out))


def set_dlm_option(peer=None, **kargs):
    """
    Set dlm option
    """
    shell = sh.cluster_shell()
    dlm_option_dict = get_dlm_option_dict(peer=peer)
    for option, value in kargs.items():
        if option not in dlm_option_dict:
            raise ValueError(f'"{option}" is not dlm config option')
        if dlm_option_dict[option] != value:
            shell.get_stdout_or_raise_error(f'dlm_tool set_config "{option}={value}"', peer)


def is_dlm_running(peer=None, on_node=None):
    """
    Check if dlm ra controld is running
    """
    return xmlutil.CrmMonXmlParser(peer).is_resource_started(constants.DLM_CONTROLD_RA, node=on_node)


def is_dlm_configured(peer=None):
    """
    Check if dlm configured
    """
    return xmlutil.CrmMonXmlParser(peer).is_resource_configured(constants.DLM_CONTROLD_RA)


def check_no_quorum_policy_with_dlm():
    """
    Give warning when no-quorum-policy not freeze while configured DLM
    """
    if not is_dlm_configured():
        return
    from . import utils
    res = utils.get_property("no-quorum-policy")
    if not res or res != "freeze":
        logger.warning("The DLM cluster best practice suggests to set the cluster property \"no-quorum-policy=freeze\"")


@dataclass(frozen=True)
class DeviceInfo:
    device: str
    parent_device: str|None
    under_multipath: bool


class MultipathInspector:
    def __init__(self, dev):
        self._shell = sh.cluster_shell()
        self._device_info = self._inspect(dev)

    def _get_parent_device(self, dev) -> str:
        resolved = Path(dev).resolve()
        cmd = f"lsblk -dn -o PKNAME {shlex.quote(str(resolved))}"
        _, out, _ = self._shell.get_rc_stdout_stderr_without_input(None, cmd)
        return out or resolved.name

    def _get_multipath_mapping(self) -> dict[str, str]:
        cmd = "multipathd show paths format \"%d %m\""
        rc, out, _ = self._shell.get_rc_stdout_stderr_without_input(None, cmd)
        mapping = dict()
        if rc != 0:
            return mapping
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            dev_name, map_name = parts[0], parts[1]
            if (dev_name, map_name) == ("dev", "multipath"):
                continue
            mapping[dev_name] = map_name
        return mapping

    def _inspect(self, dev: str) -> DeviceInfo:
        parent = self._get_parent_device(dev)
        mapping = self._get_multipath_mapping()
        return DeviceInfo(
            device=dev,
            parent_device=parent,
            under_multipath=parent in mapping
        )

    def _is_under_multipath(self) -> bool:
        return self._device_info.under_multipath

    @classmethod
    def check_device_under_multipath(cls, dev):
        inspector = cls(dev)
        if inspector._is_under_multipath():
            error_msg = f"Device {dev} is under multipath, please provide the multipath device instead"
            raise ValueError(error_msg)
