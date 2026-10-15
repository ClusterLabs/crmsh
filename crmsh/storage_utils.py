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
    output = sh.cluster_shell().get_stdout_or_raise_error("vgdisplay {}".format(shlex.quote(vg_id)))
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
    return out[0] if out else get_dev_uuid_by_blkid(dev, peer)


def get_dev_uuid_by_blkid(dev, peer=None):
    """
    Get UUID of device using blkid
    """
    out = sh.cluster_shell().get_stdout_or_raise_error("blkid {}".format(shlex.quote(dev)), peer)
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
    cmd = "lsblk -fno {} {}".format(','.join(_type), shlex.quote(dev))
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
    return xmlutil.CrmMonXMLParser(peer).is_resource_started(constants.DLM_CONTROLD_RA, node=on_node)


def is_dlm_configured(peer=None):
    """
    Check if dlm configured
    """
    return xmlutil.CrmMonXMLParser(peer).is_resource_configured(constants.DLM_CONTROLD_RA)


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


MULTIPATH_CONFIG_DEFAULTS = {
    "no_path_retry": "fail",
    "path_grouping_policy": "failover",
    "path_checker": "tur",
    "detect_checker": "yes",
}


def _split_multipath_key_value(line: str):
    """Split a multipath config "key value" line into (key, value)."""
    m = re.match(r"^(\S+)\s+(.*)$", line)
    if not m:
        return None
    value = m.group(2).strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return m.group(1), value


def _finalize_multipath_frame(result: dict, frame: dict) -> None:
    kind = frame["kind"]
    if kind == "defaults":
        result["defaults"] = frame["attrs"]
    elif kind == "overrides":
        result["overrides"] = frame["attrs"]
    elif kind == "device":
        result["devices"].append(frame)
    elif kind == "multipath":
        result["multipaths"].append(frame)


def _parse_multipath_config(out: str) -> dict:
    """
    Parse the effective multipath configuration (the output of "multipath -T")
    into its sections. Returns a dict with:
    - "defaults": attribute -> value
    - "overrides": attribute -> value
    - "devices": list of {"vendor", "product", "attrs"}
    - "multipaths": list of {"wwid", "attrs"}
    """
    result = {
        "defaults": {},
        "overrides": {},
        "devices": [],
        "multipaths": [],
    }
    stack = []
    for line in out.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        while s.startswith("}"):
            s = s[1:].strip()
            if stack:
                _finalize_multipath_frame(result, stack.pop())
        if not s:
            continue
        m = re.match(r"^(\w+)\s*\{\s*(.*)$", s)
        if m:
            name = m.group(1)
            if name in ("defaults", "overrides", "devices", "multipaths",
                        "blacklist", "blacklist_exceptions"):
                stack.append({"kind": name, "attrs": {}})
            elif name == "device":
                stack.append({"kind": "device", "vendor": None, "product": None, "attrs": {}})
            elif name == "multipath":
                stack.append({"kind": "multipath", "wwid": None, "attrs": {}})
            else:
                stack.append({"kind": "ignore", "attrs": {}})
            continue
        kv = _split_multipath_key_value(s)
        if kv is None or not stack:
            continue
        key, value = kv
        top = stack[-1]
        kind = top["kind"]
        if kind == "defaults" or kind == "overrides":
            top["attrs"][key] = value
        elif kind == "device":
            if key == "vendor":
                top["vendor"] = value
            elif key == "product":
                top["product"] = value
            else:
                top["attrs"][key] = value
        elif kind == "multipath":
            if key == "wwid":
                top["wwid"] = value
            else:
                top["attrs"][key] = value
    while stack:
        _finalize_multipath_frame(result, stack.pop())
    return result


def _resolve_multipath_value(result: dict, attribute: str, wwid, vendor, product):
    """Resolve a multipath config attribute for a device, honoring section precedence."""
    for mp in result["multipaths"]:
        if mp.get("wwid") == wwid and attribute in mp["attrs"]:
            return mp["attrs"][attribute]
    if attribute in result["overrides"]:
        return result["overrides"][attribute]
    for dev in result["devices"]:
        if dev.get("vendor") == vendor and dev.get("product") == product \
                and attribute in dev["attrs"]:
            return dev["attrs"][attribute]
    if attribute in result["defaults"]:
        return result["defaults"][attribute]
    return None


@dataclass(frozen=True)
class DeviceInfo:
    device: str
    parent_device: str|None
    under_multipath: bool


class MultipathInspector:
    def __init__(self, dev):
        self._shell = sh.cluster_shell()
        self._multipath_mapping = None
        self._device_info = self._inspect(dev)

    def _get_parent_device(self, dev) -> str:
        resolved = Path(dev).resolve()
        cmd = f"lsblk -dn -o PKNAME {shlex.quote(str(resolved))}"
        _, out, _ = self._shell.get_rc_stdout_stderr_without_input(None, cmd)
        return out or resolved.name

    def _get_multipath_mapping(self) -> dict[str, str]:
        if self._multipath_mapping is not None:
            return self._multipath_mapping
        cmd = "multipathd show paths format \"%d %m\""
        rc, out, _ = self._shell.get_rc_stdout_stderr_without_input(None, cmd)
        mapping = dict()
        if rc != 0:
            self._multipath_mapping = mapping
            return mapping
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            dev_name, map_name = parts[0], parts[1]
            if (dev_name, map_name) == ("dev", "multipath"):
                continue
            mapping[dev_name] = map_name
        self._multipath_mapping = mapping
        return mapping

    @staticmethod
    def _get_multipath_name(dev: str) -> str:
        return re.sub(r"-part\d+$", "", Path(dev).name)

    def _is_multipath_device(self, dev: str) -> bool:
        return self._get_multipath_name(dev) in self._get_multipath_mapping().values()

    def _get_multipath_path(self, multipath_dev: str) -> str|None:
        map_name = self._get_multipath_name(multipath_dev)
        for dev_name, multipath_name in self._get_multipath_mapping().items():
            if multipath_name == map_name:
                return dev_name
        return None

    def _inspect(self, dev: str) -> DeviceInfo:
        parent = self._get_parent_device(dev)
        mapping = self._get_multipath_mapping()
        map_name = self._get_multipath_name(dev)
        return DeviceInfo(
            device=dev,
            parent_device=parent,
            under_multipath=parent in mapping or map_name in mapping.values()
        )

    def _is_under_multipath(self) -> bool:
        return self._device_info.under_multipath

    def _get_multipath_config_value(self, key: str) -> int|None:
        rc, out, _ = self._shell.get_rc_stdout_stderr_without_input(None, "multipath -T")
        if rc != 0:
            return None
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            if parts[0] == key:
                return int(parts[1])
        return None

    def _get_multipath_wwid(self) -> str|None:
        map_name = self._get_multipath_name(self._device_info.device)
        rc, out, _ = self._shell.get_rc_stdout_stderr_without_input(None, 'multipathd show maps format "%n %w"')
        if rc != 0:
            return None
        for line in out.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0] == map_name:
                return parts[1]
        return None

    def _get_device_sysfs_attr(self, attr: str) -> str|None:
        device = self._get_scsi_device_name()
        if not device:
            return None
        path = f"/sys/block/{device}/device/{attr}"
        rc, out, _ = self._shell.get_rc_stdout_stderr_without_input(None, f"cat {shlex.quote(path)}")
        if rc != 0:
            return None
        return out.strip()

    def get_multipath_config_values(self) -> dict[str, str|None]:
        """
        Resolve the effective multipath configuration for this multipath device.
        Returns attribute -> effective value (None when not configured).
        """
        if not self._is_multipath_device(self._device_info.device):
            return {}
        wwid = self._get_multipath_wwid()
        vendor = self._get_device_sysfs_attr("vendor")
        product = self._get_device_sysfs_attr("model")
        rc, out, _ = self._shell.get_rc_stdout_stderr_without_input(None, "multipath -T")
        if rc != 0:
            return {}
        parsed = _parse_multipath_config(out)
        attrs = ("no_path_retry", "path_grouping_policy", "path_checker",
                 "detect_checker", "checker_timeout")
        return {attr: _resolve_multipath_value(parsed, attr, wwid, vendor, product) for attr in attrs}

    def _get_scsi_device_name(self) -> str|None:
        if self._is_multipath_device(self._device_info.device):
            return self._get_multipath_path(self._device_info.device)
        return self._device_info.parent_device

    def get_scsi_timeout(self) -> int:
        """
        Get SCSI timeout from /sys/block/<sdX>/device/timeout.
        """
        device = self._get_scsi_device_name()
        if not device:
            raise ValueError(f"Cannot find backing device for {self._device_info.device}")
        timeout_path = f"/sys/block/{device}/device/timeout"
        out = self._shell.get_stdout_or_raise_error(f"cat {shlex.quote(timeout_path)}")
        return int(out.strip())

    def is_scsi_device(self) -> bool:
        """
        Check if the backing device exposes a SCSI device timeout.
        """
        device = self._get_scsi_device_name()
        if not device:
            return False
        timeout_path = f"/sys/block/{device}/device/timeout"
        rc, _, _ = self._shell.get_rc_stdout_stderr_without_input(None, f"test -f {shlex.quote(timeout_path)}")
        return rc == 0

    def get_max_polling_interval(self) -> int|None:
        """
        Get max_polling_interval from multipath effective config.
        """
        return self._get_multipath_config_value("max_polling_interval")

    def get_checker_timeout(self) -> int:
        """
        Get checker_timeout from multipath effective config, defaulting to SCSI timeout.
        """
        value = self._get_multipath_config_value("checker_timeout")
        return value if value is not None else self.get_scsi_timeout()

    @classmethod
    def get_device_scsi_timeout(cls, dev) -> int:
        return cls(dev).get_scsi_timeout()

    @classmethod
    def check_device_under_multipath(cls, dev):
        inspector = cls(dev)
        if inspector._is_under_multipath() and not inspector._is_multipath_device(dev):
            error_msg = f"Device {dev} is under multipath, please provide the multipath device instead"
            raise ValueError(error_msg)


def is_scsi_device(dev) -> bool:
    return MultipathInspector(dev).is_scsi_device()


def is_multipath_device(dev) -> bool:
    return MultipathInspector(dev)._is_multipath_device(dev)


def get_multipath_config(dev) -> dict[str, str|None]|None:
    """
    Return the effective multipath configuration values for the given device,
    or None when the device is not a multipath device.
    """
    inspector = MultipathInspector(dev)
    if not inspector._is_multipath_device(dev):
        return None
    return inspector.get_multipath_config_values()


def get_multipath_max_polling_interval(dev) -> int|None:
    return MultipathInspector(dev).get_max_polling_interval()


def get_multipath_checker_timeout(dev) -> int:
    return MultipathInspector(dev).get_checker_timeout()


def get_scsi_timeout(dev) -> int:
    return MultipathInspector.get_device_scsi_timeout(dev)
