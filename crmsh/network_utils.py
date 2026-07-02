import ipaddress
import json
import logging
import os
import re
import selectors
import socket
import time
import typing
from dataclasses import dataclass

import crmsh.user_of_host
from . import config, constants, sh
from . import iproute2
from .sh import ShellUtils


logger = logging.getLogger(__name__)


class _XmlUtilProxy:
    def __getattr__(self, name):
        from . import xmlutil
        return getattr(xmlutil, name)


xmlutil = _XmlUtilProxy()


class NoSSHError(Exception):
    pass


def check_ssh_passwd_need(local_user, remote_user, host, shell: sh.LocalShell = None):
    """
    Check whether access to host need password
    """
    ssh_options = "-o StrictHostKeyChecking=no -o EscapeChar=none -o ConnectTimeout=15"
    ssh_cmd = "ssh {} -T -o Batchmode=yes {}@{} true".format(ssh_options, remote_user, host)
    if shell is None:
        shell = sh.LocalShell(additional_environ={'SSH_AUTH_SOCK': os.environ.get('SSH_AUTH_SOCK', '')})
    rc, _ = shell.get_rc_and_error(local_user, ssh_cmd)
    return rc != 0


def check_port_open(host, port, timeout=1.0, retry=3) -> bool:
    """
    Check whether the port is open on the host
    Use getaddrinfo to support both IPv4 and IPv6
    """
    try:
        addrinfos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.error:
        return False

    for i in range(retry):
        start_time = time.time()
        sel = selectors.DefaultSelector()
        sockets = []

        for addrinfo in addrinfos:
            af, socktype, proto, canonname, sa = addrinfo
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                sock.setblocking(False)
                if hasattr(socket, 'TCP_SYNCNT'):
                    try:
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_SYNCNT, 1)
                    except OSError:
                        pass

                err = sock.connect_ex(sa)
                if err == 0:
                    sel.close()
                    for s in sockets:
                        s.close()
                    sock.close()
                    return True

                sel.register(sock, selectors.EVENT_WRITE)
                sockets.append(sock)
            except socket.error:
                if sock:
                    sock.close()

        try:
            events = sel.select(timeout)
            for key, mask in events:
                if key.fileobj.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                    return True
        finally:
            sel.close()
            for sock in sockets:
                sock.close()

        if i < retry - 1:
            elapsed = time.time() - start_time
            if elapsed < timeout:
                time.sleep(timeout - elapsed)

    return False


def valid_port(port):
    return int(port) >= 1024 and int(port) <= 65535


class IP(object):
    """
    Class to get some properties of IP address
    """

    def __init__(self, addr):
        """
        Init function
        """
        self.addr = addr

    @property
    def ip_address(self):
        """
        Create ipaddress instance
        """
        return ipaddress.ip_address(self.addr)

    @property
    def version(self):
        """
        Get IP address version
        """
        return self.ip_address.version

    @classmethod
    def is_mcast(cls, addr):
        """
        Check whether the address is multicast address
        """
        cls_inst = cls(addr)
        return cls_inst.ip_address.is_multicast

    @classmethod
    def is_ipv6(cls, addr):
        """
        Check whether the address is IPV6 address
        """
        return cls(addr).version == 6

    @property
    def is_loopback(self):
        """
        Check whether the address is loopback address
        """
        return self.ip_address.is_loopback

    @classmethod
    def is_valid_ip(cls, addr):
        """
        Check whether the address is valid IP address
        """
        cls_inst = cls(addr)
        try:
            cls_inst.ip_address
        except ValueError:
            return False
        else:
            return True


class Interface(IP):
    """
    Class to get information from one interface
    """

    def __init__(self, ip_with_mask):
        """
        Init function
        """
        self.ip, self.mask = ip_with_mask.split('/')
        super(__class__, self).__init__(self.ip)

    @property
    def ip_with_mask(self):
        """
        Get ip with netmask
        """
        return '{}/{}'.format(self.ip, self.mask)

    @property
    def ip_interface(self):
        """
        Create ip_interface instance
        """
        return ipaddress.ip_interface(self.ip_with_mask)

    @property
    def network(self):
        """
        Get network address
        """
        return str(self.ip_interface.network.network_address)


class InterfacesInfo(object):
    """
    Class to collect interfaces information on local node
    """

    def __init__(self, ipv6: bool = False, custom_nic_addr_list: typing.List[str] = []) -> None:
        """
        Init function

        On init process,
        "ipv6" is provided by -I option
        "custom_nic_addr_list" is provided by -i option
        """
        self.ip_version = 6 if ipv6 else 4
        self._custom_nic_addr_list = custom_nic_addr_list
        self._nic_info_dict = {}
        self._ip_nic_dict = {}
        self._input_nic_list = []
        self._input_addr_list = []

    def get_interfaces_info(self):
        """
        Try to get interfaces info dictionary via "ip" command

        IMPORTANT: This is the method that populates the data, should always be called after initialize
        """
        cmd = "ip -{} -o addr show".format(self.ip_version)
        rc, out, err = ShellUtils().get_stdout_stderr(cmd)
        if rc != 0:
            raise ValueError(err)

        # format on each line will like:
        # 2: enp1s0    inet 192.168.122.241/24 brd 192.168.122.255 scope global enp1s0\       valid_lft forever preferred_lft forever
        for line in out.splitlines():
            _, nic, _, ip_with_mask, *_ = line.split()
            # maybe from tun interface
            if not '/' in ip_with_mask:
                continue
            interface_inst = Interface(ip_with_mask)
            if interface_inst.is_loopback:
                continue
            # one nic might configured multi IP addresses
            if nic not in self._nic_info_dict:
                self._nic_info_dict[nic] = []
            self._nic_info_dict[nic].append(interface_inst)

        if not self._nic_info_dict:
            raise ValueError("No address configured")

        for nic, inst_list in self._nic_info_dict.items():
            for inst in inst_list:
                self._ip_nic_dict[inst.ip] = nic

    def flatten_custom_nic_addr_list(self) -> None:
        """
        If NIC or IP is provided by the -i option, convert them to
        nic list and address list, and do some validations
        """
        for item in self._custom_nic_addr_list:
            if item in self.nic_list:
                ip = self.nic_first_ip(item)
                if ip in self._input_addr_list:
                    raise ValueError(f"Invalid input '{item}': The same NIC already used")
                self._input_nic_list.append(item)
                self._input_addr_list.append(ip)
            elif IP.is_valid_ip(item):
                nic = self.get_nic_name_by_addr(item)
                if nic in self._input_nic_list:
                    raise ValueError(f"Invalid input '{item}': the IP in the same NIC already used")
                self._input_nic_list.append(nic)
                self._input_addr_list.append(item)
            else:
                raise ValueError(f"Invalid value '{item}' for -i/--interface option, should be {', '.join(self.nic_list)} or {', '.join(self.ip_list)}")

    @property
    def nic_list(self):
        """
        Get interfaces name list
        """
        return list(self._nic_info_dict.keys())

    @property
    def interface_list(self):
        """
        Get instance list of class Interface
        """
        _interface_list = []
        for interface in self._nic_info_dict.values():
            _interface_list.extend(interface)
        return _interface_list

    @property
    def ip_list(self):
        """
        Get IP address list
        """
        return [interface.ip for interface in self.interface_list]

    @property
    def input_nic_list(self) -> typing.List[str]:
        return self._input_nic_list

    @property
    def input_addr_list(self) -> typing.List[str]:
        return self._input_addr_list

    @classmethod
    def get_local_ip_list(cls, is_ipv6):
        """
        Get IP address list
        """
        cls_inst = cls(is_ipv6)
        cls_inst.get_interfaces_info()
        return cls_inst.ip_list

    @classmethod
    def ip_in_local(cls, addr):
        """
        Check whether given address was in one of local address
        """
        cls_inst = cls(IP.is_ipv6(addr))
        cls_inst.get_interfaces_info()
        return addr in cls_inst.ip_list

    def get_nic_name_by_addr(self, addr: str) -> str:
        """
        Return NIC name by given local IP address
        Raise error if this IP is not the local address
        """
        if addr not in self.ip_list:
            raise ValueError(f"'{addr}' is not in the local address: {self.ip_list}")
        return self._ip_nic_dict[addr]

    @property
    def network_list(self):
        """
        Get network list
        """
        return list(set([interface.network for interface in self.interface_list]))

    def nic_first_ip(self, nic) -> str:
        """
        Get the first IP of specific nic
        """
        return self._nic_info_dict[nic][0].ip

    def get_default_nic_from_route(self) -> str:
        """
        Get default nic from route
        """
        #TODO what if user only has ipv6 route?
        cmd = "ip -o route show"
        out = sh.cluster_shell().get_stdout_or_raise_error(cmd)
        res = re.search(r'^default via .* dev (.*?) ', out)
        return res.group(1) if res else self.nic_list[0]


class BootstrapValidation(object):
    """
    Validate network values used by bootstrap interactive inputs.
    """

    def __init__(self, value, prev_value_list=[]):
        self.value = value
        self.prev_value_list = prev_value_list
        if self.value in self.prev_value_list:
            raise ValueError("Already in use: {}".format(self.value))

    def _is_mcast_addr(self):
        if not IP.is_mcast(self.value):
            raise ValueError("{} is not multicast address".format(self.value))

    def _is_local_addr(self, local_addr_list):
        if self.value not in local_addr_list:
            raise ValueError("Address must be a local address (one of {})".format(local_addr_list))

    def _is_valid_port(self):
        if self.prev_value_list and abs(int(self.value) - int(self.prev_value_list[0])) <= 1:
            raise ValueError("Port {} is already in use by corosync. Leave a gap between multiple rings.".format(self.value))
        if int(self.value) <= 1024 or int(self.value) > 65535:
            raise ValueError("Valid port range should be 1025-65535")

    @classmethod
    def valid_mcast_address(cls, addr, prev_value_list=[]):
        cls_inst = cls(addr, prev_value_list)
        cls_inst._is_mcast_addr()

    @classmethod
    def valid_ucast_ip(cls, addr, local_addr_list, prev_value_list=[]):
        cls_inst = cls(addr, prev_value_list)
        cls_inst._is_local_addr(local_addr_list)

    @classmethod
    def valid_mcast_ip(cls, addr, local_addr_list, network_list, prev_value_list=[]):
        cls_inst = cls(addr, prev_value_list)
        cls_inst._is_local_addr(local_addr_list + network_list)

    @classmethod
    def valid_port(cls, port, prev_value_list=[]):
        cls_inst = cls(port, prev_value_list)
        cls_inst._is_valid_port()

    @staticmethod
    def valid_admin_ip(addr, invoker, prev_value_list=[]):
        ipv6 = IP.is_ipv6(addr)
        ping_cmd = "ping6" if ipv6 else "ping"
        if invoker("{} -c 1 {}".format(ping_cmd, addr)):
            raise ValueError("Address already in use: {}".format(addr))


def get_cluster_node_ips(node: str) -> list[str]:
    """
    Get all IP addresses of the target node remotely.
    If it fails, fall back to utils.get_iplist_from_name(node).
    """
    rc, out, err = sh.cluster_shell().get_rc_stdout_stderr_without_input(node, "ip -j addr show")
    if rc == 0:
        try:
            addr_info = iproute2.IPAddr(json.loads(out))
            ips = []
            for iface in addr_info.interfaces():
                for addr in iface.addr_info:
                    ips.append(str(addr.ip))
            return ips
        except Exception as e:
            logger.warning("Failed to parse ip output from node {}: {}".format(node, e))

    from . import utils
    return utils.get_iplist_from_name(node)


class FirewallManager:

    SERVICE_NAME = "high-availability"

    def __init__(self, peer=None):
        from . import utils

        self.shell = None
        self.peer = peer
        self.firewalld_running = False
        self.firewall_cmd = None
        self.firewall_cmd_permanent_option = ""
        self.peer_msg = ""
        self.firewalld_installed = utils.package_is_installed("firewalld", self.peer)

        if self.firewalld_installed:
            self.shell = sh.cluster_shell()
            rc, _, _ = self.shell.get_rc_stdout_stderr_without_input(self.peer, "firewall-cmd --state")
            self.firewalld_running = rc == 0
            self.firewall_cmd = "firewall-cmd" if self.firewalld_running else "firewall-offline-cmd"
            self.firewall_cmd_permanent_option = " --permanent" if self.firewalld_running else ""
            self.peer_msg = f"on {self.peer}" if self.peer else f"on {utils.this_node()}"

    def _service_is_available(self) -> bool:
        cmd = f"{self.firewall_cmd} --info-service={self.SERVICE_NAME}"
        rc, _, _ = self.shell.get_rc_stdout_stderr_without_input(self.peer, cmd)
        if rc != 0:
            logger.warning("Firewalld service %s is not available %s", self.SERVICE_NAME, self.peer_msg)
            return False
        return True

    def add_service(self):
        if not self.firewalld_installed or not self._service_is_available():
            return
        cmd = f"{self.firewall_cmd}{self.firewall_cmd_permanent_option} --add-service={self.SERVICE_NAME}"
        rc, _, err = self.shell.get_rc_stdout_stderr_without_input(self.peer, cmd)
        if rc != 0:
            logger.error("Failed to add firewalld service %s %s: %s", self.SERVICE_NAME, self.peer_msg, err)
            return
        if self.firewalld_running:
            cmd = f"{self.firewall_cmd} --add-service={self.SERVICE_NAME}"
            self.shell.get_rc_stdout_stderr_without_input(self.peer, cmd)
        logger.info("Added firewalld service %s %s", self.SERVICE_NAME, self.peer_msg)

    def remove_service(self):
        if not self.firewalld_installed or not self._service_is_available():
            return
        cmd = f"{self.firewall_cmd}{self.firewall_cmd_permanent_option} --remove-service={self.SERVICE_NAME}"
        rc, _, err = self.shell.get_rc_stdout_stderr_without_input(self.peer, cmd)
        if rc != 0:
            logger.error("Failed to remove firewalld service %s %s: %s", self.SERVICE_NAME, self.peer_msg, err)
            return
        if self.firewalld_running:
            cmd = f"{self.firewall_cmd} --remove-service={self.SERVICE_NAME}"
            self.shell.get_rc_stdout_stderr_without_input(self.peer, cmd)
        logger.info("Removed firewalld service %s %s", self.SERVICE_NAME, self.peer_msg)

    @classmethod
    def firewalld_stage_finished(cls) -> bool:
        inst = cls()
        if not inst.firewalld_installed or not inst._service_is_available():
            return True
        cmd = f"{inst.firewall_cmd} --list-services"
        _, outp, _ = inst.shell.get_rc_stdout_stderr_without_input(None, cmd)
        return inst.SERVICE_NAME in outp.split()


def ssh_command():
    """
    Wrapper function for ssh command

    When ssh between cluster nodes is blocked, core.no_ssh
    should be set to 'yes', then this function will raise NoSSHError
    """
    if config.core.no_ssh:
        raise NoSSHError(constants.NO_SSH_ERROR_MSG)
    return "ssh"


def ssh_port_reachable_check(node):
    from . import utils

    """
    Check if node is reachable by checking SSH port is open
    """
    if node == utils.this_node() or check_port_open(node, 22):
        return True
    if config.core.no_ssh:
        raise NoSSHError(constants.NO_SSH_ERROR_MSG)
    else:
        raise ValueError(f"host \"{node}\" is unreachable via SSH")


def get_reachable_node_list(node_list:list[str]) -> list[str]:
    reachable_node_list = []
    for node in node_list:
        try:
            if ssh_port_reachable_check(node):
                reachable_node_list.append(node)
        except ValueError as e:
            logger.warning(str(e))
    return reachable_node_list

@dataclass
class ReachabilitySummary:
    dead_nodes: list[str] # offline and unreachable nodes
    nodes_unreachable: list[str]
    nodes_need_password: list[str]
    reachable_nodes: list[str]


class DeadNodeError(ValueError):
    def __init__(self, msg: str, summary: ReachabilitySummary = None):
        super().__init__(msg)
        self.summary = summary


class UnreachableNodeError(ValueError):
    def __init__(self, msg: str, summary: ReachabilitySummary = None):
        super().__init__(msg)
        self.summary = summary


def check_all_nodes_reachable(
    action_to_do: str,
    peer_node: str = None,
    check_passwd: bool = True
) -> ReachabilitySummary:

    from . import utils

    crm_mon_inst = xmlutil.CrmMonXmlParser(peer_node)
    if crm_mon_inst.not_connected():
        try:
            nodes_to_check = utils.list_cluster_nodes_except_me()
            offline_nodes = utils.list_cluster_nodes_except_me()
        except ValueError:
            nodes_to_check = []
            offline_nodes = []
    else:
        nodes_to_check = crm_mon_inst.get_node_list(online=True, node_type="member")
        offline_nodes = crm_mon_inst.get_node_list(online=False)

    dead_nodes = []
    for node in offline_nodes:
        try:
            ssh_port_reachable_check(node)
        except ValueError:
            dead_nodes.append(node)

    nodes_unreachable = []
    nodes_need_password = []
    reachable_nodes = []
    me = utils.this_node()

    for node in nodes_to_check:
        if node == me:
            continue

        try:
            ssh_port_reachable_check(node)
        except ValueError:
            nodes_unreachable.append(node)
            continue

        if check_passwd:
            local_user, remote_user = crmsh.user_of_host.UserOfHost.instance().user_pair_for_ssh(node)
            if check_ssh_passwd_need(local_user, remote_user, node):
                nodes_need_password.append(node)
                continue

        reachable_nodes.append(node)

    summary = ReachabilitySummary(
        dead_nodes=dead_nodes,
        nodes_unreachable=nodes_unreachable,
        nodes_need_password=nodes_need_password,
        reachable_nodes=reachable_nodes
    )

    if dead_nodes:
        msg = (
            f"There are offline nodes also unreachable: {', '.join(dead_nodes)}.\n"
            f"Please bring them online before {action_to_do}.\n"
            f"Or use `crm cluster remove <offline_node> --force` to remove the offline node."
        )
        raise DeadNodeError(msg, summary)
    if nodes_unreachable:
        msg = (
            f"There are nodes whose SSH ports are unreachable: {', '.join(nodes_unreachable)}.\n"
            f"Please check the network connectivity before {action_to_do}."
        )
        raise UnreachableNodeError(msg, summary)
    if nodes_need_password:
        msg = (
            f"There are nodes which requires a password for SSH access: {', '.join(nodes_need_password)}.\n"
            f"Please setup passwordless SSH access before {action_to_do}."
        )
        raise UnreachableNodeError(msg, summary)

    return summary
