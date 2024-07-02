"""Interface to iproute2 commands"""
import dataclasses
import ipaddress


@dataclasses.dataclass
class IPInterface:
    ifname: str
    flags: set[str]
    addr_info: set[ipaddress.IPv4Interface | ipaddress.IPv6Interface]


class IPAddr:
    def __init__(self, json: list):
        # json: the output of 'ip -j addr'
        self._json = json

    def interfaces(self) -> list[IPInterface]:
        return [
            IPInterface(
                interface['ifname'],
                set(interface['flags']),
                {
                    ipaddress.ip_interface(f'{x["local"]}/{x["prefixlen"]}')
                    for x in interface['addr_info']
                },
            )
            for interface in self._json
        ]
