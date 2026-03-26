"""Interface to iproute2 commands"""
import ipaddress


class IPInterface:
    def __init__(self, ifname, flags, addr_info):
        self.ifname = ifname
        self.flags = flags
        self.addr_info = addr_info


class IPAddr:
    def __init__(self, json):
        # json: the output of 'ip -j addr'
        self._json = json

    def interfaces(self):
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
