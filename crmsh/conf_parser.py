"""
Module to parse corosync.conf

Maintainer: XLiang@suse.com
"""
import os
from io import StringIO

from . import corosync
from . import utils
from . import corosync_config_format


COROSYNC_CONF_TEMPLATE = """
totem {
    version: 2
}

quorum {
    provider: corosync_votequorum
}

logging {
    to_logfile: yes
    logfile: /var/log/cluster/corosync.log
    to_syslog: yes
    timestamp: on
}
"""


class ConfParser(object):
    """
    Class to parse config file which format like corosync.conf
    """
    COROSYNC_KNOWN_SEC_NAMES_WITH_LIST = {("totem", "interface"), ("nodelist", "node")}

    def __init__(self, config_file=None, config_data=None, sec_names_with_list=()):
        self._config_file = config_file
        self._sec_names_with_list = set(sec_names_with_list) if sec_names_with_list else self.COROSYNC_KNOWN_SEC_NAMES_WITH_LIST
        if config_data is not None:
            self._dom = corosync_config_format.DomParser(StringIO(config_data)).dom()
        else:
            if config_file:
                self._config_file = config_file
            else:
                self._config_file = corosync.conf()
            with open(self._config_file, 'r', encoding='utf-8') as f:
                self._dom = corosync_config_format.DomParser(f).dom()
        self._dom_query = corosync_config_format.DomQuery(self._dom)

    def save(self, config_file=None, file_mode=0o644):
        """save the config to config file"""
        if not config_file:
            config_file = self._config_file
        with utils.open_atomic(config_file, 'w', fsync=True, encoding='utf-8') as f:
            corosync_config_format.DomSerializer(self._dom, f)
            os.fchmod(f.fileno(), file_mode)

    def get(self, path, index=0):
        """
        Gets the value for the path

        path: config path
        index: known index in section
        """
        try:
            return self._dom_query.get(path, index)
        except (KeyError, IndexError):
            return None

    def get_all(self, path):
        """
        Returns all values matching path
        """
        return self._dom_query.get_all(path)

    def remove(self, path, index=0):
        try:
            self._dom_query.remove(path, index)
        except (KeyError, IndexError):
            raise ValueError("Cannot find value on path \"{}:{}\"".format(path, index)) from None

    def _raw_set(self, path, value, index):
        path = path.split('.')
        node = self._dom
        path_stack = tuple()
        for key in path[:-1]:
            path_stack = (*path_stack, key)
            if key not in node:
                new_node = dict()
                node[key] = new_node
                node = new_node
            else:
                match node[key]:
                    case dict(_) as next_node:
                        if index > 0 and path_stack in self._sec_names_with_list:
                            if index == 1:
                                new_node = dict()
                                node[key] = [next_node, new_node]
                                node = new_node
                            else:
                                raise IndexError(f'index out of range: {index}')
                        else:
                            node = next_node
                    case list(_) as li:
                        if index > len(li):
                            raise IndexError(f'index out of range: {index}')
                        elif index == len(li):
                            new_node = dict()
                            li.append(new_node)
                            node = new_node
                        else:
                            node = li[index]
        key = path[-1]
        if key not in node:
            node[key] = value
        else:
            match node[key]:
                case list(_) as li:
                    if index > len(li):
                        raise IndexError(f'index out of range: {index}')
                    elif index == len(li):
                        li.append(value)
                    else:
                        li[index] = value
                case _:
                    node[key] = value

    def set(self, path, value, index=0):
        try:
            self._raw_set(path, value, index)
        except KeyError:
            raise ValueError("Invalid path \"{}\"".format(path)) from None
        except IndexError:
            raise ValueError(f'Index {index} out of range at path "{path}"') from None

    @classmethod
    def get_value(cls, path: str, index: int = 0):
        """
        Class method to get value
        Return None if not found
        """
        inst = cls()
        return inst.get(path, index)

    @classmethod
    def get_values(cls, path: str):
        """
        Class method to get value list matched by path
        Return [] if not matched
        """
        inst = cls()
        return inst.get_all(path)

    @classmethod
    def set_value(cls, path, value, index=0):
        """
        Class method to set value for path
        Then write back to config file
        """
        inst = cls()
        inst.set(path, value, index)
        inst.save()

    @classmethod
    def remove_key(cls, path, index=0):
        """
        """
        inst = cls()
        inst.remove(path, index)
        inst.save()
