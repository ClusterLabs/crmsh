"""
Module to parse corosync.conf

Maintainer: XLiang@suse.com
"""

import os
import re
from . import corosync
from . import utils


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


class Dotable(dict):
    """
    To make nested python dictionaries (json-like objects)
    accessable using dot notation
    http://andyhayden.com/2013/dotable-dictionaries
    """
    __delattr__ = dict.__delitem__

    def __init__(self, d):
        self._refresh(d)

    def _refresh(self, d=None):
        target = d or self
        self.update(**dict((k, self.parse(v)) for k, v in target.items()))

    def __setattr__(self, k, value):
        self.__setitem__(k, value)
        self._refresh()

    def __getattr__(self, k):
        self._refresh()
        return self.get(k, None)

    @classmethod
    def parse(cls, v):
        if isinstance(v, dict):
            return cls(v)
        elif isinstance(v, list):
            return [cls.parse(i) for i in v]
        else:
            return v


class ConfParser(object):
    """
    Class to parse config file which format like corosync.conf
    """
    VIRTUAL_LIST_NAME = "__list"
    COROSYNC_KNOWN_SEC_NAMES_WITH_LIST = ("totem.interface", "nodelist.node")

    def __init__(self, config_file=None, config_data=None, sec_names_with_list=()):
        """
        Initialize function
        """
        self._config_file = None
        self._config_data = None
        if config_data:
            self._config_data = config_data
        else:
            self._config_file = config_file or corosync.conf()
        self._sec_names_with_list = sec_names_with_list or self.COROSYNC_KNOWN_SEC_NAMES_WITH_LIST
        self._config_inst = None

    def _verify_config_file(self):
        """
        Verify config file
        """
        if not os.path.exists(self._config_file):
            raise ValueError("File \"{}\" not exist".format(self._config_file))
        if not os.path.isfile(self._config_file):
            raise ValueError("\"{}\" is not a file".format(self._config_file))
        with open(self._config_file) as f:
            data = f.read()
            if len(re.findall("[{}]", data)) % 2 != 0:
                raise ValueError("{}: Missing closing brace".format(self._config_file))

    def _convert2dict_raw(self, file_content_lines, initial_path=""):
        """
        Convert the corosync configuration file to a dictionary
        """
        corodict = {}
        sub_dict = {}
        index = 0

        for i, line in enumerate(file_content_lines):
            stripped_line = line.strip()
            if not stripped_line or stripped_line[0] == '#':
                continue

            if index > i:
                continue

            if '{' in stripped_line:
                sec_name = re.sub("\s*{", "", stripped_line)
                initial_path += ".{}".format(sec_name) if initial_path else sec_name
                sub_dict, new_index = self._convert2dict_raw(file_content_lines[i+1:], initial_path)
                if initial_path in self._sec_names_with_list:
                    if self.VIRTUAL_LIST_NAME not in corodict:
                        corodict[self.VIRTUAL_LIST_NAME] = []
                    corodict[self.VIRTUAL_LIST_NAME].append({sec_name: sub_dict})
                else:
                    corodict[sec_name] = sub_dict
                index = i + new_index
                initial_path = re.sub("\.{}".format(sec_name), "", initial_path) if "." in initial_path else ""
            elif ':' in stripped_line:
                # To parse the line with multi ":", like IPv6 address
                data = stripped_line.split(':')
                key, values = data[0], data[1:]
                corodict[key] = ':'.join(values).strip()
            elif '}' in stripped_line:
                return corodict, i+2

        return corodict, index

    def convert2dict(self):
        """
        Wrapped _convert2dict_raw function
        """
        if self._config_data:
            _dict, _ = self._convert2dict_raw(self._config_data.splitlines())
        else:
            self._verify_config_file()
            with open(self._config_file) as f:
                _dict, _ = self._convert2dict_raw(f.read().splitlines())
        self._config_inst = Dotable.parse(_dict)

    def _unpack_list_in_dict(self, value_list, indentation):
        """
        Convert dict list to string
        """
        output = ''
        for item_dict in value_list:
            output += self._convert2string_raw(item_dict, indentation)
        return output

    def _unpack_dict(self, key, value, indentation):
        """
        Convert dict to string
        """
        output = ''
        if isinstance(value, dict):
            output += '{}{} {{\n'.format(indentation, key)
            indentation += '\t'
            output += self._convert2string_raw(value, indentation)
            indentation = indentation[:-1]
            output += '{}}}\n\n'.format(indentation)
        elif isinstance(value, list):
            output += self._unpack_list_in_dict(value, indentation)
        else:
            output += '{}{}: {}\n'.format(indentation, key, value)
        return output

    def _convert2string_raw(self, corodict, indentation=''):
        """
        Convert a corosync like data dictionary to string
        """
        output = ''
        for key, value in corodict.items():
            output += self._unpack_dict(key, value, indentation)
        return output

    def convert2string(self):
        """
        Wrapped _convert2string_raw function
        """
        return self._convert2string_raw(self._config_inst)

    def _len_of_list(self, path):
        """
        """
        sec_name, *_ = path.split('.')
        while True:
            try:
                return len(eval("self._config_inst.{}.{}".format(sec_name, self.VIRTUAL_LIST_NAME)))
            except AttributeError:
                exec("self._config_inst.{} = {{\"{}\": []}}".format(sec_name, self.VIRTUAL_LIST_NAME))

    def _extend_list(self, path):
        """
        """
        name, sub_name, *_ = path.split('.')
        sub_name_dict = {"{}".format(sub_name): {}}
        exec("self._config_inst.{}.{}.append({})".format(name, self.VIRTUAL_LIST_NAME, sub_name_dict))

    def _is_list_path(self, path):
        """
        """
        for x in self._sec_names_with_list:
            if path.startswith(x):
                return True
        return False

    def _real_path(self, path, index=0, on_set=False):
        """
        """
        if self._is_list_path(path):
            _len = self._len_of_list(path)
            if on_set and _len <= index:
                self._extend_list(path)
                index = _len
            return re.sub("^(\w+)\.", "\\1.{}[{}].".format(self.VIRTUAL_LIST_NAME, index), path)
        return path

    def get(self, path, index=0):
        """
        Gets the value for the path

        path: config path
        index: known index in section
        """
        path = self._real_path(path, index)
        try:
            return eval("self._config_inst.{}".format(path))
        except (AttributeError, IndexError):
            return None

    def get_all(self, path):
        """
        Returns all values matching path
        """
        if not self._is_list_path(path):
            value = self.get(path)
            return [value] if value else []
        return [self.get(path, index=i) for i in range(self._len_of_list(path))]

    def remove(self, path, index=0):
        """
        """
        value = self.get(path, index)
        if not value:
            raise ValueError("Cannot find value on path \"{}:{}\"".format(path, index))
        real_path = self._real_path(path, index)
        exec("del self._config_inst.{}".format(real_path))

    def set(self, path, value, index=0):
        """
        """
        real_path = self._real_path(path, index, on_set=True)
        try:
            if isinstance(value, dict):
                exec("self._config_inst.{} = {}".format(real_path, value))
            else:
                exec("self._config_inst.{} = \"{}\"".format(real_path, value))
        except AttributeError:
            raise ValueError("Invalid path \"{}\"".format(path)) from None

    @classmethod
    def verify_config_file(cls, config_file=None):
        """
        Class method to verify config file
        """
        inst = ConfParser(config_file)
        inst._verify_config_file()

    @classmethod
    def get_value(cls, path: str, index: int = 0):
        """
        Class method to get value
        Return None if not found
        """
        inst = cls()
        inst.convert2dict()
        return inst.get(path, index)

    @classmethod
    def get_values(cls, path: str):
        """
        Class method to get value list matched by path
        Return [] if not matched
        """
        inst = cls()
        inst.convert2dict()
        return inst.get_all(path)

    @classmethod
    def set_value(cls, path, value, index=0):
        """
        Class method to set value for path
        Then write back to config file
        """
        inst = cls()
        inst.convert2dict()
        inst.set(path, value, index)
        utils.str2file(inst.convert2string(), inst._config_file)

    @classmethod
    def remove_key(cls, path, index=0):
        """
        """
        inst = cls()
        inst.convert2dict()
        inst.remove(path, index)
        utils.str2file(inst.convert2string(), inst._config_file)
