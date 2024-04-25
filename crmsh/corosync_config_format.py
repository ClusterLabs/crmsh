"""parser and serializer for corosync.conf alike format"""


import logging
import re
from io import StringIO
import typing


logger = logging.getLogger(__name__)


class Parser:
    """SAX-style parser for the configuration of corosync"""

    _SPLIT_RE = re.compile('\\s*({|:|})\\s*')

    def __init__(self, ifile):
        """Parse data form a file-like object."""
        self.__section_stack = list()
        self._parse(ifile)

    def enter_section(self, name: str):
        logger.info('entering: %s', name)

    def exit_section(self, name: str):
        logger.info('exiting: %s', name)

    def on_key_value(self, key: str, value: str):
        logger.info('%s: %s', key, value)

    def _parse(self, ifile):
        for lineno, line in enumerate(ifile):
            line = line.strip()
            if not line:
                continue
            if line[0] == '#':
                continue
            try:
                tokens = self._tokenize(line)
            except ValueError as e:
                raise MalformedLineException(lineno, line)
            logger.debug('tokens: %s', tokens)
            if tokens[1] == '{':
                if not tokens[0] or tokens[2]:
                    raise MalformedLineException(lineno, line)
                self.__section_stack.append(tokens[0])
                self.enter_section(tokens[0])
            elif tokens[1] == ':':
                if not tokens[0]:
                    raise MalformedLineException(lineno, line)
                self.on_key_value(tokens[0], tokens[2])
            else:   # if tokens[1] == '}'
                if tokens[0] or tokens[2]:
                    raise MalformedLineException(lineno, line)
                if self.__section_stack:
                    self.exit_section(self.__section_stack[-1])
                    del self.__section_stack[-1]
                else:
                    raise UnbalancedBraceException(lineno + 1)
        if self.__section_stack:
            raise UnbalancedBraceException(0)

    @classmethod
    def _tokenize(cls, line):
        split_match = cls._SPLIT_RE.search(line)
        if split_match is None:
            raise ValueError()
        else:
            return (line[:split_match.start()], split_match.group(1), line[split_match.end():])


class ParserException(Exception):
    pass


class MalformedLineException(ParserException):
    def __init__(self, lineno, text):
        super().__init__(f'Malformed line {lineno}: {text}')
        self.lineno = lineno
        self.text = text


class UnbalancedBraceException(ParserException):
    def __init__(self, lineno):
        super().__init__(f'Unbalanced brace at line {lineno}')
        self.lineno = lineno


class DomParser(Parser):
    """parse a config stream into DOM tree"""
    def __init__(self, ifile):
        self._root = dict()
        self.__node_stack = [self._root]
        super().__init__(ifile)

    def dom(self):
        return self._root

    def __current_node(self):
        return self.__node_stack[-1]

    def enter_section(self, name: str):
        if name not in self.__current_node():
            new_node = dict()
            self.__current_node()[name] = new_node
            self.__node_stack.append(new_node)
            return
        node = self.__current_node()[name]
        new_node = dict()
        match node:
            case list(_):
                node.append(new_node)
            case _:
                self.__current_node()[name] = [node, new_node]
        self.__node_stack.append(new_node)

    def on_key_value(self, key: str, value: str):
        if key not in self.__current_node():
            self.__current_node()[key] = value
            return
        node = self.__current_node()[key]
        match node:
            case list(_):
                node.append(value)
            case _:
                self.__current_node()[key] = [node, value]

    def exit_section(self, name: str):
        del self.__node_stack[-1]


class DomQuery:
    """run queries on an DOM tree"""

    def __init__(self, dom):
        self._dom = dom

    def get(self, path: str | typing.List[str], index=0):
        """
        Gets the value for the path

        path: config path
        index: known index in section
        """
        if isinstance(path, str):
            return self.get(path.split('.'), index)
        node = self._dom
        for key in path:
            match node:
                case dict(_):
                    node = node[key]
                case _:
                    raise KeyError(path)
            while isinstance(node, list):
                node = node[index]
        return node

    def get_all(self, path: str | typing.List[str]):
        """
        Returns all values matching path
        """
        if isinstance(path, str):
            return self.get_all(path.split('.'))
        node = self._dom
        for i, key in enumerate(path):
            match node:
                case dict(_):
                    node = node[key]
                case _:
                    raise KeyError(path)
            if isinstance(node, list):
                result = list()
                for item in node:
                    result.extend(DomQuery(item).get_all(path[i+1:]))
                return result
        return [node]

    def enumerate_all_paths(self):
        queue = [(self._dom, tuple())]
        result = set()
        while queue:
            node, path = queue.pop(0)
            match node:
                case dict(_):
                    for key, value in node.items():
                        queue.append((value, (*path, key)))
                case list(_) as li:
                    for item in li:
                        queue.append((item, path))
                case _:
                    result.add(path)
        return ['.'.join(item) for item in result]

    def remove(self, path, index=0):
        path = path.split('.')
        node = self.get(path[:-1], index)  # get parent node
        if not isinstance(node, dict):
            raise KeyError(path)
        key = path[-1]
        value = node[path[-1]]
        match value:
            case list(_):
                del value[index]
            case _:
                del node[key]


class DomSerializer:
    """serialize a DOM into bytes"""
    def __init__(self, node, ofile, indent='\t'):
        self._ofile = ofile
        self._indent = indent
        self._path_stack = list()
        match node:
            case dict(_):
                self.on_dict(node)
            case list(_):
                raise TypeError('invalid to serialize a list')
            case _:
                raise TypeError('invalid to serialize a scalar value')

    def on_dict(self, node):
        for key, value in node.items():
            match value:
                case dict(_):
                    self.__write_indent(len(self._path_stack))
                    self._ofile.write(key)
                    self._ofile.write(' {\n')
                    self._path_stack.append(key)
                    self.on_dict(value)
                    del self._path_stack[-1]
                    self.__write_indent(len(self._path_stack))
                    self._ofile.write('}\n')
                case list(_):
                    self._path_stack.append(key)
                    self.on_list(value)
                    del self._path_stack[-1]
                case _:
                    self.__write_indent(len(self._path_stack))
                    self._ofile.write(key)
                    self._ofile.write(': ')
                    self.on_value(value)
                    self._ofile.write('\n')

    def on_list(self, node):
        key = self._path_stack[-1]
        for item in node:
            match item:
                case dict(_):
                    self.__write_indent(len(self._path_stack) - 1)
                    self._ofile.write(key)
                    self._ofile.write(' {\n')
                    self.on_dict(item)
                    self.__write_indent(len(self._path_stack) - 1)
                    self._ofile.write('}\n')
                case list(_):
                    raise ValueError('list of list is invalid')
                case _:
                    self.__write_indent(len(self._path_stack) - 1)
                    self._ofile.write(key)
                    self._ofile.write(': ')
                    self.on_value(item)
                    self._ofile.write('\n')

    def on_value(self, value):
        self._ofile.write(str(value))

    def __write_indent(self, n):
        for _ in range(n):
            self._ofile.write(self._indent)
