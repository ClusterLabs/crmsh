import unittest
from unittest import mock

from crmsh import conf_parser


class TestConfigParserSet(unittest.TestCase):
    def setUp(self) -> None:
        self.inst = conf_parser.ConfParser(config_data='')

    def test_set_scalar_should_ignore_index(self):
        self.inst._raw_set('scalar.scalar', 'foo', 0)
        self.assertDictEqual({'scalar': {'scalar': 'foo'}}, self.inst._dom)
        self.inst._raw_set('scalar.scalar', 'bar', 1)
        self.assertDictEqual({'scalar': {'scalar': 'bar'}}, self.inst._dom)

    def test_set_vector(self):
        self.inst._dom = {'vector': []}
        self.inst._raw_set('vector.scalar', 'foo', 0)
        self.assertDictEqual({'vector': [{'scalar': 'foo'}]}, self.inst._dom)
        self.inst._raw_set('vector.scalar', 'bar', 1)
        self.assertDictEqual({'vector': [{'scalar': 'foo'}, {'scalar': 'bar'}]}, self.inst._dom)
        with self.assertRaises(IndexError):
            self.inst._raw_set('vector.scalar', 'bar', 3)

    def test_set_predefined_vector(self):
        self.inst._raw_set('totem.interface.foo', 0, 0)
        self.assertDictEqual({'totem': {'interface': {'foo': 0}}}, self.inst._dom)
        self.inst._raw_set('totem.interface.foo', 0, 1)
        self.assertDictEqual({'totem': {'interface': [{'foo': 0}, {'foo': 0}]}}, self.inst._dom)
        with self.assertRaises(IndexError):
            self.inst._raw_set('totem.interface.foo', 0, 3)
