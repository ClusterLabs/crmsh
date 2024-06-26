import unittest

from crmsh.ui_corosync import LinkArgumentParser


class TestLinkArgumentParser(unittest.TestCase):
    def test_parse_empty(self):
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, list())

    def test_invalid_link_number(self):
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, ['a0'])

    def test_no_spec(self):
        args = LinkArgumentParser().parse(True, ['0'])
        self.assertEqual(0, args.linknumber)
        self.assertFalse(args.nodes)
        self.assertFalse(args.options)

    def test_addr_spec(self):
        args = LinkArgumentParser().parse(True, ['0', 'node1=192.0.2.100', 'node2=fd00:a0::10'])
        self.assertEqual(0, args.linknumber)
        self.assertFalse(args.options)
        self.assertListEqual([('node1', '192.0.2.100'), ('node2', 'fd00:a0::10')], args.nodes)

    def test_invalid_addr_spec(self):
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, ['0', 'node1=192.0.2.300'])
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, ['0', 'node1=fd00::a0::10'])
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, ['0', 'node1=node1.example.com'])
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, ['0', 'node1=192.0.2'])

    def test_option_spec(self):
        args = LinkArgumentParser().parse(True, ['0', 'options', 'node1=192.0.2.100', 'node2=fd00:a0::10', 'foo='])
        self.assertEqual(0, args.linknumber)
        self.assertFalse(args.nodes)
        self.assertDictEqual({'node1': '192.0.2.100', 'node2': 'fd00:a0::10', 'foo': None}, args.options)

    def test_addrs_and_options(self):
        args = LinkArgumentParser().parse(True, ['0', 'node1=192.0.2.100', 'node2=fd00:a0::10', 'options', 'foo=bar=1'])
        self.assertEqual(0, args.linknumber)
        self.assertListEqual([('node1', '192.0.2.100'), ('node2', 'fd00:a0::10')], args.nodes)
        self.assertDictEqual({'foo': 'bar=1'}, args.options)

    def test_no_options(self):
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, ['0', 'options'])

    def test_garbage_inputs(self):
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, ['0', 'foo'])
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, ['0', 'node1=192.0.2.100', 'foo'])
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, ['0', 'node1=192.0.2.100', 'options', 'foo'])
        with self.assertRaises(LinkArgumentParser.SyntaxException):
            LinkArgumentParser().parse(True, ['0', 'node1=192.0.2.100', 'options', 'foo=bar', 'foo'])
