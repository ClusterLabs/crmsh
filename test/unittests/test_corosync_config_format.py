from unittest import TestCase
from io import StringIO

from crmsh.corosync_config_format import Parser, DomParser, DomQuery, DomSerializer
from crmsh.corosync_config_format import MalformedLineException, UnbalancedBraceException


class TestParserWithMalformedInput(TestCase):
    def test_malformed_line(self):
        with self.assertRaises(MalformedLineException):
            Parser(StringIO('''
foo {
    bar
}
                '''))
        with self.assertRaises(MalformedLineException):
            Parser(StringIO('''
foo { bar
    a: b
}
                '''))
        with self.assertRaises(MalformedLineException):
            Parser(StringIO('''
foo {
    : b
}
                '''))
        with self.assertRaises(MalformedLineException):
            Parser(StringIO('''
foo {
    a : b
} c
                '''))

    def test_unbalanced_brace(self):
        with self.assertRaises(UnbalancedBraceException):
            Parser(StringIO('''
foo {
    a: b
}
}
                '''))
        with self.assertRaises(UnbalancedBraceException):
            Parser(StringIO('''
foo {
    bar {
        a: b
    }
                '''))


class TestDomParserWithUnusedFeature(TestCase):
    def test_list_of_scalar(self):
        dom = DomParser(StringIO('''
# list of scalar is not used in corosync.conf
foo: a
foo: b
foo: c
        ''')).dom()
        self.assertDictEqual({'foo': ['a', 'b', 'c']}, dom)


class TestDomQueryGet(TestCase):
    def setUp(self) -> None:
        self.dom = {'scalar': {'scalar': 'value'}, 'vector': [{'scalar': 'value1'}, {'scalar': 'value2'}]}

    def test_get_scalar(self):
        self.assertEqual('value', DomQuery(self.dom).get('scalar.scalar'))
        self.assertDictEqual({'scalar': 'value'}, DomQuery(self.dom).get('scalar'))

    def test_get_scalar_with_index(self):
        self.assertEqual('value', DomQuery(self.dom).get('scalar.scalar', 0))
        self.assertDictEqual({'scalar': 'value'}, DomQuery(self.dom).get('scalar', 0))
        self.assertEqual('value', DomQuery(self.dom).get('scalar.scalar', 1))
        self.assertDictEqual({'scalar': 'value'}, DomQuery(self.dom).get('scalar', 1))
        self.assertEqual('value', DomQuery(self.dom).get('scalar.scalar', 42))
        self.assertDictEqual({'scalar': 'value'}, DomQuery(self.dom).get('scalar', 42))

    def test_get_vector(self):
        self.assertEqual('value1', DomQuery(self.dom).get('vector.scalar'))
        self.assertDictEqual({'scalar': 'value1'}, DomQuery(self.dom).get('vector'))

    def test_get_vector_with_index(self):
        self.assertEqual('value2', DomQuery(self.dom).get('vector.scalar', 1))
        self.assertDictEqual({'scalar': 'value1'}, DomQuery(self.dom).get('vector', 0))
        self.assertDictEqual({'scalar': 'value2'}, DomQuery(self.dom).get('vector', 1))
        with self.assertRaises(IndexError):
            DomQuery(self.dom).get('vector.scalar', 2)
        with self.assertRaises(IndexError):
            DomQuery(self.dom).get('vector', 2)

    def test_get_non_existing_key(self):
        with self.assertRaises(KeyError):
            DomQuery(self.dom).get('foo')
        with self.assertRaises(KeyError):
            DomQuery(self.dom).get('foo', 1)
        with self.assertRaises(KeyError):
            DomQuery(self.dom).get('scalar.foo')
        with self.assertRaises(KeyError):
            DomQuery(self.dom).get('scalar.foo', 1)
        with self.assertRaises(KeyError):
            DomQuery(self.dom).get('scalar.scalar.foo')
        with self.assertRaises(KeyError):
            DomQuery(self.dom).get('scalar.scalar.foo', 1)
        with self.assertRaises(KeyError):
            DomQuery(self.dom).get('vector.foo')
        with self.assertRaises(KeyError):
            DomQuery(self.dom).get('vector.foo', 1)
        with self.assertRaises(KeyError):
            DomQuery(self.dom).get('vector.scalar.foo')
        with self.assertRaises(KeyError):
            DomQuery(self.dom).get('vector.scalar.foo', 1)


class TestDomQueryGetAll(TestCase):
    def setUp(self) -> None:
        self.dom = {'scalar': {'scalar': 'value'}, 'vector': [{'scalar': 'value1'}, {'scalar': 'value2'}]}

    def test_get_scalar(self):
        self.assertListEqual(['value'], DomQuery(self.dom).get_all('scalar.scalar'))
        self.assertListEqual([{'scalar': 'value'}], DomQuery(self.dom).get_all('scalar'))

    def test_get_vector(self):
        self.assertListEqual(['value1', 'value2'], DomQuery(self.dom).get_all('vector.scalar'))
        self.assertListEqual([{'scalar': 'value1'}, {'scalar': 'value2'}], DomQuery(self.dom).get_all('vector'))

    def test_get_non_existing_key(self):
        with self.assertRaises(KeyError):
            DomQuery(self.dom).get_all('foo')
        with self.assertRaises(KeyError):
            DomQuery(self.dom).get_all('scalar.foo')
        with self.assertRaises(KeyError):
            DomQuery(self.dom).get_all('scalar.scalar.foo')
        with self.assertRaises(KeyError):
            DomQuery(self.dom).get_all('vector.foo')
        with self.assertRaises(KeyError):
            DomQuery(self.dom).get_all('vector.scalar.foo')


class TestDomQueryRemove(TestCase):
    def setUp(self) -> None:
        self.dom = {'scalar': {'scalar': 'value'}, 'vector': [{'scalar': 'value1'}, {'scalar': 'value2'}]}

    def test_remove_scalar(self):
        DomQuery(self.dom).remove('scalar.scalar')
        self.assertDictEqual(dict(), self.dom['scalar'])

    def test_remove_dict(self):
        DomQuery(self.dom).remove('scalar')
        self.assertNotIn('scalar', self.dom)

    def test_remove_dict_from_vector(self):
        DomQuery(self.dom).remove('vector')
        self.assertListEqual([{'scalar': 'value2'}], self.dom['vector'])

    def test_remove_scalar_from_vector(self):
        DomQuery(self.dom).remove('vector.scalar', 1)
        self.assertListEqual([{'scalar': 'value1'}, dict()], self.dom['vector'])

    def test_remove_out_of_range_from_vector(self):
        with self.assertRaises(IndexError):
            DomQuery(self.dom).remove('vector.scalar', 2)

    def test_remove_nonexistence(self):
        with self.assertRaises(KeyError):
            DomQuery(self.dom).remove('nonexistence')
        with self.assertRaises(KeyError):
            DomQuery(self.dom).remove('scalar.scalar.nonexistence')


class TestDomSerializer(TestCase):
    def test_serialize(self):
        dom = {'scalar': {'scalar': 'value'}, 'vector': [{'scalar': 'value1'}, {'scalar': 'value2'}]}
        buf = StringIO()
        DomSerializer(dom, buf)
        self.assertEqual(
                '''scalar {
\tscalar: value
}
vector {
\tscalar: value1
}
vector {
\tscalar: value2
}
''',

                buf.getvalue()
        )

    def test_serialize_scalar(self):
        dom = 'foo'
        buf = StringIO()
        with self.assertRaises(TypeError):
            DomSerializer(dom, buf)

    def test_serialize_list(self):
        dom = [{'foo': 'a'}, {'foo': 'b'}]
        buf = StringIO()
        with self.assertRaises(TypeError):
            DomSerializer(dom, buf)

    def test_serialize_list_of_list(self):
        dom = {'foo': [['a'], ['b']]}
        buf = StringIO()
        with self.assertRaises(ValueError):
            DomSerializer(dom, buf)


class TestDomSerializerUnusedFeature(TestCase):
    def test_serialize_list_of_scalar(self):
        dom = {'foo': ['a', 'b']}
        buf = StringIO()
        DomSerializer(dom, buf)
        self.assertEqual('foo: a\nfoo: b\n', buf.getvalue())


class TestParseSerialize(TestCase):
    def test_parse_serialize(self):
        data = '''totem {
\tversion: 2
\tcluster_name: capybara
\ttransport: knet
\tknet_compression_model: bzip2
\tknet_compression_threshold: 10
\tknet_compression_level: 1
\tcrypto_model: nss
\tcrypto_hash: sha1
\tcrypto_cipher: aes256
\tinterface {
\t\tlinknumber: 0
\t\tknet_transport: udp
\t\tknet_link_priority: 0
\t}
\tinterface {
\t\tlinknumber: 1
\t\tknet_transport: sctp
\t}
\tinterface {
\t\tlinknumber: 2
\t\tknet_transport: udp
\t\tknet_link_priority: 10
\t}
}
nodelist {
\tnode {
\t\tring0_addr: 192.168.1.101
\t\tring1_addr: 192.168.10.1
\t\tring2_addr: 192.168.9.1
\t\tnodeid: 1
\t\tname: mynode1
\t}
\tnode {
\t\tring0_addr: 192.168.1.102
\t\tring1_addr: 192.168.10.2
\t\tring2_addr: 192.168.9.2
\t\tnodeid: 2
\t\tname: mynode2
\t}
\tnode {
\t\tring0_addr: 192.168.1.103
\t\tring1_addr: 192.168.10.3
\t\tring2_addr: 192.168.9.3
\t\tnodeid: 3
\t\tname: mynode3
\t}
\tnode {
\t\tring0_addr: 192.168.1.104
\t\tring1_addr: 192.168.10.4
\t\tring2_addr: 192.168.9.4
\t\tnodeid: 4
\t\tname: mynode4
\t}
}
quorum {
\tprovider: corosync_votequorum
}
logging {
\tto_logfile: yes
\tlogfile: /var/log/cluster/corosync.log
\tto_syslog: yes
\tlogger_subsys {
\t\tsubsys: KNET
\t\tdebug: on
\t}
}
'''
        buf = StringIO(data)
        dom = DomParser(buf).dom()
        buf = StringIO()
        DomSerializer(dom, buf)
        self.assertEqual(data, buf.getvalue())
