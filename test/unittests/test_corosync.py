# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
#
# unit tests for parse.py

import os
import unittest
from crmsh import corosync
from crmsh.corosync import Parser, make_section, make_value


F1 = open(os.path.join(os.path.dirname(__file__), 'corosync.conf.1')).read()
F2 = open(os.path.join(os.path.dirname(__file__), 'corosync.conf.2')).read()
F3 = open(os.path.join(os.path.dirname(__file__), 'bug-862577_corosync.conf')).read()


def _valid(parser):
    depth = 0
    for t in parser._tokens:
        if t.token not in (corosync._tCOMMENT,
                           corosync._tBEGIN,
                           corosync._tEND,
                           corosync._tVALUE):
            raise AssertionError("illegal token " + str(t))
        if t.token == corosync._tBEGIN:
            depth += 1
        if t.token == corosync._tEND:
            depth -= 1
    if depth != 0:
        raise AssertionError("Unbalanced sections")


def _print(parser):
    print parser.to_string()


class TestCorosyncParser(unittest.TestCase):
    def test_parse(self):
        p = Parser(F1)
        _valid(p)
        self.assertEqual(p.get('logging.logfile'), '/var/log/cluster/corosync.log')
        self.assertEqual(p.get('totem.interface.ttl'), '1')
        p.set('totem.interface.ttl', '2')
        _valid(p)
        self.assertEqual(p.get('totem.interface.ttl'), '2')
        p.remove('quorum')
        _valid(p)
        self.assertEqual(p.count('quorum'), 0)
        p.add('', make_section('quorum', []))
        _valid(p)
        self.assertEqual(p.count('quorum'), 1)
        p.set('quorum.votequorum', '2')
        _valid(p)
        self.assertEqual(p.get('quorum.votequorum'), '2')
        p.set('bananas', '5')
        _valid(p)
        self.assertEqual(p.get('bananas'), '5')

    def test_logfile(self):
        self.assertEqual(corosync.logfile(F1), '/var/log/cluster/corosync.log')
        self.assertEqual(corosync.logfile('# nothing\n'), None)

    def test_udpu(self):
        p = Parser(F2)
        _valid(p)
        self.assertEqual(p.count('nodelist.node'), 5)
        p.add('nodelist',
              make_section('nodelist.node',
                           make_value('nodelist.node.ring0_addr', '10.10.10.10') +
                           make_value('nodelist.node.nodeid', str(corosync.next_nodeid(p)))))
        _valid(p)
        self.assertEqual(p.count('nodelist.node'), 6)
        self.assertEqual(p.get_all('nodelist.node.nodeid'),
                         ['1', '2', '3'])

    def test_add_node_no_nodelist(self):
        "test checks that if there is no nodelist, no node is added"
        from crmsh.corosync import make_section, make_value, next_nodeid

        p = Parser(F1)
        _valid(p)
        nid = next_nodeid(p)
        self.assertEqual(p.count('nodelist.node'), nid - 1)
        p.add('nodelist',
              make_section('nodelist.node',
                           make_value('nodelist.node.ring0_addr', 'foo') +
                           make_value('nodelist.node.nodeid', str(nid))))
        _valid(p)
        self.assertEqual(p.count('nodelist.node'), nid - 1)

    def test_add_node_nodelist(self):
        from crmsh.corosync import make_section, make_value, next_nodeid

        p = Parser(F2)
        _valid(p)
        nid = next_nodeid(p)
        c = p.count('nodelist.node')
        p.add('nodelist',
              make_section('nodelist.node',
                           make_value('nodelist.node.ring0_addr', 'foo') +
                           make_value('nodelist.node.nodeid', str(nid))))
        _valid(p)
        self.assertEqual(p.count('nodelist.node'), c + 1)
        self.assertEqual(next_nodeid(p), nid + 1)

    def test_remove_node(self):
        p = Parser(F2)
        _valid(p)
        self.assertEqual(p.count('nodelist.node'), 5)
        p.remove_section_where('nodelist.node', 'nodeid', '2')
        _valid(p)
        self.assertEqual(p.count('nodelist.node'), 4)
        self.assertEqual(p.get_all('nodelist.node.nodeid'),
                         ['1'])

    def test_bnc862577(self):
        p = Parser(F3)
        _valid(p)
        self.assertEqual(p.count('service.ver'), 1)

if __name__ == '__main__':
    unittest.main()
