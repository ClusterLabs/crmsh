# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#
# unit tests for cliformat.py

import utils
import parse
import cibconfig
from test_parse import MockValidation

factory = cibconfig.cib_factory


def mk_cli_list(cli):
    'Sometimes we get a string and sometimes a list.'
    if isinstance(cli, basestring):
        cp = parse.CliParser()
        mv = MockValidation()
        for p in cp.parsers.values():
            p.validation = mv
        # what follows looks strange, but the last string actually matters
        # the previous ones may be comments and are collected by the parser
        for s in utils.lines2cli(cli):
            cli_list = cp.parse2(s)
        return cli_list
    else:
        return cli


def roundtrip(type, name, cli):
    obj = factory.new_object(type, name)
    assert obj is not None
    cli_list = mk_cli_list(cli)
    node = obj.cli2node(cli_list)
    assert node is not None
    obj.node = node
    obj.set_id()
    s = obj.repr_cli(format=-1)
    if s != cli:
        print "GOT:", s
        print "EXP:", cli
    assert s == cli


def test_rscset():
    roundtrip('colocation', 'foo', 'colocation foo inf: a b')
    roundtrip('order', 'order_2', 'order order_2 Mandatory: [ A B ] C')
    roundtrip('rsc_template', 'public_vm', 'rsc_template public_vm ocf:heartbeat:Xen')


def test_bnc863736():
    roundtrip('order', 'order_3', 'order order_3 Mandatory: [ A B ] C symmetrical=true')


def test_sequential():
    roundtrip('colocation', 'rsc_colocation-master',
              'colocation rsc_colocation-master inf: [ vip-master vip-rep sequential="true" ] [ msPostgresql:Master sequential="true" ]')
