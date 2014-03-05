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


import utils
import parse
import cibconfig
from test_parse import MockValidation
from test_cliformat import roundtrip

factory = cibconfig.cib_factory

def setup_func():
    "set up test fixtures"
    import idmgmt
    idmgmt.IdMgmt.getInstance().clear()


def xtest_bug41660():
    xml = """
<clone id="libvirtd-clone">
 <primitive class="lsb" id="libvirtd" type="libvirtd">
  <operations>
   <op id="libvirtd-monitor-interval-15" interval="15" name="monitor" start-delay="15" timeout="15"/>
   <op id="libvirtd-start-interval-0" interval="0" name="start" on-fail="restart" timeout="15"/>
   <op id="libvirtd-stop-interval-0" interval="0" name="stop" on-fail="ignore" timeout="15"/>
  </operations>
  <meta_attributes id="libvirtd-meta_attributes"/>
 </primitive>
 <meta_attributes id="libvirtd-clone-meta">
  <nvpair id="libvirtd-interleave" name="interleave" value="true"/>
  <nvpair id="libvirtd-ordered" name="ordered" value="true"/>
  <nvpair id="libvirtd-clone-meta-target-role" name="target-role" value="Stopped"/>
 </meta_attributes>
 <meta_attributes id="libvirtd-clone-meta_attributes">
  <nvpair id="libvirtd-clone-meta_attributes-target-role" name="target-role" value="Stopped"/>
 </meta_attributes>
</clone>
"""
    from lxml import etree
    data = etree.fromstring(xml)
    obj = factory.new_object('clone', 'libvirtd-clone')
    assert obj is not None
    obj.node = data
    obj.set_id()
    data = obj.repr_cli(format=-1)
    print data
    exp = 'clone libvirtd-clone libvirtd meta interleave="true" ordered="true" target-role="Stopped" meta target-role="Stopped"'
    assert data == exp
    assert obj.cli_use_validate()

