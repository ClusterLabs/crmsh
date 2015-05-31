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


from os import path
from nose.tools import eq_
from crmsh import scripts

scripts._script_dirs = lambda: [path.join(path.dirname(__file__), 'scripts')]


def test_list():
    eq_(set(['v2', 'legacy', '10-webserver']),
        set(s for s in scripts.list_scripts()))


def test_load_legacy():
    script = scripts.load_script('legacy')
    assert script is not None
    eq_('legacy', script['name'])
    assert len(script['shortdesc']) > 0


def test_load_v2():
    script = scripts.load_script('v2')
    assert script is not None
    eq_('v2', script['name'])
    assert len(script['shortdesc']) > 0


def test_load_workflow():
    script = scripts.load_script('10-webserver')
    assert script is not None
    eq_('10-webserver', script['name'])
    assert len(script['shortdesc']) > 0
