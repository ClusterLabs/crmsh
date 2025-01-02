# Copyright (C) 2014 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.


from builtins import str
from builtins import object
from os import path
from pprint import pprint
import pytest
from lxml import etree
from crmsh import scripts
from crmsh import ra
from crmsh import utils

scripts._script_dirs = lambda: [path.join(path.dirname(__file__), 'scripts')]

_apache = '''<?xml version="1.0"?>
<!DOCTYPE resource-agent SYSTEM "ra-api-1.dtd">
<resource-agent name="apache">
<version>1.0</version>

<longdesc lang="en">
This is the resource agent for the Apache Web server.
This resource agent operates both version 1.x and version 2.x Apache
servers.

The start operation ends with a loop in which monitor is
repeatedly called to make sure that the server started and that
it is operational. Hence, if the monitor operation does not
succeed within the start operation timeout, the apache resource
will end with an error status.

The monitor operation by default loads the server status page
which depends on the mod_status module and the corresponding
configuration file (usually /etc/apache2/mod_status.conf).
Make sure that the server status page works and that the access
is allowed *only* from localhost (address 127.0.0.1).
See the statusurl and testregex attributes for more details.

See also http://httpd.apache.org/
</longdesc>
<shortdesc lang="en">Manages an Apache Web server instance</shortdesc>

<parameters>
<parameter name="configfile" required="0" unique="1">
<longdesc lang="en">
The full pathname of the Apache configuration file.
This file is parsed to provide defaults for various other
resource agent parameters.
</longdesc>
<shortdesc lang="en">configuration file path</shortdesc>
<content type="string" default="$(detect_default_config)" />
</parameter>

<parameter name="httpd">
<longdesc lang="en">
The full pathname of the httpd binary (optional).
</longdesc>
<shortdesc lang="en">httpd binary path</shortdesc>
<content type="string" default="/usr/sbin/httpd" />
</parameter>

<parameter name="port" >
<longdesc lang="en">
A port number that we can probe for status information
using the statusurl.
This will default to the port number found in the
configuration file, or 80, if none can be found
in the configuration file.

</longdesc>
<shortdesc lang="en">httpd port</shortdesc>
<content type="integer" />
</parameter>

<parameter name="statusurl">
<longdesc lang="en">
The URL to monitor (the apache server status page by default).
If left unspecified, it will be inferred from
the apache configuration file.

If you set this, make sure that it succeeds *only* from the
localhost (127.0.0.1). Otherwise, it may happen that the cluster
complains about the resource being active on multiple nodes.
</longdesc>
<shortdesc lang="en">url name</shortdesc>
<content type="string" />
</parameter>

<parameter name="testregex">
<longdesc lang="en">
Regular expression to match in the output of statusurl.
Case insensitive.
</longdesc>
<shortdesc lang="en">monitor regular expression</shortdesc>
<content type="string" default="exists, but impossible to show in a human readable format (try grep testregex)"/>
</parameter>

<parameter name="client">
<longdesc lang="en">
Client to use to query to Apache. If not specified, the RA will
try to find one on the system. Currently, wget and curl are
supported. For example, you can set this parameter to "curl" if
you prefer that to wget.
</longdesc>
<shortdesc lang="en">http client</shortdesc>
<content type="string" default=""/>
</parameter>

<parameter name="testurl">
<longdesc lang="en">
URL to test. If it does not start with "http", then it's
considered to be relative to the Listen address.
</longdesc>
<shortdesc lang="en">test url</shortdesc>
<content type="string" />
</parameter>

<parameter name="testregex10">
<longdesc lang="en">
Regular expression to match in the output of testurl.
Case insensitive.
</longdesc>
<shortdesc lang="en">extended monitor regular expression</shortdesc>
<content type="string" />
</parameter>

<parameter name="testconffile">
<longdesc lang="en">
A file which contains test configuration. Could be useful if
you have to check more than one web application or in case sensitive
info should be passed as arguments (passwords). Furthermore,
using a config file is the only way to specify certain
parameters.

Please see README.webapps for examples and file description.
</longdesc>
<shortdesc lang="en">test configuration file</shortdesc>
<content type="string" />
</parameter>

<parameter name="testname">
<longdesc lang="en">
Name of the test within the test configuration file.
</longdesc>
<shortdesc lang="en">test name</shortdesc>
<content type="string" />
</parameter>

<parameter name="options">
<longdesc lang="en">
Extra options to apply when starting apache. See man httpd(8).
</longdesc>
<shortdesc lang="en">command line options</shortdesc>
<content type="string" />
</parameter>

<parameter name="envfiles">
<longdesc lang="en">
Files (one or more) which contain extra environment variables.
If you want to prevent script from reading the default file, set
this parameter to empty string.
</longdesc>
<shortdesc lang="en">environment settings files</shortdesc>
<content type="string" default="/etc/apache2/envvars"/>
</parameter>

<parameter name="use_ipv6">
<longdesc lang="en">
We will try to detect if the URL (for monitor) is IPv6, but if
that doesn't work set this to true to enforce IPv6.
</longdesc>
<shortdesc lang="en">use ipv6 with http clients</shortdesc>
<content type="boolean" default="false"/>
</parameter>

</parameters>

<actions>
<action name="start"   timeout="40s" />
<action name="stop"    timeout="60s" />
<action name="status"  timeout="30s" />
<action name="monitor" depth="0"  timeout="20s" interval="10" />
<action name="meta-data"  timeout="5" />
<action name="validate-all"  timeout="5" />
</actions>
</resource-agent>
'''

_virtual_ip = '''<?xml version="1.0"?>
<!DOCTYPE resource-agent SYSTEM "ra-api-1.dtd">
<resource-agent name="IPaddr2">
<version>1.0</version>

<longdesc lang="en">
This Linux-specific resource manages IP alias IP addresses.
It can add an IP alias, or remove one.
In addition, it can implement Cluster Alias IP functionality
if invoked as a clone resource.

If used as a clone, you should explicitly set clone-node-max &gt;= 2,
and/or clone-max &lt; number of nodes. In case of node failure,
clone instances need to be re-allocated on surviving nodes.
This would not be possible if there is already an instance on those nodes,
and clone-node-max=1 (which is the default).
</longdesc>

<shortdesc lang="en">Manages virtual IPv4 and IPv6 addresses (Linux specific version)</shortdesc>

<parameters>
<parameter name="ip" unique="1" required="1">
<longdesc lang="en">
The IPv4 (dotted quad notation) or IPv6 address (colon hexadecimal notation)
example IPv4 "192.168.1.1".
example IPv6 "2001:db8:DC28:0:0:FC57:D4C8:1FFF".
</longdesc>
<shortdesc lang="en">IPv4 or IPv6 address</shortdesc>
<content type="string" default="" />
</parameter>
<parameter name="nic" unique="0">
<longdesc lang="en">
The base network interface on which the IP address will be brought
online. 
If left empty, the script will try and determine this from the
routing table.

Do NOT specify an alias interface in the form eth0:1 or anything here;
rather, specify the base interface only.
If you want a label, see the iflabel parameter.

Prerequisite:

There must be at least one static IP address, which is not managed by
the cluster, assigned to the network interface.
If you can not assign any static IP address on the interface,
modify this kernel parameter:

sysctl -w net.ipv4.conf.all.promote_secondaries=1 # (or per device)
</longdesc>
<shortdesc lang="en">Network interface</shortdesc>
<content type="string"/>
</parameter>

<parameter name="cidr_netmask">
<longdesc lang="en">
The netmask for the interface in CIDR format
(e.g., 24 and not 255.255.255.0)

If unspecified, the script will also try to determine this from the
routing table.
</longdesc>
<shortdesc lang="en">CIDR netmask</shortdesc>
<content type="string" default=""/>
</parameter>

<parameter name="broadcast">
<longdesc lang="en">
Broadcast address associated with the IP. If left empty, the script will
determine this from the netmask.
</longdesc>
<shortdesc lang="en">Broadcast address</shortdesc>
<content type="string" default=""/>
</parameter>

<parameter name="iflabel">
<longdesc lang="en">
You can specify an additional label for your IP address here.
This label is appended to your interface name.

The kernel allows alphanumeric labels up to a maximum length of 15
characters including the interface name and colon (e.g. eth0:foobar1234)

A label can be specified in nic parameter but it is deprecated.
If a label is specified in nic name, this parameter has no effect.
</longdesc>
<shortdesc lang="en">Interface label</shortdesc>
<content type="string" default=""/>
</parameter>

<parameter name="lvs_support">
<longdesc lang="en">
Enable support for LVS Direct Routing configurations. In case a IP
address is stopped, only move it to the loopback device to allow the
local node to continue to service requests, but no longer advertise it
on the network.

Notes for IPv6:
It is not necessary to enable this option on IPv6.
Instead, enable 'lvs_ipv6_addrlabel' option for LVS-DR usage on IPv6.
</longdesc>
<shortdesc lang="en">Enable support for LVS DR</shortdesc>
<content type="boolean" default="${OCF_RESKEY_lvs_support_default}"/>
</parameter>

<parameter name="lvs_ipv6_addrlabel">
<longdesc lang="en">
Enable adding IPv6 address label so IPv6 traffic originating from
the address's interface does not use this address as the source.
This is necessary for LVS-DR health checks to realservers to work. Without it,
the most recently added IPv6 address (probably the address added by IPaddr2)
will be used as the source address for IPv6 traffic from that interface and
since that address exists on loopback on the realservers, the realserver
response to pings/connections will never leave its loopback.
See RFC3484 for the detail of the source address selection.

See also 'lvs_ipv6_addrlabel_value' parameter.
</longdesc>
<shortdesc lang="en">Enable adding IPv6 address label.</shortdesc>
<content type="boolean" default="${OCF_RESKEY_lvs_ipv6_addrlabel_default}"/>
</parameter>

<parameter name="lvs_ipv6_addrlabel_value">
<longdesc lang="en">
Specify IPv6 address label value used when 'lvs_ipv6_addrlabel' is enabled.
The value should be an unused label in the policy table
which is shown by 'ip addrlabel list' command.
You would rarely need to change this parameter.
</longdesc>
<shortdesc lang="en">IPv6 address label value.</shortdesc>
<content type="integer" default="${OCF_RESKEY_lvs_ipv6_addrlabel_value_default}"/>
</parameter>

<parameter name="mac">
<longdesc lang="en">
Set the interface MAC address explicitly. Currently only used in case of
the Cluster IP Alias. Leave empty to chose automatically.

</longdesc>
<shortdesc lang="en">Cluster IP MAC address</shortdesc>
<content type="string" default=""/>
</parameter>

<parameter name="clusterip_hash">
<longdesc lang="en">
Specify the hashing algorithm used for the Cluster IP functionality.

</longdesc>
<shortdesc lang="en">Cluster IP hashing function</shortdesc>
<content type="string" default="${OCF_RESKEY_clusterip_hash_default}"/>
</parameter>

<parameter name="unique_clone_address">
<longdesc lang="en">
If true, add the clone ID to the supplied value of IP to create
a unique address to manage 
</longdesc>
<shortdesc lang="en">Create a unique address for cloned instances</shortdesc>
<content type="boolean" default="${OCF_RESKEY_unique_clone_address_default}"/>
</parameter>

<parameter name="arp_interval">
<longdesc lang="en">
Specify the interval between unsolicited ARP packets in milliseconds.
</longdesc>
<shortdesc lang="en">ARP packet interval in ms</shortdesc>
<content type="integer" default="${OCF_RESKEY_arp_interval_default}"/>
</parameter>

<parameter name="arp_count">
<longdesc lang="en">
Number of unsolicited ARP packets to send.
</longdesc>
<shortdesc lang="en">ARP packet count</shortdesc>
<content type="integer" default="${OCF_RESKEY_arp_count_default}"/>
</parameter>

<parameter name="arp_bg">
<longdesc lang="en">
Whether or not to send the ARP packets in the background.
</longdesc>
<shortdesc lang="en">ARP from background</shortdesc>
<content type="string" default="${OCF_RESKEY_arp_bg_default}"/>
</parameter>

<parameter name="arp_mac">
<longdesc lang="en">
MAC address to send the ARP packets to.

You really shouldn't be touching this.

</longdesc>
<shortdesc lang="en">ARP MAC</shortdesc>
<content type="string" default="${OCF_RESKEY_arp_mac_default}"/>
</parameter>

<parameter name="arp_sender">
<longdesc lang="en">
The program to send ARP packets with on start. For infiniband
interfaces, default is ipoibarping. If ipoibarping is not
available, set this to send_arp.
</longdesc>
<shortdesc lang="en">ARP sender</shortdesc>
<content type="string" default=""/>
</parameter>

<parameter name="flush_routes">
<longdesc lang="en">
Flush the routing table on stop. This is for
applications which use the cluster IP address
and which run on the same physical host that the
IP address lives on. The Linux kernel may force that
application to take a shortcut to the local loopback
interface, instead of the interface the address
is really bound to. Under those circumstances, an
application may, somewhat unexpectedly, continue
to use connections for some time even after the
IP address is deconfigured. Set this parameter in
order to immediately disable said shortcut when the
IP address goes away.
</longdesc>
<shortdesc lang="en">Flush kernel routing table on stop</shortdesc>
<content type="boolean" default="false"/>
</parameter>

</parameters>
<actions>
<action name="start"   timeout="20s" />
<action name="stop"    timeout="20s" />
<action name="status" depth="0"  timeout="20s" interval="10s" />
<action name="monitor" depth="0"  timeout="20s" interval="10s" />
<action name="meta-data"  timeout="5s" />
<action name="validate-all"  timeout="20s" />
</actions>
</resource-agent>
'''

_saved_get_ra = ra.get_ra
_saved_cluster_nodes = utils.list_cluster_nodes


def setup_function():
    "hijack ra.get_ra to add new resource class (of sorts)"
    class Agent(object):
        def __init__(self, name):
            self.name = name

        def meta(self):
            if self.name == 'apache':
                return etree.fromstring(_apache)
            else:
                return etree.fromstring(_virtual_ip)

    def _get_ra(agent):
        if agent.startswith('test:'):
            return Agent(agent[5:])
        return _saved_get_ra(agent)
    ra.get_ra = _get_ra

    utils.list_cluster_nodes = lambda: [utils.this_node(), 'a', 'b', 'c']


def teardown_function():
    ra.get_ra = _saved_get_ra
    utils.list_cluster_nodes = _saved_cluster_nodes


def test_list():
    assert set(['v2', 'legacy', '10-webserver', 'inc1', 'inc2', 'vip', 'vipinc', 'unified']) == set(s for s in scripts.list_scripts())


def test_load_legacy():
    script = scripts.load_script('legacy')
    assert script is not None
    assert 'legacy' == script['name']
    assert len(script['shortdesc']) > 0
    pprint(script)
    actions = scripts.verify(script, {}, external_check=False)
    pprint(actions)
    assert [{'longdesc': '',
          'name': 'apply_local',
          'shortdesc': 'Configure SSH',
          'text': '',
          'value': 'configure.py ssh'},
         {'longdesc': '',
          'name': 'collect',
          'shortdesc': 'Check state of nodes',
          'text': '',
          'value': 'collect.py'},
         {'longdesc': '',
          'name': 'validate',
          'shortdesc': 'Verify parameters',
          'text': '',
          'value': 'verify.py'},
         {'longdesc': '',
          'name': 'apply',
          'shortdesc': 'Install packages',
          'text': '',
          'value': 'configure.py install'},
         {'longdesc': '',
          'name': 'apply_local',
          'shortdesc': 'Generate corosync authkey',
          'text': '',
          'value': 'authkey.py'},
         {'longdesc': '',
          'name': 'apply',
          'shortdesc': 'Configure cluster nodes',
          'text': '',
          'value': 'configure.py corosync'},
         {'longdesc': '',
          'name': 'apply_local',
          'shortdesc': 'Initialize cluster',
          'text': '',
          'value': 'init.py'}] == actions


def test_load_workflow():
    script = scripts.load_script('10-webserver')
    assert script is not None
    assert '10-webserver' == script['name']
    assert len(script['shortdesc']) > 0


def test_v2():
    script = scripts.load_script('v2')
    assert script is not None
    assert 'v2' == script['name']
    assert len(script['shortdesc']) > 0

    actions = scripts.verify(
        script,
        {'id': 'www',
         'apache': {'id': 'apache'},
         'virtual-ip': {'id': 'www-vip', 'ip': '192.168.1.100'},
         'install': False}, external_check=False)
    pprint(actions)
    assert len(actions) == 1
    assert str(actions[0]['text']).find('group www') >= 0

    actions = scripts.verify(
        script,
        {'id': 'www',
         'apache': {'id': 'apache'},
         'virtual-ip': {'id': 'www-vip', 'ip': '192.168.1.100'},
         'install': True}, external_check=False)
    pprint(actions)
    assert len(actions) == 3


def test_agent_include():
    inc2 = scripts.load_script('inc2')
    actions = scripts.verify(
        inc2,
        {'wiz': 'abc',
         'foo': 'cde',
         'included-script': {'foo': True, 'bar': 'bah bah'}}, external_check=False)
    pprint(actions)
    assert len(actions) == 6
    assert '33\n\nabc' == actions[-1]['text'].strip()


def test_vipinc():
    script = scripts.load_script('vipinc')
    assert script is not None
    actions = scripts.verify(
        script,
        {'vip': {'id': 'vop', 'ip': '10.0.0.4'}}, external_check=False)
    assert len(actions) == 1
    pprint(actions)
    assert actions[0]['text'].find('primitive vop test:virtual-ip\n\tip="10.0.0.4"') >= 0
    assert actions[0]['text'].find("clone c-vop vop") >= 0


def test_value_replace_handles():
    a = '''---
- version: 2.2
  category: Script
  parameters:
    - name: foo
      value: bar
'''
    b = '''---
- version: 2.2
  category: Script
  include:
    - script: test-a
      parameters:
        - name: foo
          value: "{{wiz}}+{{wiz}}"
  parameters:
    - name: wiz
      required: true
  actions:
    - cib: "{{test-a:foo}}"
'''

    script_a = scripts.load_script_string('test-a', a)
    script_b = scripts.load_script_string('test-b', b)
    assert script_a is not None
    assert script_b is not None
    actions = scripts.verify(script_b,
                             {'wiz': "SARUMAN"}, external_check=False)
    assert len(actions) == 1
    pprint(actions)
    assert actions[0]['text'] == "SARUMAN+SARUMAN"


def test_optional_step_ref():
    """
    It seems I have a bug in referencing ids from substeps.
    """
    a = '''---
- version: 2.2
  category: Script
  include:
    - agent: test:apache
      name: apache
      parameters:
        - name: id
          required: true
'''
    b = '''---
- version: 2.2
  category: Script
  include:
    - script: apache
      required: false
  parameters:
    - name: wiz
      required: true
  actions:
    - cib: "primitive {{wiz}} {{apache:id}}"
'''

    script_a = scripts.load_script_string('apache', a)
    script_b = scripts.load_script_string('test-b', b)
    assert script_a is not None
    assert script_b is not None

    actions = scripts.verify(script_a,
                             {"id": "apacho"}, external_check=False)
    assert len(actions) == 1
    pprint(actions)
    assert actions[0]['text'] == "primitive apacho test:apache"

    #import ipdb
    #ipdb.set_trace()
    actions = scripts.verify(script_b,
                             {'wiz': "SARUMAN", "apache": {"id": "apacho"}}, external_check=False)
    assert len(actions) == 1
    pprint(actions)
    assert actions[0]['text'] == "primitive SARUMAN apacho"


def test_enums_basic():
    a = '''---
- version: 2.2
  category: Script
  parameters:
    - name: foo
      required: true
      type: enum
      values:
        - one
        - two
        - three
  actions:
    - cib: "{{foo}}"
'''

    script_a = scripts.load_script_string('test-a', a)
    assert script_a is not None

    actions = scripts.verify(script_a,
                             {"foo": "one"}, external_check=False)
    assert len(actions) == 1
    pprint(actions)
    assert actions[0]['text'] == "one"

    actions = scripts.verify(script_a,
                             {"foo": "three"}, external_check=False)
    assert len(actions) == 1
    pprint(actions)
    assert actions[0]['text'] == "three"


def test_enums_fail():
    a = '''---
- version: 2.2
  category: Script
  parameters:
    - name: foo
      required: true
      type: enum
      values:
        - one
        - two
        - three
  actions:
    - cib: "{{foo}}"
'''
    script_a = scripts.load_script_string('test-a', a)
    assert script_a is not None

    def ver():
        return scripts.verify(script_a, {"foo": "wrong"}, external_check=False)
    with pytest.raises(ValueError):
        ver()


def test_enums_fail2():
    a = '''---
- version: 2.2
  category: Script
  parameters:
    - name: foo
      required: true
      type: enum
  actions:
    - cib: "{{foo}}"
'''
    script_a = scripts.load_script_string('test-a', a)
    assert script_a is not None

    def ver():
        return scripts.verify(script_a, {"foo": "one"}, external_check=False)
    with pytest.raises(ValueError):
        ver()


def test_two_substeps():
    """
    There is a scoping bug
    """
    a = '''---
- version: 2.2
  category: Script
  include:
    - agent: test:apache
      name: apache
      parameters:
        - name: id
          required: true
'''
    b = '''---
- version: 2.2
  category: Script
  include:
    - script: apache
      name: apache-a
      required: true
    - script: apache
      name: apache-b
      required: true
  parameters:
    - name: wiz
      required: true
  actions:
    - include: apache-a
    - include: apache-b
    - cib: "primitive {{wiz}} {{apache-a:id}} {{apache-b:id}}"
'''

    script_a = scripts.load_script_string('apache', a)
    script_b = scripts.load_script_string('test-b', b)
    assert script_a is not None
    assert script_b is not None

    actions = scripts.verify(script_b,
                             {'wiz': "head", "apache-a": {"id": "one"}, "apache-b": {"id": "two"}}, external_check=False)
    assert len(actions) == 1
    pprint(actions)
    assert actions[0]['text'] == "primitive one test:apache\n\nprimitive two test:apache\n\nprimitive head one two"


def test_required_subscript_params():
    """
    If an optional subscript has multiple required parameters,
    excluding all = ok
    excluding one = fail
    """

    a = '''---
- version: 2.2
  category: Script
  parameters:
    - name: foo
      required: true
      type: string
    - name: bar
      required: true
      type: string
  actions:
    - cib: "{{foo}} {{bar}}"
'''

    b = '''---
- version: 2.2
  category: Script
  include:
    - script: foofoo
      required: false
  actions:
    - include: foofoo
    - cib: "{{foofoo:foo}} {{foofoo:bar}"
'''

    script_a = scripts.load_script_string('foofoo', a)
    script_b = scripts.load_script_string('test-b', b)
    assert script_a is not None
    assert script_b is not None

    def ver():
        actions = scripts.verify(script_b,
                                 {"foofoo": {"foo": "one"}}, external_check=False)
        pprint(actions)
    with pytest.raises(ValueError):
        ver()


def test_unified():
    unified = scripts.load_script('unified')
    actions = scripts.verify(
        unified,
        {'id': 'foo',
         'vip': {'id': 'bar', 'ip': '192.168.0.15'}}, external_check=False)
    pprint(actions)
    assert len(actions) == 1
    assert 'primitive bar IPaddr2 ip=192.168.0.15\ngroup g-foo foo bar' == actions[-1]['text'].strip()


class UnitTestPrinter:
    def __init__(self):
        import types
        self.actions = []

        def add_capture(name):
            def capture(obj, *args):
                obj.actions.append((name, args))
            self.__dict__[name] = types.MethodType(capture, self)
        for name in ('print_header', 'debug', 'error', 'start', 'flush', 'print_command', 'finish'):
            add_capture(name)

def test_inline_script():
    """
    Test inline script feature for call actions
    """

    a = '''---
- version: 2.2
  category: Script
  parameters:
    - name: foo
      required: true
      type: string
  actions:
    - call: |
        #!/bin/sh
        echo "{{foo}}"
      nodes: local
'''

    script_a = scripts.load_script_string('foofoo', a)
    assert script_a is not None

    actions = scripts.verify(script_a,
                             {"foo": "hello world"}, external_check=False)
    pprint(actions)
    assert len(actions) == 1
    assert actions[0]['name'] == 'call'
    assert actions[0]['value'] == '#!/bin/sh\necho "hello world"'
    tp = UnitTestPrinter()
    scripts.run(script_a,
                {"foo": "hello world"}, tp)

    for action, args in tp.actions:
        print(action, args)
        if action == 'finish':
            assert args[0]['value'] == '#!/bin/sh\necho "hello world"'


def test_when_expression():
    """
    Test when expressions
    """
    def runtest(when, val):
        the_script = '''version: 2.2
shortdesc: Test when expressions
longdesc: See if more complicated expressions work
parameters:
  - name: stringtest
    type: string
    shortdesc: A test string
actions:
  - call: "echo '{{stringtest}}'"
    when: %s
'''
        scrpt = scripts.load_script_string('{}_{}'.format(when, val), the_script % when)
        assert scrpt is not None

        a1 = scripts.verify(scrpt,
                            {"stringtest": val},
                            external_check=False)
        pprint(a1)
        return a1

    a1 = runtest('stringtest == "balloon"', "balloon")
    assert len(a1) == 1 and a1[0]['value'] == "echo 'balloon'"

    a1 = runtest('stringtest == "balloon"', "not a balloon")
    assert len(a1) == 0

    a1 = runtest('stringtest != "balloon"', "not a balloon")
    assert len(a1) == 1

    a1 = runtest('stringtest != "balloon"', "balloon")
    assert len(a1) == 0

    a1 = runtest('stringtest == "{{dry_run}}"', "no")
    assert len(a1) == 1

    a1 = runtest('stringtest == "yes" or stringtest == "no"', "yes")
    assert len(a1) == 1
