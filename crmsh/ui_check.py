# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import os
import sys
import re
import yaml
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from . import command
from . import config
from . import utils
from . import scripts
from . import completers as compl
from . import bootstrap
from . import corosync
from . import qdevice
from .cibconfig import cib_factory
from .ui_node import parse_option_for_nodes
from . import constants
from . import log
logger = log.setup_logger(__name__)

# for compatibility with easy_install; see #2198
__requires__ = 'ansible-core==2.14.1'

try:
    from importlib.metadata import distribution
except ImportError:
    try:
        from importlib_metadata import distribution
    except ImportError:
        from pkg_resources import load_entry_point

def importlib_load_entry_point(spec, group, name):
    dist_name, _, _ = spec.partition('==')
    matches = (
        entry_point
        for entry_point in distribution(dist_name).entry_points
        if entry_point.group == group and entry_point.name == name
    )
    return next(matches).load()

globals().setdefault('load_entry_point', importlib_load_entry_point)

def parse_description(kv_values_expected, check_name, description):
    # 1. remove all whitespaces between {{ and }}
    descr = ''
    is_inside = False
    for i in range(0, len(description)):
        if i > 0 and description[i-1] == '{' and description[i] == '{':
            is_inside = True
        if i > 0 and description[i-1] == '}' and description[i] == '}':
            is_inside = False
        if is_inside and description[i] == ' ':
            continue
        descr += description[i]
    pos_begin = descr.find('{{expected[')
    if pos_begin == -1:
        return description
    pos_end = descr.find('}}', pos_begin)
    if pos_end == -1:
        return description

    # 2. replace {{expected[x.y.z]}} or {{expected[name]}} with the value that's expected
    value_expected_str = descr[pos_begin+2:pos_end]
    if value_expected_str != 'expected[name]':
        index_expected_pos_begin = value_expected_str.find("'", 0)
        if index_expected_pos_begin == -1:
            return description
        index_expected_pos_end = value_expected_str.find("'", index_expected_pos_begin+1)
        if index_expected_pos_end == -1:
            return description
        name = value_expected_str[index_expected_pos_begin+1:index_expected_pos_end]
    else:
        name = check_name
    value_str = kv_values_expected[name]
    result = descr[:pos_begin] + value_str + descr[pos_end+2:]
    return result

def load_expected_values(playbook):
    checks_path = os.path.join(config.path.sharedir, 'checks/vars', playbook)
    for path in os.listdir(checks_path):
        yaml_file = os.path.join(checks_path, path)
        with open(yaml_file) as f:
            data = yaml.load(f, Loader=yaml.SafeLoader)
            kv_values_expected = data['expected_core']
            return kv_values_expected
    return None

def load_checks_meta_information(playbook):
    # TODO: Ansible is too slow for collecting the checks descriptions.
    # >5s to collect facts and >1s for each check. It would take >1min
    # to simply list all checks. So we do it by hand. Ok for now.
    kv_values_expected = load_expected_values(playbook)
    checks_path = os.path.join(config.path.sharedir, 'checks/roles/checks')
    dictionary = {}
    for path in os.listdir(checks_path):
        description_file = os.path.join(checks_path, path, 'defaults/main.yml')
        if not os.path.isfile(description_file):
            utils.fatal("{} is not a yaml file", description_file)
        with open(description_file) as f:
            try:
                data = yaml.load(f, Loader=yaml.SafeLoader)
            except yaml.YAMLError as exc:
                utils.fatal("Error parsing the yaml file {}", description_file)
            check_name = data['name']
            check_id = str(data['id']).strip()
            check_group = data['group']
            description = data['description'].strip()
            if kv_values_expected is not None:
                description = parse_description(kv_values_expected, check_name, description)
            if check_group in dictionary:
                dictionary[check_group][check_id] = description
            else:
                dictionary[check_group] = { check_id : description }
    return dictionary

def write_hosts_in_inventory_file(hosts=None):
    inventory_file = os.path.join(config.path.sharedir, 'checks/inventory')
    if hosts is None:
        hosts = utils.list_cluster_nodes()
    if hosts is None:
        hosts = ['localhost'] # FIXME! only for debugging
    with open(inventory_file,"w") as f:
        try:
            for host in hosts:
                f.write(host)
        except IOError:
            utils.fatal("Unable to write the inventory file '{}'", inventory_file)
        f.close()

class Check(command.UI):
    '''
    Check that the cluster is correctly setup.

    - Packages installed correctly
    - System configured correctly
    - Network setup cerrectly
    - Perform other callouts/cluster-wide checks
    '''
    name = "check"

    def requires(self):
        return True

    def __init__(self):
        command.UI.__init__(self)
        # ugly hack to allow overriding the node list
        # for the cluster commands that operate before
        # there is an actual cluster
        self._inventory_nodes = None
        self._inventory_target = None

    @command.skill_level('administrator') # FIXME! administrator?
    def list(self, playbook):
        'usage: list'

        dictionary = load_checks_meta_information(playbook)

        # TODO: print it prettier
        for group in dictionary:
            print(group)
            for id in dictionary[group]:
                descr = dictionary[group][id]
                print("  {0:8}{1}".format(id, descr))

    @command.skill_level('administrator')
    def execute(self, playbook, check_list, hosts=None):
        'usage: execute [ check1 [ chech2]... | all ]'
        usage='usage: execute [ check1 [ chech2]... | all ]'
        if len(check_list) == 0:
            utils.fatal(usage)

        # point out to the ansible.cfg explicitely
        if "ANSIBLE_CONFIG" not in os.environ:
            os.environ["ANSIBLE_CONFIG"] = os.path.join(config.path.sharedir, 'checks/')

        check_file = os.path.join(config.path.sharedir, 'checks/check.yml')
        inventory_file = os.path.join(config.path.sharedir, 'checks/inventory')
        external_vars = "env=" + playbook
        write_hosts_in_inventory_file(hosts)
        args = ["ansible-playbook", check_file, "-i", inventory_file, "-e", external_vars, "--check" ]

        if len(check_list) == 1:
            if check_list[0] == 'all':
                entry_point = load_entry_point('ansible-core==2.14.1', 'console_scripts', 'ansible-playbook')
                res = entry_point(args)
            else:
                utils.fatal(usage)

    @command.skill_level('administrator')
    def do_azure(self, context, *args):
        'usage: execute [ check1 [ chech2]... | all ]'
        usage='usage: execute [ check1 [ chech2]... | all ]'
        if len(list(args)) == 0:
            utils.fatal(usage)
        if args[0] == 'execute':
            self.execute('azure', [args[1]])
        if args[0] == 'list':
            self.list('azure')

    @command.skill_level('administrator')
    def do_dev(self, context, *args):
        'usage: execute [ check1 [ chech2]... | all ]'
        usage='usage: execute [ check1 [ chech2]... | all ]'
        if len(list(args)) == 0:
            utils.fatal(usage)
        if args[0] == 'execute':
            self.execute('dev', [args[1]])
        if args[0] == 'list':
            self.list('dev')

