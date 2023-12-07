# Copyright (C) 2023 Aleksei Burlakov <aburlakov@suse.com>
# Copyright (C) 2023 Soeren Schmidt <soeren.schmidt@suse.com>
# See COPYING for license information.

import collections
import json
import logging
import os
import re
import requests
import signal
import sys
import time
import yaml
import uuid
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

class Rabbiteer():
    """Class to communicate with Wanda's API."""

    def __init__(self, baseurl, access_key=None, credentials=None):
        self.baseurl = baseurl
        self.access_key = access_key
        self.trento_credentials = credentials

    def make_request(self, endpoint, post_data=None):
        """Makes a request to the endpoint and expects a JSON response.
        The response is available in self.response.
        If post_data is given, a POST else a GET request is done.

        If the HTTP connection fails, print the error message to
        stderr and terminate with exit code 1.

        If the Wanda API requires authentication, either the access key
        or credentials to the Trento web interface must be given to retrieve
        it.
        """

        # Retrieve access key from Trento, if required.
        if self.trento_credentials:
            try:
                response = requests.post(f'''{self.trento_credentials.url}/api/session''',
                                     data={'username': self.trento_credentials.username,
                                           'password': self.trento_credentials.password},
                                     timeout=10)
            except Exception as err:
                print(f'Connection error:{err}', file=sys.stderr)
                sys.exit(1)
            if not response.ok:
                print(f'Could not authenticate against Trento. Error:{response.status_code}\n{response.text}', file=sys.stderr)
                sys.exit(1)
            else:
                try:
                    self.access_key = response.json()['access_token']
                except Exception as err:
                    print(f'Could not retrieve access key from Trento: {err}', file=sys.stderr)
                    sys.exit(1)

        # Build the headers
        headers = {'accept': 'application/json', 'Content-Type': 'application/json'}
        if self.access_key:
            headers['Authorization'] = f'Bearer {self.access_key}'
        url = f'{self.baseurl}{endpoint}'

        try:
            if post_data:
                self.response = requests.post(url, headers=headers, data=post_data)
                logging.debug(f'POST REQUEST\n\tURL: {url}\n\theaders: {headers}\n\tdata: {post_data}')
            else:
                self.response = requests.get(url, headers=headers)
                logging.debug(f'GET REQUEST\n\tURL: {url}\n\theaders: {headers}\n\thttp status: {self.response.status_code}\n\tresponse: {self.response.text}')
        except Exception as err:
            print(f'Error connecting to "{url}": {err}', file=sys.stderr)
            sys.exit(1)

    def _http_status_err(self):
        """If the request returned with a error HTTP status code, print
        error message and terminates with exitcode 1.
        """
        if not self.response.ok:
            print(f'Failed with status code: {self.response.status_code}\n{self.response.text}', file=sys.stderr)
            sys.exit(1)

    def list_executions(self):
        """Returns executions from Wanda."""

        self.make_request('/api/checks/executions')
        self._http_status_err()
        return self.response.json()

    def list_catalog(self):
        """Returns check catalog from Wanda."""

        self.make_request('/api/checks/catalog')
        self._http_status_err()
        return self.response.json()

    def execute_checks(self, agent_ids, provider, check_ids, timeout=None):
        """Execute checks for provider on agents and returns
        the result as dictionary.
        Terminates if anything goes wrong or the result is not as expected.
        """

        execution_id = str(uuid.uuid4())
        data = {'env': {'provider': provider},
                'execution_id': execution_id,
                'group_id': str(uuid.uuid4()),
                'targets': [],
                'target_type': 'cluster'
               }
        for agent_id in agent_ids:
            data['targets'].append({'agent_id': agent_id, 'checks': check_ids})

        # Start execution.
        self.make_request('/api/checks/executions/start', post_data=json.dumps(data))

        # Check if the check does not exist.
        if self.response.status_code == 422:
            try:
                if self.response.json()['error']['detail'] == 'no_checks_selected':
                    print('None of the checks exist!')
                    sys.exit(2)
            except Exception as err:
                print(f'Error parsing response checking execution {execution_id}: {err}', file=sys.stderr)
                print(f'Response was: {self.response.text}', file=sys.stderr)
                sys.exit(3)
        else:
            self._http_status_err()

        endpoint = f'/api/checks/executions/{execution_id}'
        start_time = time.time()
        running = True
        time.sleep(.5)
        while running:
            self.make_request(endpoint)

            # Check if execution might not yet exist.
            if self.response.status_code == 404:
                try:
                    error_titles = [e['title'] for e in self.response.json()['errors'] if 'title' in e.keys()]
                    if 'Not Found' in error_titles:
                        logging.debug(f'Execution {execution_id} not yet available...\n\t{self.response.text}')
                        if timeout and time.time() - start_time > timeout:
                            print(f'Execution {execution_id} did not show up in time (within {timeout}s)!' , file=sys.stderr)
                            sys.exit(4)
                        time.sleep(.5)
                        continue
                except Exception as err:
                    print(f'Error parsing response checking execution {execution_id}: {err}', file=sys.stderr)
                    print(f'Response was: {self.response.text}', file=sys.stderr)
                    sys.exit(3)

            # Terminate if we encounter an unknown error response.
            self._http_status_err()

            # Check if execution has been completed yet.
            try:
                status = self.response.json()['status']
                if status == 'running':
                    print('.', end='', flush=True)

                    logging.debug(f'Execution {execution_id} still running...\n\t{self.response.text}')
                    if timeout and time.time() - start_time > timeout:
                        print(f'Execution {execution_id} did not finish in time (within {timeout}s)!' , file=sys.stderr)
                        sys.exit(4)
                    time.sleep(.5)
                    continue
                elif status == 'completed':
                    logging.debug(f'Execution {execution_id} has been completed.\n\t{self.response.text}')
                    running = False
                else:
                    print(f'Execution {execution_id} returned an unknown status: {status}', file=sys.stderr)
                    print(f'Response was:\n{self.response.text}', file=sys.stderr)
                    sys.exit(3)
            except Exception as err:
                print(f'Error accessing response checking execution {execution_id}: {err}', file=sys.stderr)
                print(f'Response was:\n{self.response.text}', file=sys.stderr)
                sys.exit(3)

        logging.debug(f'Response of {execution_id}: {self.response.text}')
        return self.response.json()

def unknown_response(response, error):
    """Prints response and error message and terminates with exit code 3."""

    print(f'Could not evaluate response:\n{response}\n\nError: {error}', file=sys.stderr)
    sys.exit(3)

def signal_handler(sig, frame):
    sys.exit(0)

class obj(object):
    def __init__(self, d):
        for k, v in d.items():
            if isinstance(k, (list, tuple)):
                setattr(self, k, [obj(x) if isinstance(x, dict) else x for x in v])
            else:
                setattr(self, k, obj(v) if isinstance(v, dict) else v)

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
        wanda_credentials = obj({
            'url': config.trento.web_url,
            'username': config.trento.wanda_username,
            'password': config.trento.wanda_password,
        })
        wanda_key = config.trento.wanda_key

        if wanda_key == '' or wanda_key is None:
            self.connection = Rabbiteer(config.trento.wanda_url, None, wanda_credentials)
        else:
            self.connection = Rabbiteer(config.trento.wanda_url, wanda_key, None)

    def get_checks_dictionary(self):
        signal.signal(signal.SIGINT, signal_handler)

        # Retrieve checks.
        response = self.connection.list_catalog()

        # Group checks.
        dictionary = {}
        try:
            checks = response['items']
            for check in checks:
                id = str(check['id']).strip()
                group = check['group']
                description = check['description'].strip()
                if group in dictionary:
                    dictionary[group][id] = description
                else:
                    dictionary[group] = { id : description }
        except Exception as err:
            print(f'Could not evaluate response:\n{response}\n\nError: {err}', file=sys.stderr)
            sys.exit(3)
        return dictionary


    def get_kv_checkid_description_group(self):
        'Resort the get_checks_dictionary as (checkid,descr,group)'
        dictionary = self.get_checks_dictionary()
        id_list = {}
        for group in dictionary:
            for id in dictionary[group]:
                id_list[id] = [dictionary[group][id], group]
        return id_list


    def get_node_agent_id(self, node_name):
        rc, id, err_msg = utils.get_stdout_stderr_auto_ssh_no_input(node_name, "trento-agent id")
        if rc != 0:
            utils.fatal("trento-agent is not running on {}: {}". format(node_name, err_msg))
        return id


    def get_kv_agentid_hostname(self):
        kv_agentid_hostname = {}
        nodes = utils.list_cluster_nodes()
        if nodes is None:
            utils.fatal("No cluster found.")
        for node_name in nodes:
            agent_id = self.get_node_agent_id(node_name)
            if agent_id in kv_agentid_hostname:
                utils.fatal("There are non-unique agent-ids.")
            kv_agentid_hostname[agent_id] = node_name

        return kv_agentid_hostname


    @command.skill_level('administrator')
    def do_list(self, context, *args):
        'usage: list'

        dictionary = self.get_checks_dictionary()

        # List checks.
        count = 0
        for group in dictionary:
            print(group)
            for id in dictionary[group]:
                count += 1
                descr = dictionary[group][id]
                print("  {0:8}{1}".format(id, descr))

        print(f'\n{count} check(s) found.')


    @command.skill_level('administrator')
    def do_execute(self, context, *args):
        'usage: execute [ check1 [ chech2]... | all ]'
        usage='usage: execute [ check1 [ chech2]... | all ]'
        check_list = args
        if len(check_list) == 0:
            utils.fatal(usage)

        kv_checkid_description = self.get_kv_checkid_description_group()
        if check_list[0] == 'all':
            if len(check_list) == 1:
                check_list = [id for id in kv_checkid_description]
            else:
                utils.fatal(usage)

        signal.signal(signal.SIGINT, signal_handler)

        kv_agentid_hostname = self.get_kv_agentid_hostname()

        # Start check(s) execution.
        agents_ids = [agentid for agentid in kv_agentid_hostname]
        response = self.connection.execute_checks(agents_ids, config.trento.provider, check_list, timeout=config.trento.restapi_timeout)

        # Print full response or evaluation.
        output = {} # group by hosts, group
        try:
            for check_result in response['check_results']:
                yes_no = check_result['result']
                check_id = check_result['check_id']
                group = kv_checkid_description[check_id][1]
                description = kv_checkid_description[check_id][0]
                for agents_check_result in check_result['agents_check_results']:
                    host = kv_agentid_hostname[agents_check_result['agent_id']]
                    message = "    {0:>9}:  {1}  {2}".format(yes_no, check_id, description)
                    if host in output:
                        if group in output[host]:
                            output[host][group].append(message)
                        else:
                            output[host][group] = [message]
                    else:
                        output[host] = {group: [message]}

        except Exception as err:
            unknown_response(response, err)

        output = collections.OrderedDict(sorted(output.items()))
        for host in output:
            print(host)
            for group in output[host]:
                print("  {}".format(group))
                for msg in output[host][group]:
                    print(msg)

