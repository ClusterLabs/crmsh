"""
crmsh callback executor.

:authors: xarbulu, aburlakov
:organization: SUSE Linux GmbH
:contact: xarbulu@suse.com, aburlakov@suse.com

:since: 2021-09-16
"""

import os
import yaml
import requests
from crmsh.ui_check import load_checks_meta_information

from ansible.plugins.callback import CallbackBase

TEST_RESULT_TASK_NAME = "set_test_result"
TEST_INCLUDE_TASK_NAME = "run_checks"
CHECK_ID = "id"


class Results(object):
    """
    Object to store and user the execution results

    Result example:

    "results": {
        "clusterId": {
            "hosts": {
                "host1": {
                    "reachable": true,
                    "msg": ""
                },
                "host2": {
                    "reachable": false,
                    "msg": "Failed to connect to the host via ssh: ..."
                },
            }
            "checks": {
                "ABCDEF": {
                    "hosts": {
                        "host1": {
                            "result": "passing",
                            "msg": "",
                        }
                    }
                }
            }
        }
    }
    """
    def __init__(self):
        self.results = {"results": {}}

    def initialize_group(self, group):
        """
        Initialize the group on the results dictionary
        """
        if group not in self.results["results"]:
            self.results["results"][group] = {}
            self.results["results"][group]["hosts"] = {}
            self.results["results"][group]["checks"] = {}

    def add_result(self, group, test, host, result, msg=""):
        """
        Add new result
        """
        # Add the group just in case it doesn't exist
        if group not in self.results["results"]:
            self.results["results"][group] = {}
            self.results["results"][group]["checks"] = {}

        checks = self.results["results"][group]["checks"]
        if test not in checks:
            checks[test] = {}
            checks[test]["hosts"] = {}

        hosts = checks[test]["hosts"]
        if host not in hosts:
            hosts[host] = {}

        hosts[host]["result"] = result
        hosts[host]["msg"] = msg

    def result_exist(self, group, test_id, host):
        """
        Check if the result already exists
        """
        try:
            return bool(self.results["results"][group]["checks"][test_id]["hosts"][host]["result"])
        except KeyError:
            return False

    def get_result(self, test_id, host):
        """
        Check if the result already exists
        """
        # TODO: We don't group hosts yet,
        # but when we do, you should de-hardcode the group name
        host_group_name = 'ungrouped'
        if self.result_exist(host_group_name, test_id, host):
            res = self.results["results"][host_group_name]["checks"][test_id]["hosts"][host]["result"]
            return res

    def set_host_state(self, group, host, state, msg=""):
        """
        Set the host state. Reachable or Unreachable
        """
        # Add the group just in case it doesn't exist
        if group not in self.results["results"]:
            self.results["results"][group] = {}
            self.results["results"][group]["hosts"] = {}

        hosts = self.results["results"][group]["hosts"]
        if host not in hosts:
            hosts[host] = {}

        hosts[host]["reachable"] = state
        hosts[host]["msg"] = msg


class CallbackModule(CallbackBase):
    """
    crmsh callback module
    """
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'aggregate'
    CALLBACK_NAME = 'crmsh'

    def __init__(self):
        super(CallbackModule, self).__init__()
        self.playbook = None
        self.play = None
        self.results = Results()
        self.meta_information = {}

    def v2_playbook_on_start(self, playbook):
        """
        On start callback
        """
        self.playbook = playbook

    def v2_playbook_on_play_start(self, play):
        """
        On Play start callback
        """
        self.play = play
        self._initialize_results()
        env = self._all_vars()["env"]
        self.meta_information = load_checks_meta_information(env)

    def v2_runner_on_ok(self, result):
        """
        On task Ok
        """
        if self._is_check_include_loop(result):
            self._store_skipped(result)
            return

        if not self._is_test_result(result):
            return

        host = result._host.get_name()
        task_vars = self._all_vars(host=result._host, task=result._task)

        test_result = result._task_fields["args"]["test_result"]
        for group in task_vars["group_names"]:
            self.results.set_host_state(group, host, True)
            if self.results.result_exist(group, task_vars[CHECK_ID], host):
                continue
            self.results.add_result(group, task_vars[CHECK_ID], host, test_result)

        test_group = task_vars["group"]
        test_id = task_vars["id"]
        test_descr = task_vars["description"].strip()
        if test_group in self.meta_information and test_id in self.meta_information[test_group]:
            test_descr = self.meta_information[test_group][test_id]
        test_result = self.results.get_result(test_id, host)
        # TODO: Refactor the ansible checks instead of replacing the severity here
        # Btw, those severities are speculative and may make long discussions,
        # so let's just leave them "for now" somewhat generic: OK and Warning
        if test_result in ['critical', 'warning']:
            test_result = 'Warning'
            msg = "{0:>7}:  {1}  {2} NOT on {3}".format(test_result, test_id, test_descr, host)
        if test_result == 'passing':
            test_result = 'OK'
            msg = "{0:>7}:  {1}  {2} on {3}".format(test_result, test_id, test_descr, host)
        print(msg)

    def v2_runner_on_failed(self, result, ignore_errors):
        """
        On task Failed
        """
        host = result._host.get_name()
        task_vars = self._all_vars(host=result._host, task=result._task)

        if CHECK_ID not in task_vars:
            return

        msg = result._check_key("msg")

        for group in task_vars["group_names"]:
            self.results.set_host_state(group, host, True)
            self.results.add_result(group, task_vars[CHECK_ID], host, "warning", msg)

    def v2_runner_on_skipped(self, result):
        """
        On task Skipped
        """
        if self._is_check_include_loop(result):
            self._store_skipped(result)

    def v2_runner_on_unreachable(self, result):
        """
        On task Unreachable
        """
        host = result._host.get_name()
        task_vars = self._all_vars(host=result._host, task=result._task)
        msg = result._check_key("msg")

        for group in task_vars["group_names"]:
            self.results.set_host_state(group, host, False, msg)

    def v2_playbook_on_stats(self, _stats):
        """
        Show results at the end of the execution
        """
        return # Don't need to do anything
        #self._display.banner("Crmsh checks results")
        #for key, group in self.results.results["results"].items():
        #    for id in group["checks"]:
        #        data = group["checks"][id]
        #        for host in data["hosts"]:
        #            res = data["hosts"][host]
        #            if(res["result"] != 'skipped'):
        #                print("{} {} on {}".format(id, res["result"], host).strip())

    def _all_vars(self, host=None, task=None):
        """
        Get task vars

        host and task need to be specified in case 'magic variables' (host vars, group vars, etc)
        need to be loaded as well
        """
        return self.play.get_variable_manager().get_vars(
            play=self.play,
            host=host,
            task=task
        )

    def _initialize_results(self):
        """
        Initialize the results object
        """
        play_vars = self._all_vars()
        for _, host_data in play_vars["hostvars"].items():
            for group in host_data["group_names"]:
                self.results.initialize_group(group)

    def _is_test_result(self, result):
        """
        Check if the current task is a test result
        (Trigers on roles/checks/x.y.z/tasks/main.yml::post-results -->
                        roles/post-results/tasks/main.yml)
        """
        if (result._task_fields.get("action") == "set_fact") and \
                (result._task_fields.get("name") == TEST_RESULT_TASK_NAME):
            return True
        return False

    def _is_check_include_loop(self, result):
        """
        Check if the current task is the checks include loop task
        """
        if (result._task_fields.get("action") == "include_role") and \
                (result._task_fields.get("name") == TEST_INCLUDE_TASK_NAME):
            return True
        return False

    def _store_skipped(self, result):
        """
        Store skipped checks
        """
        task_vars = self._all_vars(host=result._host, task=result._task)
        host = result._host.get_name()

        for check_result in result._result["results"]:
            skipped = check_result.get("skipped", False)
            if skipped:
                with open(os.path.join(
                    check_result["check_item"]["path"], "defaults/main.yml")) as file_ptr:

                    data = yaml.load(file_ptr, Loader=yaml.Loader)
                    check_id = data[CHECK_ID]

                for group in task_vars["group_names"]:
                    self.results.set_host_state(group, host, True)
                    self.results.add_result(group, check_id, host, "skipped")
