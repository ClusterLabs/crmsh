import os
import sys
import re
import time
import threading
import logging
import shutil
import tempfile
from contextlib import contextmanager
from crmsh import utils as crmshutils

from . import utils
from . import config


logger = logging.getLogger('cpc')


class TaskError(Exception):
    pass


class Task(object):
    """
    Task is a base class
    Use for record the information of each test case
    """
    def __init__(self, description, flush=False, quiet=False):
        """
        Init function
        flush, to print the message immediately
        """
        self.passed = True
        self.yes = False
        self.quiet = quiet
        self.messages = []
        self.timestamp = utils.now()
        self.description = description
        utils.msg_info(self.description, to_stdout=False)
        self.flush = flush
        self.fence_start_event = threading.Event()
        self.fence_finish_event = threading.Event()
        self.thread_stop_event = threading.Event()
        from . import main
        self.prev_task_list = main.ctx.task_list

    def info(self, msg):
        self.msg_append("info", msg)
        utils.msg_info(msg, to_stdout=self.flush)

    def warn(self, msg):
        self.msg_append("warn", msg)
        utils.msg_warn(msg, to_stdout=self.flush)

    def error(self, msg):
        self.msg_append("error", msg)
        utils.msg_error(msg, to_stdout=self.flush)

    def msg_append(self, msg_type, msg):
        if msg_type == "error":
            self.passed = False
        self.messages.append((msg_type, msg, utils.now()))
        if self.flush:
            self.to_json()
            self.to_report()

    def header(self):
        pass

    def to_report(self):
        pass

    def to_json(self):
        pass

    def build_base_result(self):
        """
        Build base results
        """
        self.result = {
            "Timestamp": self.timestamp,
            "Description": self.description,
            "Messages": ["{} {}:{}".format(m[2], m[0].upper(), m[1])
                         for m in self.messages]
        }

    def print_header(self):
        """
        Print testcase header
        """
        print(self.header())
        if not self.yes and not crmshutils.ask("Run?"):
            self.info("Testcase cancelled")
            sys.exit()

    def task_pre_check(self, need_fence=True):
        """
        Prerequisite check
          * pacemaker.service is active
          * stonith is enabled
        """
        if not crmshutils.service_is_active("pacemaker.service"):
            raise TaskError("Cluster not running!")
        if need_fence:
            self.get_fence_info()
            if not self.fence_enabled:
                raise TaskError("Require stonith enabled")

    def get_fence_info(self):
        """
        Get fence info
        """
        fence_info_inst = utils.FenceInfo()
        self.fence_enabled = fence_info_inst.fence_enabled
        self.fence_action = fence_info_inst.fence_action
        self.fence_timeout = fence_info_inst.fence_timeout

    def fence_action_monitor(self):
        """
        Monitor fencing process, running in thread, exit on two cases:
        1. There is one latest fence action successfully done
        2. No fence action during fence timeout, thread_stop_event triggered by main thread
        """
        target_node = None
        from_node = None
        fence_timestamp = None

        # Try to find out which node fire the fence action
        while not self.thread_stop_event.is_set():
            rc, out, _ = crmshutils.get_stdout_stderr("crm_mon -1|grep -A1 \"Fencing Actions:\"")
            if rc == 0 and out:
                match = re.search(r"of (.*) pending: .*origin=(.*)$", out)
                if match:
                    target_node, from_node = match.groups()
                    self.info("Node \"{}\" will be fenced by \"{}\"!".format(target_node, from_node))
                    self.fence_start_event.set()
                    break
            time.sleep(1)

        # Try to find out proof that fence happened
        while not self.thread_stop_event.is_set():
            rc, out, _ = crmshutils.get_stdout_stderr(config.FENCE_HISTORY.format(node=target_node))
            if rc == 0 and out:
                match = re.search(r"Node {} last fenced at: (.*)".format(target_node), out)
                if match:
                    fence_timestamp = match.group(1)
                    task_timestamp_dt = utils.str_to_datetime(self.timestamp, '%Y/%m/%d %H:%M:%S')
                    fence_timestamp_dt = utils.str_to_datetime(fence_timestamp, '%a %b %d %H:%M:%S %Y')
                    # If the fence action timestamp larger than this task's timestamp
                    # That is the proof
                    if task_timestamp_dt < fence_timestamp_dt:
                        self.info("Node \"{}\" was successfully fenced by \"{}\"".format(target_node, from_node))
                        # Tell main thread fence happened
                        self.fence_finish_event.set()
                        break
            time.sleep(1)


class TaskFence(Task):
    """
    Class to fence node
    """
    def  __init__(self, context):
        """
        Init function
        """
        self.target_node = context.fence_node
        description = "Fence node {}".format(self.target_node)
        super(self.__class__, self).__init__(description, flush=True)
        self.yes = context.yes

    def header(self):
        """
        Header content for this task
        """
        h = '''==============================================
Testcase:          {}
Fence action:      {}
Fence timeout:     {}
'''.format(self.description, self.fence_action, self.fence_timeout)
        return h

    def to_json(self):
        """
        Dump join result
        """
        self.build_base_result()
        self.result['Fence action'] = self.fence_action
        self.result['Fence timeout'] = self.fence_timeout
        from . import main
        main.ctx.task_list = self.prev_task_list + [self.result]
        utils.json_dumps()

    def pre_check(self):
        """
        Check the prerequisite for fence node
        """
        self.task_pre_check()

        for cmd in ['crm_node', 'stonith_admin', 'crm_attribute']:
            rc, _, err = crmshutils.get_stdout_stderr("which {}".format(cmd))
            if rc != 0 and err:
                raise TaskError(err)

        if not utils.check_node_status(self.target_node, 'member'):
            raise TaskError("Node \"{}\" not in cluster!".format(self.target_node))

    def run(self):
        """
        Fence node and start a thread to monitor the result
        """
        self.info("Trying to fence node \"{}\"".format(self.target_node))
        crmshutils.get_stdout_stderr(config.FENCE_NODE.format(self.target_node))
        th = threading.Thread(target=self.fence_action_monitor)
        th.start()

    def wait(self):
        """
        Wait until fence happened
        """
        if self.target_node == utils.this_node():
            self.info("Waiting {}s for self {}...".format(self.fence_timeout, self.fence_action))
        else:
            self.info("Waiting {}s for node \"{}\" {}...".format(self.fence_timeout,
                self.target_node, self.fence_action))

        result = self.fence_finish_event.wait(int(self.fence_timeout))
        if not result:
            self.thread_stop_event.set()
            raise TaskError("Target fence node \"{}\" still alive".format(self.target_node))


class TaskCheck(Task):
    """
    Class to define the format of output for checking item results and how to dump json
    """

    def __init__(self, description, quiet=False):
        """
        Init function
        """
        super(self.__class__, self).__init__(description, quiet=quiet)

    def to_stdout(self):
        """
        Define the format of results to stdout
        """
        with utils.manage_handler("file", keep=False):
            utils.get_handler(logger, "stream").setFormatter(utils.MyLoggingFormatter(flush=False))

            if self.passed:
                message = "{} [{}]".format(self.description, utils.CGREEN + "Pass" + utils.CEND)
            else:
                message = "{} [{}]".format(self.description, utils.CRED + "Fail" + utils.CEND)
            logger.info(message, extra={'timestamp': '[{}]'.format(self.timestamp)})

            for msg in self.messages:
                logger.log(utils.LEVEL[msg[0]], msg[1], extra={'timestamp': '  '})

            utils.get_handler(logger, "stream").setFormatter(utils.MyLoggingFormatter())

    def to_json(self):
        """
        Json results
        """
        self.build_base_result()
        self.result['Result'] = self.passed
        from . import main
        main.ctx.task_list.append(self.result)
        utils.json_dumps()

    def print_result(self):
        """
        Print results to stdout and json
        """
        if self.quiet:
            return
        self.to_stdout()
        self.to_json()

    @contextmanager
    def run(self):
        """
        Context manager to do things and print results finally
        """
        try:
            yield
        finally:
            self.print_result()


class TaskKill(Task):
    """
    Class to define how to run kill testcases
    """

    EXPECTED = {
        # process_name: (expected_results, expected_results_with_loop)
        'sbd':        ('''a) sbd process restarted
                   b) Or, this node fenced.''', 'This node fenced'),
        'corosync':   ('''a) corosync process restarted
                   b) Or, this node fenced.''', 'This node fenced'),
        'pacemakerd': ('pacemakerd process restarted', None),
    }
    WAIT_TIMEOUT = 10

    def  __init__(self, context):
        """
        Init function
        """
        self.target_kill = context.current_case
        self.description = "Force kill {}".format(self.target_kill)
        super(self.__class__, self).__init__(self.description, flush=True)
        self.cmd = "killall -9 {}".format(self.target_kill)
        self.looping = context.loop
        self.yes = context.yes
        if not self.looping:
            self.expected = self.EXPECTED[self.target_kill][0]
        else:
            self.expected = self.EXPECTED[self.target_kill][1]
        self.report = False
        self.restart_happen_event = threading.Event()

    def enable_report(self):
        """
        Enable report
        """
        self.report = True
        from . import main
        if not os.path.isdir(main.ctx.report_path):
            raise TaskError("{} is not a directory".format(main.ctx.report_path))

        report_path = main.ctx.report_path
        report_name = "{}-{}.report".format(main.ctx.process_name, utils.now("%Y%m%d-%s"))
        self.report_file = os.path.join(report_path, report_name)
        print("(Report: {})".format(self.report_file))

        if self.looping:
            content_key = "{}-l".format(self.target_kill)
        else:
            content_key = self.target_kill

        from . import explain
        self.explain = explain.contents[content_key].format(nodeA=utils.this_node(), nodeB="other node")

    def header(self):
        """
        Define descriptions
        """
        h = '''==============================================
Testcase:          {}
Looping Kill:      {}
Expected State:    {}
'''.format(self.description, self.looping, self.expected)
        return h

    def to_json(self):
        """
        Json results
        """
        self.build_base_result()
        self.result['Looping Kill'] = self.looping
        self.result['Expected State'] = self.expected
        from . import main
        main.ctx.task_list = self.prev_task_list + [self.result]
        utils.json_dumps()

    def to_report(self):
        """
        Generate report
        """
        if not self.report:
            return
        with open(self.report_file, 'w') as f:
            f.write(self.header())
            f.write("\nLog:\n")
            for m in self.messages:
                f.write("{} {}:{}\n".format(m[2], m[0].upper(), m[1]))
            f.write("\nTestcase Explained:\n")
            f.write("{}\n".format(self.explain))
            f.flush()
            os.fsync(f)

    def pre_check(self):
        """
        Check the prerequisite
        """
        self.task_pre_check()
        rc, pid = utils.get_process_status(self.target_kill)
        if not rc:
            raise TaskError("Process {} is not running!".format(self.target_kill))

    def run(self):
        """
        Execute specific kill command and monitor the results
        """
        while True:
            rc, pid = utils.get_process_status(self.target_kill)
            if rc:
                self.info("Process {}({}) is running...".format(self.target_kill, pid))
            else:
                continue
            self.info("Trying to run \"{}\"".format(self.cmd))
            crmshutils.get_stdout_stderr(self.cmd)
            # endless loop will lead to fence
            if not self.looping:
                break

        fence_check_th = threading.Thread(target=self.fence_action_monitor)
        fence_check_th.start()
        restart_check_th = threading.Thread(target=self.process_monitor)
        restart_check_th.start()

    def wait(self):
        """
        Wait process to restart
        """
        if self.fence_start_event.wait(self.WAIT_TIMEOUT) and not self.restart_happen_event.is_set():
            raise TaskError("Process {} is not restarted!".format(self.target_kill))
        self.thread_stop_event.set()

    def process_monitor(self):
        """
        Monitor process status
        """
        while not self.thread_stop_event.is_set():
            rc, pid = utils.get_process_status(self.target_kill)
            if rc:
                self.info("Process {}({}) is restarted!".format(self.target_kill, pid))
                self.restart_happen_event.set()
                break
            time.sleep(1)


class TaskSplitBrain(Task):
    """
    Class to define how to simulate split brain by blocking corosync ports
    """

    def  __init__(self, yes=False):
        """
        Init function
        """
        self.description = "Simulate split brain by blocking corosync ports"
        self.expected = "One of nodes get fenced"
        self.ports = []
        self.peer_nodelist = []
        super(self.__class__, self).__init__(self.description, flush=True)
        self.yes = yes

    def header(self):
        """
        Define descriptions
        """
        h = '''==============================================
Testcase:          {}
Expected Result:   {}
Fence action:      {}
Fence timeout:     {}
'''.format(self.description, self.expected, self.fence_action, self.fence_timeout)
        return h

    def to_json(self):
        """
        Json results
        """
        self.build_base_result()
        self.result['Fence action'] = self.fence_action
        self.result['Fence timeout'] = self.fence_timeout
        from . import main
        main.ctx.task_list = self.prev_task_list + [self.result]
        utils.json_dumps()

    def pre_check(self):
        """
        Check the prerequisite
        """
        self.task_pre_check()

        for cmd in ["iptables"]:
            rc, _, err = crmshutils.get_stdout_stderr("which {}".format(cmd))
            if rc != 0 and err:
                raise TaskError(err)

        if len(utils.online_nodes()) < 2:
            raise TaskError("At least two nodes online!")

    @contextmanager
    def do_block(self):
        """
        Context manager to block and unblock ip/ports
        """
        self.firewalld_enabled = crmshutils.service_is_active("firewalld.service")
        if self.firewalld_enabled:
            self.do_block_firewalld()
        else:
            self.do_block_iptables()
        try:
            yield
        finally:
            self.un_block()

    def do_block_firewalld(self):
        """
        Block corosync ports
        """
        self.ports = utils.corosync_port_list()
        if not self.ports:
            raise TaskError("Can not get corosync's port")
        self.info("Trying to temporarily block port {}".format(','.join(self.ports)))
        for p in self.ports:
            crmshutils.get_stdout_stderr(config.REMOVE_PORT.format(port=p))

    def do_block_iptables(self):
        """
        Block corosync communication ip
        """
        self.peer_nodelist = utils.peer_node_list()
        for node in self.peer_nodelist:
            self.info("Trying to temporarily block {} communication ip".format(node))
            for ip in crmshutils.get_iplist_from_name(node):
                crmshutils.get_stdout_stderr(config.BLOCK_IP.format(action='I', peer_ip=ip))

    def un_block(self):
        """
        Unblock corosync ip/ports
        """
        if self.firewalld_enabled:
            self.un_block_firewalld()
        else:
            self.un_block_iptables()

    def un_block_firewalld(self):
        """
        Unblock corosync ports
        """
        self.info("Trying to add port {}".format(','.join(self.ports)))
        for p in self.ports:
            crmshutils.get_stdout_stderr(config.ADD_PORT.format(port=p))

    def un_block_iptables(self):
        """
        Unblock corosync communication ip
        """
        for node in self.peer_nodelist:
            self.info("Trying to recover {} communication ip".format(node))
            for ip in crmshutils.get_iplist_from_name(node):
                crmshutils.get_stdout_stderr(config.BLOCK_IP.format(action='D', peer_ip=ip))

    def run(self):
        """
        Fence node and start a thread to monitor the result
        """
        #self.info("Trying to fence node \"{}\"".format(self.target_node))
        #crmshutils.get_stdout_stderr(config.FENCE_NODE.format(self.target_node), wait=False)
        th = threading.Thread(target=self.fence_action_monitor)
        th.start()

    def wait(self):
        """
        Wait until fence happened
        """
        result = self.fence_finish_event.wait(int(self.fence_timeout))
        if not result:
            self.thread_stop_event.set()
            # should be an error here


class TaskFixSBD(Task):
    """
    Class to fix SBD DEVICE incorrect issue
    """

    def  __init__(self, candidate, yes=False):
        self.new = candidate
        self.description = "Replace SBD_DEVICE with candidate {}".format(self.new)
        self.conf = config.SBD_CONF
        super(self.__class__, self).__init__(self.description, flush=True)
        self.bak = tempfile.mkstemp()[1]
        self.edit = tempfile.mkstemp()[1]
        self.yes = yes

        sbd_options = crmshutils.parse_sysconfig(self.conf)
        self.old = sbd_options["SBD_DEVICE"]

    def header(self):
        """
        Case header
        """
        h = '''==============================================
Case:                {}
Original SBD device: {}
New SBD device:      {}
'''.format(self.description, self.old, self.new)
        return h

    def to_json(self):
        """
        Generate json output
        """
        self.build_base_result()
        self.result['Original SBD device'] = self.old
        self.result['New SBD device'] = self.new
        from . import main
        main.ctx.task_list = self.prev_task_list + [self.result]
        utils.json_dumps()

    def pre_check(self):
        """
        Check the prerequisite
        """
        if not os.path.exists(self.conf):
            raise TaskError("Configure file {} not exist!".format(self.conf))

        if not os.path.exists(self.new):
            raise TaskError("Device {} not exist!".format(self.new))

    @contextmanager
    def backup(self):
        """
        Backup the configuration file before modify
        """
        shutil.copyfile(self.conf, self.bak)
        try:
            yield
        finally:
            if self.bak:
                shutil.copyfile(self.bak, self.conf)

    def run(self):
        """
        Change the SBD DEVICE of configuration file
        """
        with open(self.edit, "w") as editfd:
            with open(self.conf, "r") as oldfd:
                for line in oldfd.readlines():
                    if line.strip().startswith("SBD_DEVICE"):
                        line = "SBD_DEVICE='" + self.new +"'\n"
                    editfd.write(line)

        try:
            shutil.copymode(self.conf, self.edit)
            os.remove(self.conf)
            shutil.move(self.edit, self.conf)
            os.remove(self.bak)
            self.bak = None
        except:
            raise TaskError("Fail to modify file {}".format(self.conf))

    def verify(self):
        """
        Verify the modification is working
        """
        sbd_options = crmshutils.parse_sysconfig(self.conf)

        if sbd_options["SBD_DEVICE"] == self.new:
            self.info("SBD DEVICE change succeed")
        else:
            raise TaskError("Fail to replace SBD device {} in {}!".
                            format(self.new, config.SBD_CONF))
