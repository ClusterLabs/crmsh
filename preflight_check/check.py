import re
from . import utils
from . import task
from crmsh import utils as crmshutils
from crmsh import bootstrap as crmshboot
from crmsh import completers


def check(context):
    """
    Check environment and cluster state if related options are enabled
    """
    if context.env_check:
        check_environment()
    if context.cluster_check:
        check_cluster()
    print()


def check_environment():
    """
    A set of functions to check environment
    """
    print("\n============ Checking environment ============")
    check_my_hostname_resolves()
    check_time_service()
    check_firewall()


def check_my_hostname_resolves():
    """
    check if the hostname is resolvable
    """
    task_inst = task.TaskCheck("Checking hostname resolvable")
    with task_inst.run():
        if not crmshboot.my_hostname_resolves():
            task_inst.error('''Hostname "{}" is unresolvable.
  Please add an entry to /etc/hosts or configure DNS.'''.format(utils.this_node()))


def check_time_service():
    """
    Check time service
    """
    task_inst = task.TaskCheck("Checking time service")
    with task_inst.run():
        timekeepers = ('chronyd.service', 'ntp.service', 'ntpd.service')
        timekeeper = None
        for tk in timekeepers:
            if crmshutils.service_is_available(tk):
                timekeeper = tk
                break
        else:
            task_inst.warn("No NTP service found.")
            return

        task_inst.info("{} is available".format(timekeeper))
        if crmshutils.service_is_enabled(timekeeper):
            task_inst.info("{} is enabled".format(timekeeper))
        else:
            task_inst.warn("{} is disabled".format(timekeeper))
        if crmshutils.service_is_active(timekeeper):
            task_inst.info("{} is active".format(timekeeper))
        else:
            task_inst.warn("{} is not active".format(timekeeper))


def check_port_open(task, firewall_type):
    """
    Check whether corosync port is blocked by iptables
    """
    ports = utils.corosync_port_list()
    if not ports:
        task.error("Can not get corosync's port")
        return

    if firewall_type == "firewalld":
        rc, out, err = crmshutils.get_stdout_stderr('firewall-cmd --list-port')
        if rc != 0:
            task.error(err)
            return
        for p in ports:
            if re.search(' {}/udp'.format(p), out):
                task.info("UDP port {} is opened in firewalld".format(p))
            else:
                task.error("UDP port {} should open in firewalld".format(p))
    elif firewall_type == "SuSEfirewall2":
        #TODO
        pass


def check_firewall():
    """
    Check the firewall status
    """
    task_inst = task.TaskCheck("Checking firewall")
    with task_inst.run():
        for item in ("firewalld", "SuSEfirewall2"):
            if crmshutils.package_is_installed(item):
                task_inst.info("{}.service is available".format(item))
                if crmshutils.service_is_active(item):
                    task_inst.info("{}.service is active".format(item))
                    check_port_open(task_inst, item)
                else:
                    task_inst.warn("{}.service is not active".format(item))
                break
        else:
           task_inst.warn("Failed to detect firewall")


def check_cluster():
    """
    A set of functions to check cluster state
    """
    print("\n============ Checking cluster state ============")
    if not check_cluster_service():
        return
    check_fencing()
    check_nodes()
    check_resources()


def check_cluster_service(quiet=False):
    """
    Check service status of pacemaker/corosync
    """
    task_inst = task.TaskCheck("Checking cluster service", quiet=quiet)
    with task_inst.run():
        if crmshutils.service_is_enabled("pacemaker"):
            task_inst.info("pacemaker.service is enabled")
        else:
            task_inst.warn("pacemaker.service is disabled")

        if crmshutils.service_is_enabled("corosync"):
            task_inst.warn("corosync.service is enabled")

        for s in ("corosync", "pacemaker"):
            if crmshutils.service_is_active(s):
                task_inst.info("{}.service is running".format(s))
            else:
                task_inst.error("{}.service is not running!".format(s))
        return task_inst.passed


def check_fencing():
    """
    Check STONITH/Fence:
      Whether stonith is enabled
      Whether stonith resource is configured and running
    """
    task_inst = task.TaskCheck("Checking STONITH/Fence")
    with task_inst.run():
        if not utils.FenceInfo().fence_enabled:
            task_inst.warn("stonith is disabled")
            return

        task_inst.info("stonith is enabled")
        rc, outp, _ = crmshutils.get_stdout_stderr("crm_mon -r1 | grep '(stonith:.*):'")
        if rc != 0:
            task_inst.warn("No stonith resource configured!")
            return

        res = re.search(r'([^\s]+)\s+\(stonith:(.*)\):\s+(\w+)', outp)
        res_name, res_agent, res_state = res.groups()
        common_msg = "stonith resource {}({})".format(res_name, res_agent)
        state_msg = "{} is {}".format(common_msg, res_state)

        task_inst.info("{} is configured".format(common_msg))
        if res_state == "Started":
            task_inst.info(state_msg)
        else:
            task_inst.warn(state_msg)

        if re.search(r'sbd$', res_agent):
            if crmshutils.service_is_active("sbd"):
                task_inst.info("sbd service is running")
            else:
                task_inst.warn("sbd service is not running!")


def check_nodes():
    """
    Check nodes info:
      Current DC
      Quorum status
      Online/OFFLINE/UNCLEAN nodes
    """
    task_inst = task.TaskCheck("Checking nodes")
    with task_inst.run():
        rc, outp, errp = crmshutils.get_stdout_stderr("crm_mon -1")
        if rc != 0:
            task_inst.error("run \"crm_mon -1\" error: {}".format(errp))
            return
        # check DC
        res = re.search(r'Current DC: (.*) \(', outp)
        if res:
            task_inst.info("DC node: {}".format(res.group(1)))

        # check quorum
        if re.search(r'partition with quorum', outp):
            task_inst.info("Cluster have quorum")
        else:
            task_inst.warn("Cluster lost quorum!")

        # check Online nodes
        res = re.search(r'Online:\s+(\[.*\])', outp)
        if res:
            task_inst.info("Online nodes: {}".format(res.group(1)))

        # check OFFLINE nodes
        res = re.search(r'OFFLINE:\s+(\[.*\])', outp)
        if res:
            task_inst.warn("OFFLINE nodes: {}".format(res.group(1)))

        # check UNCLEAN nodes
        res = re.findall(r'Node (.*): UNCLEAN', outp)
        for item in res:
            task_inst.warn('Node {} is UNCLEAN!'.format(item))


def check_resources():
    """
    Check items of Started/Stopped/FAILED resources
    """
    task_inst = task.TaskCheck("Checking resources")
    with task_inst.run():
        started_list = completers.resources_started()
        stopped_list = completers.resources_stopped()
        # TODO need suitable method to get failed resources list
        failed_list = []
        if started_list:
            task_inst.info("Started resources: {}".format(','.join(started_list)))
        if stopped_list:
            task_inst.info("Stopped resources: {}".format(','.join(stopped_list)))
        if failed_list:
            task_inst.warn("Failed resources: {}".format(','.join(failed_list)))
