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

