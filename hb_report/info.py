
import os

import utils
from crmsh import utils as crmutils


SYSINFO_F = "sysinfo.txt"


def cluster_info():
    return utils.rpm_version("corosync")


def crmsh_info():
    return utils.rpm_version("crmsh")


def sys_info(context):
    '''
    some basic system info and stats
    '''
    out_string = "----- Cluster info -----\n"
    out_string += cluster_info()
    out_string += crmsh_info()

    out_f = os.path.join(context.work_dir, SYSINFO_F)
    crmutils.str2file(out_string, out_f)
