# Copyright (C) 2008-2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
# See COPYING for license information.

import os
import subprocess
import copy
import re
import glob
from lxml import etree
from . import cache
from . import constants
from . import config
from . import options
from . import userdir
from . import utils
from .sh import ShellUtils
from .utils import stdout2list, is_program, is_process, to_ascii
from .utils import os_types_list
from .utils import crm_msec, crm_time_cmp, VerifyResult
from . import log


logger = log.setup_logger(__name__)


#
# Resource Agents interface (meta-data, parameters, etc)
#

lrmadmin_prog = "lrmadmin"


def lrmadmin(opts, xml=False):
    """
    Get information directly from lrmd using lrmadmin.
    """
    _rc, l = stdout2list("%s %s" % (lrmadmin_prog, opts))
    if l and not xml:
        l = l[1:]  # skip the first line
    return l


def crm_resource(opts):
    '''
    Get information from crm_resource.
    '''
    _rc, l = stdout2list("crm_resource %s" % opts, stderr_on=False)
    return l


@utils.memoize
def can_use_lrmadmin():
    from distutils import version
    # after this glue release all users can get meta-data and
    # similar from lrmd
    minimum_glue = "1.0.10"
    _rc, glue_ver = ShellUtils().get_stdout("%s -v" % lrmadmin_prog, stderr_on=False)
    if not glue_ver:  # lrmadmin probably not found
        return False
    v_min = version.LooseVersion(minimum_glue)
    v_this = version.LooseVersion(glue_ver)
    if v_this < v_min:
        return False
    if userdir.getuser() not in ("root", config.path.crm_daemon_user):
        return False
    if not (is_program(lrmadmin_prog) and is_process(pacemaker_execd())):
        return False
    return utils.ext_cmd(">/dev/null 2>&1 %s -C" % lrmadmin_prog) == 0


@utils.memoize
def can_use_crm_resource():
    _rc, s = ShellUtils().get_stdout("crm_resource --list-ocf-providers", stderr_on=False)
    return s != ""


def ra_classes():
    '''
    List of RA classes.
    '''
    if cache.is_cached("ra_classes"):
        return cache.retrieve("ra_classes")
    if can_use_crm_resource():
        l = crm_resource("--list-standards")
    elif can_use_lrmadmin():
        l = lrmadmin("-C")
    else:
        l = ["heartbeat", "lsb", "nagios", "ocf", "stonith", "systemd"]
    l.sort()
    return cache.store("ra_classes", l)


def ra_providers(ra_type, ra_class="ocf"):
    'List of providers for a class:type.'
    ident = "ra_providers-%s-%s" % (ra_class, ra_type)
    if cache.is_cached(ident):
        return cache.retrieve(ident)
    if can_use_crm_resource():
        if ra_class != "ocf":
            logger.error("no providers for class %s", ra_class)
            return []
        l = crm_resource("--list-ocf-alternatives %s" % ra_type)
    elif can_use_lrmadmin():
        l = lrmadmin("-P %s %s" % (ra_class, ra_type), True)
    else:
        l = []
        if ra_class == "ocf":
            for s in glob.glob("%s/resource.d/*/%s" % (os.environ["OCF_ROOT"], ra_type)):
                a = s.split("/")
                if len(a) == 7:
                    l.append(a[5])
    l.sort()
    return cache.store(ident, l)


def ra_providers_all(ra_class="ocf"):
    '''
    List of providers for a class.
    '''
    if ra_class != "ocf":
        return []
    ident = "ra_providers_all-%s" % ra_class
    if cache.is_cached(ident):
        return cache.retrieve(ident)
    ocf = os.path.join(os.environ["OCF_ROOT"], "resource.d")
    if os.path.isdir(ocf):
        return cache.store(ident, sorted(s for s in os.listdir(ocf)
                                         if os.path.isdir(os.path.join(ocf, s))))
    return []


def os_types(ra_class):
    'List of types for a class.'
    def stonith_types():
        rc, l = stdout2list("stonith -L")
        if rc != 0:
            # stonith(8) may not be installed
            logger.debug("stonith exited with code %d", rc)
            l = []
        for ra in os_types_list("/usr/sbin/fence_*"):
            if ra not in ("fence_ack_manual", "fence_pcmk", "fence_legacy"):
                l.append(ra)
        return l

    def systemd_types():
        l = []
        rc, lines = stdout2list("systemctl list-unit-files --full")
        if rc != 0:
            return l
        t = re.compile(r'^(.+)\.service')
        for line in lines:
            m = t.search(line)
            if m:
                l.append(m.group(1))
        return l

    l = []
    if ra_class == "ocf":
        l = os_types_list("%s/resource.d/*/*" % (os.environ["OCF_ROOT"]))
    elif ra_class == "lsb":
        l = os_types_list("/etc/init.d/*")
    elif ra_class == "stonith":
        l = stonith_types()
    elif ra_class == "nagios":
        l = [x.replace("check_", "")
             for x in os_types_list("%s/check_*" % config.path.nagios_plugins)]
    elif ra_class == "systemd":
        l = systemd_types()
    l = list(set(l))
    l.sort()
    return l


def ra_types(ra_class="ocf", ra_provider=""):
    '''
    List of RA type for a class.
    '''

    def find_types():
        """
        Actually go out and ask for the types of a class.
        """
        if can_use_crm_resource():
            l = crm_resource("--list-agents %s" % ra_class)
        elif can_use_lrmadmin():
            l = lrmadmin("-T %s" % ra_class)
        else:
            l = os_types(ra_class)
        return l

    if not ra_class:
        ra_class = "ocf"
    ident = "ra_types-%s-%s" % (ra_class, ra_provider)
    if cache.is_cached(ident):
        return cache.retrieve(ident)

    if not ra_provider:
        def include(ra):
            return True
    else:
        def include(ra):
            return ra_provider in ra_providers(ra, ra_class)
    return cache.store(ident, sorted(list(set(ra for ra in find_types() if include(ra)))))


@utils.memoize
def ra_meta(ra_class, ra_type, ra_provider):
    """
    Return metadata for the given class/type/provider
    """
    if can_use_crm_resource():
        if ra_provider:
            return crm_resource("--show-metadata %s:%s:%s" % (ra_class, ra_provider, ra_type))
        return crm_resource("--show-metadata %s:%s" % (ra_class, ra_type))
    elif can_use_lrmadmin():
        return lrmadmin("-M %s %s %s" % (ra_class, ra_type, ra_provider), True)
    else:
        l = []
        if ra_class == "ocf":
            _rc, l = stdout2list("%s/resource.d/%s/%s meta-data" %
                                 (os.environ["OCF_ROOT"], ra_provider, ra_type))
        elif ra_class == "stonith":
            if ra_type.startswith("fence_") and os.path.exists("/usr/sbin/%s" % ra_type):
                _rc, l = stdout2list("/usr/sbin/%s -o metadata" % ra_type)
            else:
                _rc, l = stdout2list("stonith -m -t %s" % ra_type)
        elif ra_class == "nagios":
            _rc, l = stdout2list("%s/check_%s --metadata" %
                                 (config.path.nagios_plugins, ra_type))
        return l


@utils.memoize
def get_pe_meta():
    return RAInfo(utils.pacemaker_schedulerd(), "metadata")


@utils.memoize
def get_crmd_meta():
    return RAInfo(utils.pacemaker_controld(), "metadata",
                  exclude_from_completion=constants.controld_metadata_do_not_complete)


@utils.memoize
def get_stonithd_meta():
    return RAInfo(utils.pacemaker_fenced(), "metadata")


@utils.memoize
def get_cib_meta():
    return RAInfo(utils.pacemaker_based(), "metadata")


@utils.memoize
def get_properties_meta():
    cluster_option_meta = utils.get_cluster_option_metadata()
    if cluster_option_meta:
        return RAInfo("cluster_option", None,
                      exclude_from_completion=constants.controld_metadata_do_not_complete,
                      meta_string=cluster_option_meta)
    # get_xxx_meta() is a legacy code to get the metadata of the pacemaker daemons, 
    # which will be dropped when we fully adopt to crmsh-5.x with pacemaker 3.x.
    meta = copy.deepcopy(get_crmd_meta())
    meta.add_ra_params(get_pe_meta())
    meta.add_ra_params(get_cib_meta())
    return meta


@utils.memoize
def get_properties_list():
    try:
        return list(get_properties_meta().params().keys())
    except:
        return []


def prog_meta(prog):
    '''
    Do external program metadata.
    '''
    prog = utils.pacemaker_daemon(prog)
    if prog:
        rc, l = stdout2list("%s metadata" % prog)
        if rc == 0:
            return l
        logger.debug("%s metadata exited with code %d", prog, rc)
    return []


def get_nodes_text(n, tag):
    try:
        return n.findtext(tag).strip()
    except:
        return ''


def _param_type_default(n):
    """
    Helper function to get (type, default) from XML parameter node
    """
    try:
        content = n.find("content")
        return content.get("type"), content.get("default")
    except:
        return None, None


class RAInfo(object):
    '''
    A resource agent and whatever's useful about it.
    '''
    ra_tab = "    "  # four horses
    required_ops = ("start", "stop")
    no_interval_ops = ("start", "stop", "promote", "demote")
    skip_ops = ("meta-data", "validate-all")
    skip_op_attr = ("name",)

    def __init__(self, ra_class, ra_type, ra_provider="heartbeat", exclude_from_completion=None, meta_string=None):
        self.excluded_from_completion = exclude_from_completion or []
        self.ra_class = ra_class
        self.ra_type = ra_type
        self.ra_provider = ra_provider
        if ra_class == 'ocf' and not self.ra_provider:
            self.ra_provider = "heartbeat"
        self.ra_elem = None
        self.broken_ra = False
        self.meta_string = meta_string

    def __str__(self):
        if self.ra_class == "ocf":
            return f"{self.ra_class}:{self.ra_provider}:{self.ra_type}"
        return f"{self.ra_class}:{self.ra_type}"

    def error(self, s):
        logger.error("%s: %s", self, s)

    def warn(self, s):
        logger.warning("%s: %s", self, s)

    def info(self, s):
        logger.info("%s: %s", self, s)

    def debug(self, s):
        logger.debug("%s: %s", self, s)

    def add_ra_params(self, ra):
        '''
        Add parameters from another RAInfo instance.
        '''
        try:
            if self.mk_ra_node() is None or ra.mk_ra_node() is None:
                return
        except:
            return
        try:
            params_node = self.ra_elem.findall("parameters")[0]
        except:
            params_node = etree.SubElement(self.ra_elem, "parameters")
        for n in ra.ra_elem.xpath("//parameters/parameter"):
            params_node.append(copy.deepcopy(n))

    def mk_ra_node(self) -> etree._Element:
        '''
        Return the resource_agent node.
        '''
        if self.ra_elem is not None:
            return self.ra_elem
        # don't try again in vain
        if self.broken_ra:
            return None
        self.broken_ra = True
        meta = self.meta()
        if meta is None:
            if not config.core.ignore_missing_metadata:
                self.error("got no meta-data, does this RA exist?")
            return None
        self.ra_elem = meta
        try:
            assert self.ra_elem.tag == 'resource-agent'
        except Exception:
            self.error("meta-data contains no resource-agent element")
            return None
        if self.ra_class == "stonith":
            self.add_ra_params(get_stonithd_meta())
        self.broken_ra = False
        return self.ra_elem

    def params(self):
        '''
        Construct a dict of dicts: parameters are keys and
        dictionary of attributes/values are values. Cached too.

        completion:
        If true, filter some (advanced) parameters out.
        '''
        ident = f"ra_params-{self}"
        if cache.is_cached(ident):
            return cache.retrieve(ident)

        if self.mk_ra_node() is None:
            return None

        params_dict = {}
        for param in self.ra_elem.xpath("//parameters/parameter"):
            name = param.get("name")
            if not name or name in self.excluded_from_completion:
                continue

            deprecated = param.get("deprecated", "0")
            required = param.get("required", "0") if deprecated != "1" else "0"
            obsoletes = param.get("obsoletes")
            advanced = param.get("advanced", "0")
            generated = param.get("generated", "0")
            unique = param.get("unique")
            param_type, param_default = _param_type_default(param)

            params_dict[name] = {
                "required": required,
                "deprecated": deprecated,
                "obsoletes": obsoletes,
                "advanced": advanced,
                "generated": generated,
                "unique": unique,
                "type": param_type,
                "default": param_default,
                "options": self.get_selecte_value_list(param),
                "shortdesc": self.get_shortdesc(param),
                "longdesc": get_nodes_text(param, "longdesc")
            }

        items = list(params_dict.items())
        # Sort the dictionary by:
        # 1. Required parameters first
        # 2. Alphabetically by name
        # 3. Deprecated parameters last
        items.sort(key=lambda x: (x[1]["deprecated"] == "1", x[1]["required"] != "1", x[0]))
        params_dict = dict(items)

        return cache.store(ident, params_dict)

    def actions(self):
        '''
        Construct a dict of dicts: actions are keys and
        dictionary of attributes/values are values. Cached too.
        '''
        ident = "ra_actions-%s" % self
        if cache.is_cached(ident):
            return cache.retrieve(ident)
        if self.mk_ra_node() is None:
            return None

        actions_dict = {}
        actions_dict["monitor"] = []
        for elem in self.ra_elem.xpath("//actions/action"):
            name = elem.get("name")
            if not name or name in self.skip_ops:
                continue
            d = {}
            for key in list(elem.attrib.keys()):
                if key in self.skip_op_attr:
                    continue
                value = elem.get(key)
                if value:
                    d[key] = value
            if 'interval' not in d:
                d['interval'] = '0s'
            if name == "monitor":
                actions_dict[name].append(d)
            else:
                actions_dict[name] = d

        return cache.store(ident, actions_dict)

    def param_default(self, pname):
        '''
        Parameter's default.
        '''
        d = self.params()
        try:
            return d[pname]["default"]
        except:
            return None

    def normalize_parameters(self, root):
        """
        Find all instance_attributes/nvpair objects,
        check if parameter exists. If not, normalize name
        and check if THAT exists (replacing - with _).
        If so, change the name of the parameter.
        """
        params = self.params()
        if not params:
            return
        for nvp in root.xpath("instance_attributes/nvpair"):
            name = nvp.get("name")
            if name is not None and name not in params:
                name = name.replace("-", "_")
                if name in params:
                    nvp.attrib["name"] = name

    def sanity_check_params(self, ident, nvpairs, existence_only=False):
        '''
        nvpairs is a list of <nvpair> tags.
        - are all required parameters defined
        - do all parameters exist
        '''
        def reqd_params_list():
            '''
            List of required parameters.
            '''
            d = self.params()
            if not d:
                return []
            return [x for x in d if d[x]["required"] == '1']

        def unreq_param(p):
            '''
            Allow for some exceptions.
            '''
            if self.ra_class == "stonith" and self.ra_type.startswith("fence_"):
                if p in ("action", "port"):
                    return True
            return False

        rc = 0
        d = {}
        for nvp in nvpairs:
            if 'name' in nvp.attrib:
                d[nvp.get('name')] = nvp.get('value')
        if not existence_only:
            for p in reqd_params_list():
                if unreq_param(p):
                    continue
                if p not in d:
                    logger.error("%s: required parameter \"%s\" not defined", ident, p)
                    rc |= utils.get_check_rc()
        for p in d:
            if p.startswith("$"):
                # these are special, non-RA parameters
                continue
            if p not in self.params():
                logger.error("%s: parameter \"%s\" is not known", ident, p)
                rc |= utils.get_check_rc()
        return rc

    def get_op_attr_value(self, op, key, role=None, depth=None):
        """
        Get operation's attribute value
        Multi monitors should be distinguished by role or depth
        """
        try:
            # actions_dict example:
            # {'monitor': [
            #    {'depth': '0', 'timeout': '20s', 'interval': '10s', 'role': 'Promoted'},
            #    {'depth': '0', 'timeout': '20s', 'interval': '11s', 'role': 'Unpromoted'}
            #    ],
            #  'start': {'timeout': '20s'},
            #  'stop': {'timeout': '20s'}}
            actions_dict = self.actions()
            if not actions_dict:
                return None
            if op == 'monitor':
                if role is None and depth is None:
                    return actions_dict[op][0][key]
                if role:
                    for idx, monitor_item in enumerate(actions_dict[op]):
                        if monitor_item['role'] == role:
                            return actions_dict[op][idx][key]
                # Technically, there could be multiple entries defining different depths for a same role.
                if depth:
                    for idx, monitor_item in enumerate(actions_dict[op]):
                        if monitor_item['depth'] == depth:
                            return actions_dict[op][idx][key]
            else:
                return actions_dict[op][key]
        except:
            return None

    def sanity_check_ops(self, ident, ops, default_timeout):
        '''
        ops is a list of operations
        - do all operations exist
        - are timeouts sensible
        '''
        def timeout_check(op, item_dict, adv_timeout):
            """
            Helper method used by sanity_check_op_timeout, to check operation's timeout
            """
            rc = VerifyResult.SUCCESS
            if "timeout" in item_dict:
                actual_timeout = item_dict["timeout"]
                timeout_string = "specified timeout"
            else:
                actual_timeout = default_timeout
                timeout_string = "default timeout"
            if actual_timeout and crm_time_cmp(adv_timeout, actual_timeout) > 0:
                logger.warning("%s: %s %s for %s is smaller than the advised %s",
                        ident, timeout_string, actual_timeout, op, adv_timeout)
                rc |= VerifyResult.WARNING
            return rc

        def sanity_check_op_timeout(op, op_dict):
            """
            Helper method used by sanity_check_op, to check operation's timeout
            """
            rc = VerifyResult.SUCCESS
            role = None
            depth = None
            if op == "monitor":
                for monitor_item in op_dict[op]:
                    role = monitor_item['role'] if 'role' in monitor_item else None
                    depth = monitor_item['depth'] if 'depth' in monitor_item else None
                    adv_timeout = self.get_op_attr_value(op, "timeout", role=role, depth=depth)
                    rc |= timeout_check(op, monitor_item, adv_timeout)
            else:
                adv_timeout = self.get_op_attr_value(op, "timeout")
                rc |= timeout_check(op, op_dict[op], adv_timeout)
            return rc

        def sanity_check_op_interval(op, op_dict):
            """
            Helper method used by sanity_check_op, to check operation's interval
            """
            rc = VerifyResult.SUCCESS
            prev_intervals = []
            if op == "monitor":
                for monitor_item in op_dict[op]:
                    role = monitor_item['role'] if 'role' in monitor_item else None
                    depth = monitor_item['depth'] if 'depth' in monitor_item else None
                    # make sure interval in multi monitor operations is unique and non-zero
                    adv_interval = self.get_op_attr_value(op, "interval", role=role, depth=depth)
                    actual_interval_msec = crm_msec(monitor_item["interval"])
                    if actual_interval_msec == 0:
                        logger.warning("%s: interval in monitor should be larger than 0, advised is %s", ident, adv_interval)
                        rc |= VerifyResult.WARNING
                    elif actual_interval_msec in prev_intervals:
                        logger.warning("%s: interval in monitor must be unique, advised is %s", ident, adv_interval)
                        rc |= VerifyResult.WARNING
                    else:
                        prev_intervals.append(actual_interval_msec)
            elif "interval" in op_dict[op]:
                value = op_dict[op]["interval"]
                value_msec = crm_msec(value)
                if op in self.no_interval_ops and value_msec != 0:
                    logger.warning("%s: Specified interval for %s is %s, it must be 0", ident, op, value)
                    rc |= VerifyResult.WARNING
            return rc

        def sanity_check_op(op, op_dict):
            """
            Helper method used by sanity_check_ops.
            """
            rc = VerifyResult.SUCCESS
            if self.ra_class == "stonith" and op in ("start", "stop"):
                return rc
            if op not in self.actions():
                logger.error("Action '%s' not found in Resource Agent meta-data", op)
                rc |= VerifyResult.FATAL_ERROR
                return rc
            rc |= sanity_check_op_interval(op, op_dict)
            rc |= sanity_check_op_timeout(op, op_dict)
            return rc


        rc = VerifyResult.SUCCESS
        op_dict = {}
        op_dict["monitor"] = []
        # ops example:
        # [
        #   ['monitor', [['role', 'Promoted'], ['interval', '10s']]],
        #   ['monitor', [['role', 'Unpromoted'], ['interval', '0']]],
        #   ['start', [['timeout', '20s'], ['interval', '0']]]
        # ]
        for op in ops:
            n_op = op[0]
            d = {}
            for key, value in op[1]:
                if key in self.skip_op_attr:
                    continue
                d[key] = value
            if n_op == "monitor":
                op_dict["monitor"].append(d)
            else:
                op_dict[n_op] = d
        for req_op in self.required_ops:
            if req_op not in op_dict:
                if not (self.ra_class == "stonith" and req_op in ("start", "stop")):
                    op_dict[req_op] = {}
        # op_dict example:
        # {'monitor': [
        #    {'role': 'Promoted', 'interval': '10s'},
        #    {'role': 'Unpromoted', 'interval': '0'}],
        #    'start': {'timeout': '20s', 'interval': '0'},
        #    'stop': {}
        # }
        for op in op_dict:
            rc |= sanity_check_op(op, op_dict)
        return rc


    def meta(self):
        '''
        RA meta-data as raw xml.
        Returns an etree xml object.
        '''
        sid = "ra_meta-%s" % self
        if cache.is_cached(sid):
            return cache.retrieve(sid)
        if self.meta_string:
            l = self.meta_string.split('\n')
        elif self.ra_class in constants.meta_progs:
            l = prog_meta(self.ra_class)
        elif self.ra_class in constants.meta_progs_20:
            l = prog_meta(self.ra_class)
        else:
            l = ra_meta(self.ra_class, self.ra_type, self.ra_provider)
        if not l:
            return None
        try:
            xml = etree.fromstring('\n'.join(l))
        except Exception:
            self.error("Cannot parse meta-data XML")
            return None
        if xml.tag == "pacemaker-result":
            xml = xml.xpath("//resource-agent")[0]
        self.debug("read and cached meta-data")
        return cache.store(sid, xml)

    def meta_pretty(self):
        '''
        Print the RA meta-data in a human readable form.
        '''
        # get self.ra_elem
        if self.mk_ra_node() is None:
            return ''
        l = []
        # get title
        l.append(self.meta_title())
        # get longdesc
        longdesc = get_nodes_text(self.ra_elem, "longdesc")
        if longdesc:
            l.append(longdesc)
        # get parameters
        params = self.meta_parameters()
        if params:
            l.append(params.rstrip())
        # get actions
        actions = self.meta_actions()
        if actions:
            l.append(actions)

        return '\n\n'.join(l)

    def get_shortdesc(self, n) -> str:
        shortdesc_in_attr = n.get("shortdesc")
        if shortdesc_in_attr:
            return shortdesc_in_attr
        shortdesc_in_content = get_nodes_text(n, "shortdesc")
        if shortdesc_in_content:
            return shortdesc_in_content
        return ''

    def meta_title(self):
        name = str(self)
        shortdesc = self.get_shortdesc(self.ra_elem)
        return f"{name} - {shortdesc}" if shortdesc else name

    def format_parameter(self, name: str, parameter_dict: dict) -> str:

        def format_header(name: str, parameter_dict: dict) -> str:
            header_str = f"{name}"
            if parameter_dict.get("required") == "1":
                header_str += "*"
            if parameter_dict.get("deprecated") == "1":
                header_str += " (deprecated)"
            obsoletes = parameter_dict.get("obsoletes")
            if obsoletes:
                header_str += f" (obsoletes: {obsoletes})"

            typ, default = parameter_dict.get("type"), parameter_dict.get("default")
            if typ and default:
                header_str += f" ({typ}, [{default}]):"
            elif typ:
                header_str += f" ({typ}):"

            attr_str_map = {
                "advanced": "Advanced Use Only",
                "generated": "Automatically generated by pacemaker"
            }
            attr_str_list = [
                desc for attr, desc in attr_str_map.items()
                if parameter_dict.get(attr) == "1"
            ]
            if attr_str_list:
                header_str += f" *** {'; '.join(attr_str_list)} ***"

            shortdesc = parameter_dict.get("shortdesc")
            if shortdesc:
                header_str += f" {shortdesc}"

            return header_str

        header_str = format_header(name, parameter_dict)
        details = [header_str]

        longdesc = parameter_dict.get("longdesc")
        if longdesc:
            details.append(self.ra_tab + longdesc.replace("\n", "\n" + self.ra_tab))

        select_values = parameter_dict.get("options")
        if select_values:
            details.append(self.ra_tab + "Allowed values: " + ', '.join(select_values))

        details.append('')
        return '\n'.join(details)

    def get_selecte_value_list(self, node):
        """
        Get the list of select values from the node
        """
        content = node.find("content")
        if content is None:
            return []
        return [x.get("value") for x in content.findall("option")]

    def meta_parameter(self, param) -> str:
        parameters_dict = self.params()
        if not parameters_dict:
            return ''
        if param in parameters_dict:
            return self.format_parameter(param, parameters_dict[param])
        return ''

    def meta_parameters(self) -> str:
        parameters_dict = self.params()
        if not parameters_dict:
            return ''
        parameter_str_list = []
        for name, parameter_dict in parameters_dict.items():
            res = self.format_parameter(name, parameter_dict)
            if res:
                parameter_str_list.append(res)
        if parameter_str_list:
            return "## Parameters (*: required, []: default):\n\n" + '\n'.join(parameter_str_list)

    def meta_actions(self):
        def meta_action_head(n):
            name = n.get("name")
            if not name or name in self.skip_ops:
                return ''
            s = "%-13s" % name
            for a in list(n.attrib.keys()):
                if a in self.skip_op_attr:
                    continue
                v = n.get(a)
                if v:
                    s = "%s %s=%s" % (s, a, v)
            return s
        l = []
        for c in self.ra_elem.xpath("//actions/action"):
            s = meta_action_head(c)
            if s:
                l.append(self.ra_tab + s)
        if not l:
            return None
        return "## Operations' defaults (advisory minimum):\n\n" + '\n'.join(l)


def get_ra(r):
    """
    Argument is either an xml resource tag with class, provider and type attributes,
    or a CLI style class:provider:type string.
    """
    if isinstance(r, str):
        cls, provider, typ = disambiguate_ra_type(r)
    else:
        cls, provider, typ = r.get('class'), r.get('provider'), r.get('type')
    # note order of arguments!
    return RAInfo(cls, typ, provider)


#
# resource type definition
#
def ra_type_validate(s, ra_class, provider, rsc_type):
    '''
    Only ocf ra class supports providers.
    '''
    if not rsc_type:
        logger.error("bad resource type specification %s", s)
        return False
    if ra_class == "ocf":
        if not provider:
            logger.error("provider could not be determined for %s", s)
            return False
    else:
        if provider:
            logger.warning("ra class %s does not support providers", ra_class)
            return True
    return True


def pick_provider(providers):
    '''
    Pick the most appropriate choice from a
    list of providers, falling back to
    'heartbeat' if no good choice is found
    '''
    if not providers or 'heartbeat' in providers:
        return 'heartbeat'
    elif 'pacemaker' in providers:
        return 'pacemaker'
    return providers[0]


def disambiguate_ra_type(s):
    '''
    Unravel [class:[provider:]]type
    '''
    l = s.split(':')
    if not l or len(l) > 3:
        return ["", "", ""]
    if len(l) == 3:
        return l
    elif len(l) == 2:
        cl, tp = l
    else:
        if l[0].startswith("fence_"):
            cl, tp = "stonith", l[0]
        else:
            cl, tp = "ocf", l[0]
    pr = pick_provider(ra_providers(tp, cl)) if cl == 'ocf' else ''
    return cl, pr, tp


def can_validate_agent(agent):
    if utils.getuser() != 'root':
        return False
    if isinstance(agent, str):
        c, p, t = disambiguate_ra_type(agent)
        if c != "ocf":
            return False
        agent = RAInfo(c, t, p)
        if agent.mk_ra_node() is None:
            return False
    if len(agent.ra_elem.xpath('.//actions/action[@name="validate-all"]')) < 1:
        return False
    return True


def validate_agent(agentname, params, log=False):
    """
    Call the validate-all action on the agent, given
    the parameter hash params.
    agent: either a c:p:t agent name, or an RAInfo instance
    params: a hash of agent parameters
    Returns: (rc, out)
    """
    def find_agent():
        if not can_validate_agent(agentname):
            return None
        if isinstance(agentname, str):
            c, p, t = disambiguate_ra_type(agentname)
            if c != "ocf":
                raise ValueError("Only OCF agents are supported by this command")
            agent = RAInfo(c, t, p)
            if agent.mk_ra_node() is None:
                return None
        else:
            agent = agentname
        if len(agent.ra_elem.xpath('.//actions/action[@name="validate-all"]')) < 1:
            raise ValueError("validate-all action not supported by agent")
        return agent
    agent = find_agent()
    if agent is None:
        return (-1, "")

    my_env = os.environ.copy()
    my_env["OCF_ROOT"] = config.path.ocf_root
    for k, v in params.items():
        my_env["OCF_RESKEY_" + k] = v
    cmd = [os.path.join(config.path.ocf_root, "resource.d", agent.ra_provider, agent.ra_type), "validate-all"]
    if options.regression_tests:
        print(".EXT", " ".join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=my_env)
    _out, _ = p.communicate()
    out = to_ascii(_out)
    p.wait()

    if log is True:
        for msg in out.splitlines():
            if msg.startswith("ERROR: "):
                logger.error(msg[7:])
            elif msg.startswith("WARNING: "):
                logger.warning(msg[9:])
            elif msg.startswith("INFO: "):
                logger.info(msg[6:])
            elif msg.startswith("DEBUG: "):
                logger.debug(msg[7:])
            else:
                logger.info(msg)
    return p.returncode, out


DLM_RA_SCRIPTS = """
primitive {id} ocf:pacemaker:controld \
op start timeout=90 \
op stop timeout=100 \
op monitor interval=60 timeout=60"""
FILE_SYSTEM_RA_SCRIPTS = """
primitive {id} ocf:heartbeat:Filesystem \
params directory="{mnt_point}" fstype="{fs_type}" device="{device}" \
op monitor interval=20 timeout=40 \
op start timeout=60 \
op stop timeout=60"""
LVMLOCKD_RA_SCRIPTS = """
primitive {id} ocf:heartbeat:lvmlockd \
op start timeout=90 \
op stop timeout=100 \
op monitor interval=30 timeout=90"""
LVMACTIVATE_RA_SCRIPTS = """
primitive {id} ocf:heartbeat:LVM-activate \
params vgname={vgname} vg_access_mode=lvmlockd activation_mode=shared \
op start timeout=90s \
op stop timeout=90s \
op monitor interval=30s timeout=90s"""
GROUP_SCRIPTS = """
group {id} {ra_string}"""
CLONE_SCRIPTS = """
clone {id} {group_id} meta interleave=true"""


CONFIGURE_RA_TEMPLATE_DICT = {
        "DLM": DLM_RA_SCRIPTS,
        "Filesystem": FILE_SYSTEM_RA_SCRIPTS,
        "LVMLockd": LVMLOCKD_RA_SCRIPTS,
        "LVMActivate": LVMACTIVATE_RA_SCRIPTS,
        "GROUP": GROUP_SCRIPTS,
        "CLONE": CLONE_SCRIPTS
        }
# vim:ts=4:sw=4:et:
