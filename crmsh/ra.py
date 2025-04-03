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
from .utils import stdout2list, is_program, to_ascii
from .utils import crm_msec, crm_time_cmp
from . import log


logger = log.setup_logger(__name__)


#
# Resource Agents interface (meta-data, parameters, etc)
#


def crm_resource(opts):
    '''
    Get information from crm_resource.
    '''
    _rc, l = stdout2list("crm_resource %s" % opts, stderr_on=False)
    return l


def ra_classes():
    '''
    List of RA classes.
    '''
    if cache.is_cached("ra_classes"):
        return cache.retrieve("ra_classes")
    l = crm_resource("--list-standards")
    l = [x for x in l if x not in ("lsb", "service")]
    l.sort()
    return cache.store("ra_classes", l)


def ra_providers(ra_type, ra_class="ocf"):
    'List of providers for a class:type.'
    ident = "ra_providers-%s-%s" % (ra_class, ra_type)
    if cache.is_cached(ident):
        return cache.retrieve(ident)
    if ra_class != "ocf":
        logger.error("no providers for class %s", ra_class)
        return []
    l = crm_resource("--list-ocf-alternatives %s" % ra_type)
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


def ra_types(ra_class="ocf", ra_provider=""):
    '''
    List of RA type for a class.
    '''

    def find_types():
        """
        Actually go out and ask for the types of a class.
        """
        return crm_resource("--list-agents %s" % ra_class)

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
    if ra_provider:
        return crm_resource("--show-metadata %s:%s:%s" % (ra_class, ra_provider, ra_type))
    return crm_resource("--show-metadata %s:%s" % (ra_class, ra_type))


@utils.memoize
def get_stonithd_meta():
    return RAInfo(utils.pacemaker_fenced(), "metadata")


@utils.memoize
def get_properties_meta():
    cluster_option_meta = utils.get_cluster_option_metadata()
    if cluster_option_meta:
        return RAInfo("cluster_option", None,
                      exclude_from_completion=constants.controld_metadata_do_not_complete,
                      meta_string=cluster_option_meta)
    else:
        raise ValueError("No cluster option metadata found")


@utils.memoize
def get_property_options(property_name):
    return get_properties_meta().param_options(property_name)


@utils.memoize
def get_properties_list():
    try:
        return list(get_properties_meta().params().keys())
    except:
        return []


@utils.memoize
def get_resource_meta():
    resource_meta = utils.get_resource_metadata()
    if resource_meta:
        return RAInfo("resource_meta", None, meta_string=resource_meta)
    return None


@utils.memoize
def get_resource_meta_list():
    try:
        return list(get_resource_meta().params().keys())
    # use legacy code to get the resource metadata list
    except:
        return constants.rsc_meta_attributes


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
        return "%s:%s:%s" % (self.ra_class, self.ra_provider, self.ra_type) \
            if self.ra_class == "ocf" \
               else "%s:%s" % (self.ra_class, self.ra_type)

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

    def mk_ra_node(self):
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
        ident = "ra_params-%s" % self
        if cache.is_cached(ident):
            return cache.retrieve(ident)
        if self.mk_ra_node() is None:
            return None
        d = {}
        for c in self.ra_elem.xpath("//parameters/parameter"):
            name = c.get("name")
            if not name or name in self.excluded_from_completion:
                continue
            required = c.get("required") if not (c.get("deprecated") or c.get("obsoletes")) else "0"
            unique = c.get("unique")
            typ, default = _param_type_default(c)
            d[name] = {
                "required": required,
                "unique": unique,
                "type": typ,
                "default": default,
                "options": self.get_selecte_value_list(c)
            }
        items = list(d.items())
        # Sort the dictionary by required and then alphabetically
        items.sort(key=lambda item: (item[1]["required"] != '1', item[0]))
        d = dict(items)
        return cache.store(ident, d)

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

    def param_options(self, pname):
        '''
        Return parameter's option values if available
        '''
        d = self.params()
        try:
            return d[pname]["options"]
        except:
            return None

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
            rc = 0
            if "timeout" in item_dict:
                actual_timeout = item_dict["timeout"]
                timeout_string = "specified timeout"
            else:
                actual_timeout = default_timeout
                timeout_string = "default timeout"
            if actual_timeout and crm_time_cmp(adv_timeout, actual_timeout) > 0:
                logger.warning("%s: %s %s for %s is smaller than the advised %s",
                        ident, timeout_string, actual_timeout, op, adv_timeout)
                rc |= 1
            return rc

        def sanity_check_op_timeout(op, op_dict):
            """
            Helper method used by sanity_check_op, to check operation's timeout
            """
            rc = 0
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
            rc = 0
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
                        rc |= 1
                    elif actual_interval_msec in prev_intervals:
                        logger.warning("%s: interval in monitor must be unique, advised is %s", ident, adv_interval)
                        rc |= 1
                    else:
                        prev_intervals.append(actual_interval_msec)
            elif "interval" in op_dict[op]:
                value = op_dict[op]["interval"]
                value_msec = crm_msec(value)
                if op in self.no_interval_ops and value_msec != 0:
                    logger.warning("%s: Specified interval for %s is %s, it must be 0", ident, op, value)
                    rc |= 1
            return rc

        def sanity_check_op(op, op_dict):
            """
            Helper method used by sanity_check_ops.
            """
            rc = 0
            if self.ra_class == "stonith" and op in ("start", "stop"):
                return rc
            if op not in self.actions():
                logger.warning("%s: action '%s' not found in Resource Agent meta-data", ident, op)
                rc |= 1
                return rc
            rc |= sanity_check_op_interval(op, op_dict)
            rc |= sanity_check_op_timeout(op, op_dict)
            return rc


        rc = 0
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
        if self.mk_ra_node() is None:
            return ''
        l = []
        title = self.meta_title()
        l.append(title)
        longdesc = get_nodes_text(self.ra_elem, "longdesc")
        if longdesc:
            l.append(longdesc)
        if self.ra_class != "heartbeat":
            params = self.meta_parameters()
            if params:
                l.append(params.rstrip())
        actions = self.meta_actions()
        if actions:
            l.append(actions)
        return '\n\n'.join(l)

    def get_shortdesc(self, n):
        name = n.get("name")
        shortdesc = get_nodes_text(n, "shortdesc")
        longdesc = get_nodes_text(n, "longdesc")
        if shortdesc and shortdesc not in (name, longdesc, self.ra_type):
            return shortdesc
        return ''

    def meta_title(self):
        s = str(self)
        shortdesc = self.get_shortdesc(self.ra_elem)
        if shortdesc:
            s = "%s (%s)" % (shortdesc, s)
        return s

    def format_parameter(self, n):
        def meta_param_head():
            name = n.get("name")
            if not name:
                return None
            s = name
            if n.get("required") == "1":
                s = s + "*"
            typ, default = _param_type_default(n)
            if typ and default:
                s = "%s (%s, [%s])" % (s, typ, default)
            elif typ:
                s = "%s (%s)" % (s, typ)
            shortdesc = self.get_shortdesc(n)
            s = "%s: %s" % (s, shortdesc)
            return s
        head = meta_param_head()
        if not head:
            self.error("no name attribute for parameter")
            return ""
        l = [head]
        longdesc = get_nodes_text(n, "longdesc")
        select_values = self.get_selecte_value_list(n)
        if n.get("advanced") == "1":
            l.append(self.ra_tab + "*** Advanced Use Only ***")
        if n.get("generated") == "1":
            l.append(self.ra_tab + "*** Automatically generated by pacemaker ***")
        if n.find("deprecated") is not None:
            l.append(self.ra_tab + "*** Deprecated ***")
        if longdesc:
            l.append(self.ra_tab + longdesc.replace("\n", "\n" + self.ra_tab))
        if select_values:
            l.append(self.ra_tab + "Allowed values: " + ', '.join(select_values))
        l.append('')
        return '\n'.join(l)

    def get_selecte_value_list(self, node):
        """
        Get the list of select values from the node
        """
        content = node.find("content")
        if content is None:
            return []
        return [x.get("value") for x in content.findall("option")]

    def meta_parameter(self, param):
        if self.mk_ra_node() is None:
            return ''
        for c in self.ra_elem.xpath("//parameters/parameter"):
            if c.get("name") == param:
                return self.format_parameter(c)

    def meta_parameters(self):
        if self.mk_ra_node() is None:
            return ''
        l = []
        for c in self.ra_elem.xpath("//parameters/parameter"):
            s = self.format_parameter(c)
            if s:
                l.append(s)
        if l:
            return "Parameters (*: required, []: default):\n\n" + '\n'.join(l)

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
        return "Operations' defaults (advisory minimum):\n\n" + '\n'.join(l)


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
