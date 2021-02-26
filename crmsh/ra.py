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
from .utils import stdout2list, is_program, is_process, to_ascii
from .utils import os_types_list, get_stdout, find_value
from .utils import crm_msec, crm_time_cmp
from .msg import common_debug, common_err, common_warn, common_info

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
    _rc, glue_ver = get_stdout("%s -v" % lrmadmin_prog, stderr_on=False)
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
    _rc, s = get_stdout("crm_resource --list-standards", stderr_on=False)
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
            common_err("no providers for class %s" % ra_class)
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
            common_debug("stonith exited with code %d" % rc)
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
                  exclude_from_completion=constants.crmd_metadata_do_not_complete)


@utils.memoize
def get_stonithd_meta():
    return RAInfo(utils.pacemaker_fenced(), "metadata")


@utils.memoize
def get_cib_meta():
    return RAInfo(utils.pacemaker_based(), "metadata")


@utils.memoize
def get_properties_meta():
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
        common_debug("%s metadata exited with code %d" % (prog, rc))
    return []


def get_nodes_text(n, tag):
    try:
        return n.findtext(tag).strip()
    except:
        return ''


def mk_monitor_name(role, depth):
    depth = ("_%s" % depth) if depth != "0" else ""
    return role and role != "Started" and \
        "monitor_%s%s" % (role, depth) or \
        "monitor%s" % depth


def monitor_name_node(node):
    depth = node.get("depth") or '0'
    role = node.get("role")
    return mk_monitor_name(role, depth)


def monitor_name_pl(pl):
    depth = find_value(pl, "depth") or '0'
    role = find_value(pl, "role")
    return mk_monitor_name(role, depth)


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
    skip_ops = ("meta-data", "validate-all")
    skip_op_attr = ("name", "depth", "role")

    def __init__(self, ra_class, ra_type, ra_provider="heartbeat", exclude_from_completion=None):
        self.excluded_from_completion = exclude_from_completion or []
        self.ra_class = ra_class
        self.ra_type = ra_type
        self.ra_provider = ra_provider
        if ra_class == 'ocf' and not self.ra_provider:
            self.ra_provider = "heartbeat"
        self.ra_elem = None
        self.broken_ra = False

    def __str__(self):
        return "%s:%s:%s" % (self.ra_class, self.ra_provider, self.ra_type) \
            if self.ra_class == "ocf" \
               else "%s:%s" % (self.ra_class, self.ra_type)

    def error(self, s):
        common_err("%s: %s" % (self, s))

    def warn(self, s):
        common_warn("%s: %s" % (self, s))

    def info(self, s):
        common_info("%s: %s" % (self, s))

    def debug(self, s):
        common_debug("%s: %s" % (self, s))

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

    def params(self, completion=False):
        '''
        Construct a dict of dicts: parameters are keys and
        dictionary of attributes/values are values. Cached too.

        completion:
        If true, filter some (advanced) parameters out.
        '''
        if completion:
            if self.mk_ra_node() is None:
                return None
            return [c.get("name")
                    for c in self.ra_elem.xpath("//parameters/parameter")
                    if c.get("name") and c.get("name") not in self.excluded_from_completion]
        ident = "ra_params-%s" % self
        if cache.is_cached(ident):
            return cache.retrieve(ident)
        if self.mk_ra_node() is None:
            return None
        d = {}
        for c in self.ra_elem.xpath("//parameters/parameter"):
            name = c.get("name")
            if not name:
                continue
            required = c.get("required") if not (c.get("deprecated") or c.get("obsoletes")) else "0"
            unique = c.get("unique")
            typ, default = _param_type_default(c)
            d[name] = {
                "required": required,
                "unique": unique,
                "type": typ,
                "default": default,
            }
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
        d = {}
        for c in self.ra_elem.xpath("//actions/action"):
            name = c.get("name")
            if not name or name in self.skip_ops:
                continue
            if name == "monitor":
                name = monitor_name_node(c)
            d[name] = {}
            for a in list(c.attrib.keys()):
                if a in self.skip_op_attr:
                    continue
                v = c.get(a)
                if v:
                    d[name][a] = v
        # add monitor ops without role, if they don't already
        # exist
        d2 = {}
        for op in d:
            if re.match("monitor_[^0-9]", op):
                norole_op = re.sub(r'monitor_[^0-9_]+_(.*)', r'monitor_\1', op)
                if norole_op not in d:
                    d2[norole_op] = d[op]
        d.update(d2)
        return cache.store(ident, d)

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

            - the rhcs stonith agents sometimes require "action" (in
              the meta-data) and "port", but they're automatically
              supplied by stonithd
            '''
            if self.ra_class == "stonith" and \
                (self.ra_type.startswith("rhcs/") or
                 self.ra_type.startswith("fence_")):
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
                    common_err("{}: required parameter \"{}\" not defined".format(ident, p))
                    rc |= utils.get_check_rc()
        for p in d:
            if p.startswith("$"):
                # these are special, non-RA parameters
                continue
            if p not in self.params():
                common_err("{}: parameter \"{}\" is not known".format(ident, p))
                rc |= utils.get_check_rc()
        return rc

    def get_adv_timeout(self, op, node=None):
        if node is not None and op == "monitor":
            name = monitor_name_node(node)
        else:
            name = op
        try:
            return self.actions()[name]["timeout"]
        except:
            return None

    def sanity_check_ops(self, ident, ops, default_timeout):
        '''
        ops is a list of operations
        - do all operations exist
        - are timeouts sensible
        '''
        def sanity_check_op(op, n_ops, intervals):
            """
            Helper method used by sanity_check_ops.
            """
            rc = 0
            if self.ra_class == "stonith" and op in ("start", "stop"):
                return rc
            if op not in self.actions():
                common_warn("%s: action '%s' not found in Resource Agent meta-data" % (ident, op))
                rc |= 1
            if "interval" in n_ops[op]:
                v = n_ops[op]["interval"]
                v_msec = crm_msec(v)
                if op in ("start", "stop") and v_msec != 0:
                    common_warn("%s: Specified interval for %s is %s, it must be 0" % (ident, op, v))
                    rc |= 1
                if op.startswith("monitor") and v_msec != 0:
                    if v_msec not in intervals:
                        intervals[v_msec] = 1
                    else:
                        common_warn("%s: interval in %s must be unique" % (ident, op))
                        rc |= 1
            try:
                adv_timeout = self.actions()[op]["timeout"]
            except:
                return rc
            if "timeout" in n_ops[op]:
                v = n_ops[op]["timeout"]
                timeout_string = "specified timeout"
            else:
                v = default_timeout
                timeout_string = "default timeout"
            if crm_msec(v) < 0:
                return rc
            if crm_time_cmp(adv_timeout, v) > 0:
                common_warn("%s: %s %s for %s is smaller than the advised %s" %
                            (ident, timeout_string, v, op, adv_timeout))
                rc |= 1
            return rc

        rc = 0
        n_ops = {}
        for op in ops:
            n_op = monitor_name_pl(op[1]) if op[0] == "monitor" else op[0]
            n_ops[n_op] = {}
            for p, v in op[1]:
                if p in self.skip_op_attr:
                    continue
                n_ops[n_op][p] = v
        for req_op in self.required_ops:
            if req_op not in n_ops:
                if not (self.ra_class == "stonith" and req_op in ("start", "stop")):
                    n_ops[req_op] = {}
        intervals = {}
        for op in n_ops:
            rc |= sanity_check_op(op, n_ops, intervals)
        return rc

    def meta(self):
        '''
        RA meta-data as raw xml.
        Returns an etree xml object.
        '''
        sid = "ra_meta-%s" % self
        if cache.is_cached(sid):
            return cache.retrieve(sid)
        if self.ra_class in constants.meta_progs:
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
        if longdesc:
            l.append(self.ra_tab + longdesc.replace("\n", "\n" + self.ra_tab) + '\n')
        return '\n'.join(l)

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
            if name == "monitor":
                name = monitor_name_node(n)
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
        common_err("bad resource type specification %s" % s)
        return False
    if ra_class == "ocf":
        if not provider:
            common_err("provider could not be determined for %s" % s)
            return False
    else:
        if provider:
            common_warn("ra class %s does not support providers" % ra_class)
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
        from . import msg as msglog
        for msg in out.splitlines():
            if msg.startswith("ERROR: "):
                msglog.err_buf.error(msg[7:])
            elif msg.startswith("WARNING: "):
                msglog.err_buf.warning(msg[9:])
            elif msg.startswith("INFO: "):
                msglog.err_buf.info(msg[6:])
            elif msg.startswith("DEBUG: "):
                msglog.err_buf.debug(msg[7:])
            else:
                msglog.err_buf.writemsg(msg)
    return p.returncode, out


# vim:ts=4:sw=4:et:
