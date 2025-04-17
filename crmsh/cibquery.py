"""utilities for parsing CIB xml"""
import dataclasses
import typing

import lxml.etree

from crmsh import constants


@dataclasses.dataclass(frozen=True)
class ResourceAgent:
    m_class: str
    m_provider: typing.Optional[str]
    m_type: str


@dataclasses.dataclass(frozen=True)
class ClusterNode:
    node_id: int
    uname: str


def get_configured_resource_agents(cib: lxml.etree.Element) -> typing.Set[ResourceAgent]:
    return set(
        ResourceAgent(e.get('class'), e.get('provider'), e.get('type'))
        for e in cib.xpath('/cib/configuration/resources//primitive')
    )


def has_primitive_filesystem_with_fstype(cib: lxml.etree.Element, fstype: str) -> bool:
    return bool(cib.xpath(
        '/cib/configuration/resources//primitive[@class="ocf" and @provider="heartbeat" and @type="Filesystem"]'
        f'/instance_attributes/nvpair[@name="fstype" and @value="{fstype}"]'
    ))


def get_primitives_with_ra(cib: lxml.etree.Element, ra: ResourceAgent) -> list[str]:
    """
    Given cib and ResourceAgent instance, return id list of primitives that matched
    consider provider as optional
    """
    provider_condition = f' and @provider="{ra.m_provider}"' if ra.m_provider else ""
    return cib.xpath(
        f'/cib/configuration/resources//primitive[@class="{ra.m_class}"{provider_condition} and @type="{ra.m_type}"]/@id'
    )


def get_parameter_value(cib: lxml.etree.Element, res_id: str, param_name: str) -> typing.Optional[str]:
    result = cib.xpath(
        f'/cib/configuration/resources//primitive[@id="{res_id}"]'
        f'/instance_attributes/nvpair[@name="{param_name}"]/@value'
    )
    return result[0] if result else None


def get_cluster_nodes(cib: lxml.etree.Element) -> list[ClusterNode]:
    """Return a list of cluster nodes, excluding pacemaker-remote nodes"""
    result = list()
    for element in cib.xpath(constants.XML_NODE_PATH):
        node_id = element.get('id')
        uname = element.get('uname')
        if element.get('type') == 'remote':
            xpath = "//primitive[@provider='pacemaker' and @type='remote']/instance_attributes/nvpair[@name='server' and @value='{}']".format(
                uname if uname is not None else node_id
            )
            if cib.xpath(xpath):
                continue
        assert node_id
        assert uname
        result.append(ClusterNode(int(node_id), uname))
    return result
