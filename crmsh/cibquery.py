"""utilities for parsing CIB xml"""
import collections
import typing

import lxml.etree


ResourceAgent = collections.namedtuple('ResourceAgentDO', ['m_class', 'm_provider', 'm_type'])
# class: str
# provider: Optional[str]
# type: str


def get_configured_resource_agents(cib: lxml.etree.Element) -> typing.Set[ResourceAgent]:
    return set(
        ResourceAgent(e.get('class'), e.get('provider'), e.get('type'))
        for e in cib.xpath('/cib/configuration/resources/primitive')
    )
