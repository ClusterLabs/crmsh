"""utilities for parsing CIB xml"""
import dataclasses
import typing

import lxml.etree


@dataclasses.dataclass(frozen=True)
class ResourceAgent:
    m_class: str
    m_provider: typing.Optional[str]
    m_type: str


def get_configured_resource_agents(cib: lxml.etree.Element) -> typing.Set[ResourceAgent]:
    return set(
        ResourceAgent(e.get('class'), e.get('provider'), e.get('type'))
        for e in cib.xpath('/cib/configuration/resources/primitive')
    )
