1. ensure these packages are installed
2. ensure these configuration files are installed
  2.1 configuration files can use some templating language
  2.2 variables collected from environment on target node
  2.3 variables can also be provided by caller
3. ensure these CIB elements exist
  2.2 same thing there, template input => output

old-style: runs steps
new-style: services + install + cib

services:
  - haproxy

install:
  - template: corosync.cfg
    target: /etc/corosync/corosync.cfg

  - edit: /etc/csync2/csync2.cfg
    replace: "}\n"
    with: "include /etc/haproxy/haproxy.cfg\n}\n"

cib: >
    primitive blah1 Dummy params ip={{node.ip}}
