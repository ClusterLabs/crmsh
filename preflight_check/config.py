FENCE_TIMEOUT = 60
FENCE_NODE = "crm_attribute -t status -N '{}' -n terminate -v true"
BLOCK_IP = '''iptables -{action} INPUT -s {peer_ip} -j DROP;
              iptables -{action} OUTPUT -d {peer_ip} -j DROP'''
REMOVE_PORT = "firewall-cmd --zone=public --remove-port={port}/udp"
ADD_PORT = "firewall-cmd --zone=public --add-port={port}/udp"
FENCE_HISTORY = "stonith_admin -h {node}"
