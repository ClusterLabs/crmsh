FENCE_TIMEOUT = 60
FENCE_NODE = "crm_attribute -t status -N '{}' -n terminate -v true"
BLOCK_IP = '''iptables -{action} INPUT -s {peer_ip} -j DROP;
              iptables -{action} OUTPUT -d {peer_ip} -j DROP'''
NFT_TABLE = "crmsh_split_brain"
NFT_RULESET = '''destroy table inet {table}
table inet {table} {{
  chain input {{
    type filter hook input priority -300; policy accept;
{input_rules}
  }}
  chain output {{
    type filter hook output priority -300; policy accept;
{output_rules}
  }}
}}'''
NFT_APPLY_RULESET = "nft -f - <<'EOF'\n{ruleset}\nEOF"
NFT_DELETE_TABLE = "nft destroy table inet {table}"
SBD_CONF = "/etc/sysconfig/sbd"
