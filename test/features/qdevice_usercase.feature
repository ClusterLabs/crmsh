@qdevice
Feature: Verify usercase master survive when split-brain

  Steps to setup a two-nodes cluster with heuristics qdevice,
  started with a promotable clone resource, and make sure master side always with quorum:
  1. Setup a two-nodes cluster
  2. Generate script to check whether this node is master
  3. Add a promotable clone resource
  4. Setup qdevice with heuristics
  5. Use iptables command to simulate split-brain
  6. Check whether hanode1 has quorum, while hanode2 doesn't

  Tag @clean means need to stop cluster service if the service is available
  Need nodes: hanode1 hanode2 qnetd-node

  Background: Cluster and qdevice service are stopped
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    And     Service "corosync-qdevice" is "stopped" on "hanode1"
    And     Service "corosync-qdevice" is "stopped" on "hanode2"

  @clean
  Scenario: Setup qdevice with heuristics
    When    Run "crm cluster init -y --qnetd-hostname=qnetd-node --qdevice-heuristics="/usr/bin/test -f /tmp/heuristics.txt" --qdevice-heuristics-mode="on"" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    And     Service "corosync-qdevice" is "started" on "hanode2"
    And     Service "corosync-qnetd" is "started" on "qnetd-node"
    And     Show corosync qdevice configuration
    When    Run "crm corosync status qnetd" on "hanode1"
    Then    Expected regex "Heuristics:\s+Fail" in stdout
    When    Run "touch /tmp/heuristics.txt" on "hanode1"
    When    Run "sleep 30" on "hanode1"
    When    Run "crm corosync status qnetd" on "hanode1"
    Then    Expected regex "Heuristics:\s+Pass" in stdout

  @clean
  Scenario: Master survive when split-brain
    # Setup a two-nodes cluster
    When    Run "crm cluster init -y -i eth0" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y -i eth0" on "hanode2"
    Then    Cluster service is "started" on "hanode2"

    # Generate script to check whether this node is master
    When    Write multi lines to file "/etc/corosync/qdevice/check_master.sh" on "hanode1"
      """
      #!/usr/bin/sh
      crm_resource --locate -r promotable-1 2>&1 | grep -E "Master|Promoted" | grep `crm_node -n` >/dev/null 2>&1
      """
    And     Run "chmod +x /etc/corosync/qdevice/check_master.sh" on "hanode1"
    When    Write multi lines to file "/etc/corosync/qdevice/check_master.sh" on "hanode2"
      """
      #!/usr/bin/sh
      crm_resource --locate -r promotable-1 2>&1 | grep -E "Master|Promoted" | grep `crm_node -n` >/dev/null 2>&1
      """
    And     Run "chmod +x /etc/corosync/qdevice/check_master.sh" on "hanode2"
    # Add a promotable clone resource and make sure hanode1 is master
    And     Run "crm configure primitive stateful-1 ocf:pacemaker:Stateful op monitor role=Promoted interval=10s op monitor role=Unpromoted interval=5s" on "hanode1"
    And     Run "crm configure clone promotable-1 stateful-1 meta promotable=true" on "hanode1"
    And     Run "sleep 5" on "hanode1"
    Then    Show cluster status on "hanode1"

    # Setup qdevice with heuristics
    When    Run "crm cluster init qdevice --qnetd-hostname=qnetd-node --qdevice-heuristics=/etc/corosync/qdevice/check_master.sh -y" on "hanode1"
    Then    Service "corosync-qdevice" is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode2"
    When    Run "sleep 5" on "hanode1"
    Then    Show status from qnetd
    When    Run "corosync-quorumtool -s" on "hanode1"
    Then    Expected "Quorate:          Yes" in stdout
    # Use iptables command to simulate split-brain
    When    Run "iptables -I INPUT -s @hanode2.ip.default -j DROP; sudo iptables -I OUTPUT -d @hanode2.ip.default -j DROP" on "hanode1"
    And     Run "iptables -I INPUT -s @hanode1.ip.default -j DROP; sudo iptables -I OUTPUT -d @hanode1.ip.default -j DROP" on "hanode2"
    # Check whether hanode1 has quorum, while hanode2 doesn't
    And     Run "sleep 20" on "hanode1"
    When    Run "crm corosync status quorum" on "hanode1"
    Then    Expected "Quorate:          Yes" in stdout
    When    Run "crm corosync status quorum" on "hanode2"
    Then    Expected "Quorate:          No" in stdout
    And     Show cluster status on "hanode1"
    And     Show cluster status on "hanode2"
