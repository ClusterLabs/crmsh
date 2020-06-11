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

  Background: Cluster and qdevice service are stopped
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    And     Service "corosync-qdevice" is "stopped" on "hanode1"
    And     Service "corosync-qdevice" is "stopped" on "hanode2"

  @clean
  Scenario: Master survive when split-brain
    # Setup a two-nodes cluster
    When    Run "crm cluster init -y -i eth0 --no-overwrite-sshkey" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"

    # Generate script to check whether this node is master
    When    Write multi lines to file "/etc/corosync/qdevice/check_master.sh"
      """
      #!/usr/bin/sh
      crm_resource --locate -r promotable-1 2>&1 | grep Master | grep `crm_node -n` >/dev/null 2>&1
      """
    And     Run "chmod +x /etc/corosync/qdevice/check_master.sh" on "hanode1"
    And     Run "scp -p /etc/corosync/qdevice/check_master.sh root@hanode2:/etc/corosync/qdevice" on "hanode1"
    # Add a promotable clone resource and make sure hanode1 is master
    And     Run "crm configure primitive stateful-1 ocf:pacemaker:Stateful op monitor_Slave interval=10s op monitor_Master interval=5s" on "hanode1"
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
    When    Run "ssh root@hanode2 corosync-quorumtool -s" on "hanode1"
    Then    Expected "Quorate:          Yes" in stdout
    # Use iptables command to simulate split-brain
    When    Run "iptables -I INPUT -s 172.17.0.3 -j DROP; iptables -I OUTPUT -d 172.17.0.3 -j DROP" on "hanode1"
    And     Run "iptables -I INPUT -s 172.17.0.2 -j DROP; iptables -I OUTPUT -d 172.17.0.2 -j DROP" on "hanode2"
    # Check whether hanode1 has quorum, while hanode2 doesn't
    And     Run "sleep 20" on "hanode1"
    When    Run "corosync-quorumtool -s" on "hanode1"
    Then    Expected "Quorate:          Yes" in stdout
    When    Run "ssh root@hanode2 corosync-quorumtool -s" on "hanode1"
    Then    Expected "Quorate:          No" in stdout
    And     Show cluster status on "hanode1"
    And     Show cluster status on "hanode2"
