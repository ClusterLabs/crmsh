@qdevice
Feature: corosync qdevice/qnetd setup/remove process

  Test corosync qdevice/qnetd setup/remove process
  Tag @clean means need to stop cluster service if the service is available
  Need nodes: hanode1 hanode2 hanode3 hanode4 qnetd-node

  Background: Cluster and qdevice service are stopped
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    And     Service "corosync-qdevice" is "stopped" on "hanode1"
    And     Service "corosync-qdevice" is "stopped" on "hanode2"

  @clean
  Scenario: Setup qdevice/qnetd during init/join process
    When    Run "crm cluster init --qnetd-hostname=qnetd-node -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    # for bsc#1181415
    Then    Expected "Restarting cluster service" in stdout
    And     Service "corosync-qdevice" is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    And     Service "corosync-qdevice" is "started" on "hanode2"
    And     Service "corosync-qnetd" is "started" on "qnetd-node"
    And     Show status from qnetd
    And     Show corosync qdevice configuration

  @clean
  Scenario: Setup qdevice/qnetd on running cluster
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "corosync-qdevice" is "stopped" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    And     Service "corosync-qdevice" is "stopped" on "hanode2"
    When    Run "echo "# This is a test for bsc#1166684"|sudo tee -a /etc/corosync/corosync.conf" on "hanode1"
    When    Run "scp /etc/corosync/corosync.conf root@hanode2:/etc/corosync" on "hanode1"
    When    Run "crm cluster init qdevice --qnetd-hostname=qnetd-node -y" on "hanode1"
    # for bsc#1181415
    Then    Expected "Starting corosync-qdevice.service in cluster" in stdout
    Then    Service "corosync-qdevice" is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode2"
    And     Service "corosync-qnetd" is "started" on "qnetd-node"
    And     Show status from qnetd
    And     Show corosync qdevice configuration

  @clean
  Scenario: Remove qdevice from a two nodes cluster
    When    Run "crm cluster init --qnetd-hostname=qnetd-node -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    And     Service "corosync-qdevice" is "started" on "hanode2"
    And     Show corosync qdevice configuration
    When    Run "crm cluster remove --qdevice -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Cluster service is "started" on "hanode2"
    And     Service "corosync-qdevice" is "stopped" on "hanode1"
    And     Service "corosync-qdevice" is "stopped" on "hanode2"
    And     Show corosync qdevice configuration

  @clean
  Scenario: Setup qdevice on multi nodes
    When    Run "crm cluster init --qnetd-hostname=qnetd-node -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    And     Service "corosync-qdevice" is "started" on "hanode2"
    And     Expected votes will be "3"
    When    Run "crm cluster join -c hanode1 -y" on "hanode3"
    Then    Cluster service is "started" on "hanode3"
    And     Online nodes are "hanode1 hanode2 hanode3"
    And     Service "corosync-qdevice" is "started" on "hanode3"
    And     Expected votes will be "4"
    When    Run "crm cluster join -c hanode1 -y" on "hanode4"
    Then    Cluster service is "started" on "hanode4"
    And     Online nodes are "hanode1 hanode2 hanode3 hanode4"
    And     Service "corosync-qdevice" is "started" on "hanode4"
    And     Expected votes will be "5"
    And     Show corosync qdevice configuration
    And     Show status from qnetd

  @clean
  Scenario: Setup qdevice on multi nodes existing cluster
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    When    Run "crm cluster join -c hanode1 -y" on "hanode3"
    Then    Cluster service is "started" on "hanode3"
    And     Online nodes are "hanode1 hanode2 hanode3"
    When    Run "crm cluster join -c hanode1 -y" on "hanode4"
    Then    Cluster service is "started" on "hanode4"
    And     Online nodes are "hanode1 hanode2 hanode3 hanode4"
    And     Expected votes will be "4"
    When    Run "crm cluster init qdevice --qnetd-hostname=qnetd-node -y" on "hanode1"
    Then    Show corosync qdevice configuration
    And     Expected votes will be "5"
    And     Service "corosync-qdevice" is "started" on "hanode4"
    And     Service "corosync-qdevice" is "started" on "hanode3"
    And     Service "corosync-qdevice" is "started" on "hanode2"
    And     Service "corosync-qdevice" is "started" on "hanode1"
    And     Show status from qnetd

  @clean
  Scenario: Setup qdevice using IPv6
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    When    Run "crm cluster init qdevice --qnetd-hostname @qnetd-node.ip6.0 -y" on "hanode1"
    Then    Show corosync qdevice configuration
    And     Service "corosync-qdevice" is "started" on "hanode2"
    And     Service "corosync-qdevice" is "started" on "hanode1"
    And     Show status from qnetd

  @skip_non_root
  @clean
  Scenario: Passwordless for root, not for sudoer (bsc#1209193)
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    When    Run "useradd -m -s /bin/bash xin" on "hanode1"
    When    Run "echo "xin ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/xin" on "hanode1"
    When    Run "rm -f /root/.config/crm/crm.conf" on "hanode1"
    When    Run "useradd -m -s /bin/bash xin" on "hanode2"
    When    Run "echo "xin ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/xin" on "hanode2"
    When    Run "rm -f /root/.config/crm/crm.conf" on "hanode2"
    When    Run "su xin -c "sudo crm cluster init qdevice --qnetd-hostname=qnetd-node -y"" on "hanode1"
    Then    Service "corosync-qdevice" is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode2"

  @skip_non_root
  @clean
  Scenario: Missing crm/crm.conf (bsc#1209193)
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    When    Run "rm -f /root/.config/crm/crm.conf" on "hanode1"
    When    Run "rm -f /root/.config/crm/crm.conf" on "hanode2"
    When    Run "crm cluster init qdevice --qnetd-hostname=qnetd-node -y" on "hanode1"
    Then    Service "corosync-qdevice" is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode2"

  @clean
  Scenario: One qnetd for multi cluster, add in parallel
    When    Run "crm cluster init -n cluster1 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster init -n cluster2 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    When    Run "crm cluster init qdevice --qnetd-hostname qnetd-node -y" on "hanode1,hanode2"
    Then    Service "corosync-qdevice" is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode2"
    And     Service "corosync-qnetd" is "started" on "qnetd-node"
