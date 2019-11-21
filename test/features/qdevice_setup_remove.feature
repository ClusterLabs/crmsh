@qdevice
Feature: corosync qdevice/qnetd setup/remove process

  Test corosync qdevice/qnetd setup/remove process
  Tag @clean means need to stop cluster service if the service is available

  Background: Cluster and qdevice service are stopped
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    And     Service "corosync-qdevice" is "stopped" on "hanode1"
    And     Service "corosync-qdevice" is "stopped" on "hanode2"

  @clean
  Scenario: Setup qdevice/qnetd during init/join process
    When    Run "crm cluster init --qdevice=qnetd-node -y --no-overwrite-sshkey" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
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
    When    Run "crm cluster init -y --no-overwrite-sshkey" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "corosync-qdevice" is "stopped" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    And     Service "corosync-qdevice" is "stopped" on "hanode2"
    When    Run "crm cluster init qdevice --qdevice=qnetd-node -y" on "hanode1"
    Then    Service "corosync-qdevice" is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode2"
    And     Service "corosync-qnetd" is "started" on "qnetd-node"
    And     Show status from qnetd
    And     Show corosync qdevice configuration

  @clean
  Scenario: Remove qdevice from a two nodes cluster
    When    Run "crm cluster init --qdevice=qnetd-node -y --no-overwrite-sshkey" on "hanode1"
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
