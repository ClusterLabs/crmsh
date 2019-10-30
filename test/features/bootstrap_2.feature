@bootstrap
Feature: HA bootstrap process 2

  Scenario: 5. Init whole cluster service on node "hanode1"
    Given   Cluster service is "stopped" on "local"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y --no-overwrite-sshkey --nodes \"hanode1 hanode2\"" on "local"
    Then    Cluster service is "started" on "local"
    And     Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"

  @clean
  Scenario: 6. Bind specific network interface
    Given   Cluster service is "stopped" on "local"
    And     IP "20.20.20.2" is belong to "eth1"
    When    Run "crm cluster init -i eth1 -y" on "local"
    Then    Cluster service is "started" on "local"
    And     IP "20.20.20.2" is used by corosync

  @clean
  Scenario: 7. Using multiple network interface
    Given   Cluster service is "stopped" on "local"
    And     IP "10.10.10.2" is belong to "eth0"
    And     IP "20.20.20.2" is belong to "eth1"
    When    Run "crm cluster init -M -y" on "local"
    Then    Cluster service is "started" on "local"
    And     IP "10.10.10.2" is used by corosync
    And     IP "20.20.20.2" is used by corosync

  @clean
  Scenario: 8. Setup cluster name and virtual IP
    Given   Cluster service is "stopped" on "local"
    When    Run "crm cluster init -n hatest -A 10.10.10.123 -y" on "local"
    Then    Cluster service is "started" on "local"
    And     Cluster name is "hatest"
    And     Cluster virtual IP is "10.10.10.123"
