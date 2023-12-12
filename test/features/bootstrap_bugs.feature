@bootstrap
Feature: Regression test for bootstrap bugs

  Tag @clean means need to stop cluster service if the service is available
  Need nodes: hanode1 hanode2 hanode3

  @clean
  Scenario: Set placement-strategy value as "default"(bsc#1129462)
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Show cluster status on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    And     Show cluster status on "hanode1"
    When    Run "crm configure get_property placement-strategy" on "hanode1"
    Then    Got output "default"

  @clean
  Scenario: Space value not allowed for option(bsc#1141976)
    When    Try "crm -c ' '"
    Then    Except "ERROR: Space value not allowed for dest "cib""
    When    Try "crm cluster init --name ' '"
    Then    Except "ERROR: cluster.init: Space value not allowed for dest "cluster_name""
    When    Try "crm cluster join -c ' '"
    Then    Except "ERROR: cluster.join: Space value not allowed for dest "cluster_node""
    When    Try "crm cluster remove -c ' '"
    Then    Except "ERROR: cluster.remove: Space value not allowed for dest "cluster_node""
    When    Try "crm cluster geo_init -a ' '"
    Then    Except "ERROR: cluster.geo_init: Space value not allowed for dest "arbitrator""
    When    Try "crm cluster geo_join -c ' '"
    Then    Except "ERROR: cluster.geo_join: Space value not allowed for dest "cluster_node""
    When    Try "crm cluster geo_init_arbitrator -c ' '"
    Then    Except "ERROR: cluster.geo_init_arbitrator: Space value not allowed for dest "cluster_node""

  @clean
  Scenario: Setup cluster with crossed network(udpu only)
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -u -i eth0 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Try "crm cluster join -c hanode1 -i eth1 -y" on "hanode2"
    Then    Cluster service is "stopped" on "hanode2"
    And     Except "Cannot see peer node "hanode1", please check the communication IP" in stderr
    When    Run "crm cluster join -c hanode1 -i eth0 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"

  @clean
  Scenario: Remove correspond nodelist in corosync.conf while remove(bsc#1165644)
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -u -i eth1 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -i eth1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    When    Run "crm corosync get nodelist.node.ring0_addr" on "hanode1"
    Then    Expected "@hanode2.ip.0" in stdout
    #And     Service "hawk.service" is "started" on "hanode2"
    When    Run "crm cluster remove hanode2 -y" on "hanode1"
    Then    Online nodes are "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    # verify bsc#1175708
    #And     Service "hawk.service" is "stopped" on "hanode2"
    When    Run "crm corosync get nodelist.node.ring0_addr" on "hanode1"
    Then    Expected "@hanode2.ip.0" not in stdout

  @clean
  Scenario: Multi nodes join in parallel(bsc#1175976)
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    And     Cluster service is "stopped" on "hanode3"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Show cluster status on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2,hanode3"
    Then    Cluster service is "started" on "hanode2"
    And     Cluster service is "started" on "hanode3"
    And     Online nodes are "hanode1 hanode2 hanode3"
    And     Show cluster status on "hanode1"
    And     File "/etc/corosync/corosync.conf" was synced in cluster

  @clean
  Scenario: Multi nodes join in parallel timed out(bsc#1175976)
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    And     Cluster service is "stopped" on "hanode3"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Show cluster status on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    # Try to simulate the join process hanging on hanode2 or hanode2 died
    # Just leave the lock directory unremoved
    When    Run "mkdir /run/.crmsh_lock_directory" on "hanode1"
    When    Try "crm cluster join -c hanode1 -y" on "hanode3"
    Then    Except "ERROR: cluster.join: Timed out after 120 seconds. Cannot continue since the lock directory exists at the node (hanode1:/run/.crmsh_lock_directory)"
    When    Run "rm -rf /run/.crmsh_lock_directory" on "hanode1"

  @clean
  Scenario: Change host name in /etc/hosts as alias(bsc#1183654)
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "echo '@hanode1.ip.0 HANODE1' >> /etc/hosts" on "hanode1"
    When    Run "echo '@hanode2.ip.0 HANODE2' >> /etc/hosts" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c HANODE1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    When    Run "crm cluster remove HANODE2 -y" on "hanode1"
    Then    Cluster service is "stopped" on "hanode2"
    And     Online nodes are "hanode1"

  @clean
  Scenario: Stop service quickly(bsc#1203601)
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    When    Run "crm cluster stop --all" on "hanode1"
    Then    Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster start --all;crm cluster stop --all" on "hanode1"
    Then    Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "systemctl start corosync" on "hanode1"
    Then    Service "corosync" is "started" on "hanode1"
    When    Run "crm cluster stop" on "hanode1"
    Then    Service "corosync" is "stopped" on "hanode1"

  @clean
  Scenario: Can't stop all nodes' cluster service when local node's service is down(bsc#1213889)
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    When    Wait for DC
    When    Wait "10" seconds
    Then    Online nodes are "hanode1 hanode2"
    # Add more operations
    When    Run "crm node standby hanode1" on "hanode1"
    When    Run "crm node online hanode1" on "hanode1"
    When    Run "crm node standby hanode2" on "hanode1"
    When    Run "crm node online hanode2" on "hanode1"
    When    Wait "10" seconds
    When    Run "crm cluster stop" on "hanode1"
    And     Run "crm cluster stop --all" on "hanode1"
    Then    Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
