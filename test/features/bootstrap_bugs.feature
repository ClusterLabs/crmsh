@bootstrap
Feature: Regression test for bootstrap bugs

  Tag @clean means need to stop cluster service if the service is available

  @clean
  Scenario: Set placement-strategy value as "default"(bsc#1129462)
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y --no-overwrite-sshkey" on "hanode1"
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
    When    Run "crm cluster init -u -i eth0 -y --no-overwrite-sshkey" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Try "crm cluster join -c hanode1 -i eth1 -y" on "hanode2"
    Then    Cluster service is "stopped" on "hanode2"
    And     Except "Cannot see peer node "hanode1", please check the communication IP" in stderr
    When    Run "crm cluster join -c hanode1 -i eth0 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
