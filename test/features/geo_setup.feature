@geo
Feature: geo cluster

  Test geo cluster setup using bootstrap
  Tag @clean means need to stop cluster service if the service is available
  Need nodes: hanode1 hanode2 hanode3

  @clean
  Scenario: GEO cluster setup
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y -n cluster1" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm configure primitive vip IPaddr2 params ip=@vip.0" on "hanode1"

    When    Run "crm cluster init -y -n cluster2" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    When    Run "crm configure primitive vip IPaddr2 params ip=@vip.1" on "hanode2"

    When    Run "crm cluster geo_init -y --clusters "cluster1=@vip.0 cluster2=@vip.1" --tickets tickets-geo --arbitrator hanode3" on "hanode1"
    When    Run "crm cluster geo_join -y --cluster-node hanode1 --clusters "cluster1=@vip.0 cluster2=@vip.1"" on "hanode2"

    Given   Service "booth@booth" is "stopped" on "hanode3"
    When    Run "crm cluster geo_init_arbitrator -y --cluster-node hanode1" on "hanode3"
    Then    Service "booth@booth" is "started" on "hanode3"
    When    Run "crm resource start g-booth" on "hanode1"
    Then    Show cluster status on "hanode1"
    When    Run "crm resource start g-booth" on "hanode2"
    Then    Show cluster status on "hanode2"
