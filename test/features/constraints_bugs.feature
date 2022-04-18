@constraints
Feature: Verify constraints(order/colocation/location) bug

  Tag @clean means need to stop cluster service if the service is available
  Need nodes: hanode1 hanode2

  Background: Setup a two nodes cluster
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Show cluster status on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    And     Show cluster status on "hanode1"

  @clean
  Scenario: Convert score to kind for rsc_order(bsc#1122391)
    When    Run "crm configure primitive d1 Dummy op monitor interval=10s" on "hanode1"
    And     Run "crm configure primitive d2 Dummy op monitor interval=10s" on "hanode1"
    And     Run "crm configure order o1 100: d1 d2" on "hanode1"
    When    Run "crm configure show" on "hanode1"
    Then    Expected "order o1 Mandatory: d1 d2" in stdout
