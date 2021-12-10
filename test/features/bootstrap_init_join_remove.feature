@bootstrap
Feature: crmsh bootstrap process - init, join and remove

  Test crmsh bootstrap init/join/remove process
  Tag @clean means need to stop cluster service if the service is available

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
  Scenario: Init cluster service on node "hanode1", and join on node "hanode2"

  @clean
  Scenario: Support --all or specific node to manage cluster and nodes
    When    Run "crm node standby --all" on "hanode1"
    Then    Node "hanode1" is standby
    And     Node "hanode2" is standby
    When    Run "crm node online --all" on "hanode1"
    Then    Node "hanode1" is online
    And     Node "hanode2" is online
    When    Wait for DC
    When    Run "crm cluster stop --all" on "hanode1"
    Then    Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster start --all" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Cluster service is "started" on "hanode2"
    When    Wait for DC
    When    Run "crm cluster stop hanode2" on "hanode1"
    Then    Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster start hanode2" on "hanode1"
    Then    Cluster service is "started" on "hanode2"
    When    Run "crm cluster disable hanode2" on "hanode1"
    Then    Cluster service is "disabled" on "hanode2"
    When    Run "crm cluster enable hanode2" on "hanode1"
    Then    Cluster service is "enabled" on "hanode2"
    When    Run "crm cluster restart --all" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Cluster service is "started" on "hanode2"

  @clean
  Scenario: Remove peer node "hanode2"
    When    Run "crm cluster remove hanode2 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    And     Online nodes are "hanode1"
    And     Show cluster status on "hanode1"

  @clean
  Scenario: Remove local node "hanode1"
    When    Run "crm cluster remove hanode1 -y --force" on "hanode1"
    Then    Cluster service is "stopped" on "hanode1"
    And     Cluster service is "started" on "hanode2"
    And     Show cluster status on "hanode2"
