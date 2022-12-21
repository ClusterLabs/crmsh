@bootstrap
Feature: crmsh bootstrap process - init, join and remove

  Test crmsh bootstrap init/join/remove process
  Need nodes: hanode1 hanode2

  Scenario: Setup a two nodes cluster as alice and bob
    Given   Nodes ["hanode1", "hanode2"] are cleaned up
    And     Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "su alice -c 'crm cluster init -y'" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Show cluster status on "hanode1"
    When    Run "su bob -c 'crm cluster join -c alice@hanode1 -y'" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    And     Show cluster status on "hanode1"
