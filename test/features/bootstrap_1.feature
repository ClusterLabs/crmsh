@bootstrap
Feature: HA bootstrap process 1

  Scenario: 1. Init cluster service on node "hanode1"
    Given   Cluster service is "stopped" on "local"
    When    Run "crm cluster init -y --no-overwrite-sshkey" on "local"
    Then    Cluster service is "started" on "local"

  Scenario: 2. Node "hanode2" join the cluster
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"

  Scenario: 3. Remove peer node "hanode2"
    Given   Cluster service is "started" on "local"
    And     Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    When    Run "crm cluster remove hanode2 -y" on "local"
    Then    Cluster service is "started" on "local"
    And     Cluster service is "stopped" on "hanode2"
    And     Online nodes are "hanode1"

  Scenario: 4. Remove local node "hanode1"
    Given   Cluster service is "started" on "local"
    And     Online nodes are "hanode1"
    When    Run "crm cluster remove hanode1 -y --force" on "local"
    Then    Cluster service is "stopped" on "hanode1"
