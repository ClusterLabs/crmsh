@operation
Feature: Test cluster/node/resources maintenance

  Tag @clean means need to stop cluster service if the service is available

  Background: Setup one node cluster and configure some resources
    Given     Cluster service is "stopped" on "hanode1"
    Given     Cluster service is "stopped" on "hanode2"
    When      Run "crm cluster init -y" on "hanode1"
    Then      Cluster service is "started" on "hanode1"
    When      Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then      Cluster service is "started" on "hanode2"
    When      Run "crm configure primitive d Dummy op monitor interval=3s" on "hanode1"
    Then      Resource "d" type "Dummy" is "Started"

  @clean
  Scenario:   Give error when start/stop resources while cluster in maintenance
    When      Run "crm maintenance on" on "hanode1"
    And       Try "crm resource stop d" on "hanode1"
    Then      Except "ERROR: resource.stop: Resource d is unmanaged" in stderr
    Then      Resource "d" type "Dummy" is "Started"
    When      Run "crm maintenance off" on "hanode1"
    When      Run "crm resource stop d" on "hanode1"
    Then      Resource "d" type "Dummy" is "Stopped"

  @clean
  Scenario:   Give error when start/stop resources while all nodes in maintenance
    When      Run "crm node maintenance hanode1" on "hanode1"
    When      Run "crm node maintenance hanode2" on "hanode2"
    And       Try "crm resource stop d" on "hanode1"
    Then      Except "ERROR: resource.stop: Resource d is unmanaged" in stderr
    Then      Resource "d" type "Dummy" is "Started"
    When      Run "crm node ready hanode1" on "hanode1"
    When      Run "crm node ready hanode2" on "hanode2"
    When      Run "crm resource stop d" on "hanode1"
    Then      Resource "d" type "Dummy" is "Stopped"

  @clean
  Scenario:   Give error when start/stop resources while node running this RA in maintenance
    When      Run "crm configure location loc1 d 100: hanode1" on "hanode1"
    And       Run "crm node maintenance hanode1" on "hanode1"
    And       Try "crm resource stop d" on "hanode1"
    Then      Except "ERROR: resource.stop: Resource d is unmanaged" in stderr
    Then      Resource "d" type "Dummy" is "Started"
    When      Run "crm node ready hanode1" on "hanode1"
    When      Run "crm resource stop d" on "hanode1"
    Then      Resource "d" type "Dummy" is "Stopped"

  @clean
  Scenario:   Give error when start/stop resources while this RA in maintenance
    When      Run "crm resource maintenance d on" on "hanode1"
    And       Try "crm resource stop d" on "hanode1"
    Then      Except "ERROR: resource.stop: Resource d is unmanaged" in stderr
    Then      Resource "d" type "Dummy" is "Started"
    When      Run "crm resource maintenance d off" on "hanode1"
    When      Run "crm resource stop d" on "hanode1"
    Then      Resource "d" type "Dummy" is "Stopped"
