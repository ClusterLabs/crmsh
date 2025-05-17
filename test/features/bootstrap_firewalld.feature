@bootstrap
Feature: Test deployment of high-availability firewalld service

  Need nodes: hanode1 hanode2 qnetd-node

  Scenario: The high-availability firewalld service is available
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    And     Service "firewalld" is "stopped" on "hanode1"
    And     Service "firewalld" is "stopped" on "hanode2"
    And     The "high-availability" firewalld service is available on "hanode1"
    And     The "high-availability" firewalld service is available on "hanode2"
