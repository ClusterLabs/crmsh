@bootstrap
Feature: HA bootstrap process 3

  Scenario: 9. Init cluster service with udpu
    Given   Cluster service is "stopped" on "local"
    When    Run "crm cluster init -u -y --no-overwrite-sshkey" on "local"
    Then    Cluster service is "started" on "local"
    And     Cluster is using udpu transport mode
    And     IP "10.10.10.2" is used by corosync
