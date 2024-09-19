@healthcheck
Feature: healthcheck detect and fix problems in a crmsh deployment

  Tag @clean means need to stop cluster service if the service is available
  Need nodes: hanode1 hanode2 hanode3

  Background: Setup a two nodes cluster
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    And     Cluster service is "stopped" on "hanode3"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Show cluster status on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    And     Show cluster status on "hanode1"

  @clean
  Scenario: An upgrade_seq file in ~hacluster/crmsh/ will be migrated to /var/lib/crmsh (bsc#1213050)
    When    Run "rm -rf ~hacluster/.ssh" on "hanode1"
    And     Try "crm cluster health hawk2" on "hanode1"
    Then    Expected "hawk2: passwordless ssh authentication: FAIL." in stderr
    When    Run "crm cluster health hawk2 --fix" on "hanode1"
    Then    Expected "hawk2: passwordless ssh authentication: OK." in stdout
    When    Run "rm -rf ~hacluster/.ssh /root/.config/crm" on "hanode1"
    And     Try "crm cluster health hawk2" on "hanode1"
    Then    Expected "hawk2: passwordless ssh authentication: FAIL." in stderr
    When    Try "crm cluster health hawk2 --fix" on "hanode1"
    Then    Expected "Cannot fix automatically" in stderr
