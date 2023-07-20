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
  Scenario: a new node joins when directory ~hacluster/.ssh is removed from cluster
    When    Run "rm -rf ~hacluster/.ssh" on "hanode1"
    And     Run "rm -rf ~hacluster/.ssh" on "hanode2"
    And     Run "crm cluster join -c hanode1 -y" on "hanode3"
    Then    Cluster service is "started" on "hanode3"
    # FIXME: new join implement does not trigger a exception any longer, and the auto fix is not applied
    # And     File "~hacluster/.ssh/id_rsa" exists on "hanode1"
    # And     File "~hacluster/.ssh/id_rsa" exists on "hanode2"
    # And     File "~hacluster/.ssh/id_rsa" exists on "hanode3"

  # skip non-root as behave_agent is not able to run commands interactively with non-root sudoer
  @skip_non_root
  @clean
  Scenario: An upgrade_seq file in ~hacluster/crmsh/ will be migrated to /var/lib/crmsh (bsc#1213050)
    When    Run "mv /var/lib/crmsh ~hacluster/" on "hanode1"
    Then    File "~hacluster/crmsh/upgrade_seq" exists on "hanode1"
    When    Run "crm cluster status" on "hanode1"
    Then    File "/var/lib/crmsh/upgrade_seq" exists on "hanode1"
