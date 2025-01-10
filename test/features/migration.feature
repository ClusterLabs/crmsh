# vim: sw=2 sts=2
Feature: migration

  Test migration and pre-migration checks
  Need nodes: hanode1 hanode2

  Scenario: Run pre-migration checks
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    And     Run "crm cluster init -y -N hanode2" OK on "hanode1"
    When    Try "crm cluster health sles16" on "hanode1"
    Then    Expected return code is "1"
    And     Expect stdout contains snippets ["[WARN] Corosync transport \"udpu\" will be deprecated in corosync 3.", "[FAIL] Please fix all the \"FAIL\" problems above before migrating to SLES 16.", "----- localhost -----", "----- hanode2 -----"].

  Scenario: Should not run fixes.
    When    Try "crm cluster health sles16 --fix" on "hanode1"
    Then    Expected return code is "1"
    And     Expected "ERROR: "--fix" is only available in SLES 16." in stderr

  Scenario: Run pre-migration checks with cluster services stopped.
    When    Run "crm cluster stop --all" on "hanode1"
    And     Try "crm cluster health sles16" on "hanode1"
    Then    Expected return code is "1"
    And     Expect stdout contains snippets ["Check results may be outdated or inaccurate.", "[WARN] Corosync transport \"udpu\" will be deprecated in corosync 3.", "[FAIL] Please fix all the \"FAIL\" problems above before migrating to SLES 16.", "----- localhost -----", "----- hanode2 -----"].

  Scenario: Run pre-migration checks when some of the nodes are offline.
    When    Run "systemctl stop sshd" on "hanode2"
    And     Try "crm cluster health sles16" on "hanode1"
    Then    Expected return code is "1"
    And     Expect stdout contains snippets ["Cannot create SSH connection to", "[FAIL] Please fix all the \"FAIL\" problems above before migrating to SLES 16.", "----- localhost -----", "----- hanode2 -----"].
