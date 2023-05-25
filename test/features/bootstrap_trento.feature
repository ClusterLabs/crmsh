@bootstrap
Feature: Regression test for crm check feature

  Tag @clean means need to stop cluster service if the service is available
  Need nodes: hanode1 hanode2

  @clean
  Scenario: Setup a two nodes cluster
    Given   Nodes ["hanode1", "hanode2"] are cleaned up
    And     Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Show cluster status on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    And     Show cluster status on "hanode1"
    When    Run "crm check list" on "hanode1"
    Then    Expected return code is "0"
    And     Expected "34 check(s) found." in stdout
    When    Run "crm check execute 00081D CAEFF1 D028B9 DC5429 790926" on "hanode1"
    Then    Expected multiple lines in output
    """
    hanode1
      Corosync
          passing:  00081D  Corosync is running with max_messages set to the recommended value
      Miscellaneous
          warning:  790926  The hacluster user password has been changed from the default value
      OS and package versions
         critical:  CAEFF1  Operating system vendor is supported
         critical:  D028B9  Operating system version is supported
          passing:  DC5429  Corosync version is supported
    hanode2
      Corosync
          passing:  00081D  Corosync is running with max_messages set to the recommended value
      Miscellaneous
          warning:  790926  The hacluster user password has been changed from the default value
      OS and package versions
         critical:  CAEFF1  Operating system vendor is supported
         critical:  D028B9  Operating system version is supported
          passing:  DC5429  Corosync version is supported
    """
