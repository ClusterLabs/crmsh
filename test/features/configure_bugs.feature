@configure
Feature: Functional test for configure sub level

  Tag @clean means need to stop cluster service if the service is available
  Need nodes: hanode1 hanode2

  @clean
  Scenario: Load CIB_file env before read-only commands
    Given   Cluster service is "stopped" on "hanode1"
    # Should put this scenario at the beginning of the test suite
    And     File "/var/lib/pacemaker/cib/cib.xml" not exist on "hanode1"
    When    Try "crm configure show" on "hanode1"
    Then    Except "Cannot find cib file: /var/lib/pacemaker/cib/cib.xml" in stderr
    And     Expected return code is "1"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster stop" on "hanode1"
    Then    Cluster service is "stopped" on "hanode1"
    When    Try "crm configure show" on "hanode1"
    Then    Except "Cluster is not running, loading the CIB file from /var/lib/pacemaker/cib/cib.xml" in stderr
    And     Expected return code is "0"

  @clean
  Scenario: Replace sensitive data by default(bsc#1163581)
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"

    # mask password by default
    When    Run "crm node utilization hanode1 set password=qwertyui" on "hanode1"
    When    Try "crm configure show|grep password|grep qwertyui"
    Then    Expected return code is "1"
    When    Run "crm node utilization hanode2 set password testingpass" on "hanode1"
    When    Try "crm configure show|grep password|grep testingpass"
    Then    Expected return code is "1"
    And     Show crm configure

    # mask password and ip address
    When    Run "crm configure primitive ip2 IPaddr2 params ip=@vip.0" on "hanode1"
    And     Run "sed -i 's/; \[core\]/[core]/' /etc/crm/crm.conf" on "hanode1"
    And     Run "sed -i 's/; obscure_pattern = .*$/obscure_pattern = passw*|ip/g' /etc/crm/crm.conf" on "hanode1"
    And     Try "crm configure show|grep -E "@vip.0|qwertyui""
    Then    Expected return code is "1"
    And     Show crm configure

    # mask password and ip address with another pattern
    When    Run "sed -i 's/obscure_pattern = .*$/obscure_pattern = passw* ip/g' /etc/crm/crm.conf" on "hanode1"
    And     Try "crm configure show|grep -E "@vip.0|qwertyui""
    Then    Expected return code is "1"
    And     Show crm configure

  @clean
  Scenario: Setting schema and upgrade
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    When    Try "crm configure schema xxx" on "hanode1"
    Then    Except "schema xxx is not supported" in stderr
    # test for 'configure schema'
    When    Set to previous schema version
    Then    The schema version is the previous
    # test for 'configure upgrade'
    When    Try "crm configure upgrade" on "hanode1"
    Then    Except "'force' option is required" in stderr
    Given   Get the latest schema version
    When    Use crm configure upgrade to upgrade the schema
    Then    The schema version is the latest

  @clean
  Scenario: Edit attributes starts with a hashtag (bsc#1239782)
    Given   Cluster service is "stopped" on "hanode1"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm node attribute hanode1 set cpu 2" on "hanode1"
    Then    Run "crm -F configure filter "sed 's/cpu=/#cpu='/g"" OK on "hanode1"

  @clean
  Scenario: Set stonith-watchdog-timeout when sbd.service is disactive
    Given   Cluster service is "stopped" on "hanode1"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Try "crm configure property stonith-watchdog-timeout=20" on "hanode1"
    Then    Except "Can't set stonith-watchdog-timeout because sbd.service is not active" in stderr
