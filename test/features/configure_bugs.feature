@configure
Feature: Functional test for configure sub level

  Tag @clean means need to stop cluster service if the service is available
  Need nodes: hanode1 hanode2

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
    When    Run "crm node utilization hanode1 set password qwertyui" on "hanode1"
    When    Try "crm configure show|grep password|grep qwertyui"
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
