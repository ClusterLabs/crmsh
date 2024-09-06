# vim: sw=2 sts=2
@bootstrap
Feature: crm corosync ui test cases

  Need nodes: hanode1 hanode2

  Scenario: Empty cluster
    When    Try "crm corosync show" on "hanode1"
    Then    Except "No such file or directory: '/etc/corosync/corosync.conf'" in stderr
    When    Try "crm corosync set totem.cluster_name xin" on "hanode1"
    Then    Except "No such file or directory: '/etc/corosync/corosync.conf'" in stderr
    When    Try "crm corosync link show" on "hanode1"
    Then    Except "No such file or directory: '/etc/corosync/corosync.conf'" in stderr
    When    Try "crm corosync link update 0 hanode1=192.0.2.1" on "hanode1"
    Then    Except "No such file or directory: '/etc/corosync/corosync.conf'" in stderr
    When    Try "crm corosync link add hanode1=192.0.2.1" on "hanode1"
    Then    Except "No such file or directory: '/etc/corosync/corosync.conf'" in stderr
    When    Try "crm corosync link remove 0" on "hanode1"
    Then    Except "No such file or directory: '/etc/corosync/corosync.conf'" in stderr

  Scenario: link show/add/update/remove
    # background
    Given   Nodes ["hanode1", "hanode2"] are cleaned up
    And     Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    And     Cluster is using "knet" transport mode
    # tests
    When    Run "crm corosync link show" on "hanode1"
    Then    Expected "Node 2: hanode2" in stdout
    When    Run "crm corosync link update 0" on "hanode1"
    Then    Expected "Nothing is updated." in stdout
    When    Run "crm corosync link update 0 hanode1=@hanode1.ip.1 hanode2=@hanode2.ip.1 options knet_link_priority=10" on "hanode1"
    Then    Expected "Restarting corosync.service is needed to apply the changes, ie. crm cluster restart --all" in stderr
    Given   Run "systemctl restart corosync.service" OK on "hanode1,hanode2"
    When    Wait "5" seconds
    And     Try "crm corosync link add hanode1=@hanode1.ip.0 hanode2=@hanode2.ip.0 options knet_link_priority=" on "hanode1"
    Then    Expected "invalid option" in stderr
    Given   Run "crm corosync link add hanode1=@hanode1.ip.0 hanode2=@hanode2.ip.0 options knet_link_priority=11" OK on "hanode1"
    When    Try "crm corosync link update 1 hanode1=@hanode1.ip.1" on "hanode1"
    Then    Expected "Duplicated" in stderr
    Given   Run "crm corosync link remove 1" OK on "hanode1"
    When    Try "crm corosync link add hanode1=@hanode1.ip.1 hanode2=@hanode2.ip.0" on "hanode1"
    Then    Expected "Duplicated" in stderr
    When    Try "crm corosync link add hanode1=192.0.2.101 hanode2=192.0.2.102 options knet_link_priority=10" on "hanode1"
    Then    Expected "not a configured interface address" in stderr
