@bootstrap
Feature: crm corosync ui test cases

  Need nodes: hanode1 hanode2

  Scenario: Empty cluster
    When    Try "crm corosync show" on "hanode1"
    Then    Except "corosync.show: /etc/corosync/corosync.conf not exist" in stderr
    When    Try "crm corosync set totem.cluster_name xin" on "hanode1"
    Then    Except "corosync.set: /etc/corosync/corosync.conf not exist" in stderr
