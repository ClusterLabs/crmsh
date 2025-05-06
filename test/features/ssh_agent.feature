# vim: sw=2 sts=2
Feature: ssh-agent support

  Test ssh-agent support for crmsh
  Need nodes: hanode1 hanode2 hanode3 qnetd-node

  Scenario: Skip creating ssh key pairs when keys are available from ssh-agent
    Given   ssh-agent is started at "/tmp/ssh-auth-sock" on nodes ["hanode1", "hanode2", "hanode3"]
    And     Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock ssh-add ~/.ssh/id_rsa" OK on "hanode1,hanode2,hanode3"
    And     Run "rm -f ~/.ssh/id_*" OK on "hanode1,hanode2,hanode3"
    And     crm.conf poisoned on nodes ["hanode1", "hanode2", "hanode3"]
    When    Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster init -y" on "hanode1"
    And     Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster join -y -c hanode1" on "hanode2"
    And     Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster join -y -c hanode1" on "hanode3"
    Then    Cluster service is "started" on "hanode1"
    And     Online nodes are "hanode1 hanode2 hanode3"
    # check the number of keys in authorized_keys
    And     Run "test x1 == x$(awk 'END {print NR}' ~/.ssh/authorized_keys)" OK
    And     Run "test x3 == x$(sudo awk 'END {print NR}' ~hacluster/.ssh/authorized_keys)" OK
    And     Run "grep -E 'hosts = (root|alice)@hanode1' /root/.config/crm/crm.conf" OK on "hanode1,hanode2,hanode3"

  Scenario: Skip creating ssh key pairs when using -N and keys are available from ssh-agent
    Given   Run "crm cluster stop" OK on "hanode1,hanode2,hanode3"
    When    Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster init -y -N hanode2 -N hanode3" on "hanode1"
    Then    Cluster service is "started" on "hanode3"
    And     Online nodes are "hanode1 hanode2 hanode3"
    And     Run "test x1 == x$(awk 'END {print NR}' ~/.ssh/authorized_keys)" OK on "hanode3"
    And     Run "test x3 == x$(sudo awk 'END {print NR}' ~hacluster/.ssh/authorized_keys)" OK on "hanode3"

  Scenario: crm report
    Then    Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm report /tmp/report1" OK on "hanode1"
    Then    Directory "hanode2" in "/tmp/report1.tar.bz2"
    Then    Directory "hanode3" in "/tmp/report1.tar.bz2"

  Scenario: Use qnetd
    Given   Run "crm cluster stop" OK on "hanode1,hanode2,hanode3"
    When    Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster init -y" on "hanode1"
    And     Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster init qdevice -y --qnetd-hostname qnetd-node" on "hanode1"
    And     Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster join -y -c hanode1" on "hanode2"
    Then    Cluster service is "started" on "hanode1"
    And     Online nodes are "hanode1 hanode2"
    And     Service "corosync-qdevice" is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode2"
    And     Service "corosync-qnetd" is "started" on "qnetd-node"

  Scenario: Use qnetd with -N
    Given   Run "crm cluster stop" OK on "hanode1,hanode2"
    When    Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster init -y -N hanode2 --qnetd-hostname qnetd-node" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Online nodes are "hanode1 hanode2"
    And     Service "corosync-qdevice" is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode2"
    And     Service "corosync-qnetd" is "started" on "qnetd-node"

  Scenario: GEO cluster setup with ssh-agent
    Given   Run "crm cluster stop" OK on "hanode1,hanode2"
    And     Run "systemctl disable --now booth@booth" OK on "hanode1,hanode2,hanode3"
    And     Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    And     crm.conf poisoned on nodes ["hanode1", "hanode2", "hanode3"]
    When    Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster init -y -n cluster1" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm configure primitive vip IPaddr2 params ip=@vip.0" on "hanode1"

    When    Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster init -y -n cluster2" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    When    Run "crm configure primitive vip IPaddr2 params ip=@vip.1" on "hanode2"

    When    Run "crm cluster geo_init -y --clusters "cluster1=@vip.0 cluster2=@vip.1" --tickets tickets-geo --arbitrator hanode3" on "hanode1"
    When    Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster geo_join -y --cluster-node hanode1 --clusters "cluster1=@vip.0 cluster2=@vip.1"" on "hanode2"

    Given   Service "booth@booth" is "stopped" on "hanode3"
    When    Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster geo_init_arbitrator -y --cluster-node hanode1" on "hanode3"
    Then    Service "booth@booth" is "started" on "hanode3"
    When    Run "crm resource start g-booth" on "hanode1"
    Then    Show cluster status on "hanode1"
    When    Run "crm resource start g-booth" on "hanode2"
    Then    Show cluster status on "hanode2"
