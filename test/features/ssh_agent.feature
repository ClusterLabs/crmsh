# vim: sw=2 sts=2
Feature: ssh-agent support

  Test ssh-agent support for crmsh
  Need nodes: hanode1 hanode2 hanode3 qnetd-node

  Scenario: Errors are reported when ssh-agent is not avaible
    When    Try "crm cluster init --use-ssh-agent -y" on "hanode1"
    Then    Expected "Environment variable SSH_AUTH_SOCK does not exist." in stderr
    When    Try "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster init --use-ssh-agent -y" on "hanode1"
    Then    Expected "Environment variable SSH_AUTH_SOCK does not exist." not in stderr

  Scenario: Errors are reported when there are no keys in ssh-agent
    Given   ssh-agent is started at "/tmp/ssh-auth-sock" on nodes ["hanode1", "hanode2", "hanode3"]
    When    Try "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster init --use-ssh-agent -y" on "hanode1"
    Then    Expected "ssh-add" in stderr

  Scenario: Skip creating ssh key pairs with --use-ssh-agent
    Given   Run "mkdir ~/ssh_disabled" OK on "hanode1,hanode2,hanode3"
    And     Run "mv ~/.ssh/id_* ~/ssh_disabled" OK on "hanode1,hanode2,hanode3"
    And     crm.conf poisoned on nodes ["hanode1", "hanode2", "hanode3"]
    When    Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock ssh-add ~/ssh_disabled/id_rsa" on "hanode1,hanode2,hanode3"
    And     Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster init --use-ssh-agent -y" on "hanode1"
    And     Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster join --use-ssh-agent -y -c hanode1" on "hanode2"
    And     Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster join --use-ssh-agent -y -c hanode1" on "hanode3"
    Then    Cluster service is "started" on "hanode1"
    And     Online nodes are "hanode1 hanode2 hanode3"
    # check the number of keys in authorized_keys
    And     Run "test x1 == x$(awk 'END {print NR}' ~/.ssh/authorized_keys)" OK
    And     Run "test x3 == x$(sudo awk 'END {print NR}' ~hacluster/.ssh/authorized_keys)" OK
    And     Run "grep -E 'hosts = (root|alice)@hanode1' /root/.config/crm/crm.conf" OK on "hanode1,hanode2,hanode3"

  # This test is not applicable for non-root user, since the root ssh key pair exists
  @skip_non_root
  Scenario: Verify expected error message when SSH_AUTH_SOCK is not set
    When    Try "crm cluster remove hanode3 -y" on "hanode1"
    Then    Expected "Environment variable SSH_AUTH_SOCK does not exist" in stderr

  Scenario: Give a warning when detected SSH_AUTH_SOCK but not using --use-ssh-agent
    Given   Run "crm cluster stop" OK on "hanode1,hanode2,hanode3"
    When    Try "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster init -y" on "hanode1"
    Then    Expected "$SSH_AUTH_SOCK is detected. As a tip, using the --use-ssh-agent option could avoid generate local root ssh keys on cluster nodes" in stderr

  Scenario: Skip creating ssh key pairs with --use-ssh-agent and use -N
    Given   Run "crm cluster stop" OK on "hanode1,hanode2,hanode3"
    When    Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster init --use-ssh-agent -y -N hanode2 -N hanode3" on "hanode1"
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
    When    Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster init --use-ssh-agent -y" on "hanode1"
    And     Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster init qdevice --use-ssh-agent -y --qnetd-hostname qnetd-node" on "hanode1"
    And     Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster join --use-ssh-agent -y -c hanode1" on "hanode2"
    Then    Cluster service is "started" on "hanode1"
    And     Online nodes are "hanode1 hanode2"
    And     Service "corosync-qdevice" is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode2"
    And     Service "corosync-qnetd" is "started" on "qnetd-node"

  Scenario: Use qnetd with -N
    Given   Run "crm cluster stop" OK on "hanode1,hanode2"
    When    Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster init --use-ssh-agent -y -N hanode2 --qnetd-hostname qnetd-node" on "hanode1"
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
    When    Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster init -y -n cluster1 --use-ssh-agent" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm configure primitive vip IPaddr2 params ip=@vip.0" on "hanode1"

    When    Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster init -y -n cluster2 --use-ssh-agent" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    When    Run "crm configure primitive vip IPaddr2 params ip=@vip.1" on "hanode2"

    When    Run "crm cluster geo_init -y --clusters "cluster1=@vip.0 cluster2=@vip.1" --tickets tickets-geo --arbitrator hanode3" on "hanode1"
    When    Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster geo_join -y --use-ssh-agent --cluster-node hanode1 --clusters "cluster1=@vip.0 cluster2=@vip.1"" on "hanode2"

    Given   Service "booth@booth" is "stopped" on "hanode3"
    When    Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock crm cluster geo_init_arbitrator -y --use-ssh-agent --cluster-node hanode1" on "hanode3"
    Then    Service "booth@booth" is "started" on "hanode3"
    When    Run "crm resource start g-booth" on "hanode1"
    Then    Show cluster status on "hanode1"
    When    Run "crm resource start g-booth" on "hanode2"
    Then    Show cluster status on "hanode2"
