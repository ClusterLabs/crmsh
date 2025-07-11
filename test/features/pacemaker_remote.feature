Feature: Test deployment of pacemaker remote

  Need nodes: hanode1 hanode2 pcmk-remote-node1 pcmk-remote-node2

  Scenario: Setup a two nodes cluster with two pacemaker-remote nodes
    Given   Nodes ["hanode1", "hanode2"] are cleaned up
    And     Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"

    When    Run "scp -rp /etc/pacemaker pcmk-remote-node1:/etc" on "hanode1"
    And     Run "scp -rp /etc/pacemaker pcmk-remote-node2:/etc" on "hanode1"
    And     Run "systemctl start pacemaker_remote" on "pcmk-remote-node1"
    And     Run "systemctl start pacemaker_remote" on "pcmk-remote-node2"
    And     Run "crm configure primitive remote-node1 ocf:pacemaker:remote params server=pcmk-remote-node1 reconnect_interval=10m op monitor interval=30s" on "hanode1"
    And     Run "crm configure primitive remote-node2 ocf:pacemaker:remote params server=pcmk-remote-node2 reconnect_interval=10m op monitor interval=30s" on "hanode1"
    And     Wait "5" seconds
    Then    Remote online nodes are "remote-node1 remote-node2"

  Scenario: Prevent adding remote RA to group, order and colocation
    When    Run "crm configure primitive d Dummy" on "hanode1"
    When    Try "crm configure group g d remote-node1"
    Then    Expected "Cannot put remote resource 'remote-node1' in a group" in stderr
    When    Try "crm configure order o1 d remote-node1"
    Then    Expected "Cannot put remote resource 'remote-node1' in order constraint" in stderr
    When    Try "crm configure colocation c1 inf: d remote-node1"
    Then    Expected "Cannot put remote resource 'remote-node1' in colocation constraint" in stderr
