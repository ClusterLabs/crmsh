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
    And     Run "crm configure primitive pcmk-remote-node1 ocf:pacemaker:remote params server=pcmk-remote-node1 reconnect_interval=10m op monitor interval=30s" on "hanode1"
    And     Run "crm configure primitive pcmk-remote-node2 ocf:pacemaker:remote params server=pcmk-remote-node2 reconnect_interval=10m op monitor interval=30s" on "hanode1"
    And     Wait "5" seconds
    Then    Remote online nodes are "pcmk-remote-node1 pcmk-remote-node2"

  Scenario: Test standby/online/maintenance/ready remote node
    When    Run "crm node standby pcmk-remote-node1" on "hanode1"
    Then    Node "pcmk-remote-node1" is standby
    When    Run "crm node online pcmk-remote-node1" on "hanode1"
    Then    Node "pcmk-remote-node1" is online
    When    Run "crm node maintenance pcmk-remote-node1" on "hanode1"
    Then    Node "pcmk-remote-node1" is maintenance
    When    Run "crm node ready pcmk-remote-node1" on "hanode1"
    Then    Node "pcmk-remote-node1" is ready

  Scenario: Prevent adding remote RA to group, order and colocation
    When    Run "crm configure primitive d Dummy" on "hanode1"
    When    Try "crm configure group g d pcmk-remote-node1"
    Then    Expected "Cannot put remote resource 'pcmk-remote-node1' in a group" in stderr
    When    Try "crm configure order o1 d pcmk-remote-node1"
    Then    Expected "Cannot put remote resource 'pcmk-remote-node1' in order constraint" in stderr
    When    Try "crm configure colocation c1 inf: d pcmk-remote-node1"
    Then    Expected "Cannot put remote resource 'pcmk-remote-node1' in colocation constraint" in stderr

  Scenario: Remove pacemaker remove node
    When    Run "crm cluster remove pcmk-remote-node1 -y" on "hanode1"
    Then    Remote online nodes are "pcmk-remote-node2"
    When    Run "crm cluster remove pcmk-remote-node2 -y" on "hanode1"
    Then    No remote nodes
