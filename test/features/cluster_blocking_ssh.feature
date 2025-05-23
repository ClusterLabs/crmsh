Feature: cluster testing with ssh blocked

  Need nodes: hanode1 hanode2

  Scenario: Cluster testing with ssh blocked (bsc#1228899)
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    # without bootstrap, write corosync.conf and authkey directly
    When    Run "dd if=/dev/urandom of=/etc/corosync/authkey bs=1 count=256" on "hanode1"
    And     Write multi lines to file "/etc/corosync/corosync.conf" on "hanode1"
      """
      totem {
        version: 2
        cluster_name: hacluster
        transport: knet
        token: 5000
        join: 60
        max_messages: 20
        token_retransmits_before_loss_const: 10
        crypto_hash: sha1
        crypto_cipher: aes256
      }

      quorum {
        provider: corosync_votequorum
        two_node: 1
      }

      logging {
        to_logfile: yes
        logfile: /var/log/cluster/corosync.log
        to_syslog: yes
        timestamp: on
      }

      nodelist {
        node {
                ring0_addr: @hanode1.ip.0
                name: hanode1
                nodeid: 1
        }

        node {
                ring0_addr: @hanode2.ip.0
                name: hanode2
                nodeid: 2
        }

      }
      """
    And     Run "scp /etc/corosync/authkey /etc/corosync/corosync.conf hanode2:/etc/corosync/" on "hanode1"
    And     Run "systemctl start pacemaker" on "hanode1"
    And     Run "systemctl start pacemaker" on "hanode2"
    And     Wait for DC
    Then    Cluster service is "started" on "hanode1"
    And     Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    # block ssh between nodes
    When    Run "systemctl start firewalld" on "hanode2"
    And     Run "firewall-cmd --zone=public --add-rich-rule='rule port port=22 protocol=tcp drop' --permanent && firewall-cmd --reload" on "hanode2"
    And     Try "ssh -o ConnectTimeout=5 hanode2" on "hanode1"
    Then    Except "ssh: connect to host hanode2 port 22: Connection timed out" in stderr
    When    Run "timeout 5s crm report || echo "timeout"" on "hanode1"
    Then    Expected "timeout" in stdout
    When    Write multi lines to file "/etc/crm/crm.conf" on "hanode1"
      """
      [core]
      no_ssh = yes
      """
    When    Run "crm configure property stonith-enabled=false" on "hanode1"
    And     Run "crm report -d /tmp/report" on "hanode1"
    Then    Directory "/tmp/report/hanode1" created
    Then    Directory "/tmp/report/hanode2" not created
    Then    Expected "ERROR: ssh-related operations are disabled. crmsh works in local mode." in stderr
    Then    Run "crm status" OK on "hanode1"
    When    Try "crm cluster stop --all"
    Then    Except "ERROR: ssh-related operations are disabled. crmsh works in local mode." in stderr
