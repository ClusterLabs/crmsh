# vim: sw=2 sts=2
Feature: migration

  Test migration and pre-migration checks
  Need nodes: hanode1 hanode2

  Scenario: Run pre-migration checks when cluster services are running.
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    And     Run "crm cluster init -y -N hanode2" OK on "hanode1"
    When    Try "crm cluster health sles16" on "hanode1"
    Then    Expected return code is "0"
    And     Expected "[INFO] This cluster works on SLES 16. No migration is needed." in stdout

  Scenario: Run pre-migration checks with cluster services stopped.
    When    Run "crm cluster stop --all" on "hanode1"
    And     Run "crm cluster stop --all" on "hanode2"
    And     Try "crm cluster health sles16" on "hanode1"
    Then    Expected return code is "0"
    And     Expected "[INFO] This cluster works on SLES 16. No migration is needed." in stdout


  Scenario: Should run fixes.
    When    Try "crm cluster health sles16 --fix" on "hanode1"
    Then    Expected return code is "0"

  Scenario: run pre-migration checks against corosync.conf generated in crmsh-4.6
    When    Run "rm -f /etc/corosync/corosync.conf" on "hanode1"
    And     Write multi lines to file "/etc/corosync/corosync.conf" on "hanode1"
      """
      # Please read the corosync.conf.5 manual page
      totem {
              version: 2
              cluster_name: hacluster
              clear_node_high_bit: yes
              interface {
                      ringnumber: 0
                      mcastport: 5405
                      ttl: 1
              }

              transport: udpu
              crypto_hash: sha1
              crypto_cipher: aes256
              token: 5000
              join: 60
              max_messages: 20
              token_retransmits_before_loss_const: 10
      }

      logging {
              fileline: off
              to_stderr: no
              to_logfile: yes
              logfile: /var/log/cluster/corosync.log
              to_syslog: yes
              debug: off
              timestamp: on
              logger_subsys {
                      subsys: QUORUM
                      debug: off
              }

      }

      quorum {

              # Enable and configure quorum subsystem (default: off)
              # see also corosync.conf.5 and votequorum.5
              provider: corosync_votequorum
              expected_votes: 2
              two_node: 1
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
    And Run "crm cluster copy /etc/corosync/corosync.conf" on "hanode1"
    And Try "crm cluster health sles16" on "hanode1"
    Then    Expected return code is "1"
    And     Expect stdout contains snippets ["[PASS] This cluster is good to migrate to SLES 16.", "[INFO] Please run \"crm cluster health sles16 --fix\" on on any one of above nodes.", "[WARN] Corosync transport \"udpu\" will be deprecated in corosync 3. Please use knet.", "----- node: localhost -----", "----- node: hanode2 -----"].

  Scenario: Run fixes against corosync.conf generated in crmsh-4.6
    When    Try "crm cluster health sles16 --fix" on "hanode1"
    Then    Expected return code is "0"

  Scenario: Run fixes against multicast corosync.conf containing incorrect bindnetaddr.
    When    Run "rm -f /etc/corosync/corosync.conf" on "hanode1"
    And     Write multi lines to file "/etc/corosync/corosync.conf" on "hanode1"
      """
      # Please read the corosync.conf.5 manual page
      totem {
              version: 2
              cluster_name: hacluster
              clear_node_high_bit: yes
              interface {
                      ringnumber: 0
                      bindnetaddr: @hanode1.ip.0
                      mcastaddr: 239.247.90.152
                      mcastport: 5405
                      ttl: 1
              }

              crypto_hash: sha1
              crypto_cipher: aes256
              token: 5000
              join: 60
              max_messages: 20
              token_retransmits_before_loss_const: 10
      }

      logging {
              fileline: off
              to_stderr: no
              to_logfile: no
              logfile: /var/log/cluster/corosync.log
              to_syslog: yes
              debug: off
              timestamp: on
              logger_subsys {
                      subsys: QUORUM
                      debug: off
              }

      }

      quorum {

              # Enable and configure quorum subsystem (default: off)
              # see also corosync.conf.5 and votequorum.5
              provider: corosync_votequorum
              expected_votes: 2
              two_node: 1
      }
      """
    And     Run "crm cluster copy /etc/corosync/corosync.conf" on "hanode1"
    And     Try "crm cluster health sles16 --fix" on "hanode1"
    Then    Expected return code is "0"
    And     Run "grep -F 'ring0_addr: @hanode2.ip.0' /etc/corosync/corosync.conf" OK

  Scenario: Run pre-migration checks when some of the nodes are offline.
    When    Run "systemctl stop sshd" on "hanode2"
    And     Try "crm cluster health sles16" on "hanode1"
    Then    Expected return code is "1"
    And     Expect stdout contains snippets ["Cannot create SSH connection to", "----- node: localhost -----", "----- node: hanode2 -----"].

