# vim: sw=2 sts=2
Feature: crmsh bootstrap process - with password authentication

  Need nodes: hanode1 hanode2 hanode3

  Scenario: Disable key-based authentication
    Given Permit root ssh login with password on "hanode1"
    Given Permit root ssh login with password on "hanode2"
    Given Permit root ssh login with password on "hanode3"
    Given The password of user "root" set to "root123" on "hanode1"
    Given The password of user "root" set to "root123" on "hanode2"
    Given The password of user "root" set to "root123" on "hanode3"
    Given The password of user "alice" set to "alice123" on "hanode1"
    Given The password of user "alice" set to "alice123" on "hanode2"
    Given The password of user "alice" set to "alice123" on "hanode3"
    Given Directory ~root/.ssh is empty on "hanode1"
    Given Directory ~root/.ssh is empty on "hanode2"
    Given Directory ~root/.ssh is empty on "hanode3"
    Given Directory ~alice/.ssh is empty on "hanode1"
    Given Directory ~alice/.ssh is empty on "hanode2"
    Given Directory ~alice/.ssh is empty on "hanode3"

  Scenario: Init cluster service on node "hanode1", and join on node "hanode2"
    When Run "crm cluster init -y" on "hanode1"
    Then Cluster service is "started" on "hanode1"
    Then This expect program exits with 0 on "root"@"hanode2"
      """
      set timeout 120
      spawn crm cluster join -c hanode1 -y
      expect "Password: " {
          send "root123\n"
      }
      expect eof
      """
    Then Cluster service is "started" on "hanode2"
    Then Online nodes are "hanode1 hanode2"
    Then two_node in corosync.conf is "1"
    Then Cluster is using "knet" transport mode
    Then Run "corosync-cmapctl|grep "votequorum.two_node .* = 1"" OK on "hanode1"
    Then Run "corosync-cmapctl|grep "votequorum.two_node .* = 1"" OK on "hanode2"

  Scenario: Join on a 3rd node "hanode3"
    Then This expect program exits with 0 on "root"@"hanode3"
      """
      set timeout 120
      spawn crm cluster join -c hanode1 -y
      for {set i 0} {$i < 2} {incr i} {
        expect "Password: " {
          send "root123\n"
        }
      }
      expect eof
      """
    Then Cluster service is "started" on "hanode3"
    Then Online nodes are "hanode1 hanode2 hanode3"
    Then two_node in corosync.conf is "0"
    Then Cluster is using "knet" transport mode
    Then Run "corosync-cmapctl|grep "votequorum.two_node .* = 0"" OK on "hanode1"
    Then Run "corosync-cmapctl|grep "votequorum.two_node .* = 0"" OK on "hanode2"
    Then Run "corosync-cmapctl|grep "votequorum.two_node .* = 0"" OK on "hanode3"

  @clean
  Scenario: Bootstrap using `init -N`
    Given Directory ~root/.ssh is empty on "hanode1"
    Given Directory ~root/.ssh is empty on "hanode2"
    Given Directory ~root/.ssh is empty on "hanode3"
    Given Directory ~alice/.ssh is empty on "hanode1"
    Given Directory ~alice/.ssh is empty on "hanode2"
    Given Directory ~alice/.ssh is empty on "hanode3"
    Then This expect program exits with 0 on "root"@"hanode1"
      """
      set timeout 120
      spawn crm cluster init -N hanode2 -N hanode3 -y
      for {set i 0} {$i < 2} {incr i} {
        expect "Password: " {
          send "root123\n"
        }
      }
      expect eof
      """
    Then Online nodes are "hanode1 hanode2 hanode3"
    Then two_node in corosync.conf is "0"
    Then Cluster is using "knet" transport mode

  @clean
  Scenario: Init cluster service on node "hanode1", and join on node "hanode2" (non-root)
    When Run "crm cluster init -y" on "hanode1"
    Then Cluster service is "started" on "hanode1"
    Then This expect program exits with 0 on "alice"@"hanode2"
      """
      set timeout 120
      spawn sudo crm cluster join -c alice@hanode1 -y
      expect "Password: " {
          send "alice123\n"
      }
      expect eof
      """
    Then Cluster service is "started" on "hanode2"
    Then Online nodes are "hanode1 hanode2"
    Then two_node in corosync.conf is "1"
    Then Cluster is using "knet" transport mode
    Then Run "corosync-cmapctl|grep "votequorum.two_node .* = 1"" OK on "hanode1"
    Then Run "corosync-cmapctl|grep "votequorum.two_node .* = 1"" OK on "hanode2"

  Scenario: Join on a 3rd node "hanode3" (non-root)
    Then This expect program exits with 0 on "alice"@"hanode3"
      """
      set timeout 120
      spawn sudo crm cluster join -c alice@hanode1 -y
      for {set i 0} {$i < 2} {incr i} {
        expect "Password: " {
          send "alice123\n"
        }
      }
      expect eof
      """
    Then Cluster service is "started" on "hanode3"
    Then Online nodes are "hanode1 hanode2 hanode3"
    Then two_node in corosync.conf is "0"
    Then Cluster is using "knet" transport mode
    Then Run "corosync-cmapctl|grep "votequorum.two_node .* = 0"" OK on "hanode1"
    Then Run "corosync-cmapctl|grep "votequorum.two_node .* = 0"" OK on "hanode2"
    Then Run "corosync-cmapctl|grep "votequorum.two_node .* = 0"" OK on "hanode3"

  @clean
  Scenario: Bootstrap using `init -N` (non-root)
    Given Directory ~root/.ssh is empty on "hanode1"
    Given Directory ~root/.ssh is empty on "hanode2"
    Given Directory ~root/.ssh is empty on "hanode3"
    Given Directory ~alice/.ssh is empty on "hanode1"
    Given Directory ~alice/.ssh is empty on "hanode2"
    Given Directory ~alice/.ssh is empty on "hanode3"
    Then This expect program exits with 0 on "alice"@"hanode1"
      """
      set timeout 120
      spawn sudo crm cluster init -N alice@hanode2 -N alice@hanode3 -y
      for {set i 0} {$i < 2} {incr i} {
        expect "Password: " {
          send "alice123\n"
        }
      }
      expect eof
      """
    Then Online nodes are "hanode1 hanode2 hanode3"
    Then two_node in corosync.conf is "0"
    Then Cluster is using "knet" transport mode
