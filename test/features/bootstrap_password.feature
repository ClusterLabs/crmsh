# vim: sw=2 sts=2
Feature: crmsh bootstrap process - with password authentication

  Need nodes: hanode1 hanode2 hanode3 qnetd-node

  Scenario: Disable key-based authentication
    Given Permit root ssh login with password on "hanode1"
    Given Permit root ssh login with password on "hanode2"
    Given Permit root ssh login with password on "hanode3"
    Given Permit root ssh login with password on "qnetd-node"
    Given The password of user "root" set to "root123" on "hanode1"
    Given The password of user "root" set to "root123" on "hanode2"
    Given The password of user "root" set to "root123" on "hanode3"
    Given The password of user "root" set to "root123" on "qnetd-node"
    Given The password of user "alice" set to "alice123" on "hanode1"
    Given The password of user "alice" set to "alice123" on "hanode2"
    Given The password of user "alice" set to "alice123" on "hanode3"
    Given The password of user "alice" set to "alice123" on "qnetd-node"
    Given Directory ~root/.ssh is empty on "hanode1"
    Given Directory ~root/.ssh is empty on "hanode2"
    Given Directory ~root/.ssh is empty on "hanode3"
    Given Directory ~root/.ssh is empty on "qnetd-node"
    Given Directory ~alice/.ssh is empty on "hanode1"
    Given Directory ~alice/.ssh is empty on "hanode2"
    Given Directory ~alice/.ssh is empty on "hanode3"
    Given Directory ~alice/.ssh is empty on "qnetd-node"
    Given Directory ~hacluster/.ssh is empty on "hanode1"
    Given Directory ~hacluster/.ssh is empty on "hanode2"
    Given Directory ~hacluster/.ssh is empty on "hanode3"
    Given Directory ~hacluster/.ssh is empty on "qnetd-node"

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
    Given Directory ~hacluster/.ssh is empty on "hanode1"
    Given Directory ~hacluster/.ssh is empty on "hanode2"
    Given Directory ~hacluster/.ssh is empty on "hanode3"
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
    Given Directory ~hacluster/.ssh is empty on "hanode1"
    Given Directory ~hacluster/.ssh is empty on "hanode2"
    Given Directory ~hacluster/.ssh is empty on "hanode3"
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

  @clean
  Scenario: Setup qdevice/qnetd during init/join process
    Given Directory ~root/.ssh is empty on "hanode1"
    Given Directory ~root/.ssh is empty on "hanode2"
    Given Directory ~root/.ssh is empty on "qnetd-node"
    Given Directory ~alice/.ssh is empty on "hanode1"
    Given Directory ~alice/.ssh is empty on "hanode2"
    Given Directory ~alice/.ssh is empty on "qnetd-node"
    Given Directory ~hacluster/.ssh is empty on "hanode1"
    Given Directory ~hacluster/.ssh is empty on "hanode2"
    Given Directory ~hacluster/.ssh is empty on "qnetd-node"
    Then This expect program exits with 0 on "root"@"hanode1"
      """
      set timeout 120
      spawn crm cluster init --qnetd-hostname=qnetd-node -y
      expect "Password: " {
        send "root123\n"
      }
      expect eof
      """
    Then    Cluster service is "started" on "hanode1"
    Then    Service "corosync-qdevice" is "started" on "hanode1"
    Then    Service "corosync-qnetd" is "started" on "qnetd-node"
    Then This expect program exits with 0 on "root"@"hanode2"
      """
      set timeout 120
      spawn crm cluster join -c hanode1 -y
      expect "Password: " {
        send "root123\n"
      }
      expect eof
      """
    Then    Cluster service is "started" on "hanode2"
    Then    Online nodes are "hanode1 hanode2"
    Then    Service "corosync-qdevice" is "started" on "hanode2"
    Then    Service "corosync-qnetd" is "started" on "qnetd-node"

  @clean
  Scenario: Setup qdevice/qnetd on running cluster
    Given Directory ~root/.ssh is empty on "hanode1"
    Given Directory ~root/.ssh is empty on "hanode2"
    Given Directory ~root/.ssh is empty on "qnetd-node"
    Given Directory ~alice/.ssh is empty on "hanode1"
    Given Directory ~alice/.ssh is empty on "hanode2"
    Given Directory ~alice/.ssh is empty on "qnetd-node"
    Given Directory ~hacluster/.ssh is empty on "hanode1"
    Given Directory ~hacluster/.ssh is empty on "hanode2"
    Given Directory ~hacluster/.ssh is empty on "qnetd-node"
    Then This expect program exits with 0 on "root"@"hanode1"
      """
      set timeout 120
      spawn crm cluster init -N hanode1 -N hanode2 -y
      expect "Password: " {
        send "root123\n"
      }
      expect eof
      """
    Then    Online nodes are "hanode1 hanode2"
    Then This expect program exits with 0 on "root"@"hanode1"
      """
      set timeout 120
      spawn crm cluster init qdevice --qnetd-hostname=qnetd-node -y
      expect "Password: " {
        send "root123\n"
      }
      expect eof
      """
    Then    Service "corosync-qdevice" is "started" on "hanode1"
    Then    Service "corosync-qdevice" is "started" on "hanode2"
    Then    Service "corosync-qnetd" is "started" on "qnetd-node"

  @clean
  Scenario: Setup qdevice/qnetd during init/join process (non-root)
    Given Directory ~root/.ssh is empty on "hanode1"
    Given Directory ~root/.ssh is empty on "hanode2"
    Given Directory ~root/.ssh is empty on "qnetd-node"
    Given Directory ~alice/.ssh is empty on "hanode1"
    Given Directory ~alice/.ssh is empty on "hanode2"
    Given Directory ~alice/.ssh is empty on "qnetd-node"
    Given Directory ~hacluster/.ssh is empty on "hanode1"
    Given Directory ~hacluster/.ssh is empty on "hanode2"
    Given Directory ~hacluster/.ssh is empty on "qnetd-node"
    Then This expect program exits with 0 on "alice"@"hanode1"
      """
      set timeout 120
      spawn sudo crm cluster init --qnetd-hostname=alice@qnetd-node -y
      expect "Password: " {
        send "alice123\n"
      }
      expect eof
      """
    Then    Cluster service is "started" on "hanode1"
    Then    Service "corosync-qdevice" is "started" on "hanode1"
    Then    Service "corosync-qnetd" is "started" on "qnetd-node"
    Then This expect program exits with 0 on "alice"@"hanode2"
      """
      set timeout 120
      spawn sudo crm cluster join -c alice@hanode1 -y
      expect "Password: " {
        send "alice123\n"
      }
      expect eof
      """
    Then    Cluster service is "started" on "hanode2"
    Then    Online nodes are "hanode1 hanode2"
    Then    Service "corosync-qdevice" is "started" on "hanode2"
    Then    Service "corosync-qnetd" is "started" on "qnetd-node"

  @clean
  Scenario: Setup qdevice/qnetd on running cluster
    Given Directory ~root/.ssh is empty on "hanode1"
    Given Directory ~root/.ssh is empty on "hanode2"
    Given Directory ~root/.ssh is empty on "qnetd-node"
    Given Directory ~alice/.ssh is empty on "hanode1"
    Given Directory ~alice/.ssh is empty on "hanode2"
    Given Directory ~alice/.ssh is empty on "qnetd-node"
    Given Directory ~hacluster/.ssh is empty on "hanode1"
    Given Directory ~hacluster/.ssh is empty on "hanode2"
    Given Directory ~hacluster/.ssh is empty on "qnetd-node"
    Then This expect program exits with 0 on "alice"@"hanode1"
      """
      set timeout 120
      spawn sudo crm cluster init -N alice@hanode2 -y
      expect "Password: " {
        send "alice123\n"
      }
      expect eof
      """
    Then    Online nodes are "hanode1 hanode2"
    Then This expect program exits with 0 on "alice"@"hanode1"
      """
      set timeout 120
      spawn sudo crm cluster init qdevice --qnetd-hostname=alice@qnetd-node -y
      expect "Password: " {
        send "alice123\n"
      }
      expect eof
      """
    Then    Service "corosync-qdevice" is "started" on "hanode1"
    Then    Service "corosync-qdevice" is "started" on "hanode2"
    Then    Service "corosync-qnetd" is "started" on "qnetd-node"

  @clean
  Scenario: Skip creating ssh key pairs when keys are available from ssh-agent fowarding
    Given Directory ~root/.ssh is empty on "hanode1"
    Given Directory ~root/.ssh is empty on "hanode2"
    Given Directory ~root/.ssh is empty on "hanode3"
    Given Directory ~root/.ssh is empty on "qnetd-node"
    Given Directory ~alice/.ssh is empty on "hanode1"
    Given Directory ~alice/.ssh is empty on "hanode2"
    Given Directory ~alice/.ssh is empty on "hanode3"
    Given Directory ~alice/.ssh is empty on "qnetd-node"
    Given Directory ~hacluster/.ssh is empty on "hanode1"
    Given Directory ~hacluster/.ssh is empty on "hanode2"
    Given Directory ~hacluster/.ssh is empty on "hanode3"
    Given Directory ~hacluster/.ssh is empty on "qnetd-node"
    Given crm.conf poisoned on nodes ["hanode1", "hanode2", "hanode3"]
    Given ssh-agent is started at "/tmp/ssh-auth-sock" on nodes ["hanode3"]
    Given Run "ssh-keygen -q -N '' -t ed25519 -f /root/.ssh/id_ed25519" OK on "hanode3"
    Given Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock ssh-add ~/.ssh/id_ed25519" OK on "hanode3"
    Then This expect program exits with 0 on "root"@"hanode3"
      """
      set timeout 120
      spawn env SSH_AUTH_SOCK=/tmp/ssh-auth-sock ssh -At root@hanode1 crm cluster init -y
      expect "Password: " {
        send "root123\n"
      }
      expect eof
      """
    Then This expect program exits with 0 on "root"@"hanode3"
      """
      set timeout 15
      spawn env SSH_AUTH_SOCK=/tmp/ssh-auth-sock ssh -A root@hanode1 echo 'NO-NEED-FOR-PASSWORD'
      expect "NO-NEED-FOR-PASSWORD"
      expect eof
      """
    Then Cluster service is "started" on "hanode1"
    Then Run "test x1 == x$(awk 'END {print NR}' ~/.ssh/authorized_keys)" OK
    Then This expect program exits with 0 on "root"@"hanode3"
      """
      set timeout 120
      spawn env SSH_AUTH_SOCK=/tmp/ssh-auth-sock ssh -At root@hanode2 crm cluster join -c hanode1 -y
      expect "Password: " {
        send "root123\n"
      }
      expect eof
      """
    Then This expect program exits with 0 on "root"@"hanode3"
      """
      set timeout 15
      spawn env SSH_AUTH_SOCK=/tmp/ssh-auth-sock ssh -A root@hanode2 echo 'NO-NEED-FOR-PASSWORD'
      expect "NO-NEED-FOR-PASSWORD"
      expect eof
      """
    Then Online nodes are "hanode1 hanode2"
    Then Run "test x1 == x$(awk 'END {print NR}' ~/.ssh/authorized_keys)" OK
    Then Run "test x2 == x$(sudo awk 'END {print NR}' ~hacluster/.ssh/authorized_keys)" OK
    Then Run "grep -E 'hosts = (root|alice)@hanode1' /root/.config/crm/crm.conf" OK on "hanode1,hanode2"
    Then Run "SSH_AUTH_SOCK=/tmp/ssh-auth-sock ssh -A root@hanode1 crm report /tmp/report1" OK on "hanode3"
    Then Directory "hanode2" in "/tmp/report1.tar.bz2"
    Then This expect program exits with 0 on "root"@"hanode3"
      """
      set timeout 120
      spawn env SSH_AUTH_SOCK=/tmp/ssh-auth-sock ssh -At root@hanode1 crm cluster init qdevice --qnetd-hostname qnetd-node -y
      expect "Password: " {
        send "root123\n"
      }
      expect eof
      """
    Then This expect program exits with 0 on "root"@"hanode3"
      """
      set timeout 15
      spawn env SSH_AUTH_SOCK=/tmp/ssh-auth-sock ssh -A root@qnetd-node echo 'NO-NEED-FOR-PASSWORD'
      expect "NO-NEED-FOR-PASSWORD"
      expect eof
      """
    Then Service "corosync-qdevice" is "started" on "hanode1"
    Then Service "corosync-qdevice" is "started" on "hanode2"
    Then Service "corosync-qnetd" is "started" on "qnetd-node"
