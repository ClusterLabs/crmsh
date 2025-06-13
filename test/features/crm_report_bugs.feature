@crm_report
Feature: crm report functional test for verifying bugs

  Tag @clean means need to stop cluster service if the service is available
  Need nodes: hanode1 hanode2 hanode3

  Background: Setup a two nodes cluster
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Show cluster status on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"
    And     Show cluster status on "hanode1"

  @clean
  Scenario: Verify crm report handle files contain non-utf-8 characters (bsc#1130715)
    When    Run "echo 'abc#$%%^' | iconv -f UTF-8 -t UTF-16 > /opt/text_non_utf8" on "hanode1"
    Then    This file "/opt/text_non_utf8" will trigger UnicodeDecodeError exception
    When    Run "crm report -E /opt/text_non_utf8 report1" on "hanode1"
    Then    File "text_non_utf8" in "report1.tar.bz2"
    When    Run "rm -f report1.tar.bz2" on "hanode1"

  @clean
  Scenario: Compressed file ended before the end-of-stream marker was reached (bsc#1206606)
    When    Run "touch /var/log/pacemaker/pacemaker.log-20221220.xz" on "hanode1"
    When    Try "crm report report1" on "hanode1"
    Then    File "pacemaker.log" in "report1.tar.bz2"
    And     Expected "When reading file "/var/log/pacemaker/pacemaker.log-20221220.xz": Compressed file ended before the end-of-stream marker was reached" in stderr
    When    Run "rm -f report1.tar.bz2" on "hanode1"

  @clean
  Scenario: Include archived logs(bsc#1148873)
    # For syslog
    When    Write multi lines to file "/var/log/log1" on "hanode1"
      """
      Sep 08 08:36:34 node1 log message line1
      Sep 08 08:37:01 node1 log message line2
      Sep 08 08:37:02 node1 log message line3
      """
    And     Run "xz /var/log/log1" on "hanode1"
    # bsc#1218491, unable to gather log files that are in the syslog format
    And     Run "touch -m -t 202201010000 /var/log/log1.xz" on "hanode1"
    When    Write multi lines to file "/var/log/log1" on "hanode1"
      """
      Sep 08 09:37:02 node1 log message line4
      Sep 08 09:37:12 node1 log message line5
      """
    # bsc#1218491, unable to gather log files that are in the syslog format
    And     Run "touch -m -t 202201010001 /var/log/log1" on "hanode1"
    And     Run "crm report -f 20200901 -E /var/log/log1 report1" on "hanode1"
    Then    File "log1" in "report1.tar.bz2"
    When    Run "tar jxf report1.tar.bz2" on "hanode1"
    And     Run "cat report1/hanode1/log1" on "hanode1"
    Then    Expected multiple lines in output
      """
      Sep 08 08:36:34 node1 log message line1
      Sep 08 08:37:01 node1 log message line2
      Sep 08 08:37:02 node1 log message line3
      Sep 08 09:37:02 node1 log message line4
      Sep 08 09:37:12 node1 log message line5
      """
    When    Run "rm -rf report1.tar.gz report1" on "hanode1"

    # For rfc5424
    When    Write multi lines to file "/var/log/log2" on "hanode1"
      """
      2022-09-08T14:24:36.003Z mymachine.example.com myapp - ID47
      2022-09-08T14:25:15.003Z mymachine.example.com myapp - ID48
      2022-09-08T14:26:15.003Z mymachine.example.com myapp - ID49
      """
    And     Run "xz /var/log/log2" on "hanode1"
    When    Write multi lines to file "/var/log/log2" on "hanode1"
      """
      2022-09-08T14:27:15.003Z mymachine.example.com myapp - ID50
      2022-09-08T14:28:15.003Z mymachine.example.com myapp - ID51
      """
    And     Run "crm report -f 20200901 -E /var/log/log2 report1" on "hanode1"
    Then    File "log2" in "report1.tar.bz2"
    When    Run "tar jxf report1.tar.bz2" on "hanode1"
    And     Run "cat report1/hanode1/log2" on "hanode1"
    Then    Expected multiple lines in output
      """
      2022-09-08T14:24:36.003Z mymachine.example.com myapp - ID47
      2022-09-08T14:25:15.003Z mymachine.example.com myapp - ID48
      2022-09-08T14:26:15.003Z mymachine.example.com myapp - ID49
      2022-09-08T14:27:15.003Z mymachine.example.com myapp - ID50
      2022-09-08T14:28:15.003Z mymachine.example.com myapp - ID51
      """
    When    Run "rm -rf report1.tar.gz report1" on "hanode1"

  @clean
  Scenario: Collect corosync.log(bsc#1148874)
    When    Run "sed -i 's/\(\s*to_logfile:\s*\).*/\1no/' /etc/corosync/corosync.conf" on "hanode1"
    When    Run "sed -i 's/\(\s*to_logfile:\s*\).*/\1no/' /etc/corosync/corosync.conf" on "hanode2"
    And     Run "corosync-cfgtool -R" on "hanode1"
    And     Run "rm -f /var/log/cluster/corosync.log" on "hanode1"
    And     Run "rm -f /var/log/cluster/corosync.log" on "hanode2"
    And     Run "crm cluster stop --all" on "hanode1"
    And     Run "crm cluster start --all" on "hanode1"
    And     Run "sleep 15" on "hanode1"

    And     Run "crm report report" on "hanode1"
    And     Run "tar jxf report.tar.bz2" on "hanode1"
    Then    File "corosync.log" not in "report.tar.bz2"
    When    Run "rm -rf report.tar.gz report" on "hanode1"

    When    Run "sed -i 's/\(\s*to_logfile:\s*\).*/\1yes/' /etc/corosync/corosync.conf" on "hanode1"
    When    Run "sed -i 's/\(\s*to_logfile:\s*\).*/\1yes/' /etc/corosync/corosync.conf" on "hanode2"
    And     Run "crm cluster stop --all" on "hanode1"
    And     Run "crm cluster start --all" on "hanode1"
    And     Run "sleep 15" on "hanode1"

    And     Run "crm report report" on "hanode1"
    And     Run "tar jxf report.tar.bz2" on "hanode1"
    Then    File "corosync.log" in "report.tar.bz2"
    When    Run "rm -rf report.tar.bz2 report" on "hanode1"

  @clean
  Scenario: Replace sensitive data(bsc#1163581)
    # Set sensitive data TEL and password
    When    Run "crm node utilization hanode1 set TEL 13356789876" on "hanode1"
    When    Run "crm node utilization hanode1 set password qwertyui" on "hanode1"
    When    Run "crm report report" on "hanode1"
    When    Run "tar jxf report.tar.bz2" on "hanode1"
    And     Try "grep -R 'qwertyui' report"
    # crm report mask passw.* by default
    # No password here
    Then    Expected return code is "1"
    When    Run "rm -rf report.tar.bz2 report" on "hanode1"

    # mask password and ip address by using crm.conf
    When    Run "crm configure primitive ip2 IPaddr2 params ip=@vip.0" on "hanode1"
    And     Run "sed -i 's/; \[report\]/[report]/' /etc/crm/crm.conf" on "hanode1"
    And     Run "sed -i 's/; sanitize_rule = .*$/sanitize_rule = passw.*|ip.*:raw/g' /etc/crm/crm.conf" on "hanode1"
    And     Run "crm report report" on "hanode1"
    And     Run "tar jxf report.tar.bz2" on "hanode1"
    And     Try "grep -R -E '@vip.0|qwertyui' report"
    # No password here
    Then    Expected return code is "1"
    When    Run "rm -rf report.tar.bz2 report" on "hanode1"

    # Do sanitize job, also for TEL
    When    Run "crm report -s -p TEL report" on "hanode1"
    When    Run "tar jxf report.tar.bz2" on "hanode1"
    And     Try "grep -R 'qwertyui' report"
    # No password here
    Then    Expected return code is "1"
    When    Try "grep -R '13356789876' report"
    # No TEL number here
    Then    Expected return code is "1"
    When    Run "rm -rf report.tar.bz2 report" on "hanode1"

    # bsc#1220022 with special characters
    When    Run "crm node utilization hanode2 set password "xin!(liang8e"" on "hanode1"
    When    Run "crm report report" on "hanode1"
    When    Run "tar jxf report.tar.bz2" on "hanode1"
    And     Try "grep -F -R 'xin!(liang8e' report"
    # No password here
    Then    Expected return code is "1"
    When    Run "rm -rf report.tar.bz2 report" on "hanode1"
    
    # disable sanitize
    When    Run "sed -i 's/; \[report\]/[report]/' /etc/crm/crm.conf" on "hanode1"
    And     Run "sed -i 's/sanitize_rule = .*$/sanitize_rule = /g' /etc/crm/crm.conf" on "hanode1"
    When    Run "crm report report" on "hanode1"
    When    Run "tar jxf report.tar.bz2" on "hanode1"
    And     Try "grep -R 'qwertyui' report"
    # found password
    Then    Expected return code is "0"
    When    Run "rm -rf report.tar.bz2 report" on "hanode1"

  @clean
  Scenario: When no logfile in corosync.conf (bsc#1244515, bsc#1232821)
    When    Run "sed -i '/logfile:/d' /etc/corosync/corosync.conf" on "hanode1"
    When    Run "sed -i '/logfile:/d' /etc/corosync/corosync.conf" on "hanode2"
    When    Try "crm report report" on "hanode1"
    # Should no exception here
    Then    Expected "TypeError:" not in stderr
