@hb_report
Feature: hb_report functional test

  Tag @clean means need to stop cluster service if the service is available

  @clean
  Scenario: Run hb_report on new environment
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Try "hb_report"
    Then    Except "ERROR: hanode1#Master: Could not figure out a list of nodes; is this a cluster node?"
    When    Run "hb_report -n hanode1" on "hanode1"
    Then    Default hb_report tar file created
    When    Remove default hb_report tar file
    When    Run "hb_report -n hanode2" on "hanode1"
    Then    Default hb_report tar file created
    When    Remove default hb_report tar file

  @clean
  Scenario: Verify log file filter by time span
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y --no-overwrite-sshkey" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"

    When    Run "echo "Feb 01 08:57:29 node1 line1" > /opt/text_time_span" on "hanode1"
    When    Run "echo "Feb 05 09:00:00 node1 line2" >> /opt/text_time_span" on "hanode1"
    When    Run "echo "Feb 15 09:00:00 node1 line3" >> /opt/text_time_span" on "hanode1"
    When    Run "echo "Feb 15 09:23:00 node1 line4" >> /opt/text_time_span" on "hanode1"
    When    Run "echo "Feb 15 09:45:00 node1 line5" >> /opt/text_time_span" on "hanode1"
    # file not in time span
    When     Run "hb_report -E /opt/text_time_span -f "Jan01" -t "Jan31" report1" on "hanode1"
    Then    File "text_time_span" not in "report1.tar.bz2"
    When    Run "rm -f report1.tar.bz2" on "hanode1"

    # file content all in time span
    When    Run "hb_report -E /opt/text_time_span -f "Jan01" -t "Feb16" report1" on "hanode1"
    Then    File "text_time_span" in "report1.tar.bz2"
    When    Get "text_time_span" content from "report1.tar.bz2"
    Then    Expected multiple lines
      """
      Feb 01 08:57:29 node1 line1
      Feb 05 09:00:00 node1 line2
      Feb 15 09:00:00 node1 line3
      Feb 15 09:23:00 node1 line4
      Feb 15 09:45:00 node1 line5
      """
    When    Run "rm -f report1.tar.bz2" on "hanode1"

    # part of file content in time span
    When    Run "hb_report -E /opt/text_time_span -f "Jan01" -t "Feb10" report1" on "hanode1"
    Then    File "text_time_span" in "report1.tar.bz2"
    When    Get "text_time_span" content from "report1.tar.bz2"
    Then    Expected multiple lines
      """
      Feb 01 08:57:29 node1 line1
      Feb 05 09:00:00 node1 line2
      """
    When    Run "rm -f report1.tar.bz2" on "hanode1"

    # part of file content in time span
    When    Run "hb_report -E /opt/text_time_span -f "Feb15 09:00" -t "Feb15 09:43" report1" on "hanode1"
    Then    File "text_time_span" in "report1.tar.bz2"
    When    Get "text_time_span" content from "report1.tar.bz2"
    Then    Expected multiple lines
      """
      Feb 15 09:00:00 node1 line3
      Feb 15 09:23:00 node1 line4
      """
    When    Run "rm -f report1.tar.bz2" on "hanode1"
    And     Run "rm -f /opt/text" on "hanode1"

  @clean
  Scenario: Verify hb_report options
    Given   Cluster service is "stopped" on "hanode1"
    And     Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y --no-overwrite-sshkey" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Online nodes are "hanode1 hanode2"

    # -f and -t option
    When    Run "hb_report -f 2019 /opt/report" on "hanode1"
    Then    "/opt/report.tar.bz2" created
    And     "/opt/report.tar.bz2" include essential files for "hanode1 hanode2"
    When    Run "rm -f /opt/report.tar.bz2" on "hanode1"
    # from time after to time
    When    Try "hb_report -f 2020 -t 2019"
    Then    Except "ERROR: hanode1#Master: Start time must be before finish time"
    # wrong format of from time
    When    Try "hb_report -f xxxx"
    Then    Except multiline:
      """
      ERROR: parse_time xxxx: Unknown string format: xxxx
      ERROR: hanode1#Master: Try these format like: 2pm; 1:00; "2019/9/5 12:30"; "09-Sep-07 2:00"
      """
    # wrong format of to time
    When    Try "hb_report -f 2020/01/01 -t wrong"
    Then    Except multiline:
      """
      ERROR: parse_time wrong: Unknown string format: wrong
      ERROR: hanode1#Master: Try these format like: 2pm; 1:00; "2019/9/5 12:30"; "09-Sep-07 2:00"
      """
    # -b option
    When    Run "hb_report -b 12d report" on "hanode1"
    Then    "report.tar.bz2" created
    And     "report.tar.bz2" include essential files for "hanode1 hanode2"
    When    Run "rm -f report.tar.bz2" on "hanode1"
    # wrong format of -b time
    When    Try "hb_report -b 2019"
    Then    Except "ERROR: hanode1#Master: Wrong format of -b option ([1-9][0-9]*[YmdHM])"

    # -d and -Z option
    When    Run "hb_report -d" on "hanode1"
    Then    Default hb_report directory created
    When    Run "hb_report -f 2019 -d /opt/report" on "hanode1"
    Then    "/opt/report" created
    And     "/opt/report" include essential files for "hanode1 hanode2"
    When    Try "hb_report -d /opt/report"
    Then    Except "ERROR: hanode1#Master: Destination directory /opt/report exists, please cleanup or use -Z option"
    When    Run "hb_report -d -Z /opt/report" on "hanode1"
    Then    "/opt/report" created
    When    Run "rm -rf /opt/report" on "hanode1"

    # -n option
    When    Run "hb_report -f 2019 -n hanode2 onenode" on "hanode1"
    Then    "onenode.tar.bz2" created
    And     "onenode.tar.bz2" include essential files for "hanode2"
    When    Run "rm -f onenode.tar.bz2" on "hanode1"

    # -S option
    When    Run "hb_report -S onenode" on "hanode1"
    Then    "onenode.tar.bz2" created
    And     "onenode.tar.bz2" include essential files for "hanode1"
    When    Run "rm -f onenode.tar.bz2" on "hanode1"
