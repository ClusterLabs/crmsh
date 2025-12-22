@sbd
Feature: configure sbd delay start correctly

  Tag @clean means need to stop cluster service if the service is available

  @clean
  Scenario: disk-based SBD with small sbd_watchdog_timeout
    Given   Run "test -f /etc/crm/profiles.yml" OK
    Given   Yaml "default:corosync.totem.token" value is "5000"
    Given   Yaml "default:sbd.watchdog_timeout" value is "15"

    Given   Has disk "/dev/sda1" on "hanode1"
    Given   Cluster service is "stopped" on "hanode1"
    When    Run "crm cluster init -s /dev/sda1 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode1"
    And     Resource "stonith-sbd" type "fence_sbd" is "Started"
    And     SBD option "SBD_DELAY_START" value is "no"
    And     SBD option "SBD_WATCHDOG_TIMEOUT" value is "5"
    And     SBD option "msgwait" value for "/dev/sda1" is "30"
    # original value is 43, which is calculated by external/sbd RA
    # now fence_sbd doesn't calculate it, so this value is the default one
    # from pacemaker
    And     Cluster property "stonith-timeout" is "60"
    And     Parameter "pcmk_delay_max" not configured in "stonith-sbd"

    Given   Has disk "/dev/sda1" on "hanode2"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Service "sbd" is "started" on "hanode2"
    # SBD_DELAY_START >= (token + consensus + pcmk_delay_max + msgwait)  # for disk-based sbd
    And     SBD option "SBD_DELAY_START" value is "71"
    And     SBD option "SBD_WATCHDOG_TIMEOUT" value is "5"
    And     SBD option "msgwait" value for "/dev/sda1" is "30"
    # value_from_sbd >= 1.2 * msgwait  # for disk-based sbd
    # stonith_timeout >= max(value_from_sbd, constants.STONITH_TIMEOUT_DEFAULT) + token + consensus
    And     Cluster property "stonith-timeout" is "71"
    And     Parameter "pcmk_delay_max" configured in "stonith-sbd"

    Given   Has disk "/dev/sda1" on "hanode3"
    Given   Cluster service is "stopped" on "hanode3"
    When    Run "crm cluster join -c hanode1 -y" on "hanode3"
    Then    Cluster service is "started" on "hanode3"
    And     Service "sbd" is "started" on "hanode3"
    # SBD_DELAY_START >= (token + consensus + pcmk_delay_max + msgwait)  # for disk-based sbd
    # runtime value is "41", we keep the larger one here
    And     SBD option "SBD_DELAY_START" value is "41"
    And     SBD option "SBD_WATCHDOG_TIMEOUT" value is "5"
    And     SBD option "msgwait" value for "/dev/sda1" is "30"
    # value_from_sbd >= 1.2 * msgwait  # for disk-based sbd
    # stonith_timeout >= max(value_from_sbd, constants.STONITH_TIMEOUT_DEFAULT) + token + consensus
    # runtime value is "71", we keep ther larger one here
    And     Cluster property "stonith-timeout" is "71"
    And     Parameter "pcmk_delay_max" not configured in "stonith-sbd"

    # Increase expected value
    When    Run "crm sbd configure watchdog-timeout=45" on "hanode1"
    Then    SBD option "SBD_DELAY_START" value is "101"
    And     SBD option "msgwait" value for "/dev/sda1" is "90"
    And     Cluster property "stonith-timeout" is "119"
    And     Start timeout for sbd.service is "121" seconds

    # Decrease expected value
    When    Run "crm sbd configure watchdog-timeout=15" on "hanode1"
    Then    SBD option "SBD_DELAY_START" value is "41"
    And     SBD option "msgwait" value for "/dev/sda1" is "30"
    And     Cluster property "stonith-timeout" is "71"
    And     Start timeout for sbd.service is "90" seconds

    When    Run "crm cluster remove hanode3 -y" on "hanode1"
    Then    Cluster service is "stopped" on "hanode3"
    And     Service "sbd" is "stopped" on "hanode3"
    And     SBD option "SBD_DELAY_START" value is "71"
    And     SBD option "SBD_WATCHDOG_TIMEOUT" value is "5"
    And     SBD option "msgwait" value for "/dev/sda1" is "30"
    And     Cluster property "stonith-timeout" is "71"
    And     Parameter "pcmk_delay_max" configured in "stonith-sbd"

  @clean
  Scenario: disk-less SBD with small sbd_watchdog_timeout
    Given   Run "test -f /etc/crm/profiles.yml" OK
    Given   Yaml "default:corosync.totem.token" value is "5000"
    Given   Yaml "default:sbd.watchdog_timeout" value is "15"

    Given   Cluster service is "stopped" on "hanode1"
    When    Run "crm cluster init -S -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     SBD option "SBD_DELAY_START" value is "no"
    And     SBD option "SBD_WATCHDOG_TIMEOUT" value is "15"
    And     Cluster property "stonith-timeout" is "60"

    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    # SBD_DELAY_START >= (token + consensus + 2*SBD_WATCHDOG_TIMEOUT) # for disk-less sbd
    And     SBD option "SBD_DELAY_START" value is "41"
    And     SBD option "SBD_WATCHDOG_TIMEOUT" value is "15"
    # stonith-timeout >= 1.2 * max(stonith_watchdog_timeout, 2*SBD_WATCHDOG_TIMEOUT)  # for disk-less sbd
    # stonith_timeout >= max(value_from_sbd, constants.STONITH_TIMEOUT_DEFAULT) + token + consensus
    And     Cluster property "stonith-timeout" is "71"

    Given   Cluster service is "stopped" on "hanode3"
    When    Run "crm cluster join -c hanode1 -y" on "hanode3"
    Then    Cluster service is "started" on "hanode3"
    And     SBD option "SBD_DELAY_START" value is "41"
    And     SBD option "SBD_WATCHDOG_TIMEOUT" value is "15"
    And     Cluster property "stonith-timeout" is "71"

    When    Run "crm cluster remove hanode3 -y" on "hanode1"
    Then    Cluster service is "stopped" on "hanode3"
    And     SBD option "SBD_DELAY_START" value is "41"
    And     SBD option "SBD_WATCHDOG_TIMEOUT" value is "15"
    And     Cluster property "stonith-timeout" is "71"

    When    Try "crm configure property stonith-watchdog-timeout=1" on "hanode1"
    Then    Except "Can't set stonith-watchdog-timeout to 1 because it is less than SBD_WATCHDOG_TIMEOUT(now: 15)" in stderr

  @clean
  Scenario: disk-based SBD with big sbd_watchdog_timeout
    When    Run "sed -i 's/watchdog_timeout: 15/watchdog_timeout: 60/' /etc/crm/profiles.yml" on "hanode1"
    Given   Yaml "default:corosync.totem.token" value is "5000"
    Given   Yaml "default:sbd.watchdog_timeout" value is "60"

    Given   Has disk "/dev/sda1" on "hanode1"
    Given   Cluster service is "stopped" on "hanode1"
    When    Run "crm cluster init -s /dev/sda1 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode1"
    And     Resource "stonith-sbd" type "fence_sbd" is "Started"
    And     SBD option "SBD_DELAY_START" value is "no"
    And     SBD option "SBD_WATCHDOG_TIMEOUT" value is "5"
    And     SBD option "msgwait" value for "/dev/sda1" is "120"
    # original value is 172, which is calculated by external/sbd RA
    # now fence_sbd doesn't calculate it, so this value is the default one
    # from pacemaker
    And     Cluster property "stonith-timeout" is "60"
    And     Parameter "pcmk_delay_max" not configured in "stonith-sbd"

    Given   Has disk "/dev/sda1" on "hanode2"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Service "sbd" is "started" on "hanode2"
    # SBD_DELAY_START >= (token + consensus + pcmk_delay_max + msgwait)  # for disk-based sbd
    And     SBD option "SBD_DELAY_START" value is "161"
    And     SBD option "SBD_WATCHDOG_TIMEOUT" value is "5"
    And     SBD option "msgwait" value for "/dev/sda1" is "120"
    # stonith-timeout >= 1.2 * msgwait  # for disk-based sbd
    # stonith_timeout >= max(value_from_sbd, constants.STONITH_TIMEOUT_DEFAULT) + token + consensus
    And     Cluster property "stonith-timeout" is "155"
    And     Parameter "pcmk_delay_max" configured in "stonith-sbd"
    # since SBD_DELAY_START value(161s) > default systemd startup value(1min 30s)
    And     Run "test -f /etc/systemd/system/sbd.service.d/sbd_delay_start.conf" OK
    # 1.2*SBD_DELAY_START
    And     Run "grep 'TimeoutStartSec=193' /etc/systemd/system/sbd.service.d/sbd_delay_start.conf" OK

    Given   Has disk "/dev/sda1" on "hanode3"
    Given   Cluster service is "stopped" on "hanode3"
    When    Run "crm cluster join -c hanode1 -y" on "hanode3"
    Then    Cluster service is "started" on "hanode3"
    And     Service "sbd" is "started" on "hanode3"
    And     SBD option "SBD_DELAY_START" value is "131"
    And     SBD option "SBD_WATCHDOG_TIMEOUT" value is "5"
    And     SBD option "msgwait" value for "/dev/sda1" is "120"
    And     Cluster property "stonith-timeout" is "155"
    And     Parameter "pcmk_delay_max" not configured in "stonith-sbd"
    And     Run "test -f /etc/systemd/system/sbd.service.d/sbd_delay_start.conf" OK
    And     Run "grep 'TimeoutStartSec=157' /etc/systemd/system/sbd.service.d/sbd_delay_start.conf" OK

    When    Run "crm cluster remove hanode3 -y" on "hanode1"
    Then    Cluster service is "stopped" on "hanode3"
    And     Service "sbd" is "stopped" on "hanode3"
    And     SBD option "SBD_DELAY_START" value is "161"
    And     SBD option "SBD_WATCHDOG_TIMEOUT" value is "5"
    And     SBD option "msgwait" value for "/dev/sda1" is "120"
    And     Cluster property "stonith-timeout" is "155"
    And     Parameter "pcmk_delay_max" configured in "stonith-sbd"
    And     Run "test -f /etc/systemd/system/sbd.service.d/sbd_delay_start.conf" OK
    And     Run "grep 'TimeoutStartSec=193' /etc/systemd/system/sbd.service.d/sbd_delay_start.conf" OK
    When    Run "sed -i 's/watchdog_timeout: 60/watchdog_timeout: 15/g' /etc/crm/profiles.yml" on "hanode1"

  @clean
  Scenario: Add sbd via stage on a running cluster
    Given   Run "test -f /etc/crm/profiles.yml" OK
    Given   Yaml "default:corosync.totem.token" value is "5000"
    Given   Yaml "default:sbd.watchdog_timeout" value is "15"

    Given   Has disk "/dev/sda1" on "hanode1"
    Given   Has disk "/dev/sda1" on "hanode2"
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"

    When    Run "crm cluster init sbd -s /dev/sda1 -y" on "hanode1"
    Then    Service "sbd" is "started" on "hanode1"
    Then    Service "sbd" is "started" on "hanode2"
    And     SBD option "SBD_DELAY_START" value is "71"
    And     SBD option "SBD_WATCHDOG_TIMEOUT" value is "5"
    And     SBD option "msgwait" value for "/dev/sda1" is "30"
    And     Cluster property "stonith-timeout" is "71"
    And     Parameter "pcmk_delay_max" configured in "stonith-sbd"

  @clean
  Scenario: Add disk-based sbd with qdevice
    Given   Run "test -f /etc/crm/profiles.yml" OK
    Given   Yaml "default:corosync.totem.token" value is "5000"
    Given   Yaml "default:sbd.watchdog_timeout" value is "15"
    Given   Has disk "/dev/sda1" on "hanode1"
    Given   Has disk "/dev/sda1" on "hanode2"
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"

    When    Run "crm cluster init -s /dev/sda1 --qnetd-hostname=qnetd-node -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Service "corosync-qdevice" is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode2"
    And     Service "sbd" is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode2"

    And     SBD option "SBD_DELAY_START" value is "41"
    And     SBD option "SBD_WATCHDOG_TIMEOUT" value is "5"
    And     SBD option "msgwait" value for "/dev/sda1" is "30"
    And     Cluster property "stonith-timeout" is "71"
    And     Parameter "pcmk_delay_max" not configured in "stonith-sbd"

  @clean
  Scenario: Add disk-less sbd with qdevice
    Given   Run "test -f /etc/crm/profiles.yml" OK
    Given   Yaml "default:corosync.totem.token" value is "5000"
    Given   Yaml "default:sbd.watchdog_timeout" value is "15"
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"

    When    Run "crm cluster init -S --qnetd-hostname=qnetd-node -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Service "corosync-qdevice" is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode2"
    And     Service "sbd" is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode2"

    And     SBD option "SBD_DELAY_START" value is "81"
    And     SBD option "SBD_WATCHDOG_TIMEOUT" value is "35"
    And     Cluster property "stonith-timeout" is "95"
    And     Cluster property "stonith-watchdog-timeout" is "70"

  @clean
  Scenario: Add qdevice on a diskless SBD cluster (bsc#1254571)
    Given   Cluster service is "stopped" on "hanode1"
    When    Run "crm cluster init -S -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode1"
    When    Run "crm cluster init qdevice --qnetd-hostname=qnetd-node -y" on "hanode1"
    Then    Service "corosync-qdevice" is "started" on "hanode1"
    And     SBD option "SBD_WATCHDOG_TIMEOUT" value is "35"
    And     Cluster property "stonith-timeout" is "95"
    And     Cluster property "stonith-watchdog-timeout" is "70"

  @clean
  Scenario: Add and remove qdevice from cluster with sbd running
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -s /dev/sda1 -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Service "sbd" is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode2"
    And     Parameter "pcmk_delay_max" configured in "stonith-sbd"
    When    Run "crm cluster init qdevice --qnetd-hostname=qnetd-node -y" on "hanode1"
    Then    Service "corosync-qdevice" is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode2"
    And     Parameter "pcmk_delay_max" not configured in "stonith-sbd"
    When    Run "crm cluster remove --qdevice -y" on "hanode1"
    Then    Service "corosync-qdevice" is "stopped" on "hanode1"
    And     Service "corosync-qdevice" is "stopped" on "hanode2"
    And     Parameter "pcmk_delay_max" configured in "stonith-sbd"

  @clean
  Scenario: Test priority-fence-delay and priority
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Property "priority" in "rsc_defaults" is "1"
    When    Run "crm cluster remove hanode2 -y" on "hanode1"
    Then    Cluster service is "stopped" on "hanode2"
    And     Property "priority" in "rsc_defaults" is "0"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    And     Property "priority" in "rsc_defaults" is "1"
    When    Run "crm cluster init qdevice --qnetd-hostname=qnetd-node -y" on "hanode1"
    Then    Service "corosync-qdevice" is "started" on "hanode1"
    And     Service "corosync-qdevice" is "started" on "hanode2"
    And     Property "priority" in "rsc_defaults" is "0"
    When    Run "crm cluster remove --qdevice -y" on "hanode1"
    Then    Service "corosync-qdevice" is "stopped" on "hanode1"
    And     Service "corosync-qdevice" is "stopped" on "hanode2"
    And     Property "priority" in "rsc_defaults" is "1"
    When    Run "crm cluster init sbd -s /dev/sda1 -y" on "hanode1"
    Then    Service "sbd" is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode2"
    And     Parameter "pcmk_delay_max" configured in "stonith-sbd"
    And     Cluster property "stonith-timeout" is "71"
    And     Cluster property "priority-fencing-delay" is "60"
    When    Run "crm cluster remove hanode2 -y" on "hanode1"
    Then    Cluster service is "stopped" on "hanode2"
    And     Property "priority" in "rsc_defaults" is "0"
    And     Cluster property "priority-fencing-delay" is "0"
    And     Parameter "pcmk_delay_max" not configured in "stonith-sbd"

  @clean
  Scenario: Check and fix sbd-related timeout values for disk-based sbd
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    When    Run "crm cluster init sbd -s /dev/sda1 -y" on "hanode1"
    Then    Service "sbd" is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode2"
    # check /etc/sysconf/sbd consistency
    When    Run "sed -i 's/SBD_DELAY_START=.*/SBD_DELAY_START="no"/' /etc/sysconfig/sbd" on "hanode2"
    When    Try "crm sbd configure show"
    Then    Expected "/etc/sysconfig/sbd is not consistent across cluster nodes" in stderr
    When    Try "crm cluster health sbd"
    Then    Expected "/etc/sysconfig/sbd is not consistent across cluster nodes" in stderr
    When    Run "sed -i 's/SBD_DELAY_START=.*/SBD_DELAY_START=71/' /etc/sysconfig/sbd" on "hanode2"
    When    Run "crm cluster health sbd" on "hanode1"
    Then    Expected "SBD: Check sbd timeout configuration: OK" in stdout
    # check sbd disk metadata
    When    Run "sbd -1 15 -4 16 -d /dev/sda1 create" on "hanode1"
    When    Try "crm sbd configur show disk_metadata" on "hanode1"
    Then    Expected "It's recommended that msgwait(now 16) >= 2*watchdog timeout(now 15)" in stderr
    When    Try "crm cluster health sbd" on "hanode1"
    Then    Expected "It's recommended that msgwait(now 16) >= 2*watchdog timeout(now 15)" in stderr
    When    Run "crm cluster health sbd --fix" on "hanode1"
    Then    Expected "SBD: Check sbd timeout configuration: OK" in stdout
    # check SBD_DELAY_START
    When    Run "sed -i 's/SBD_DELAY_START=.*/SBD_DELAY_START=40/' /etc/sysconfig/sbd" on "hanode1"
    When    Run "sed -i 's/SBD_DELAY_START=.*/SBD_DELAY_START=40/' /etc/sysconfig/sbd" on "hanode2"
    When    Try "crm sbd configure show" on "hanode1"
    Then    Expected "It's recommended that SBD_DELAY_START is set to 71, now is 40" in stderr
    When    Try "crm cluster health sbd" on "hanode1"
    Then    Expected "It's recommended that SBD_DELAY_START is set to 71, now is 40" in stderr
    When    Run "crm cluster health sbd --fix" on "hanode1"
    Then    Expected "SBD: Check sbd timeout configuration: OK" in stdout
    # check stonith-timeout
    When    Run "crm configure property stonith-timeout=50" on "hanode1"
    When    Try "crm sbd configure show" on "hanode1"
    Then    Expected "It's recommended that stonith-timeout is set to 71, now is 50" in stderr
    When    Try "crm cluster health sbd" on "hanode1"
    Then    Expected "It's recommended that stonith-timeout is set to 71, now is 50" in stderr
    When    Run "crm cluster health sbd --fix" on "hanode1"
    Then    Expected "SBD: Check sbd timeout configuration: OK" in stdout
    # Adjust token timeout in corosync.conf
    When    Run "sed -i 's/token: .*/token: 10000/' /etc/corosync/corosync.conf" on "hanode1"
    When    Run "sed -i 's/token: .*/token: 10000/' /etc/corosync/corosync.conf" on "hanode2"
    When    Run "corosync-cfgtool -R" on "hanode1"
    When    Try "crm sbd configure show" on "hanode1"
    Then    Expected "It's recommended that SBD_DELAY_START is set to 82, now is 71" in stderr
    When    Try "crm cluster health sbd" on "hanode1"
    Then    Expected "It's recommended that SBD_DELAY_START is set to 82, now is 71" in stderr
    When    Run "crm cluster health sbd --fix" on "hanode1"
    Then    Expected "SBD: Check sbd timeout configuration: OK" in stdout

  @clean
  Scenario: Check and fix sbd-related timeout values for diskless sbd
    Given   Cluster service is "stopped" on "hanode1"
    Given   Cluster service is "stopped" on "hanode2"
    When    Run "crm cluster init -y" on "hanode1"
    Then    Cluster service is "started" on "hanode1"
    When    Run "crm cluster join -c hanode1 -y" on "hanode2"
    Then    Cluster service is "started" on "hanode2"
    When    Run "crm cluster init sbd -S -y" on "hanode1"
    Then    Service "sbd" is "started" on "hanode1"
    And     Service "sbd" is "started" on "hanode2"
    # Delete stonith-watchdog-timeout
    When    Delete property "stonith-watchdog-timeout" from cluster
    When    Try "crm sbd configure show" on "hanode1"
    Then    Expected "It's recommended that stonith-watchdog-timeout is set to 30, now is not set" in stderr
    When    Try "crm cluster health sbd" on "hanode1"
    Then    Expected "It's recommended that stonith-watchdog-timeout is set to 30, now is not set" in stderr
    When    Run "crm cluster health sbd --fix" on "hanode1"
    Then    Expected "SBD: Check sbd timeout configuration: OK" in stdout
