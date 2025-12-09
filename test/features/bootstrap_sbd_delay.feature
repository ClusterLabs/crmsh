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
    And     SBD option "SBD_DELAY_START" value is "71"
    And     SBD option "SBD_WATCHDOG_TIMEOUT" value is "5"
    And     SBD option "msgwait" value for "/dev/sda1" is "30"
    # value_from_sbd >= 1.2 * msgwait  # for disk-based sbd
    # stonith_timeout >= max(value_from_sbd, constants.STONITH_TIMEOUT_DEFAULT) + token + consensus
    # runtime value is "71", we keep ther larger one here
    And     Cluster property "stonith-timeout" is "71"
    And     Parameter "pcmk_delay_max" not configured in "stonith-sbd"

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
    And     Run "grep 'TimeoutSec=193' /etc/systemd/system/sbd.service.d/sbd_delay_start.conf" OK

    Given   Has disk "/dev/sda1" on "hanode3"
    Given   Cluster service is "stopped" on "hanode3"
    When    Run "crm cluster join -c hanode1 -y" on "hanode3"
    Then    Cluster service is "started" on "hanode3"
    And     Service "sbd" is "started" on "hanode3"
    And     SBD option "SBD_DELAY_START" value is "161"
    And     SBD option "SBD_WATCHDOG_TIMEOUT" value is "5"
    And     SBD option "msgwait" value for "/dev/sda1" is "120"
    And     Cluster property "stonith-timeout" is "155"
    And     Parameter "pcmk_delay_max" not configured in "stonith-sbd"
    And     Run "test -f /etc/systemd/system/sbd.service.d/sbd_delay_start.conf" OK
    And     Run "grep 'TimeoutSec=193' /etc/systemd/system/sbd.service.d/sbd_delay_start.conf" OK

    When    Run "crm cluster remove hanode3 -y" on "hanode1"
    Then    Cluster service is "stopped" on "hanode3"
    And     Service "sbd" is "stopped" on "hanode3"
    And     SBD option "SBD_DELAY_START" value is "161"
    And     SBD option "SBD_WATCHDOG_TIMEOUT" value is "5"
    And     SBD option "msgwait" value for "/dev/sda1" is "120"
    And     Cluster property "stonith-timeout" is "155"
    And     Parameter "pcmk_delay_max" configured in "stonith-sbd"
    And     Run "test -f /etc/systemd/system/sbd.service.d/sbd_delay_start.conf" OK
    And     Run "grep 'TimeoutSec=193' /etc/systemd/system/sbd.service.d/sbd_delay_start.conf" OK
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
