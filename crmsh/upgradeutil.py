import logging
import os.path
import typing

import parallax
import sys

import crmsh.healthcheck
import crmsh.parallax
import crmsh.utils


# pump this seq when upgrade check need to be run
CURRENT_UPGRADE_SEQ = (1, 0)
DATA_DIR = '/var/lib/crmsh'
SEQ_FILE_PATH = DATA_DIR + '/upgrade_seq'
# touch this file to force a upgrade process
FORCE_UPGRADE_FILE_PATH = DATA_DIR + '/upgrade_forced'


VERSION_FEATURES = {
    (1, 0): [crmsh.healthcheck.PasswordlessHaclusterAuthenticationFeature]
}


logger = logging.getLogger(__name__)


class _SkipUpgrade(Exception):
    pass


def _parse_upgrade_seq(s: bytes) -> typing.Tuple[int, int]:
    parts = s.split(b'.', 1)
    if len(parts) != 2:
        raise ValueError('Invalid upgrade seq {}'.format(s))
    major = int(parts[0])
    minor = int(parts[1])
    return major, minor


def _format_upgrade_seq(s: typing.Tuple[int, int]) -> str:
    return '.'.join((str(x) for x in s))


def _get_file_content(path, default=None):
    try:
        with open(path, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        return default


def _is_upgrade_needed(nodes):
    """decide whether upgrading is needed by checking local sequence file"""
    needed = False
    try:
        os.stat(FORCE_UPGRADE_FILE_PATH)
        needed = True
    except FileNotFoundError:
        pass
    if not needed:
        try:
            local_seq = _parse_upgrade_seq(_get_file_content(SEQ_FILE_PATH, b'').strip())
        except ValueError:
            local_seq = (0, 0)
        needed = CURRENT_UPGRADE_SEQ > local_seq
    return needed


def _is_cluster_target_seq_consistent(nodes):
    cmd = '/usr/bin/env python3 -m crmsh.upgradeutil get-seq'
    try:
        results = list(crmsh.parallax.parallax_run(nodes, cmd).values())
    except parallax.Error as e:
        raise _SkipUpgrade() from None
    try:
        return all(CURRENT_UPGRADE_SEQ == _parse_upgrade_seq(stdout.strip()) if rc == 0 else False for rc, stdout, stderr in results)
    except ValueError as e:
        logger.warning("Remote command '%s' returns unexpected output: %s", cmd, results, exc_info=e)
        return False


def _get_minimal_seq_in_cluster(nodes) -> typing.Tuple[int, int]:
    try:
        return min(
            _parse_upgrade_seq(stdout.strip()) if rc == 0 else (0, 0)
            for rc, stdout, stderr in crmsh.parallax.parallax_run(nodes, 'cat {}'.format(SEQ_FILE_PATH)).values()
        )
    except ValueError:
        return 0, 0


def _upgrade(nodes, seq):
    def ask(msg: str):
        if not crmsh.utils.ask('Upgrade of crmsh configuration: ' + msg, background_wait=False):
            raise crmsh.healthcheck.AskDeniedByUser()
    try:
        for key in VERSION_FEATURES.keys():
            if seq < key <= CURRENT_UPGRADE_SEQ:
                for feature_class in VERSION_FEATURES[key]:
                    feature = feature_class()
                    if crmsh.healthcheck.feature_full_check(feature, nodes):
                        logger.info("Upgrade: feature %s is already functional.")
                    else:
                        logger.debug("Upgrade: fixing feature %s...")
                        crmsh.healthcheck.feature_fix(feature, nodes, ask)
        logger.info("Upgrade of crmsh configuration succeeded.")
    except crmsh.healthcheck.AskDeniedByUser:
        raise _SkipUpgrade() from None


def upgrade_if_needed():
    if os.geteuid() != 0:
        return
    nodes = crmsh.utils.list_cluster_nodes(no_reg=True)
    if nodes and _is_upgrade_needed(nodes):
        logger.info("crmsh version is newer than its configuration. Configuration upgrade is needed.")
        try:
            if not _is_cluster_target_seq_consistent(nodes):
                logger.warning("crmsh version is inconsistent in cluster.")
                raise _SkipUpgrade()
            seq = _get_minimal_seq_in_cluster(nodes)
            logger.debug(
                "Upgrading crmsh configuration from seq %s to %s.",
                seq, _format_upgrade_seq(CURRENT_UPGRADE_SEQ),
            )
            _upgrade(nodes, seq)
        except _SkipUpgrade:
            logger.warning("Upgrade of crmsh configuration skipped.")
            return
        crmsh.parallax.parallax_call(
            nodes,
            "mkdir -p '{}' && echo '{}' > '{}'".format(
                DATA_DIR,
                _format_upgrade_seq(CURRENT_UPGRADE_SEQ),
                SEQ_FILE_PATH,
            ),
        )
        crmsh.parallax.parallax_call(nodes, 'rm -f {}'.format(FORCE_UPGRADE_FILE_PATH))
        logger.debug("Upgrade of crmsh configuration finished.", seq)


def force_set_local_upgrade_seq():
    """Create the upgrade sequence file and set it to CURRENT_UPGRADE_SEQ.

    It should only be used when initializing new cluster nodes."""
    if not os.path.exists(DATA_DIR):
        crmsh.utils.mkdirs_owned(DATA_DIR, mode=0o755, uid='root', gid='root')
    up_seq = _format_upgrade_seq(CURRENT_UPGRADE_SEQ)
    crmsh.utils.str2file(up_seq, SEQ_FILE_PATH)


def main():
    if sys.argv[1] == 'get-seq':
        print(_format_upgrade_seq(CURRENT_UPGRADE_SEQ))


if __name__ == '__main__':
    main()
