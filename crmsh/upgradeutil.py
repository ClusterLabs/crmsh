import logging
import os.path
import typing

import parallax
import sys

import crmsh.parallax
import crmsh.utils


# pump this seq when upgrade check need to be run
CURRENT_UPGRADE_SEQ = 1
DATA_DIR = os.path.expanduser('~hacluster/crmsh')
SEQ_FILE_PATH = DATA_DIR + '/upgrade_seq'
# touch this file to force a upgrade process
FORCE_UPGRADE_FILE_PATH = DATA_DIR + '/upgrade_forced'


logger = logging.getLogger(__name__)


class _SkipUpgrade(Exception):
    pass


def _get_file_content(path, default=None):
    try:
        with open(path, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        return default


def _parallax_run(nodes: str, cmd: str) -> typing.Dict[str, typing.Tuple[int, bytes, bytes]]:
    parallax_options = parallax.Options()
    parallax_options.ssh_options = ['StrictHostKeyChecking=no', 'ConnectTimeout=10']
    ret = dict()
    for node, result in parallax.run(nodes, cmd, parallax_options).items():
        if isinstance(result, parallax.Error):
            logger.warning("SSH connection to remote node %s failed.", node, exc_info=result)
            raise result
        ret[node] = result
    return ret


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
            local_seq = int(_get_file_content(SEQ_FILE_PATH, b'').strip())
        except ValueError:
            local_seq = 0
        needed = CURRENT_UPGRADE_SEQ > local_seq
    return needed


def _is_cluster_target_seq_consistent(nodes):
    cmd = '/usr/bin/env python3 -m crmsh.upgradeutil get-seq'
    try:
        results = list(_parallax_run(nodes, cmd).values())
    except parallax.Error as e:
        raise _SkipUpgrade() from None
    try:
        return all(CURRENT_UPGRADE_SEQ == int(stdout.strip()) if rc == 0 else False for rc, stdout, stderr in results)
    except ValueError as e:
        logger.warning("Remote command '%s' returns unexpected output: %s", cmd, results, exc_info=e)
        return False


def _get_minimal_seq_in_cluster(nodes):
    try:
        return min(
            int(stdout.strip()) if rc == 0 else 0
            for rc, stdout, stderr in _parallax_run(nodes, 'cat {}'.format(SEQ_FILE_PATH)).values()
        )
    except ValueError:
        return 0


def _upgrade(nodes, seq):
    logger.info("Upgrading cluster...")
    if seq <= 0:
        seq_0_setup_hacluster_passwordless(nodes)


def upgrade_if_needed():
    nodes = crmsh.utils.list_cluster_nodes(no_reg=True)
    if nodes and _is_upgrade_needed(nodes):
        logger.info("crmsh version is newer than its configuration. Configuration upgrade is needed.")
        try:
            if not _is_cluster_target_seq_consistent(nodes):
                logger.warning("crmsh version is inconsistent in cluster.")
                raise _SkipUpgrade()
            seq = _get_minimal_seq_in_cluster(nodes)
            logger.debug("Upgrading crmsh configuration from seq %s to %s.", seq, CURRENT_UPGRADE_SEQ)
            _upgrade(nodes, seq)
        except _SkipUpgrade:
            logger.warning("Configuration upgrade skipped.")
            return
        crmsh.parallax.parallax_call(
            nodes,
            "mkdir -p '{}' && echo '{}' > '{}'".format(DATA_DIR, CURRENT_UPGRADE_SEQ, SEQ_FILE_PATH),
        )
        crmsh.parallax.parallax_call(nodes, 'rm -f {}'.format(FORCE_UPGRADE_FILE_PATH))
        logger.debug("Configuration upgrade finished.", seq, CURRENT_UPGRADE_SEQ)


def force_set_local_upgrade_seq():
    """Create the upgrade sequence file and set it to CURRENT_UPGRADE_SEQ.

    It should only be used when initializing new cluster nodes."""
    try:
        os.mkdir(DATA_DIR)
    except FileExistsError:
        pass
    with open(SEQ_FILE_PATH, 'w', encoding='ascii') as f:
        print(CURRENT_UPGRADE_SEQ, file=f)


def seq_0_setup_hacluster_passwordless(nodes):
    """setup passwordless ssh authentication by running crm cluster ssh init/join on appreciated nodes."""
    # https://bugzilla.suse.com/show_bug.cgi?id=1201785
    logger.debug("upgradeutil: setup passwordless ssh authentication for user hacluster")
    try:
        nodes_without_keys = [
            node for node, result in
            _parallax_run(
                nodes,
                '[ -f ~hacluster/.ssh/id_rsa ] || [ -f ~hacluster/.ssh/id_ecdsa ] || [ -f ~hacluster/.ssh/id_ed25519 ]'
            ).items()
            if result[0] != 0
        ]
    except parallax.Error:
        raise _SkipUpgrade() from None
    if nodes_without_keys:
        if not crmsh.utils.ask("Configuration upgrade: setup passwordless ssh authentication for user hacluster?"):
            raise _SkipUpgrade()
        if len(nodes_without_keys) == len(nodes):
            # pick one node to run init ssh on it
            init_node = nodes_without_keys[0]
            # and run join ssh on other nodes
            join_nodes = list()
            join_nodes.extend(nodes)
            join_nodes.remove(init_node)
            join_target_node = init_node
        else:
            nodes_with_keys = set(nodes) - set(nodes_without_keys)
            # no need to init ssh
            init_node = None
            join_nodes = nodes_without_keys
            # pick one node as join target
            join_target_node = next(iter(nodes_with_keys))
        if init_node is not None:
            try:
                crmsh.parallax.parallax_call([init_node], 'crm cluster init ssh -y')
            except ValueError as e:
                logger.error('Failed to initialize passwordless ssh authentication on node %s.', init_node, exc_info=e)
                raise _SkipUpgrade from None
        try:
            for node in join_nodes:
                crmsh.parallax.parallax_call([node], 'crm cluster join ssh -c {} -y'.format(join_target_node))
        except ValueError as e:
            logger.error('Failed to initialize passwordless ssh authentication.', exc_info=e)
            raise _SkipUpgrade from None


def main():
    if sys.argv[1] == 'get-seq':
        print(CURRENT_UPGRADE_SEQ)


if __name__ == '__main__':
    main()
