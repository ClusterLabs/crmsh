import logging
import argparse
import os
import os.path
import parallax
import subprocess
import sys
import typing

import crmsh.parallax
import crmsh.utils


logger = logging.getLogger(__name__)


class Feature:
    _feature_registry = dict()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        Feature._feature_registry[cls.__name__.rsplit('.', 1)[-1]] = cls

    @staticmethod
    def get_feature_by_name(name: str):
        return Feature._feature_registry[name]

    def check_quick(self) -> bool:
        raise NotImplementedError

    def check_local(self, nodes: typing.Iterable[str]) -> bool:
        """Check whether the feature is functional on local node."""
        raise NotImplementedError

    def check_cluster(self, nodes: typing.Iterable[str]) -> bool:
        """Check whether the feature is functional on the cluster."""
        raise NotImplementedError

    def fix_local(self, nodes: typing.Iterable[str], ask: typing.Callable[[str], None]) -> None:
        """Fix the feature on local node.

        At least one of fix_local and fix_cluster should be implemented. If fix_local is not implemented, this method
        will be run on each node.
        """
        raise NotImplementedError

    def fix_cluster(self, nodes: typing.Iterable[str], ask: typing.Callable[[str], None]) -> None:
        """Fix the feature on the cluster.

        At least one of fix_local and fix_cluster should be implemented. If this method is not implemented, fix_local
        will be run on each node.
        """
        raise NotImplementedError


class FixFailure(Exception):
    pass


class AskDeniedByUser(Exception):
    pass


def feature_quick_check(feature: Feature):
    return feature.check_quick()


def feature_local_check(feature: Feature, nodes: typing.Iterable[str]):
    try:
        if not feature.check_quick():
            return False
    except NotImplementedError:
        pass
    return feature.check_local(nodes)


def feature_full_check(feature: Feature, nodes: typing.Iterable[str]) -> bool:
    try:
        if not feature.check_quick():
            return False
    except NotImplementedError:
        pass
    try:
        if not feature.check_local(nodes):
            return False
    except NotImplementedError:
        pass
    try:
        return feature.check_cluster(nodes)
    except NotImplementedError:
        results = _parallax_run(
            nodes,
            '/usr/bin/env python3 -m crmsh.healthcheck check-local {}'.format(
                feature.__class__.__name__.rsplit('.', 1)[-1],
            )
        )
        return all(rc == 0 for rc, _, _ in results.values())


def feature_fix(feature: Feature, nodes: typing.Iterable[str], ask: typing.Callable[[str], None]) -> None:
    try:
        return feature.fix_cluster(nodes, ask)
    except NotImplementedError:
        results = _parallax_run(
            nodes,
            '/usr/bin/env python3 -m crmsh.healthcheck fix-local {}'.format(
                feature.__class__.__name__.rsplit('.', 1)[-1],
            )
        )
        if any(rc != 0 for rc, _, _ in results.values()):
            raise FixFailure


class PasswordlessHaclusterAuthenticationFeature(Feature):
    SSH_DIR = os.path.expanduser('~hacluster/.ssh')
    KEY_TYPES = ['ed25519', 'ecdsa', 'rsa']

    def check_quick(self) -> bool:
        for key_type in self.KEY_TYPES:
            try:
                os.stat('{}/{}'.format(self.SSH_DIR, key_type))
                os.stat('{}/{}.pub'.format(self.SSH_DIR, key_type))
                return True
            except FileNotFoundError:
                pass
        return False

    def check_local(self, nodes: typing.Iterable[str]) -> bool:
        try:
            for node in nodes:
                subprocess.check_call(
                    ['sudo', 'su', '-', 'hacluster', '-c', 'ssh hacluster@{} true'.format(node)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            return True
        except subprocess.CalledProcessError:
            return False

    def fix_cluster(self, nodes: typing.Iterable[str], ask: typing.Callable[[str], None]) -> None:
        logger.debug("setup passwordless ssh authentication for user hacluster")
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
            raise FixFailure()
        if nodes_without_keys:
            ask("Setup passwordless ssh authentication for user hacluster?")
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
                    raise FixFailure from None
            try:
                for node in join_nodes:
                    crmsh.parallax.parallax_call([node], 'crm cluster join ssh -c {} -y'.format(join_target_node))
            except ValueError as e:
                logger.error('Failed to initialize passwordless ssh authentication.', exc_info=e)
                raise FixFailure from None


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


def main_check_local(args) -> int:
    try:
        feature = Feature.get_feature_by_name(args.feature)()
        nodes = crmsh.utils.list_cluster_nodes(no_reg=True)
        if nodes:
            if feature_local_check(feature, nodes):
                return 0
            else:
                return 1
    except KeyError:
        logger.error('No such feature: %s.', args.feature)
    return 2


def main_fix_local(args) -> int:
    try:
        feature = Feature.get_feature_by_name(args.feature)()
        nodes = crmsh.utils.list_cluster_nodes(no_reg=True)
        if nodes:
            if args.yes:
                def ask(msg): return True
            else:
                def ask(msg): return crmsh.utils.ask('Healthcheck: fix: ' + msg, background_wait=False)
            if args.without_check or not feature_local_check(feature, nodes):
                feature.fix_local(nodes, ask)
            return 0
    except KeyError:
        logger.error('No such feature: %s.', args.feature)
    return 2


def main_fix_cluster(args) -> int:
    try:
        feature = Feature.get_feature_by_name(args.feature)()
        nodes = crmsh.utils.list_cluster_nodes(no_reg=True)
        if nodes:
            if args.yes:
                def ask(msg): return True
            else:
                def ask(msg): return crmsh.utils.ask('Healthcheck: fix: ' + msg, background_wait=False)
            if args.without_check or not feature_full_check(feature, nodes):
                feature_fix(feature, nodes, ask)
            return 0
    except KeyError:
        logger.error('No such feature: %s.', args.feature)
    return 2


def main() -> int:
    # This entrance is for internal programmatic use only.
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    check_local_parser = subparsers.add_parser('check-local')
    check_local_parser.add_argument('feature')
    check_local_parser.set_defaults(func=main_check_local)

    fix_cluster_parser = subparsers.add_parser('fix-local')
    fix_cluster_parser.add_argument('--yes', action='store_true')
    fix_cluster_parser.add_argument('--without-check', action='store_true')
    fix_cluster_parser.add_argument('feature')
    fix_cluster_parser.set_defaults(func=main_fix_local)

    fix_cluster_parser = subparsers.add_parser('fix-cluster')
    fix_cluster_parser.add_argument('--yes', action='store_true')
    fix_cluster_parser.add_argument('--without-check', action='store_true')
    fix_cluster_parser.add_argument('feature')
    fix_cluster_parser.set_defaults(func=main_fix_cluster)

    args = parser.parse_args()
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
