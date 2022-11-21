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
        raise NotImplementedError

    def check_cluster(self, nodes: typing.Iterable[str]) -> bool:
        raise NotImplementedError

    def fix_local(self, nodes: typing.Iterable[str], ask: typing.Callable[[str], None]) -> None:
        raise NotImplementedError

    def fix_cluster(self, nodes: typing.Iterable[str], ask: typing.Callable[[str], None]) -> None:
        raise NotImplementedError


class FixFailure(Exception):
    pass


class AskDeniedByUser(Exception):
    pass


def feature_quick_check(feature: Feature):
    return feature.check_quick()


def feature_full_check(feature: Feature, nodes: typing.Iterable[str]) -> bool:
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
            '/usr/bin/env python3 -m crmsh.healthcheck --check-local {}'.format(
                feature.__class__.__name__.rsplit('.', 1)[-1],
            )
        )
        return all(rc == 0 for rc, _, _ in results.values())


def feature_fix(feature: Feature, nodes: typing.Iterable[str], ask: typing.Callable[[str], None]) -> None:
    try:
        return feature.fix_cluster(nodes, ask)
    except NotImplementedError:
        for node in nodes:
            raise NotImplementedError
            _parallax_run(node, _)


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
                subprocess.check_call(['sudo', 'su', '-', 'hacluster', '-c', 'ssh hacluster@{} true'.format(node)])
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check-local')
    parser.add_argument('feature')
    args = parser.parse_args()
    try:
        feature = Feature.get_feature_by_name(args.feature)
        if args.check_local:
            nodes = crmsh.utils.list_cluster_nodes(no_reg=True)
            if nodes:
                if feature.check_local(nodes):
                    return 0
                else:
                    return 1
    except KeyError:
        logger.error('No such feature: %s.', args.feature)
    return 2


if __name__ == '__main__':
    sys.exit(main())
