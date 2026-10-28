import sys
import unittest
from unittest import mock

from crmsh import main, options, ui_root, ui_context


class TestInitShadowCib(unittest.TestCase):
    def setUp(self):
        self.orig_shadow = options.shadow
        self.context = mock.Mock()

    def tearDown(self):
        options.shadow = self.orig_shadow

    def test_no_shadow_option(self):
        options.shadow = None
        result = main._init_shadow_cib(self.context)
        self.assertTrue(result)
        self.context.run.assert_not_called()

    def test_shadow_option_success(self):
        options.shadow = "test_shadow"
        self.context.run.return_value = True
        result = main._init_shadow_cib(self.context)
        self.assertTrue(result)
        self.context.run.assert_called_once_with("cib use test_shadow")

    def test_shadow_option_failure(self):
        options.shadow = "test_shadow"
        self.context.run.return_value = False
        result = main._init_shadow_cib(self.context)
        self.assertFalse(result)
        self.context.run.assert_called_once_with("cib use test_shadow")


class TestHandleSingleShot(unittest.TestCase):
    def setUp(self):
        self.context = mock.Mock()

    @mock.patch('crmsh.main.logger_utils.reset_lineno')
    def test_success(self, mock_reset_lineno):
        self.context.run.return_value = True

        rc = main.handle_single_shot(self.context, ["status"])

        self.assertEqual(rc, 0)
        mock_reset_lineno.assert_called_once_with()
        self.context.run.assert_called_once_with("status")

    @mock.patch('crmsh.main.logger_utils.reset_lineno')
    def test_failure(self, mock_reset_lineno):
        self.context.run.return_value = False

        rc = main.handle_single_shot(self.context, ["status"])

        self.assertEqual(rc, 1)
        mock_reset_lineno.assert_called_once_with()
        self.context.run.assert_called_once_with("status")

    @mock.patch('crmsh.main.logger_utils.reset_lineno')
    def test_with_arguments_and_quotes(self, mock_reset_lineno):
        self.context.run.return_value = True
        rc = main.handle_single_shot(self.context, ["resource", "param", "rsc1", "set", "key=val with space"])
        self.assertEqual(rc, 0)
        self.context.run.assert_called_once_with('resource param rsc1 set "key=val with space"')


class TestIsLevelNavigation(unittest.TestCase):
    def setUp(self):
        root = ui_root.Root()
        self.context = ui_context.Context(root)

    def test_empty_args(self):
        self.assertFalse(main._is_level_navigation(self.context, []))
        self.assertFalse(main._is_level_navigation(self.context, None))

    def test_conf_prefix(self):
        self.assertTrue(main._is_level_navigation(self.context, ["conf"]))
        self.assertTrue(main._is_level_navigation(self.context, ["configure"]))

    def test_top_level(self):
        self.assertTrue(main._is_level_navigation(self.context, ["cluster"]))
        self.assertTrue(main._is_level_navigation(self.context, ["node"]))
        self.assertTrue(main._is_level_navigation(self.context, ["resource"]))

    def test_multi_token_level(self):
        self.assertTrue(main._is_level_navigation(self.context, ["corosync", "link"]))

    def test_single_shot_subcommands(self):
        self.assertFalse(main._is_level_navigation(self.context, ["status"]))
        self.assertFalse(main._is_level_navigation(self.context, ["cluster", "start"]))
        self.assertFalse(main._is_level_navigation(self.context, ["configure", "show"]))

    def test_unknown_subcommand(self):
        self.assertFalse(main._is_level_navigation(self.context, ["nonexistent"]))
        self.assertFalse(main._is_level_navigation(self.context, ["cluster", "nonexistent"]))


class TestEnterLevelFromArgs(unittest.TestCase):
    def setUp(self):
        self.context = mock.Mock()

    def test_conf_shorthand_success(self):
        self.context.run.return_value = True

        result = main._enter_level_from_args(self.context, ["conf"])

        self.assertTrue(result)
        self.context.run.assert_called_once_with("configure")

    def test_level_success(self):
        self.context.run.return_value = True

        result = main._enter_level_from_args(self.context, ["corosync", "link"])

        self.assertTrue(result)
        self.context.run.assert_called_once_with("corosync link")

    def test_enter_level_failure(self):
        self.context.run.return_value = False
        result = main._enter_level_from_args(self.context, ["cluster"])
        self.assertFalse(result)
        self.context.run.assert_called_once_with("cluster")


class TestDispatch(unittest.TestCase):
    def setUp(self):
        self.context = mock.Mock()

    @mock.patch('crmsh.main.handle_single_shot')
    @mock.patch('crmsh.main.main_input_loop')
    @mock.patch('crmsh.main._enter_level_from_args')
    @mock.patch('crmsh.main._is_level_navigation')
    def test_dispatch_level_navigation_success(self, mock_is_level, mock_enter_level, mock_loop, mock_single_shot):
        mock_is_level.return_value = True
        mock_enter_level.return_value = True
        mock_loop.return_value = 0

        rc = main.dispatch(self.context, ["configure"])

        self.assertEqual(rc, 0)
        mock_is_level.assert_called_once_with(self.context, ["configure"])
        mock_enter_level.assert_called_once_with(self.context, ["configure"])
        mock_loop.assert_called_once_with(self.context)
        mock_single_shot.assert_not_called()

    @mock.patch('crmsh.main.handle_single_shot')
    @mock.patch('crmsh.main.main_input_loop')
    @mock.patch('crmsh.main._enter_level_from_args')
    @mock.patch('crmsh.main._is_level_navigation')
    def test_dispatch_level_navigation_failure(self, mock_is_level, mock_enter_level, mock_loop, mock_single_shot):
        mock_is_level.return_value = True
        mock_enter_level.return_value = False

        rc = main.dispatch(self.context, ["configure"])

        self.assertEqual(rc, 1)
        mock_is_level.assert_called_once_with(self.context, ["configure"])
        mock_enter_level.assert_called_once_with(self.context, ["configure"])
        mock_loop.assert_not_called()
        mock_single_shot.assert_not_called()

    @mock.patch('crmsh.main.handle_single_shot')
    @mock.patch('crmsh.main.main_input_loop')
    @mock.patch('crmsh.main._is_level_navigation')
    def test_dispatch_single_shot(self, mock_is_level, mock_loop, mock_single_shot):
        mock_is_level.return_value = False
        mock_single_shot.return_value = 0

        rc = main.dispatch(self.context, ["status"])

        self.assertEqual(rc, 0)
        mock_is_level.assert_called_once_with(self.context, ["status"])
        mock_single_shot.assert_called_once_with(self.context, ["status"])
        mock_loop.assert_not_called()

    @mock.patch('crmsh.main.handle_single_shot')
    @mock.patch('crmsh.main.main_input_loop')
    @mock.patch('crmsh.main._is_level_navigation')
    def test_dispatch_no_args(self, mock_is_level, mock_loop, mock_single_shot):
        mock_is_level.return_value = False
        mock_loop.return_value = 0

        rc = main.dispatch(self.context, [])

        self.assertEqual(rc, 0)
        mock_is_level.assert_called_once_with(self.context, [])
        mock_single_shot.assert_not_called()
        mock_loop.assert_called_once_with(self.context)


class TestMainInputLoop(unittest.TestCase):
    def setUp(self):
        self.context = mock.Mock()
        self.orig_in_repl = options.in_repl()
        self.orig_batch = options.batch

    def tearDown(self):
        options.set_in_repl(self.orig_in_repl)
        options.batch = self.orig_batch

    @mock.patch('crmsh.main.setup_context')
    @mock.patch('crmsh.utils.multi_input')
    def test_input_loop_runs_and_exits(self, mock_multi_input, mock_setup_context):
        options.batch = False
        options.set_in_repl(False)
        mock_multi_input.side_effect = ["node status", None]
        self.context.run.return_value = True
        self.context.quit.side_effect = SystemExit(0)

        with self.assertRaises(SystemExit) as cm:
            main.main_input_loop(self.context)

        self.assertEqual(cm.exception.code, 0)
        self.assertTrue(options.in_repl())
        mock_setup_context.assert_called_once_with(self.context)
        self.context.run.assert_called_once_with("node status")
        self.context.quit.assert_called_once_with(0)

    @mock.patch('crmsh.main.setup_context')
    @mock.patch('crmsh.utils.multi_input')
    def test_input_loop_keyboard_interrupt(self, mock_multi_input, mock_setup_context):
        options.batch = True
        options.set_in_repl(False)
        mock_multi_input.side_effect = KeyboardInterrupt
        self.context.quit.side_effect = SystemExit(1)

        with self.assertRaises(SystemExit) as cm:
            main.main_input_loop(self.context)

        self.assertEqual(cm.exception.code, 1)
        self.context.quit.assert_called_once_with(1)
