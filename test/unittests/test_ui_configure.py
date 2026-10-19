import unittest
from unittest import mock

from crmsh import constants
from crmsh import ui_configure


@mock.patch('crmsh.ui_configure.options')
class TestCompletionHelp(unittest.TestCase):
    def test_enabled(self, mock_options):
        for in_repl, shell_completion, expected in (
                (False, False, False), (True, False, True), (False, True, True)):
            mock_options.in_repl.return_value = in_repl
            mock_options.shell_completion = shell_completion
            self.assertEqual(expected, ui_configure.CompletionHelp.enabled())

    @mock.patch('builtins.print')
    def test_help_shell_completion(self, mock_print, mock_options):
        mock_options.shell_completion = True
        ui_configure.CompletionHelp.help('topic', 'line1\nline2', ['property', 'topic='])
        mock_print.assert_has_calls([
            mock.call(f'{constants.COMPGEN_HELP_PREFIX}line1'),
            mock.call(f'{constants.COMPGEN_HELP_PREFIX}line2'),
        ])
