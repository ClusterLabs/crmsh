import subprocess
import sys
import unittest
from unittest import mock

from crmsh import config
from crmsh import term


class TestColorize(unittest.TestCase):
    @mock.patch("crmsh.term.colors")
    def test_colorize(self, mock_colors):
        mock_colors.GREEN = "<g>"
        mock_colors.NORMAL = "</>"
        self.assertEqual("<g>text</>", term.colorize("green", "text"))

    @mock.patch("crmsh.term.colors")
    def test_colorize_unsupported(self, mock_colors):
        mock_colors.RED = ""
        mock_colors.NORMAL = ""
        self.assertEqual("text", term.colorize("red", "text"))

    def test_colorize_unknown_color(self):
        self.assertEqual("text", term.colorize("no-such-color", "text"))


class TestInit(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch("crmsh.term.colors", new_callable=type("Colors", (), {}))
        self.colors = patcher.start()
        self.colors.GREEN = self.colors.NORMAL = ""
        self.addCleanup(patcher.stop)
        style = config.color.style
        self.addCleanup(setattr, config.color, "style", style)

    @mock.patch("crmsh.term.sys.stdout")
    def test_tty(self, mock_stdout):
        mock_stdout.isatty.return_value = True
        config.color.style = "color"
        term.init()
        self.assertEqual("\033[32m", self.colors.GREEN)
        self.assertEqual("\033[0m", self.colors.NORMAL)

    @mock.patch("crmsh.term.sys.stdout")
    def test_not_tty(self, mock_stdout):
        mock_stdout.isatty.return_value = False
        config.color.style = "color"
        term.init()
        self.assertEqual("", self.colors.GREEN)

    @mock.patch("crmsh.term.sys.stdout")
    def test_color_always(self, mock_stdout):
        mock_stdout.isatty.return_value = False
        config.color.style = "color-always"
        term.init()
        self.assertEqual("\033[32m", self.colors.GREEN)


class TestImport(unittest.TestCase):
    def test_import_in_fresh_interpreter(self):
        # userdir -> log -> term must not import config at module level (config imports userdir)
        subprocess.run([sys.executable, "-c", "import crmsh.userdir"], check=True)
