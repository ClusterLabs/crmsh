import unittest
from unittest import mock

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
