import logging
import unittest
from unittest import mock

from crmsh import log


class TestQuietLogging(unittest.TestCase):

    def test_quiet_logger_adapter_logs_when_not_quiet(self):
        logger = mock.Mock()
        adapter = log.QuietLoggerAdapter(logger, quiet=False)

        adapter.error("message %s", "value")

        logger.log.assert_called_once_with(logging.ERROR, "message %s", "value")

    def test_quiet_logger_adapter_drops_when_quiet(self):
        logger = mock.Mock()
        adapter = log.QuietLoggerAdapter(logger, quiet=True)

        adapter.warning("message")

        logger.log.assert_not_called()

    def test_quiet_logger_adapter_resolves_callable_quiet(self):
        quiet = False
        logger = mock.Mock()
        adapter = log.QuietLoggerAdapter(logger, quiet=lambda: quiet)

        adapter.warning("visible")
        logger.log.assert_called_once_with(logging.WARNING, "visible")

        quiet = True
        logger.log.reset_mock()
        adapter.warning("hidden")
        logger.log.assert_not_called()



class TestConsoleColoredFormatter(unittest.TestCase):
    @staticmethod
    def _record(level):
        return logging.LogRecord("test", level, __file__, 1, "message", None, None)

    @mock.patch("crmsh.term.colors")
    def test_levelname_colored(self, mock_colors):
        mock_colors.GREEN = "<g>"
        mock_colors.NORMAL = "</>"
        record = self._record(logging.INFO)

        formatted = log.ConsoleColoredFormatter("%(levelname)s: %(message)s").format(record)

        self.assertEqual("<g>INFO</>: message", formatted)
        self.assertEqual("INFO", record.levelname)

    @mock.patch("crmsh.term.colors")
    def test_no_color_support(self, mock_colors):
        mock_colors.RED = ""
        mock_colors.NORMAL = ""

        formatted = log.ConsoleColoredFormatter("%(levelname)s: %(message)s").format(self._record(logging.ERROR))

        self.assertEqual("ERROR: message", formatted)

    def test_uncolored_level(self):
        formatted = log.ConsoleColoredFormatter("%(levelname)s: %(message)s").format(self._record(logging.DEBUG))

        self.assertEqual("DEBUG: message", formatted)
