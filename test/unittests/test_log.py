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
