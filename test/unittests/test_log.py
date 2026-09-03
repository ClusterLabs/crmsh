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


class TestLoggerUtilsConfirm(unittest.TestCase):

    def test_confirm_default_none_input_y(self):
        logger_utils = log.LoggerUtils(mock.Mock())
        logger_utils.wait_input = mock.Mock(return_value='y')
        res = logger_utils.confirm("Proceed")
        self.assertTrue(res)
        logger_utils.wait_input.assert_called_once_with("Proceed (y/n)? ")

    def test_confirm_default_none_input_n(self):
        logger_utils = log.LoggerUtils(mock.Mock())
        logger_utils.wait_input = mock.Mock(return_value='n')
        res = logger_utils.confirm("Proceed")
        self.assertFalse(res)
        logger_utils.wait_input.assert_called_once_with("Proceed (y/n)? ")

    def test_confirm_default_none_input_empty_then_y(self):
        logger_utils = log.LoggerUtils(mock.Mock())
        logger_utils.wait_input = mock.Mock(side_effect=['', 'y'])
        res = logger_utils.confirm("Proceed")
        self.assertTrue(res)
        logger_utils.wait_input.assert_has_calls([
            mock.call("Proceed (y/n)? "),
            mock.call("Proceed (y/n)? ")
        ])

    def test_confirm_garbage_input_then_n(self):
        logger_utils = log.LoggerUtils(mock.Mock())
        logger_utils.wait_input = mock.Mock(side_effect=['foo', 'n'])
        res = logger_utils.confirm("Proceed")
        self.assertFalse(res)
        logger_utils.wait_input.assert_has_calls([
            mock.call("Proceed (y/n)? "),
            mock.call("Proceed (y/n)? ")
        ])

    def test_confirm_default_true_garbage_then_empty(self):
        logger_utils = log.LoggerUtils(mock.Mock())
        logger_utils.wait_input = mock.Mock(side_effect=['foo', ''])
        res = logger_utils.confirm("Proceed", default=True)
        self.assertTrue(res)
        logger_utils.wait_input.assert_has_calls([
            mock.call("Proceed (Y/n)? "),
            mock.call("Proceed (Y/n)? ")
        ])

    def test_confirm_default_true_input_empty(self):
        logger_utils = log.LoggerUtils(mock.Mock())
        logger_utils.wait_input = mock.Mock(return_value='')
        res = logger_utils.confirm("Proceed", default=True)
        self.assertTrue(res)
        logger_utils.wait_input.assert_called_once_with("Proceed (Y/n)? ")

    def test_confirm_default_true_input_n(self):
        logger_utils = log.LoggerUtils(mock.Mock())
        logger_utils.wait_input = mock.Mock(return_value='n')
        res = logger_utils.confirm("Proceed", default=True)
        self.assertFalse(res)
        logger_utils.wait_input.assert_called_once_with("Proceed (Y/n)? ")

    def test_confirm_default_false_input_empty(self):
        logger_utils = log.LoggerUtils(mock.Mock())
        logger_utils.wait_input = mock.Mock(return_value='')
        res = logger_utils.confirm("Proceed", default=False)
        self.assertFalse(res)
        logger_utils.wait_input.assert_called_once_with("Proceed (y/N)? ")

    def test_confirm_default_false_input_y(self):
        logger_utils = log.LoggerUtils(mock.Mock())
        logger_utils.wait_input = mock.Mock(return_value='y')
        res = logger_utils.confirm("Proceed", default=False)
        self.assertTrue(res)
        logger_utils.wait_input.assert_called_once_with("Proceed (y/N)? ")
