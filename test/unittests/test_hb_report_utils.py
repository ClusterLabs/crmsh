import unittest
from hb_report import utils

try:
    from unittest import mock
except ImportError:
    import mock

class TestUtils(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('hb_report.utils.crmmsg.common_info')
    @mock.patch('hb_report.utils.me')
    def test_log_info(self, mock_me, mock_info):
        mock_me.return_value = "host1"
        utils.log_info("This is a test message")
        mock_me.assert_called_once_with()
        mock_info.assert_called_once_with("host1# This is a test message")

    @mock.patch('hb_report.utils.crmmsg.common_warn')
    @mock.patch('hb_report.utils.me')
    def test_log_warn(self, mock_me, mock_warn):
        mock_me.return_value = "host1"
        utils.log_warning("This is a test message")
        mock_me.assert_called_once_with()
        mock_warn.assert_called_once_with("host1# This is a test message")

    @mock.patch('hb_report.utils.crmmsg.common_err')
    @mock.patch('hb_report.utils.me')
    @mock.patch('sys.exit')
    def test_log_fatal(self, mock_exit, mock_me, mock_error):
        mock_me.return_value = "host1"
        utils.log_fatal("This is a test message")
        mock_me.assert_called_once_with()
        mock_error.assert_called_once_with("host1# This is a test message")
        mock_exit.assert_called_once_with(1)

    @mock.patch('os.path.dirname')
    def test_dirname1(self, mock_dirname):
        mock_dirname.return_value = ''
        result = utils.dirname('.')
        self.assertEqual(result, '.')
        mock_dirname.assert_called_once_with('.')

    @mock.patch('os.path.dirname')
    def test_dirname2(self, mock_dirname):
        mock_dirname.return_value = '/usr/local'
        result = utils.dirname('/usr/local/test.bin')
        self.assertEqual(result, '/usr/local')
        mock_dirname.assert_called_once_with('/usr/local/test.bin')
