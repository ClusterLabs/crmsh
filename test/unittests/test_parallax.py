from __future__ import unicode_literals
# Copyright (C) 2019 Xin Liang <XLiang@suse.com>
# See COPYING for license information.
#
# unit tests for parallax.py


import os
import unittest
from unittest import mock
import parallax
from crmsh import parallax as cparallax


class TestParallax(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """
        # Use the setup to create a fresh instance for each test
        self.parallax_call_instance = cparallax.Parallax(["node1"], cmd="ls")
        self.parallax_slurp_instance = cparallax.Parallax(["node1"], localdir="/opt", filename="/opt/file.c")
        self.parallax_copy_instance = cparallax.Parallax(["node1", "node2"], src="/opt/file.c", dst="/tmp")

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch("crmsh.utils.user_of")
    @mock.patch("parallax.call")
    @mock.patch("crmsh.parallax.Parallax.handle")
    def test_call(self, mock_handle, mock_call, mock_userof):
        mock_call.return_value = {"node1": (0, None, None)}
        mock_userof.return_value = "alice"
        mock_handle.return_value = [("node1", (0, None, None))]

        result = self.parallax_call_instance.call()
        self.assertEqual(result, mock_handle.return_value)

        mock_userof.assert_called_once_with("node1")
        mock_call.assert_called_once_with([["node1", None, "alice"]], "ls", self.parallax_call_instance.opts)
        mock_handle.assert_called_once_with(list(mock_call.return_value.items()))

    @mock.patch("parallax.Error")
    @mock.patch("crmsh.utils.user_of")
    @mock.patch("parallax.call")
    @mock.patch("crmsh.parallax.Parallax.handle")
    def test_call_exception(self, mock_handle, mock_call, mock_userof, mock_error):
        mock_error = mock.Mock()
        mock_call.return_value = {"node1": mock_error}
        mock_userof.return_value = "alice"
        mock_handle.side_effect = ValueError("error happen")

        with self.assertRaises(ValueError) as err:
            self.parallax_call_instance.call()
        self.assertEqual("error happen", str(err.exception))

        mock_userof.assert_called_once_with("node1")
        mock_call.assert_called_once_with([["node1", None, "alice"]], "ls", self.parallax_call_instance.opts)
        mock_handle.assert_called_once_with(list(mock_call.return_value.items()))

    @mock.patch("crmsh.parallax.Parallax.handle")
    @mock.patch("parallax.slurp")
    @mock.patch("os.path.basename")
    def test_slurp(self, mock_basename, mock_slurp, mock_handle):
        mock_basename.return_value = "file.c"
        mock_slurp.return_value = {"node1": (0, None, None, "/opt")}
        mock_handle.return_value = [("node1", (0, None, None, "/opt"))]

        result = self.parallax_slurp_instance.slurp()
        self.assertEqual(result, mock_handle.return_value)

        mock_basename.assert_called_once_with("/opt/file.c")
        mock_slurp.assert_called_once_with(["node1"], "/opt/file.c", "file.c", self.parallax_slurp_instance.opts)
        mock_handle.assert_called_once_with(list(mock_slurp.return_value.items()))

    @mock.patch("parallax.Error")
    @mock.patch("crmsh.parallax.Parallax.handle")
    @mock.patch("parallax.slurp")
    @mock.patch("os.path.basename")
    def test_slurp_exception(self, mock_basename, mock_slurp, mock_handle, mock_error):
        mock_basename.return_value = "file.c"
        mock_error = mock.Mock()
        mock_slurp.return_value = {"node1": mock_error}
        mock_handle.side_effect = ValueError("error happen")

        with self.assertRaises(ValueError) as err:
            self.parallax_slurp_instance.slurp()
        self.assertEqual("error happen", str(err.exception))

        mock_basename.assert_called_once_with("/opt/file.c")
        mock_slurp.assert_called_once_with(["node1"], "/opt/file.c", "file.c", self.parallax_slurp_instance.opts)
        mock_handle.assert_called_once_with(list(mock_slurp.return_value.items()))

    @mock.patch("parallax.copy")
    @mock.patch("crmsh.parallax.Parallax.handle")
    def test_copy(self, mock_handle, mock_copy):
        mock_copy.return_value = {"node1": (0, None, None), "node2": (0, None, None)}
        mock_handle.return_value = [("node1", (0, None, None)), ("node2", (0, None, None))]

        result = self.parallax_copy_instance.copy()
        self.assertEqual(result, mock_handle.return_value)

        mock_copy.assert_called_once_with(["node1", "node2"], "/opt/file.c", "/tmp", self.parallax_copy_instance.opts)
        mock_handle.assert_called_once_with(list(mock_copy.return_value.items()))

    @mock.patch("parallax.Error")
    @mock.patch("parallax.copy")
    @mock.patch("crmsh.parallax.Parallax.handle")
    def test_copy_exception(self, mock_handle, mock_copy, mock_error):
        mock_error = mock.Mock()
        mock_copy.return_value = {"node1": mock_error, "node2": (0, None, None)}
        mock_handle.side_effect = ValueError("error happen")

        with self.assertRaises(ValueError) as err:
            self.parallax_copy_instance.copy()
        self.assertEqual("error happen", str(err.exception))

        mock_copy.assert_called_once_with(["node1", "node2"], "/opt/file.c", "/tmp", self.parallax_copy_instance.opts)
        mock_handle.assert_called_once_with(list(mock_copy.return_value.items()))
