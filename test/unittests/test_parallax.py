from __future__ import unicode_literals
# Copyright (C) 2019 Xin Liang <XLiang@suse.com>
# See COPYING for license information.
#
# unit tests for parallax.py


import unittest
from unittest import mock

import crmsh.parallax
import crmsh.prun.prun


class TestParallax(unittest.TestCase):
    def setUp(self):
        """
        Test setUp.
        """
        # Use the setup to create a fresh instance for each test

    @mock.patch("crmsh.prun.prun.prun")
    def test_call(self, mock_prun: mock.MagicMock):
        mock_prun.return_value = {
            "node1": crmsh.prun.prun.ProcessResult(0, None, None)
        }
        result = crmsh.parallax.parallax_call(["node1"], "ls")
        self.assertEqual(
            result,
            [("node1", (0, None, None))],
        )

    @mock.patch("crmsh.prun.prun.prun")
    def test_call_non_zero_exit_code(self, mock_prun: mock.MagicMock):
        mock_prun.return_value = {
            "node1": crmsh.prun.prun.ProcessResult(1, None, None)
        }
        with self.assertRaises(ValueError):
            crmsh.parallax.parallax_call(["node1"], "ls")

    @mock.patch("crmsh.prun.prun.prun")
    def test_call_255_exit_code(self, mock_prun: mock.MagicMock):
        mock_prun.return_value = {
            "node1": crmsh.prun.prun.ProcessResult(255, None, None)
        }
        with self.assertRaises(ValueError):
            crmsh.parallax.parallax_call(["node1"], "ls")

    @mock.patch("crmsh.prun.prun.prun")
    def test_run(self, mock_prun: mock.MagicMock):
        mock_prun.return_value = {
            "node1": crmsh.prun.prun.ProcessResult(0, None, None)
        }
        result = crmsh.parallax.parallax_run(["node1"], "ls")
        self.assertEqual(
            {"node1": (0, None, None)},
            result,
        )

    @mock.patch("crmsh.prun.prun.prun")
    def test_run_non_zero_exit_code(self, mock_prun: mock.MagicMock):
        mock_prun.return_value = {
            "node1": crmsh.prun.prun.ProcessResult(1, None, None)
        }
        result = crmsh.parallax.parallax_run(["node1"], "ls")
        self.assertEqual(
            {"node1": (1, None, None)},
            result,
        )

    @mock.patch("crmsh.prun.prun.prun")
    def test_run_255_exit_code(self, mock_prun: mock.MagicMock):
        mock_prun.return_value = {
            "node1": crmsh.prun.prun.SSHError("alice", "node1", "foo")
        }
        with self.assertRaises(ValueError):
            crmsh.parallax.parallax_run(["node1"], "ls")

    @mock.patch("crmsh.prun.prun.pfetch_from_remote")
    def test_slurp(self, mock_pfetch: mock.MagicMock):
        mock_pfetch.return_value = {"node1": "/opt/node1/file.c"}
        results = crmsh.parallax.parallax_slurp(["node1"], "/opt", "/opt/file.c")
        self.assertListEqual([("node1", "/opt/node1/file.c")], results)
        mock_pfetch.assert_called_once_with(["node1"], "/opt/file.c", "/opt")

    @mock.patch("crmsh.prun.prun.pfetch_from_remote")
    def test_slurp_exception(self, mock_pfetch: mock.MagicMock):
        mock_pfetch.return_value = {"node1": crmsh.prun.prun.PRunError("alice", "node1", "foo")}
        with self.assertRaises(ValueError):
            crmsh.parallax.parallax_slurp(["node1"], "/opt", "/opt/file.c")
        mock_pfetch.assert_called_once_with(["node1"], "/opt/file.c", "/opt")

    @mock.patch("crmsh.prun.prun.pcopy_to_remote")
    def test_copy(self, mock_pcopy: mock.MagicMock):
        mock_pcopy.return_value = {"node1": None, "node2": None}
        crmsh.parallax.parallax_copy(["node1", "node2"], "/opt/file.c", "/tmp")
        mock_pcopy.assert_called_once_with("/opt/file.c", ["node1", "node2"], "/tmp", False, timeout_seconds=-1)

    @mock.patch("crmsh.prun.prun.pcopy_to_remote")
    def test_copy_exception(self, mock_pcopy: mock.MagicMock):
        mock_pcopy.return_value = {"node1": crmsh.prun.prun.PRunError("alice", "node1", "foo"), "node2": None}
        with self.assertRaises(ValueError):
            crmsh.parallax.parallax_copy(["node1", "node2"], "/opt/file.c", "/tmp")
        mock_pcopy.assert_called_once_with("/opt/file.c", ["node1", "node2"], "/tmp", False, timeout_seconds=-1)
