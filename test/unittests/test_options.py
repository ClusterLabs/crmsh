import unittest
from crmsh import options


class TestOptions(unittest.TestCase):
    def setUp(self):
        self.orig_in_repl = options.in_repl()

    def tearDown(self):
        options.set_in_repl(self.orig_in_repl)

    def test_in_repl_default(self):
        options.set_in_repl(False)
        self.assertFalse(options.in_repl())

    def test_set_in_repl_true(self):
        options.set_in_repl(True)
        self.assertTrue(options.in_repl())

    def test_set_in_repl_false(self):
        options.set_in_repl(True)
        self.assertTrue(options.in_repl())
        options.set_in_repl(False)
        self.assertFalse(options.in_repl())
