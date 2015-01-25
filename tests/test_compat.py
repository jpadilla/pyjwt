from .compat import unittest

from jwt.compat import constant_time_compare

class TestCompat(unittest.TestCase):
    def setUp(self):  # noqa
        pass

    def test_constant_time_compare_returns_true_if_same(self):
        self.assertTrue(constant_time_compare('abc', 'abc'))

    def test_constant_time_compare_returns_false_if_diff_lengths(self):
        self.assertFalse(constant_time_compare('abc', 'abcd'))

    def test_constant_time_compare_returns_false_if_totally_different(self):
        self.assertFalse(constant_time_compare('abcd', 'efgh'))
