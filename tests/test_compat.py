from jwt.compat import constant_time_compare

from .compat import unittest
from .utils import ensure_bytes


class TestCompat(unittest.TestCase):
    def setUp(self):  # noqa
        pass

    def test_constant_time_compare_returns_true_if_same(self):
        self.assertTrue(constant_time_compare(
            ensure_bytes('abc'), ensure_bytes('abc')
        ))

    def test_constant_time_compare_returns_false_if_diff_lengths(self):
        self.assertFalse(constant_time_compare(
            ensure_bytes('abc'), ensure_bytes('abcd')
        ))

    def test_constant_time_compare_returns_false_if_totally_different(self):
        self.assertFalse(constant_time_compare(
            ensure_bytes('abcd'), ensure_bytes('efgh')
        ))
