from jwt.compat import constant_time_compare
from jwt.utils import force_bytes


class TestCompat:
    def test_constant_time_compare_returns_true_if_same(self):
        assert constant_time_compare(
            force_bytes('abc'), force_bytes('abc')
        )

    def test_constant_time_compare_returns_false_if_diff_lengths(self):
        assert not constant_time_compare(
            force_bytes('abc'), force_bytes('abcd')
        )

    def test_constant_time_compare_returns_false_if_totally_different(self):
        assert not constant_time_compare(
            force_bytes('abcd'), force_bytes('efgh')
        )
