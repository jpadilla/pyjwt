from jwt.compat import constant_time_compare

from .utils import ensure_bytes


class TestCompat:
    def test_constant_time_compare_returns_true_if_same(self):
        assert constant_time_compare(
            ensure_bytes('abc'), ensure_bytes('abc')
        )

    def test_constant_time_compare_returns_false_if_diff_lengths(self):
        assert not constant_time_compare(
            ensure_bytes('abc'), ensure_bytes('abcd')
        )

    def test_constant_time_compare_returns_false_if_totally_different(self):
        assert not constant_time_compare(
            ensure_bytes('abcd'), ensure_bytes('efgh')
        )
