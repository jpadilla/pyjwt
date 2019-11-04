"""
The `compat` module provides support for backwards compatibility with older
versions of python, and compatibility wrappers around optional packages.
"""
# flake8: noqa
import hmac

text_type = str
binary_type = bytes
string_types = (str, bytes)

try:
    # Importing ABCs from collections will be removed in PY3.8
    from collections.abc import Iterable, Mapping
except ImportError:
    from collections import Iterable, Mapping


constant_time_compare = hmac.compare_digest


def bytes_from_int(val):
    remaining = val
    byte_length = 0

    while remaining != 0:
        remaining = remaining >> 8
        byte_length += 1

    return val.to_bytes(byte_length, "big", signed=False)
