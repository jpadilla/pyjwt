"""
The `compat` module provides support for backwards compatibility with older
versions of python, and compatibility wrappers around optional packages.
"""
# flake8: noqa
import sys
import hmac

try:
    import json
except ImportError:
    import simplejson as json


if sys.version_info >= (3, 0, 0):
    unicode = str
    basestring = str
else:
    unicode = unicode
    basestring = basestring


def timedelta_total_seconds(delta):
    try:
        delta.total_seconds
    except AttributeError:
        # On Python 2.6, timedelta instances do not have
        # a .total_seconds() method.
        total_seconds = delta.days * 24 * 60 * 60 + delta.seconds
    else:
        total_seconds = delta.total_seconds()

    return total_seconds


try:
    constant_time_compare = hmac.compare_digest
except AttributeError:
    # Fallback for Python < 2.7.7 and Python < 3.3
    def constant_time_compare(val1, val2):
        """
        Returns True if the two strings are equal, False otherwise.

        The time taken is independent of the number of characters that match.
        """
        if len(val1) != len(val2):
            return False

        result = 0

        if sys.version_info >= (3, 0, 0):
            # Bytes are numbers
            for x, y in zip(val1, val2):
                result |= x ^ y
        else:
            for x, y in zip(val1, val2):
                result |= ord(x) ^ ord(y)

        return result == 0
