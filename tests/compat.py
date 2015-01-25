# flake8: noqa

import sys

if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest

PY3 = sys.version_info[0] == 3

if PY3:
    string_types = str,
    text_type = str
else:
    string_types = basestring,
    text_type = unicode
