import os
from calendar import timegm
from datetime import datetime, timezone

import pytest

from jwt.algorithms import has_crypto


def utc_timestamp():
    return timegm(datetime.now(tz=timezone.utc).utctimetuple())


def key_path(key_name):
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), "keys", key_name)


no_crypto_required = pytest.mark.skipif(
    has_crypto,
    reason="Requires cryptography library not installed",
)


crypto_required = pytest.mark.skipif(
    not has_crypto,
    reason="Requires cryptography library installed",
)
