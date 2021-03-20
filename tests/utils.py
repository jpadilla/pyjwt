import os
import time
from datetime import datetime

import pytest

from jwt.algorithms import has_crypto


def utc_timestamp():
    return int(time.mktime(datetime.utcnow().utctimetuple()))


def key_path(key_name):
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), "keys", key_name)


def no_crypto_required(class_or_func):
    decorator = pytest.mark.skipif(
        has_crypto,
        reason="Requires cryptography library not installed",
    )
    return decorator(class_or_func)


def crypto_required(class_or_func):
    decorator = pytest.mark.skipif(
        not has_crypto, reason="Requires cryptography library installed"
    )
    return decorator(class_or_func)
