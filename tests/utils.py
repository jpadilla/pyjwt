import os
from calendar import timegm
from datetime import datetime, timezone

import pytest

from jwt.algorithms import has_crypto


def utc_timestamp() -> int:
    return timegm(datetime.now(tz=timezone.utc).utctimetuple())


def key_path(key_name: str) -> str:
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), "keys", key_name)


no_crypto_required = pytest.mark.skipif(
    has_crypto,
    reason="Requires cryptography library not installed",
)


crypto_required = pytest.mark.skipif(
    not has_crypto,
    reason="Requires cryptography library installed",
)


def _p192_supported() -> bool:
    if not has_crypto:
        return False
    from cryptography.hazmat.backends.openssl import backend
    from cryptography.hazmat.primitives.asymmetric.ec import SECP192R1

    return backend.elliptic_curve_supported(SECP192R1())


p192_required = pytest.mark.skipif(
    not _p192_supported(),
    reason="Requires a cryptography backend that supports SECP192R1",
)
