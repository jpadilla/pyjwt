import pytest

import jwt

from .utils import utc_timestamp


@pytest.mark.parametrize("secret", ["secret", b"\xb1\xe7+z"])
def test_encode_decode(secret):
    """
    This test exists primarily to ensure that calls to jwt.encode and
    jwt.decode don't explode. Most functionality is tested by the PyJWT class
    tests. This is primarily a sanity check to make sure we don't break the
    public global functions.
    """
    payload = {"iss": "jeff", "exp": utc_timestamp() + 15, "claim": "insanity"}

    jwt_message = jwt.encode(payload, secret, algorithm="HS256")
    decoded_payload = jwt.decode(jwt_message, secret, algorithms=["HS256"])

    assert decoded_payload == payload
