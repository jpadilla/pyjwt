import jwt

from .utils import utc_timestamp


def test_encode_decode():
    """
    This test exists primarily to ensure that calls to jwt.encode and
    jwt.decode don't explode. Most functionality is tested by the PyJWT class
    tests. This is primarily a sanity check to make sure we don't break the
    public global functions.
    """
    payload = {
        'iss': 'jeff',
        'exp': utc_timestamp() + 15,
        'claim': 'insanity'
    }

    secret = 'secret'
    jwt_message = jwt.encode(payload, secret)
    decoded_payload = jwt.decode(jwt_message, secret)

    assert decoded_payload == payload
