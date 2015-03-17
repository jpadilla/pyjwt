from calendar import timegm
from datetime import datetime

import jwt

from .compat import unittest


def utc_timestamp():
    return timegm(datetime.utcnow().utctimetuple())


class TestJWT(unittest.TestCase):
    """
    These tests exist primarily to ensure that calls to jwt.encode and
    jwt.decode don't explode. Most functionality is tested by the PyJWT class
    tests. This is primarily a sanity check to make sure we don't break the
    public global functions.
    """
    def setUp(self):  # noqa
        self.payload = {'iss': 'jeff', 'exp': utc_timestamp() + 15,
                        'claim': 'insanity'}

    def test_encode_decode(self):
        secret = 'secret'
        jwt_message = jwt.encode(self.payload, secret)
        decoded_payload = jwt.decode(jwt_message, secret)

        self.assertEqual(decoded_payload, self.payload)


if __name__ == '__main__':
    unittest.main()
