from __future__ import unicode_literals
from calendar import timegm
from datetime import datetime
import sys
import time
import unittest

import jwt

if sys.version_info >= (3, 0, 0):
    unicode = str


def utc_timestamp():
    return timegm(datetime.utcnow().utctimetuple())


class TestJWT(unittest.TestCase):

    def setUp(self):
        self.payload = {"iss": "jeff", "exp": utc_timestamp() + 1,
                        "claim": "insanity"}

    def test_encode_decode(self):
        secret = 'secret'
        jwt_message = jwt.encode(self.payload, secret)
        decoded_payload = jwt.decode(jwt_message, secret)
        self.assertEqual(decoded_payload, self.payload)

    def test_encode_bad_type(self):

        types = ['string', tuple(), list(), 42, set()]

        for t in types:
            with self.assertRaises(TypeError):
                jwt.encode(t, 'secret')

    def test_encode_expiration_datetime(self):
        secret = "secret"
        current_datetime = datetime.utcnow()
        payload = {"exp": current_datetime}
        jwt_message = jwt.encode(payload, secret)
        decoded_payload = jwt.decode(jwt_message, secret, leeway=1)
        self.assertEqual(
            decoded_payload['exp'],
            timegm(current_datetime.utctimetuple()))

    def test_bad_secret(self):
        right_secret = 'foo'
        bad_secret = 'bar'
        jwt_message = jwt.encode(self.payload, right_secret)
        with self.assertRaises(jwt.DecodeError):
            jwt.decode(jwt_message, bad_secret)

    def test_decodes_valid_jwt(self):
        example_payload = {"hello": "world"}
        example_secret = "secret"
        example_jwt = (
            b"eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"
            b".eyJoZWxsbyI6ICJ3b3JsZCJ9"
            b".tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8")
        decoded_payload = jwt.decode(example_jwt, example_secret)
        self.assertEqual(decoded_payload, example_payload)

    def test_allow_skip_verification(self):
        right_secret = 'foo'
        jwt_message = jwt.encode(self.payload, right_secret)
        decoded_payload = jwt.decode(jwt_message, verify=False)
        self.assertEqual(decoded_payload, self.payload)

    def test_no_secret(self):
        right_secret = 'foo'
        jwt_message = jwt.encode(self.payload, right_secret)

        with self.assertRaises(jwt.DecodeError):
            jwt.decode(jwt_message)

    def test_invalid_crypto_alg(self):
        self.assertRaises(NotImplementedError, jwt.encode, self.payload,
                          "secret", "HS1024")

    def test_unicode_secret(self):
        secret = u'\xc2'
        jwt_message = jwt.encode(self.payload, secret)
        decoded_payload = jwt.decode(jwt_message, secret)
        self.assertEqual(decoded_payload, self.payload)

    def test_nonascii_secret(self):
        secret = '\xc2'  # char value that ascii codec cannot decode
        jwt_message = jwt.encode(self.payload, secret)
        decoded_payload = jwt.decode(jwt_message, secret)
        self.assertEqual(decoded_payload, self.payload)

    def test_decode_unicode_value(self):
        example_payload = {"hello": "world"}
        example_secret = "secret"
        example_jwt = (
            "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"
            ".eyJoZWxsbyI6ICJ3b3JsZCJ9"
            ".tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8")
        decoded_payload = jwt.decode(example_jwt, example_secret)
        self.assertEqual(decoded_payload, example_payload)

    def test_decode_invalid_header_padding(self):
        example_jwt = (
            "aeyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"
            ".eyJoZWxsbyI6ICJ3b3JsZCJ9"
            ".tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8")
        example_secret = "secret"
        with self.assertRaises(jwt.DecodeError):
            jwt.decode(example_jwt, example_secret)

    def test_decode_invalid_header_string(self):
        example_jwt = (
            "eyJhbGciOiAiSFMyNTbpIiwgInR5cCI6ICJKV1QifQ=="
            ".eyJoZWxsbyI6ICJ3b3JsZCJ9"
            ".tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8")
        example_secret = "secret"
        with self.assertRaisesRegexp(jwt.DecodeError, "Invalid header string"):
            jwt.decode(example_jwt, example_secret)

    def test_decode_invalid_payload_padding(self):
        example_jwt = (
            "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"
            ".aeyJoZWxsbyI6ICJ3b3JsZCJ9"
            ".tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8")
        example_secret = "secret"
        with self.assertRaises(jwt.DecodeError):
            jwt.decode(example_jwt, example_secret)

    def test_decode_invalid_payload_string(self):
        example_jwt = (
            "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"
            ".eyJoZWxsb-kiOiAid29ybGQifQ=="
            ".tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8")
        example_secret = "secret"
        with self.assertRaisesRegexp(jwt.DecodeError,
                                     "Invalid payload string"):
            jwt.decode(example_jwt, example_secret)

    def test_decode_invalid_crypto_padding(self):
        example_jwt = (
            "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"
            ".eyJoZWxsbyI6ICJ3b3JsZCJ9"
            ".aatvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8")
        example_secret = "secret"
        with self.assertRaises(jwt.DecodeError):
            jwt.decode(example_jwt, example_secret)

    def test_decode_with_expiration(self):
        self.payload['exp'] = utc_timestamp() - 1
        secret = 'secret'
        jwt_message = jwt.encode(self.payload, secret)
        with self.assertRaises(jwt.ExpiredSignature):
            jwt.decode(jwt_message, secret)

    def test_decode_skip_expiration_verification(self):
        self.payload['exp'] = time.time() - 1
        secret = 'secret'
        jwt_message = jwt.encode(self.payload, secret)
        jwt.decode(jwt_message, secret, verify_expiration=False)

    def test_decode_with_expiration_with_leeway(self):
        self.payload['exp'] = utc_timestamp() - 2
        secret = 'secret'
        jwt_message = jwt.encode(self.payload, secret)

        # With 3 seconds leeway, should be ok
        jwt.decode(jwt_message, secret, leeway=3)

        # With 1 secondes, should fail
        with self.assertRaises(jwt.ExpiredSignature):
            jwt.decode(jwt_message, secret, leeway=1)

    def test_encode_decode_with_rsa_sha256(self):
        try:
            from Crypto.PublicKey import RSA

            with open('tests/testkey','r') as rsa_priv_file:
                priv_rsakey = RSA.importKey(rsa_priv_file.read())
                jwt_message = jwt.encode(self.payload, priv_rsakey, algorithm='RS256')

            with open('tests/testkey.pub','r') as rsa_pub_file:
                pub_rsakey = RSA.importKey(rsa_pub_file.read())
                assert jwt.decode(jwt_message, pub_rsakey)
        except ImportError:
            pass

    def test_encode_decode_with_rsa_sha384(self):
        try:
            from Crypto.PublicKey import RSA

            with open('tests/testkey','r') as rsa_priv_file:
                priv_rsakey = RSA.importKey(rsa_priv_file.read())
                jwt_message = jwt.encode(self.payload, priv_rsakey, algorithm='RS384')

            with open('tests/testkey.pub','r') as rsa_pub_file:
                pub_rsakey = RSA.importKey(rsa_pub_file.read())
                assert jwt.decode(jwt_message, pub_rsakey)
        except ImportError:
            pass

    def test_encode_decode_with_rsa_sha512(self):
        try:
            from Crypto.PublicKey import RSA

            with open('tests/testkey','r') as rsa_priv_file:
                priv_rsakey = RSA.importKey(rsa_priv_file.read())
                jwt_message = jwt.encode(self.payload, priv_rsakey, algorithm='RS512')

            with open('tests/testkey.pub','r') as rsa_pub_file:
                pub_rsakey = RSA.importKey(rsa_pub_file.read())
                assert jwt.decode(jwt_message, pub_rsakey)
        except ImportError:
            pass

    def test_crypto_related_signing_methods(self):
        try:
            import Crypto
            self.assertTrue('RS256' in jwt.signing_methods)
            self.assertTrue('RS384' in jwt.signing_methods)
            self.assertTrue('RS512' in jwt.signing_methods)
        except ImportError:
            self.assertFalse('RS256' in jwt.signing_methods)
            self.assertFalse('RS384' in jwt.signing_methods)
            self.assertFalse('RS512' in jwt.signing_methods)

    def test_crypto_related_verify_methods(self):
        try:
            import Crypto
            self.assertTrue('RS256' in jwt.verify_methods)
            self.assertTrue('RS384' in jwt.verify_methods)
            self.assertTrue('RS512' in jwt.verify_methods)
        except ImportError:
            self.assertFalse('RS256' in jwt.verify_methods)
            self.assertFalse('RS384' in jwt.verify_methods)
            self.assertFalse('RS512' in jwt.verify_methods)


if __name__ == '__main__':
    unittest.main()
