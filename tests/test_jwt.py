import unittest
import time

import jwt

class TestJWT(unittest.TestCase):

    def setUp(self):
        self.payload = {"iss": "jeff", "exp": int(time.time()) + 1, "claim": "insanity"}

    def test_encode_decode(self):
        secret = 'secret'
        jwt_message = jwt.encode(self.payload, secret)
        decoded_payload = jwt.decode(jwt_message, secret)
        self.assertEqual(decoded_payload, self.payload)

    def test_bad_secret(self):
        right_secret = 'foo'
        bad_secret = 'bar'
        jwt_message = jwt.encode(self.payload, right_secret)
        with self.assertRaises(jwt.DecodeError):
            jwt.decode(jwt_message, bad_secret)

    def test_decodes_valid_jwt(self):
        example_payload = {"hello": "world"}
        example_secret = "secret"
        example_jwt = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8"
        decoded_payload = jwt.decode(example_jwt, example_secret)
        self.assertEqual(decoded_payload, example_payload)

    def test_allow_skip_verification(self):
        right_secret = 'foo'
        bad_secret = 'bar'
        jwt_message = jwt.encode(self.payload, right_secret)
        decoded_payload = jwt.decode(jwt_message, verify=False)
        self.assertEqual(decoded_payload, self.payload)

    def test_no_secret(self):
        right_secret = 'foo'
        bad_secret = 'bar'
        jwt_message = jwt.encode(self.payload, right_secret)

        with self.assertRaises(jwt.DecodeError):
            jwt.decode(jwt_message)

    def test_invalid_crypto_alg(self):
        self.assertRaises(NotImplementedError, jwt.encode, self.payload, "secret", "HS1024")

    def test_unicode_secret(self):
        secret = u'\xc2'
        jwt_message = jwt.encode(self.payload, secret)
        decoded_payload = jwt.decode(jwt_message, secret)
        self.assertEqual(decoded_payload, self.payload)

    def test_nonascii_secret(self):
        secret = '\xc2' # char value that ascii codec cannot decode
        jwt_message = jwt.encode(self.payload, secret)
        decoded_payload = jwt.decode(jwt_message, secret)
        self.assertEqual(decoded_payload, self.payload)

    def test_decode_unicode_value(self):
        example_payload = {"hello": "world"}
        example_secret = "secret"
        example_jwt = unicode("eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8")
        decoded_payload = jwt.decode(example_jwt, example_secret)
        self.assertEqual(decoded_payload, example_payload)

    def test_decode_invalid_header_padding(self):
        example_jwt = unicode("aeyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8")
        example_secret = "secret"
        with self.assertRaises(jwt.DecodeError):
            jwt_message = jwt.decode(example_jwt, example_secret)

    def test_decode_invalid_header_string(self):
        example_jwt = unicode("eyJhbGciOiAiSFMyNTbpIiwgInR5cCI6ICJKV1QifQ==.eyJoZWxsbyI6ICJ3b3JsZCJ9.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8")
        example_secret = "secret"
        with self.assertRaisesRegexp(jwt.DecodeError, "Invalid header string"):
            jwt_message = jwt.decode(example_jwt, example_secret)

    def test_decode_invalid_payload_padding(self):
        example_jwt = unicode("eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.aeyJoZWxsbyI6ICJ3b3JsZCJ9.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8")
        example_secret = "secret"
        with self.assertRaises(jwt.DecodeError):
            jwt_message = jwt.decode(example_jwt, example_secret)

    def test_decode_invalid_payload_string(self):
        example_jwt = unicode("eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsb-kiOiAid29ybGQifQ==.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8")
        example_secret = "secret"
        with self.assertRaisesRegexp(jwt.DecodeError, "Invalid payload string"):
            jwt_message = jwt.decode(example_jwt, example_secret)

    def test_decode_invalid_crypto_padding(self):
        example_jwt = unicode("eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.aatvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8")
        example_secret = "secret"
        with self.assertRaises(jwt.DecodeError):
            jwt_message = jwt.decode(example_jwt, example_secret)

    def test_decode_with_expiration(self):
        self.payload['exp'] = time.time() - 1
        secret = 'secret'
        jwt_message = jwt.encode(self.payload, secret)
        with self.assertRaises(jwt.ExpiredSignature):
            jwt.decode(jwt_message, secret)

    def test_decode_with_expiration_with_leeway(self):
        self.payload['exp'] = time.time() - 2
        secret = 'secret'
        jwt_message = jwt.encode(self.payload, secret)

        # With 3 seconds leeway, should be ok
        jwt.decode(jwt_message, secret, leeway=3)

        # With 2 secondes, should fail
        with self.assertRaises(jwt.ExpiredSignature):
            jwt.decode(jwt_message, secret, leeway=2)


if __name__ == '__main__':
    unittest.main()
