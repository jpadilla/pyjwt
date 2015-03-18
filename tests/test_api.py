
import json
import time

from calendar import timegm
from datetime import datetime, timedelta
from decimal import Decimal

from jwt.algorithms import Algorithm
from jwt.api import PyJWT
from jwt.exceptions import (
    DecodeError, ExpiredSignatureError, InvalidAlgorithmError,
    InvalidAudienceError, InvalidIssuerError
)

from .compat import text_type, unittest
from .utils import ensure_bytes

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key, load_pem_public_key, load_ssh_public_key
    )

    has_crypto = True
except ImportError:
    has_crypto = False


def utc_timestamp():
    return timegm(datetime.utcnow().utctimetuple())


class TestAPI(unittest.TestCase):

    def setUp(self):  # noqa
        self.payload = {'iss': 'jeff', 'exp': utc_timestamp() + 15,
                        'claim': 'insanity'}
        self.jwt = PyJWT()

    def test_register_algorithm_does_not_allow_duplicate_registration(self):
        self.jwt.register_algorithm('AAA', Algorithm())

        with self.assertRaises(ValueError):
            self.jwt.register_algorithm('AAA', Algorithm())

    def test_register_algorithm_rejects_non_algorithm_obj(self):
        with self.assertRaises(TypeError):
            self.jwt.register_algorithm('AAA123', {})

    def test_unregister_algorithm_removes_algorithm(self):
        supported = self.jwt.get_algorithms()
        self.assertIn('none', supported)
        self.assertIn('HS256', supported)

        self.jwt.unregister_algorithm('HS256')

        supported = self.jwt.get_algorithms()
        self.assertNotIn('HS256', supported)

    def test_unregister_algorithm_throws_error_if_not_registered(self):
        with self.assertRaises(KeyError):
            self.jwt.unregister_algorithm('AAA')

    def test_algorithms_parameter_removes_alg_from_algorithms_list(self):
        self.assertIn('none', self.jwt.get_algorithms())
        self.assertIn('HS256', self.jwt.get_algorithms())

        self.jwt = PyJWT(algorithms=['HS256'])
        self.assertNotIn('none', self.jwt.get_algorithms())
        self.assertIn('HS256', self.jwt.get_algorithms())

    def test_encode_decode(self):
        secret = 'secret'
        jwt_message = self.jwt.encode(self.payload, secret)
        decoded_payload = self.jwt.decode(jwt_message, secret)

        self.assertEqual(decoded_payload, self.payload)

    def test_decode_fails_when_alg_is_not_on_method_algorithms_param(self):
        secret = 'secret'
        jwt_token = self.jwt.encode(self.payload, secret, algorithm='HS256')
        self.jwt.decode(jwt_token, secret)

        with self.assertRaises(InvalidAlgorithmError):
            self.jwt.decode(jwt_token, secret, algorithms=['HS384'])

    def test_decode_works_with_unicode_token(self):
        secret = 'secret'
        unicode_jwt = text_type(
            'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')

        self.jwt.decode(unicode_jwt, secret)

    def test_decode_missing_segments_throws_exception(self):
        secret = 'secret'
        example_jwt = ('eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
                       '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
                       '')  # Missing segment

        with self.assertRaises(DecodeError) as context:
            self.jwt.decode(example_jwt, secret)

        exception = context.exception
        self.assertEqual(str(exception), 'Not enough segments')

    def test_decode_with_non_mapping_header_throws_exception(self):
        secret = 'secret'
        example_jwt = ('MQ'  # == 1
                       '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
                       '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')

        with self.assertRaises(DecodeError) as context:
            self.jwt.decode(example_jwt, secret)

        exception = context.exception
        self.assertEqual(str(exception), 'Invalid header string: must be a json object')

    def test_decode_with_non_mapping_payload_throws_exception(self):
        secret = 'secret'
        example_jwt = ('eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
                       '.MQ'  # == 1
                       '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')

        with self.assertRaises(DecodeError) as context:
            self.jwt.decode(example_jwt, secret)

        exception = context.exception
        self.assertEqual(str(exception), 'Invalid payload string: must be a json object')

    def test_decode_with_invalid_audience_param_throws_exception(self):
        secret = 'secret'
        example_jwt = ('eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
                       '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
                       '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')

        with self.assertRaises(TypeError) as context:
            self.jwt.decode(example_jwt, secret, audience=1)

        exception = context.exception
        self.assertEqual(str(exception), 'audience must be a string or None')

    def test_decode_with_nonlist_aud_claim_throws_exception(self):
        secret = 'secret'
        example_jwt = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
                       '.eyJoZWxsbyI6IndvcmxkIiwiYXVkIjoxfQ'  # aud = 1
                       '.Rof08LBSwbm8Z_bhA2N3DFY-utZR1Gi9rbIS5Zthnnc')

        with self.assertRaises(InvalidAudienceError) as context:
            self.jwt.decode(example_jwt, secret, audience='my_audience')

        exception = context.exception
        self.assertEqual(str(exception), 'Invalid claim format in token')

    def test_decode_with_invalid_aud_list_member_throws_exception(self):
        secret = 'secret'
        example_jwt = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
                       '.eyJoZWxsbyI6IndvcmxkIiwiYXVkIjpbMV19'
                       '.iQgKpJ8shetwNMIosNXWBPFB057c2BHs-8t1d2CCM2A')

        with self.assertRaises(InvalidAudienceError) as context:
            self.jwt.decode(example_jwt, secret, audience='my_audience')

        exception = context.exception
        self.assertEqual(str(exception), 'Invalid claim format in token')

    def test_encode_bad_type(self):

        types = ['string', tuple(), list(), 42, set()]

        for t in types:
            self.assertRaises(TypeError, lambda: self.jwt.encode(t, 'secret'))

    def test_encode_algorithm_param_should_be_case_sensitive(self):
        payload = {'hello': 'world'}

        self.jwt.encode(payload, 'secret', algorithm='HS256')

        with self.assertRaises(NotImplementedError) as context:
            self.jwt.encode(payload, None, algorithm='hs256')

        exception = context.exception
        self.assertEquals(str(exception), 'Algorithm not supported')

    def test_decode_algorithm_param_should_be_case_sensitive(self):
        example_jwt = ('eyJhbGciOiJoczI1NiIsInR5cCI6IkpXVCJ9'  # alg = hs256
                       '.eyJoZWxsbyI6IndvcmxkIn0'
                       '.5R_FEPE7SW2dT9GgIxPgZATjFGXfUDOSwo7TtO_Kd_g')

        with self.assertRaises(InvalidAlgorithmError) as context:
            self.jwt.decode(example_jwt, 'secret')

        exception = context.exception
        self.assertEquals(str(exception), 'Algorithm not supported')

    def test_encode_datetime(self):
        secret = 'secret'
        current_datetime = datetime.utcnow()
        payload = {
            'exp': current_datetime,
            'iat': current_datetime,
            'nbf': current_datetime
        }
        jwt_message = self.jwt.encode(payload, secret)
        decoded_payload = self.jwt.decode(jwt_message, secret, leeway=1)

        self.assertEqual(
            decoded_payload['exp'],
            timegm(current_datetime.utctimetuple()))
        self.assertEqual(
            decoded_payload['iat'],
            timegm(current_datetime.utctimetuple()))
        self.assertEqual(
            decoded_payload['nbf'],
            timegm(current_datetime.utctimetuple()))

    def test_bad_secret(self):
        right_secret = 'foo'
        bad_secret = 'bar'
        jwt_message = self.jwt.encode(self.payload, right_secret)

        self.assertRaises(
            DecodeError,
            lambda: self.jwt.decode(jwt_message, bad_secret))

    def test_decodes_valid_jwt(self):
        example_payload = {'hello': 'world'}
        example_secret = 'secret'
        example_jwt = (
            b'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            b'.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            b'.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        decoded_payload = self.jwt.decode(example_jwt, example_secret)

        self.assertEqual(decoded_payload, example_payload)

    # 'Control' Elliptic Curve JWT created by another library.
    # Used to test for regressions that could affect both
    # encoding / decoding operations equally (causing tests
    # to still pass).
    @unittest.skipIf(not has_crypto, "Can't run without cryptography library")
    def test_decodes_valid_es384_jwt(self):
        example_payload = {'hello': 'world'}
        with open('tests/keys/testkey_ec.pub', 'r') as fp:
            example_pubkey = fp.read()
        example_jwt = (
            b'eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9'
            b'.eyJoZWxsbyI6IndvcmxkIn0'
            b'.MIGHAkEdh2kR7IRu5w0tGuY6Xz3Vqa7PHHY2DgXWeee'
            b'LXotEqpn9udp2NfVL-XFG0TDoCakzXbIGAWg42S69GFl'
            b'KZzxhXAJCAPLPuJoKyAixFnXPBkvkti-UzSIj4s6DePe'
            b'uTu7102G_QIXiijY5bx6mdmZa3xUuKeu-zobOIOqR8Zw'
            b'FqGjBLZum')
        decoded_payload = self.jwt.decode(example_jwt, example_pubkey)

        self.assertEqual(decoded_payload, example_payload)

    # 'Control' RSA JWT created by another library.
    # Used to test for regressions that could affect both
    # encoding / decoding operations equally (causing tests
    # to still pass).
    @unittest.skipIf(not has_crypto, "Can't run without cryptography library")
    def test_decodes_valid_rs384_jwt(self):
        example_payload = {'hello': 'world'}
        with open('tests/keys/testkey_rsa.pub', 'r') as fp:
            example_pubkey = fp.read()
        example_jwt = (
            b'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9'
            b'.eyJoZWxsbyI6IndvcmxkIn0'
            b'.yNQ3nI9vEDs7lEh-Cp81McPuiQ4ZRv6FL4evTYYAh1X'
            b'lRTTR3Cz8pPA9Stgso8Ra9xGB4X3rlra1c8Jz10nTUju'
            b'O06OMm7oXdrnxp1KIiAJDerWHkQ7l3dlizIk1bmMA457'
            b'W2fNzNfHViuED5ISM081dgf_a71qBwJ_yShMMrSOfxDx'
            b'mX9c4DjRogRJG8SM5PvpLqI_Cm9iQPGMvmYK7gzcq2cJ'
            b'urHRJDJHTqIdpLWXkY7zVikeen6FhuGyn060Dz9gYq9t'
            b'uwmrtSWCBUjiN8sqJ00CDgycxKqHfUndZbEAOjcCAhBr'
            b'qWW3mSVivUfubsYbwUdUG3fSRPjaUPcpe8A')
        decoded_payload = self.jwt.decode(example_jwt, example_pubkey)

        self.assertEqual(decoded_payload, example_payload)

    def test_load_verify_valid_jwt(self):
        example_payload = {'hello': 'world'}
        example_secret = 'secret'
        example_jwt = (
            b'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            b'.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            b'.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')

        decoded_payload, signing, header, signature = self.jwt._load(example_jwt)

        self.jwt._verify_signature(decoded_payload, signing, header,
                                   signature, example_secret)

        self.assertEqual(decoded_payload, example_payload)

    def test_allow_skip_verification(self):
        right_secret = 'foo'
        jwt_message = self.jwt.encode(self.payload, right_secret)
        decoded_payload = self.jwt.decode(jwt_message, verify=False)

        self.assertEqual(decoded_payload, self.payload)

    def test_load_no_verification(self):
        right_secret = 'foo'
        jwt_message = self.jwt.encode(self.payload, right_secret)

        decoded_payload, signing, header, signature = self.jwt._load(jwt_message)

        self.assertEqual(decoded_payload, self.payload)

    def test_no_secret(self):
        right_secret = 'foo'
        jwt_message = self.jwt.encode(self.payload, right_secret)

        self.assertRaises(
            DecodeError,
            lambda: self.jwt.decode(jwt_message))

    def test_verify_signature_no_secret(self):
        right_secret = 'foo'
        jwt_message = self.jwt.encode(self.payload, right_secret)

        decoded_payload, signing, header, signature = self.jwt._load(jwt_message)

        self.assertRaises(
            DecodeError,
            lambda: self.jwt._verify_signature(decoded_payload, signing,
                                               header, signature))

    def test_custom_headers(self):
        right_secret = 'foo'
        headers = {'foo': 'bar', 'kid': 'test'}
        jwt_message = self.jwt.encode(self.payload, right_secret, headers=headers)

        decoded_payload, signing, header, signature = self.jwt._load(jwt_message)

        for key, value in headers.items():
            self.assertEqual(header[key], value)

    def test_invalid_crypto_alg(self):
        self.assertRaises(NotImplementedError, self.jwt.encode, self.payload,
                          'secret', 'HS1024')

    def test_unicode_secret(self):
        secret = '\xc2'
        jwt_message = self.jwt.encode(self.payload, secret)
        decoded_payload = self.jwt.decode(jwt_message, secret)

        self.assertEqual(decoded_payload, self.payload)

        decoded_payload, signing, header, signature = self.jwt._load(jwt_message)

        self.jwt._verify_signature(decoded_payload, signing, header,
                                   signature, secret)

        self.assertEqual(decoded_payload, self.payload)

    def test_nonascii_secret(self):
        secret = '\xc2'  # char value that ascii codec cannot decode
        jwt_message = self.jwt.encode(self.payload, secret)

        decoded_payload = self.jwt.decode(jwt_message, secret)

        self.assertEqual(decoded_payload, self.payload)

        decoded_payload, signing, header, signature = self.jwt._load(jwt_message)

        self.jwt._verify_signature(decoded_payload, signing,
                                   header, signature, secret)

        self.assertEqual(decoded_payload, self.payload)

    def test_bytes_secret(self):
        secret = b'\xc2'  # char value that ascii codec cannot decode
        jwt_message = self.jwt.encode(self.payload, secret)

        decoded_payload = self.jwt.decode(jwt_message, secret)

        self.assertEqual(decoded_payload, self.payload)

        decoded_payload, signing, header, signature = self.jwt._load(jwt_message)

        self.jwt._verify_signature(decoded_payload, signing,
                                   header, signature, secret)

        self.assertEqual(decoded_payload, self.payload)

    def test_decode_unicode_value(self):
        example_payload = {'hello': 'world'}
        example_secret = 'secret'
        example_jwt = (
            'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        decoded_payload = self.jwt.decode(example_jwt, example_secret)

        self.assertEqual(decoded_payload, example_payload)
        decoded_payload, signing, header, signature = self.jwt._load(example_jwt)
        self.assertEqual(decoded_payload, example_payload)

    def test_decode_invalid_header_padding(self):
        example_jwt = (
            'aeyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        example_secret = 'secret'

        self.assertRaises(
            DecodeError,
            lambda: self.jwt._load(example_jwt))

        self.assertRaises(
            DecodeError,
            lambda: self.jwt.decode(example_jwt, example_secret))

    def test_decode_invalid_header_string(self):
        example_jwt = (
            'eyJhbGciOiAiSFMyNTbpIiwgInR5cCI6ICJKV1QifQ=='
            '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        example_secret = 'secret'

        try:
            self.jwt._load(example_jwt)
        except DecodeError as e:
            self.assertTrue('Invalid header string' in str(e))
        else:
            self.fail('DecodeError not raised')

        try:
            self.jwt.decode(example_jwt, example_secret)
        except DecodeError as e:
            self.assertTrue('Invalid header string' in str(e))
        else:
            self.fail('DecodeError not raised')

    def test_decode_invalid_payload_padding(self):
        example_jwt = (
            'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            '.aeyJoZWxsbyI6ICJ3b3JsZCJ9'
            '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        example_secret = 'secret'

        self.assertRaises(
            DecodeError,
            lambda: self.jwt._load(example_jwt))

        self.assertRaises(
            DecodeError,
            lambda: self.jwt.decode(example_jwt, example_secret))

    def test_decode_invalid_payload_string(self):
        example_jwt = (
            'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            '.eyJoZWxsb-kiOiAid29ybGQifQ=='
            '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        example_secret = 'secret'

        try:
            self.jwt._load(example_jwt)
        except DecodeError as e:
            self.assertTrue('Invalid payload string' in str(e))
        else:
            self.fail('DecodeError not raised')

        try:
            self.jwt.decode(example_jwt, example_secret)
        except DecodeError as e:
            self.assertTrue('Invalid payload string' in str(e))
        else:
            self.fail('DecodeError not raised')

    def test_decode_invalid_crypto_padding(self):
        example_jwt = (
            'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            '.aatvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        example_secret = 'secret'

        self.assertRaises(
            DecodeError,
            lambda: self.jwt._load(example_jwt))

        self.assertRaises(
            DecodeError,
            lambda: self.jwt.decode(example_jwt, example_secret))

    def test_decode_with_expiration(self):
        self.payload['exp'] = utc_timestamp() - 1
        secret = 'secret'
        jwt_message = self.jwt.encode(self.payload, secret)

        self.assertRaises(
            ExpiredSignatureError,
            lambda: self.jwt.decode(jwt_message, secret))

        decoded_payload, signing, header, signature = self.jwt._load(jwt_message)

        self.assertRaises(
            ExpiredSignatureError,
            lambda: self.jwt._verify_signature(
                decoded_payload, signing, header, signature, secret))

    def test_decode_with_notbefore(self):
        self.payload['nbf'] = utc_timestamp() + 10
        secret = 'secret'
        jwt_message = self.jwt.encode(self.payload, secret)

        self.assertRaises(
            ExpiredSignatureError,
            lambda: self.jwt.decode(jwt_message, secret))

        decoded_payload, signing, header, signature = self.jwt._load(jwt_message)

        self.assertRaises(
            ExpiredSignatureError,
            lambda: self.jwt._verify_signature(
                decoded_payload, signing, header, signature, secret))

    def test_decode_skip_expiration_verification(self):
        self.payload['exp'] = time.time() - 1
        secret = 'secret'
        jwt_message = self.jwt.encode(self.payload, secret)

        self.jwt.decode(jwt_message, secret, verify_expiration=False)

        decoded_payload, signing, header, signature = self.jwt._load(jwt_message)
        self.jwt._verify_signature(decoded_payload, signing, header,
                                   signature, secret, verify_expiration=False)

    def test_decode_skip_notbefore_verification(self):
        self.payload['nbf'] = time.time() + 10
        secret = 'secret'
        jwt_message = self.jwt.encode(self.payload, secret)

        self.jwt.decode(jwt_message, secret, verify_expiration=False)

        decoded_payload, signing, header, signature = self.jwt._load(jwt_message)
        self.jwt._verify_signature(decoded_payload, signing, header,
                                   signature, secret, verify_expiration=False)

    def test_decode_with_expiration_with_leeway(self):
        self.payload['exp'] = utc_timestamp() - 2
        secret = 'secret'
        jwt_message = self.jwt.encode(self.payload, secret)

        decoded_payload, signing, header, signature = self.jwt._load(jwt_message)

        # With 3 seconds leeway, should be ok
        for leeway in (3, timedelta(seconds=3)):
            self.jwt.decode(jwt_message, secret, leeway=leeway)

            self.jwt._verify_signature(decoded_payload, signing, header,
                                       signature, secret, leeway=leeway)

        # With 1 seconds, should fail
        for leeway in (1, timedelta(seconds=1)):
            self.assertRaises(
                ExpiredSignatureError,
                lambda: self.jwt.decode(jwt_message, secret, leeway=leeway))

            self.assertRaises(
                ExpiredSignatureError,
                lambda: self.jwt._verify_signature(decoded_payload, signing,
                                                   header, signature, secret,
                                                   leeway=leeway))

    def test_decode_with_notbefore_with_leeway(self):
        self.payload['nbf'] = utc_timestamp() + 10
        secret = 'secret'
        jwt_message = self.jwt.encode(self.payload, secret)

        decoded_payload, signing, header, signature = self.jwt._load(jwt_message)

        # With 13 seconds leeway, should be ok
        self.jwt.decode(jwt_message, secret, leeway=13)

        self.jwt._verify_signature(decoded_payload, signing, header,
                                   signature, secret, leeway=13)

        # With 1 seconds, should fail
        self.assertRaises(
            ExpiredSignatureError,
            lambda: self.jwt.decode(jwt_message, secret, leeway=1))

        self.assertRaises(
            ExpiredSignatureError,
            lambda: self.jwt._verify_signature(decoded_payload, signing,
                                               header, signature, secret, leeway=1))

    def test_encode_decode_with_algo_none(self):
        jwt_message = self.jwt.encode(self.payload, key=None, algorithm=None)

        self.assertRaises(
            DecodeError,
            lambda: self.jwt.decode(jwt_message))

        self.jwt.decode(jwt_message, verify=False)

    @unittest.skipIf(not has_crypto, 'Not supported without cryptography library')
    def test_encode_decode_with_rsa_sha256(self):
        # PEM-formatted RSA key
        with open('tests/keys/testkey_rsa', 'r') as rsa_priv_file:
            priv_rsakey = load_pem_private_key(ensure_bytes(rsa_priv_file.read()),
                                               password=None, backend=default_backend())
            jwt_message = self.jwt.encode(self.payload, priv_rsakey,
                                          algorithm='RS256')

        with open('tests/keys/testkey_rsa.pub', 'r') as rsa_pub_file:
            pub_rsakey = load_ssh_public_key(ensure_bytes(rsa_pub_file.read()),
                                             backend=default_backend())
            assert self.jwt.decode(jwt_message, pub_rsakey)

            load_output = self.jwt._load(jwt_message)
            self.jwt._verify_signature(key=pub_rsakey, *load_output)

        # string-formatted key
        with open('tests/keys/testkey_rsa', 'r') as rsa_priv_file:
            priv_rsakey = rsa_priv_file.read()
            jwt_message = self.jwt.encode(self.payload, priv_rsakey,
                                          algorithm='RS256')

        with open('tests/keys/testkey_rsa.pub', 'r') as rsa_pub_file:
            pub_rsakey = rsa_pub_file.read()
            assert self.jwt.decode(jwt_message, pub_rsakey)

            load_output = self.jwt._load(jwt_message)
            self.jwt._verify_signature(key=pub_rsakey, *load_output)

    @unittest.skipIf(not has_crypto, 'Not supported without cryptography library')
    def test_encode_decode_with_rsa_sha384(self):
        # PEM-formatted RSA key
        with open('tests/keys/testkey_rsa', 'r') as rsa_priv_file:
            priv_rsakey = load_pem_private_key(ensure_bytes(rsa_priv_file.read()),
                                               password=None, backend=default_backend())
            jwt_message = self.jwt.encode(self.payload, priv_rsakey,
                                          algorithm='RS384')

        with open('tests/keys/testkey_rsa.pub', 'r') as rsa_pub_file:
            pub_rsakey = load_ssh_public_key(ensure_bytes(rsa_pub_file.read()),
                                             backend=default_backend())
            assert self.jwt.decode(jwt_message, pub_rsakey)

        # string-formatted key
        with open('tests/keys/testkey_rsa', 'r') as rsa_priv_file:
            priv_rsakey = rsa_priv_file.read()
            jwt_message = self.jwt.encode(self.payload, priv_rsakey,
                                          algorithm='RS384')

        with open('tests/keys/testkey_rsa.pub', 'r') as rsa_pub_file:
            pub_rsakey = rsa_pub_file.read()
            assert self.jwt.decode(jwt_message, pub_rsakey)

            load_output = self.jwt._load(jwt_message)
            self.jwt._verify_signature(key=pub_rsakey, *load_output)

    @unittest.skipIf(not has_crypto, 'Not supported without cryptography library')
    def test_encode_decode_with_rsa_sha512(self):
        # PEM-formatted RSA key
        with open('tests/keys/testkey_rsa', 'r') as rsa_priv_file:
            priv_rsakey = load_pem_private_key(ensure_bytes(rsa_priv_file.read()),
                                               password=None, backend=default_backend())
            jwt_message = self.jwt.encode(self.payload, priv_rsakey,
                                          algorithm='RS512')

        with open('tests/keys/testkey_rsa.pub', 'r') as rsa_pub_file:
            pub_rsakey = load_ssh_public_key(ensure_bytes(rsa_pub_file.read()),
                                             backend=default_backend())
            assert self.jwt.decode(jwt_message, pub_rsakey)

            load_output = self.jwt._load(jwt_message)
            self.jwt._verify_signature(key=pub_rsakey, *load_output)

        # string-formatted key
        with open('tests/keys/testkey_rsa', 'r') as rsa_priv_file:
            priv_rsakey = rsa_priv_file.read()
            jwt_message = self.jwt.encode(self.payload, priv_rsakey,
                                          algorithm='RS512')

        with open('tests/keys/testkey_rsa.pub', 'r') as rsa_pub_file:
            pub_rsakey = rsa_pub_file.read()
            assert self.jwt.decode(jwt_message, pub_rsakey)

            load_output = self.jwt._load(jwt_message)
            self.jwt._verify_signature(key=pub_rsakey, *load_output)

    def test_rsa_related_algorithms(self):
        self.jwt = PyJWT()
        jwt_algorithms = self.jwt.get_algorithms()

        if has_crypto:
            self.assertTrue('RS256' in jwt_algorithms)
            self.assertTrue('RS384' in jwt_algorithms)
            self.assertTrue('RS512' in jwt_algorithms)
        else:
            self.assertFalse('RS256' in jwt_algorithms)
            self.assertFalse('RS384' in jwt_algorithms)
            self.assertFalse('RS512' in jwt_algorithms)

    @unittest.skipIf(not has_crypto, "Can't run without cryptography library")
    def test_encode_decode_with_ecdsa_sha256(self):
        # PEM-formatted EC key
        with open('tests/keys/testkey_ec', 'r') as ec_priv_file:
            priv_eckey = load_pem_private_key(ensure_bytes(ec_priv_file.read()),
                                              password=None, backend=default_backend())
            jwt_message = self.jwt.encode(self.payload, priv_eckey,
                                          algorithm='ES256')

        with open('tests/keys/testkey_ec.pub', 'r') as ec_pub_file:
            pub_eckey = load_pem_public_key(ensure_bytes(ec_pub_file.read()),
                                            backend=default_backend())
            assert self.jwt.decode(jwt_message, pub_eckey)

            load_output = self.jwt._load(jwt_message)
            self.jwt._verify_signature(key=pub_eckey, *load_output)

        # string-formatted key
        with open('tests/keys/testkey_ec', 'r') as ec_priv_file:
            priv_eckey = ec_priv_file.read()
            jwt_message = self.jwt.encode(self.payload, priv_eckey,
                                          algorithm='ES256')

        with open('tests/keys/testkey_ec.pub', 'r') as ec_pub_file:
            pub_eckey = ec_pub_file.read()
            assert self.jwt.decode(jwt_message, pub_eckey)

            load_output = self.jwt._load(jwt_message)
            self.jwt._verify_signature(key=pub_eckey, *load_output)

    @unittest.skipIf(not has_crypto, "Can't run without cryptography library")
    def test_encode_decode_with_ecdsa_sha384(self):

        # PEM-formatted EC key
        with open('tests/keys/testkey_ec', 'r') as ec_priv_file:
            priv_eckey = load_pem_private_key(ensure_bytes(ec_priv_file.read()),
                                              password=None, backend=default_backend())
            jwt_message = self.jwt.encode(self.payload, priv_eckey,
                                          algorithm='ES384')

        with open('tests/keys/testkey_ec.pub', 'r') as ec_pub_file:
            pub_eckey = load_pem_public_key(ensure_bytes(ec_pub_file.read()),
                                            backend=default_backend())
            assert self.jwt.decode(jwt_message, pub_eckey)

            load_output = self.jwt._load(jwt_message)
            self.jwt._verify_signature(key=pub_eckey, *load_output)

        # string-formatted key
        with open('tests/keys/testkey_ec', 'r') as ec_priv_file:
            priv_eckey = ec_priv_file.read()
            jwt_message = self.jwt.encode(self.payload, priv_eckey,
                                          algorithm='ES384')

        with open('tests/keys/testkey_ec.pub', 'r') as ec_pub_file:
            pub_eckey = ec_pub_file.read()
            assert self.jwt.decode(jwt_message, pub_eckey)

            load_output = self.jwt._load(jwt_message)
            self.jwt._verify_signature(key=pub_eckey, *load_output)

    @unittest.skipIf(not has_crypto, "Can't run without cryptography library")
    def test_encode_decode_with_ecdsa_sha512(self):
        # PEM-formatted EC key
        with open('tests/keys/testkey_ec', 'r') as ec_priv_file:
            priv_eckey = load_pem_private_key(ensure_bytes(ec_priv_file.read()),
                                              password=None, backend=default_backend())
            jwt_message = self.jwt.encode(self.payload, priv_eckey,
                                          algorithm='ES512')

        with open('tests/keys/testkey_ec.pub', 'r') as ec_pub_file:
            pub_eckey = load_pem_public_key(ensure_bytes(ec_pub_file.read()), backend=default_backend())
            assert self.jwt.decode(jwt_message, pub_eckey)

            load_output = self.jwt._load(jwt_message)
            self.jwt._verify_signature(key=pub_eckey, *load_output)

        # string-formatted key
        with open('tests/keys/testkey_ec', 'r') as ec_priv_file:
            priv_eckey = ec_priv_file.read()
            jwt_message = self.jwt.encode(self.payload, priv_eckey,
                                          algorithm='ES512')

        with open('tests/keys/testkey_ec.pub', 'r') as ec_pub_file:
            pub_eckey = ec_pub_file.read()
            assert self.jwt.decode(jwt_message, pub_eckey)

            load_output = self.jwt._load(jwt_message)
            self.jwt._verify_signature(key=pub_eckey, *load_output)

    def test_ecdsa_related_algorithms(self):
        self.jwt = PyJWT()
        jwt_algorithms = self.jwt.get_algorithms()

        if has_crypto:
            self.assertTrue('ES256' in jwt_algorithms)
            self.assertTrue('ES384' in jwt_algorithms)
            self.assertTrue('ES512' in jwt_algorithms)
        else:
            self.assertFalse('ES256' in jwt_algorithms)
            self.assertFalse('ES384' in jwt_algorithms)
            self.assertFalse('ES512' in jwt_algorithms)

    def test_check_audience(self):
        payload = {
            'some': 'payload',
            'aud': 'urn:me'
        }
        token = self.jwt.encode(payload, 'secret')
        decoded = self.jwt.decode(token, 'secret', audience='urn:me')
        self.assertEqual(decoded, payload)

    def test_check_audience_in_array(self):
        payload = {
            'some': 'payload',
            'aud': ['urn:me', 'urn:someone-else']
        }
        token = self.jwt.encode(payload, 'secret')
        decoded = self.jwt.decode(token, 'secret', audience='urn:me')
        self.assertEqual(decoded, payload)

    def test_raise_exception_invalid_audience(self):
        payload = {
            'some': 'payload',
            'aud': 'urn:someone-else'
        }
        token = self.jwt.encode(payload, 'secret')
        self.assertRaises(
            InvalidAudienceError,
            lambda: self.jwt.decode(token, 'secret', audience='urn-me'))

    def test_raise_exception_invalid_audience_in_array(self):
        payload = {
            'some': 'payload',
            'aud': ['urn:someone', 'urn:someone-else']
        }
        token = self.jwt.encode(payload, 'secret')
        self.assertRaises(
            InvalidAudienceError,
            lambda: self.jwt.decode(token, 'secret', audience='urn:me'))

    def test_raise_exception_token_without_audience(self):
        payload = {
            'some': 'payload',
        }
        token = self.jwt.encode(payload, 'secret')
        self.assertRaises(
            InvalidAudienceError,
            lambda: self.jwt.decode(token, 'secret', audience='urn:me'))

    def test_check_issuer(self):
        issuer = 'urn:foo'
        payload = {
            'some': 'payload',
            'iss': 'urn:foo'
        }
        token = self.jwt.encode(payload, 'secret')
        decoded = self.jwt.decode(token, 'secret', issuer=issuer)

        self.assertEqual(decoded, payload)

    def test_raise_exception_invalid_issuer(self):
        issuer = 'urn:wrong'

        payload = {
            'some': 'payload',
            'iss': 'urn:foo'
        }

        token = self.jwt.encode(payload, 'secret')

        self.assertRaises(
            InvalidIssuerError,
            lambda: self.jwt.decode(token, 'secret', issuer=issuer))

    def test_raise_exception_token_without_issuer(self):
        issuer = 'urn:wrong'

        payload = {
            'some': 'payload',
        }

        token = self.jwt.encode(payload, 'secret')

        self.assertRaises(
            InvalidIssuerError,
            lambda: self.jwt.decode(token, 'secret', issuer=issuer))

    def test_custom_json_encoder(self):

        class CustomJSONEncoder(json.JSONEncoder):

            def default(self, o):
                if isinstance(o, Decimal):
                    return 'it worked'
                return super(CustomJSONEncoder, self).default(o)

        data = {
            'some_decimal': Decimal('2.2')
        }

        self.assertRaises(
            TypeError,
            lambda: self.jwt.encode(data, 'secret'))

        token = self.jwt.encode(data, 'secret', json_encoder=CustomJSONEncoder)
        payload = self.jwt.decode(token, 'secret')
        self.assertEqual(payload, {'some_decimal': 'it worked'})


if __name__ == '__main__':
    unittest.main()
