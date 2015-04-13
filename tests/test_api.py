
import json
import time
import warnings

from calendar import timegm
from datetime import datetime, timedelta
from decimal import Decimal

from jwt.algorithms import Algorithm
from jwt.api import PyJWT
from jwt.exceptions import (
    DecodeError, ExpiredSignatureError, ImmatureSignatureError,
    InvalidAlgorithmError, InvalidAudienceError, InvalidIssuedAtError,
    InvalidIssuerError
)
from jwt.utils import base64url_decode

import pytest

from .compat import string_types, text_type, unittest
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
        self.warnings_context = warnings.catch_warnings(record=True)
        self.warnings = self.warnings_context.__enter__()

        warnings.simplefilter('always', DeprecationWarning)

        self.payload = {'iss': 'jeff', 'exp': utc_timestamp() + 15,
                        'claim': 'insanity'}
        self.jwt = PyJWT()

    def tearDown(self):  # noqa
        self.warnings_context.__exit__()

    def test_register_algorithm_does_not_allow_duplicate_registration(self):
        self.jwt.register_algorithm('AAA', Algorithm())

        with pytest.raises(ValueError):
            self.jwt.register_algorithm('AAA', Algorithm())

    def test_register_algorithm_rejects_non_algorithm_obj(self):
        with pytest.raises(TypeError):
            self.jwt.register_algorithm('AAA123', {})

    def test_unregister_algorithm_removes_algorithm(self):
        supported = self.jwt.get_algorithms()
        assert 'none' in supported
        assert 'HS256' in supported

        self.jwt.unregister_algorithm('HS256')

        supported = self.jwt.get_algorithms()
        assert 'HS256' not in supported

    def test_unregister_algorithm_throws_error_if_not_registered(self):
        with pytest.raises(KeyError):
            self.jwt.unregister_algorithm('AAA')

    def test_algorithms_parameter_removes_alg_from_algorithms_list(self):
        assert 'none' in self.jwt.get_algorithms()
        assert 'HS256' in self.jwt.get_algorithms()

        self.jwt = PyJWT(algorithms=['HS256'])
        assert 'none' not in self.jwt.get_algorithms()
        assert 'HS256' in self.jwt.get_algorithms()

    def test_override_options(self):
        self.jwt = PyJWT(options={'verify_exp': False, 'verify_nbf': False})
        expected_options = self.jwt.options
        expected_options['verify_exp'] = False
        expected_options['verify_nbf'] = False
        assert expected_options == self.jwt.options

    def test_non_object_options_persist(self):
        self.jwt = PyJWT(options={'verify_iat': False, 'foobar': False})
        expected_options = self.jwt.options
        expected_options['verify_iat'] = False
        expected_options['foobar'] = False
        assert expected_options == self.jwt.options

    def test_options_must_be_dict(self):
        pytest.raises(TypeError, PyJWT, options=object())
        pytest.raises(TypeError, PyJWT, options=('something'))

    def test_encode_decode(self):
        secret = 'secret'
        jwt_message = self.jwt.encode(self.payload, secret)
        decoded_payload = self.jwt.decode(jwt_message, secret)

        assert decoded_payload == self.payload

    def test_decode_fails_when_alg_is_not_on_method_algorithms_param(self):
        secret = 'secret'
        jwt_token = self.jwt.encode(self.payload, secret, algorithm='HS256')
        self.jwt.decode(jwt_token, secret)

        with pytest.raises(InvalidAlgorithmError):
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

        with pytest.raises(DecodeError) as context:
            self.jwt.decode(example_jwt, secret)

        exception = context.value
        assert str(exception) == 'Not enough segments'

    def test_decode_with_non_mapping_header_throws_exception(self):
        secret = 'secret'
        example_jwt = ('MQ'  # == 1
                       '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
                       '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')

        with pytest.raises(DecodeError) as context:
            self.jwt.decode(example_jwt, secret)

        exception = context.value
        assert str(exception) == 'Invalid header string: must be a json object'

    def test_decode_with_non_mapping_payload_throws_exception(self):
        secret = 'secret'
        example_jwt = ('eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
                       '.MQ'  # == 1
                       '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')

        with pytest.raises(DecodeError) as context:
            self.jwt.decode(example_jwt, secret)

        exception = context.value
        assert str(exception) == 'Invalid payload string: must be a json object'

    def test_decode_with_invalid_audience_param_throws_exception(self):
        secret = 'secret'
        example_jwt = ('eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
                       '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
                       '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')

        with pytest.raises(TypeError) as context:
            self.jwt.decode(example_jwt, secret, audience=1)

        exception = context.value
        assert str(exception) == 'audience must be a string or None'

    def test_decode_with_nonlist_aud_claim_throws_exception(self):
        secret = 'secret'
        example_jwt = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
                       '.eyJoZWxsbyI6IndvcmxkIiwiYXVkIjoxfQ'  # aud = 1
                       '.Rof08LBSwbm8Z_bhA2N3DFY-utZR1Gi9rbIS5Zthnnc')

        with pytest.raises(InvalidAudienceError) as context:
            self.jwt.decode(example_jwt, secret, audience='my_audience')

        exception = context.value
        assert str(exception) == 'Invalid claim format in token'

    def test_decode_with_invalid_aud_list_member_throws_exception(self):
        secret = 'secret'
        example_jwt = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
                       '.eyJoZWxsbyI6IndvcmxkIiwiYXVkIjpbMV19'
                       '.iQgKpJ8shetwNMIosNXWBPFB057c2BHs-8t1d2CCM2A')

        with pytest.raises(InvalidAudienceError) as context:
            self.jwt.decode(example_jwt, secret, audience='my_audience')

        exception = context.value
        assert str(exception) == 'Invalid claim format in token'

    def test_encode_bad_type(self):

        types = ['string', tuple(), list(), 42, set()]

        for t in types:
            pytest.raises(TypeError, lambda: self.jwt.encode(t, 'secret'))

    def test_encode_algorithm_param_should_be_case_sensitive(self):
        payload = {'hello': 'world'}

        self.jwt.encode(payload, 'secret', algorithm='HS256')

        with pytest.raises(NotImplementedError) as context:
            self.jwt.encode(payload, None, algorithm='hs256')

        exception = context.value
        assert str(exception) == 'Algorithm not supported'

    def test_decode_algorithm_param_should_be_case_sensitive(self):
        example_jwt = ('eyJhbGciOiJoczI1NiIsInR5cCI6IkpXVCJ9'  # alg = hs256
                       '.eyJoZWxsbyI6IndvcmxkIn0'
                       '.5R_FEPE7SW2dT9GgIxPgZATjFGXfUDOSwo7TtO_Kd_g')

        with pytest.raises(InvalidAlgorithmError) as context:
            self.jwt.decode(example_jwt, 'secret')

        exception = context.value
        assert str(exception) == 'Algorithm not supported'

    def test_decode_raises_exception_if_exp_is_not_int(self):
        # >>> jwt.encode({'exp': 'not-an-int'}, 'secret')
        example_jwt = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
                       'eyJleHAiOiJub3QtYW4taW50In0.'
                       'P65iYgoHtBqB07PMtBSuKNUEIPPPfmjfJG217cEE66s')

        with pytest.raises(DecodeError) as exc:
            self.jwt.decode(example_jwt, 'secret')

        assert 'exp' in str(exc.value)

    def test_decode_raises_exception_if_iat_is_not_int(self):
        # >>> jwt.encode({'iat': 'not-an-int'}, 'secret')
        example_jwt = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
                       'eyJpYXQiOiJub3QtYW4taW50In0.'
                       'H1GmcQgSySa5LOKYbzGm--b1OmRbHFkyk8pq811FzZM')

        with pytest.raises(DecodeError):
            self.jwt.decode(example_jwt, 'secret')

    def test_decode_raises_exception_if_nbf_is_not_int(self):
        # >>> jwt.encode({'nbf': 'not-an-int'}, 'secret')
        example_jwt = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
                       'eyJuYmYiOiJub3QtYW4taW50In0.'
                       'c25hldC8G2ZamC8uKpax9sYMTgdZo3cxrmzFHaAAluw')

        with pytest.raises(DecodeError):
            self.jwt.decode(example_jwt, 'secret')

    def test_decode_raises_exception_if_iat_in_the_future(self):
        now = datetime.utcnow()
        token = self.jwt.encode({'iat': now + timedelta(days=1)}, key='secret')

        with pytest.raises(InvalidIssuedAtError):
            self.jwt.decode(token, 'secret')

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

        assert (decoded_payload['exp'] ==
                timegm(current_datetime.utctimetuple()))
        assert (decoded_payload['iat'] ==
                timegm(current_datetime.utctimetuple()))
        assert (decoded_payload['nbf'] ==
                timegm(current_datetime.utctimetuple()))

    def test_bad_secret(self):
        right_secret = 'foo'
        bad_secret = 'bar'
        jwt_message = self.jwt.encode(self.payload, right_secret)

        with pytest.raises(DecodeError):
            self.jwt.decode(jwt_message, bad_secret)

    def test_decodes_valid_jwt(self):
        example_payload = {'hello': 'world'}
        example_secret = 'secret'
        example_jwt = (
            b'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            b'.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            b'.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        decoded_payload = self.jwt.decode(example_jwt, example_secret)

        assert decoded_payload == example_payload

    # 'Control' Elliptic Curve JWT created by another library.
    # Used to test for regressions that could affect both
    # encoding / decoding operations equally (causing tests
    # to still pass).
    @pytest.mark.skipif(not has_crypto, reason="Can't run without cryptography library")
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

        assert decoded_payload == example_payload

    # 'Control' RSA JWT created by another library.
    # Used to test for regressions that could affect both
    # encoding / decoding operations equally (causing tests
    # to still pass).
    @pytest.mark.skipif(not has_crypto, reason="Can't run without cryptography library")
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

        assert decoded_payload == example_payload

    def test_load_verify_valid_jwt(self):
        example_payload = {'hello': 'world'}
        example_secret = 'secret'
        example_jwt = (
            b'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            b'.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            b'.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')

        decoded_payload = self.jwt.decode(example_jwt, key=example_secret)

        assert decoded_payload == example_payload

    def test_allow_skip_verification(self):
        right_secret = 'foo'
        jwt_message = self.jwt.encode(self.payload, right_secret)
        decoded_payload = self.jwt.decode(jwt_message, verify=False)

        assert decoded_payload == self.payload

    def test_verify_false_deprecated(self):
        example_jwt = (
            b'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            b'.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            b'.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')

        assert len(self.warnings) == 0
        self.jwt.decode(example_jwt, verify=False)

        assert len(self.warnings) ==  1
        assert self.warnings[-1].category == DeprecationWarning

    def test_load_no_verification(self):
        right_secret = 'foo'
        jwt_message = self.jwt.encode(self.payload, right_secret)

        decoded_payload = self.jwt.decode(jwt_message, key=None, verify=False)

        assert decoded_payload == self.payload

    def test_no_secret(self):
        right_secret = 'foo'
        jwt_message = self.jwt.encode(self.payload, right_secret)

        with pytest.raises(DecodeError):
            self.jwt.decode(jwt_message)

    def test_verify_signature_with_no_secret(self):
        right_secret = 'foo'
        jwt_message = self.jwt.encode(self.payload, right_secret)

        with pytest.raises(DecodeError) as exc:
            self.jwt.decode(jwt_message)

        assert 'Signature verification' in str(exc.value)

    def test_invalid_crypto_alg(self):
        with pytest.raises(NotImplementedError):
            self.jwt.encode(self.payload, 'secret', algorithm='HS1024')

    def test_unicode_secret(self):
        secret = '\xc2'
        jwt_message = self.jwt.encode(self.payload, secret)
        decoded_payload = self.jwt.decode(jwt_message, secret)

        assert decoded_payload == self.payload

    def test_nonascii_secret(self):
        secret = '\xc2'  # char value that ascii codec cannot decode
        jwt_message = self.jwt.encode(self.payload, secret)

        decoded_payload = self.jwt.decode(jwt_message, secret)

        assert decoded_payload == self.payload

    def test_bytes_secret(self):
        secret = b'\xc2'  # char value that ascii codec cannot decode
        jwt_message = self.jwt.encode(self.payload, secret)

        decoded_payload = self.jwt.decode(jwt_message, secret)

        assert decoded_payload == self.payload

    def test_decode_unicode_value(self):
        example_payload = {'hello': 'world'}
        example_secret = 'secret'
        example_jwt = (
            'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        decoded_payload = self.jwt.decode(example_jwt, example_secret)

        assert decoded_payload == example_payload

    def test_decode_invalid_header_padding(self):
        example_jwt = (
            'aeyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        example_secret = 'secret'

        with pytest.raises(DecodeError) as exc:
            self.jwt.decode(example_jwt, example_secret)

        assert 'header padding' in str(exc.value)

    def test_decode_invalid_header_string(self):
        example_jwt = (
            'eyJhbGciOiAiSFMyNTbpIiwgInR5cCI6ICJKV1QifQ=='
            '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        example_secret = 'secret'

        with pytest.raises(DecodeError) as exc:
            self.jwt.decode(example_jwt, example_secret)

        assert 'Invalid header' in str(exc.value)

    def test_decode_invalid_payload_padding(self):
        example_jwt = (
            'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            '.aeyJoZWxsbyI6ICJ3b3JsZCJ9'
            '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        example_secret = 'secret'

        with pytest.raises(DecodeError) as exc:
            self.jwt.decode(example_jwt, example_secret)

        assert 'Invalid payload padding' in str(exc.value)

    def test_decode_invalid_payload_string(self):
        example_jwt = (
            'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            '.eyJoZWxsb-kiOiAid29ybGQifQ=='
            '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        example_secret = 'secret'

        with pytest.raises(DecodeError) as exc:
            self.jwt.decode(example_jwt, example_secret)

        assert 'Invalid payload string' in str(exc.value)

    def test_decode_invalid_crypto_padding(self):
        example_jwt = (
            'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            '.aatvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        example_secret = 'secret'

        with pytest.raises(DecodeError) as exc:
            self.jwt.decode(example_jwt, example_secret)

        assert 'Invalid crypto padding' in str(exc.value)

    def test_decode_with_expiration(self):
        self.payload['exp'] = utc_timestamp() - 1
        secret = 'secret'
        jwt_message = self.jwt.encode(self.payload, secret)

        with pytest.raises(ExpiredSignatureError):
            self.jwt.decode(jwt_message, secret)

    def test_decode_with_notbefore(self):
        self.payload['nbf'] = utc_timestamp() + 10
        secret = 'secret'
        jwt_message = self.jwt.encode(self.payload, secret)

        with pytest.raises(ImmatureSignatureError):
            self.jwt.decode(jwt_message, secret)

    def test_decode_skip_expiration_verification(self):
        self.payload['exp'] = time.time() - 1
        secret = 'secret'
        jwt_message = self.jwt.encode(self.payload, secret)

        self.jwt.decode(jwt_message, secret, options={'verify_exp': False})

    def test_decode_skip_notbefore_verification(self):
        self.payload['nbf'] = time.time() + 10
        secret = 'secret'
        jwt_message = self.jwt.encode(self.payload, secret)

        self.jwt.decode(jwt_message, secret, options={'verify_nbf': False})

    def test_decode_with_expiration_with_leeway(self):
        self.payload['exp'] = utc_timestamp() - 2
        secret = 'secret'
        jwt_message = self.jwt.encode(self.payload, secret)

        decoded_payload, signing, header, signature = self.jwt._load(jwt_message)

        # With 3 seconds leeway, should be ok
        for leeway in (3, timedelta(seconds=3)):
            self.jwt.decode(jwt_message, secret, leeway=leeway)

        # With 1 seconds, should fail
        for leeway in (1, timedelta(seconds=1)):
            with pytest.raises(ExpiredSignatureError):
                self.jwt.decode(jwt_message, secret, leeway=leeway)

    def test_decode_with_notbefore_with_leeway(self):
        self.payload['nbf'] = utc_timestamp() + 10
        secret = 'secret'
        jwt_message = self.jwt.encode(self.payload, secret)

        # With 13 seconds leeway, should be ok
        self.jwt.decode(jwt_message, secret, leeway=13)

        with pytest.raises(ImmatureSignatureError):
            self.jwt.decode(jwt_message, secret, leeway=1)

    def test_decode_with_algo_none_should_fail(self):
        jwt_message = self.jwt.encode(self.payload, key=None, algorithm=None)

        with pytest.raises(DecodeError):
            self.jwt.decode(jwt_message)

    def test_decode_with_algo_none_and_verify_false_should_pass(self):
        jwt_message = self.jwt.encode(self.payload, key=None, algorithm=None)
        self.jwt.decode(jwt_message, verify=False)

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
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

            self.jwt.decode(jwt_message, pub_rsakey)

        # string-formatted key
        with open('tests/keys/testkey_rsa', 'r') as rsa_priv_file:
            priv_rsakey = rsa_priv_file.read()
            jwt_message = self.jwt.encode(self.payload, priv_rsakey,
                                          algorithm='RS256')

        with open('tests/keys/testkey_rsa.pub', 'r') as rsa_pub_file:
            pub_rsakey = rsa_pub_file.read()
            self.jwt.decode(jwt_message, pub_rsakey)

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
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
            self.jwt.decode(jwt_message, pub_rsakey)

        # string-formatted key
        with open('tests/keys/testkey_rsa', 'r') as rsa_priv_file:
            priv_rsakey = rsa_priv_file.read()
            jwt_message = self.jwt.encode(self.payload, priv_rsakey,
                                          algorithm='RS384')

        with open('tests/keys/testkey_rsa.pub', 'r') as rsa_pub_file:
            pub_rsakey = rsa_pub_file.read()
            self.jwt.decode(jwt_message, pub_rsakey)

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
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
            self.jwt.decode(jwt_message, pub_rsakey)

        # string-formatted key
        with open('tests/keys/testkey_rsa', 'r') as rsa_priv_file:
            priv_rsakey = rsa_priv_file.read()
            jwt_message = self.jwt.encode(self.payload, priv_rsakey,
                                          algorithm='RS512')

        with open('tests/keys/testkey_rsa.pub', 'r') as rsa_pub_file:
            pub_rsakey = rsa_pub_file.read()
            self.jwt.decode(jwt_message, pub_rsakey)

    def test_rsa_related_algorithms(self):
        self.jwt = PyJWT()
        jwt_algorithms = self.jwt.get_algorithms()

        if has_crypto:
            assert 'RS256' in jwt_algorithms
            assert 'RS384' in jwt_algorithms
            assert 'RS512' in jwt_algorithms
            assert 'PS256' in jwt_algorithms
            assert 'PS384' in jwt_algorithms
            assert 'PS512' in jwt_algorithms

        else:
            assert 'RS256' not in jwt_algorithms
            assert 'RS384' not in jwt_algorithms
            assert 'RS512' not in jwt_algorithms
            assert 'PS256' not in jwt_algorithms
            assert 'PS384' not in jwt_algorithms
            assert 'PS512' not in jwt_algorithms

    @pytest.mark.skipif(not has_crypto, reason="Can't run without cryptography library")
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
            self.jwt.decode(jwt_message, pub_eckey)

        # string-formatted key
        with open('tests/keys/testkey_ec', 'r') as ec_priv_file:
            priv_eckey = ec_priv_file.read()
            jwt_message = self.jwt.encode(self.payload, priv_eckey,
                                          algorithm='ES256')

        with open('tests/keys/testkey_ec.pub', 'r') as ec_pub_file:
            pub_eckey = ec_pub_file.read()
            self.jwt.decode(jwt_message, pub_eckey)

    @pytest.mark.skipif(not has_crypto, reason="Can't run without cryptography library")
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
            self.jwt.decode(jwt_message, pub_eckey)

        # string-formatted key
        with open('tests/keys/testkey_ec', 'r') as ec_priv_file:
            priv_eckey = ec_priv_file.read()
            jwt_message = self.jwt.encode(self.payload, priv_eckey,
                                          algorithm='ES384')

        with open('tests/keys/testkey_ec.pub', 'r') as ec_pub_file:
            pub_eckey = ec_pub_file.read()
            self.jwt.decode(jwt_message, pub_eckey)

    @pytest.mark.skipif(not has_crypto, reason="Can't run without cryptography library")
    def test_encode_decode_with_ecdsa_sha512(self):
        # PEM-formatted EC key
        with open('tests/keys/testkey_ec', 'r') as ec_priv_file:
            priv_eckey = load_pem_private_key(ensure_bytes(ec_priv_file.read()),
                                              password=None, backend=default_backend())
            jwt_message = self.jwt.encode(self.payload, priv_eckey,
                                          algorithm='ES512')

        with open('tests/keys/testkey_ec.pub', 'r') as ec_pub_file:
            pub_eckey = load_pem_public_key(ensure_bytes(ec_pub_file.read()), backend=default_backend())
            self.jwt.decode(jwt_message, pub_eckey)

        # string-formatted key
        with open('tests/keys/testkey_ec', 'r') as ec_priv_file:
            priv_eckey = ec_priv_file.read()
            jwt_message = self.jwt.encode(self.payload, priv_eckey,
                                          algorithm='ES512')

        with open('tests/keys/testkey_ec.pub', 'r') as ec_pub_file:
            pub_eckey = ec_pub_file.read()
            self.jwt.decode(jwt_message, pub_eckey)

    def test_ecdsa_related_algorithms(self):
        self.jwt = PyJWT()
        jwt_algorithms = self.jwt.get_algorithms()

        if has_crypto:
            assert 'ES256' in jwt_algorithms
            assert 'ES384' in jwt_algorithms
            assert 'ES512' in jwt_algorithms
        else:
            assert 'ES256' not in jwt_algorithms
            assert 'ES384' not in jwt_algorithms
            assert 'ES512' not in jwt_algorithms

    def test_check_audience_when_valid(self):
        payload = {
            'some': 'payload',
            'aud': 'urn:me'
        }
        token = self.jwt.encode(payload, 'secret')
        self.jwt.decode(token, 'secret', audience='urn:me')

    def test_check_audience_in_array_when_valid(self):
        payload = {
            'some': 'payload',
            'aud': ['urn:me', 'urn:someone-else']
        }
        token = self.jwt.encode(payload, 'secret')
        self.jwt.decode(token, 'secret', audience='urn:me')

    def test_raise_exception_invalid_audience(self):
        payload = {
            'some': 'payload',
            'aud': 'urn:someone-else'
        }

        token = self.jwt.encode(payload, 'secret')

        with pytest.raises(InvalidAudienceError):
            self.jwt.decode(token, 'secret', audience='urn-me')

    def test_raise_exception_invalid_audience_in_array(self):
        payload = {
            'some': 'payload',
            'aud': ['urn:someone', 'urn:someone-else']
        }

        token = self.jwt.encode(payload, 'secret')

        with pytest.raises(InvalidAudienceError):
            self.jwt.decode(token, 'secret', audience='urn:me')

    def test_raise_exception_token_without_audience(self):
        payload = {
            'some': 'payload',
        }
        token = self.jwt.encode(payload, 'secret')

        with pytest.raises(InvalidAudienceError):
            self.jwt.decode(token, 'secret', audience='urn:me')

    def test_check_issuer_when_valid(self):
        issuer = 'urn:foo'
        payload = {
            'some': 'payload',
            'iss': 'urn:foo'
        }
        token = self.jwt.encode(payload, 'secret')
        self.jwt.decode(token, 'secret', issuer=issuer)

    def test_raise_exception_invalid_issuer(self):
        issuer = 'urn:wrong'

        payload = {
            'some': 'payload',
            'iss': 'urn:foo'
        }

        token = self.jwt.encode(payload, 'secret')

        with pytest.raises(InvalidIssuerError):
            self.jwt.decode(token, 'secret', issuer=issuer)

    def test_raise_exception_token_without_issuer(self):
        issuer = 'urn:wrong'

        payload = {
            'some': 'payload',
        }

        token = self.jwt.encode(payload, 'secret')

        with pytest.raises(InvalidIssuerError):
            self.jwt.decode(token, 'secret', issuer=issuer)

    def test_skip_check_audience(self):
        payload = {
            'some': 'payload',
            'aud': 'urn:me',
        }
        token = self.jwt.encode(payload, 'secret')
        self.jwt.decode(token, 'secret', options={'verify_aud': False})

    def test_skip_check_exp(self):
        payload = {
            'some': 'payload',
            'exp': datetime.utcnow() - timedelta(days=1)
        }
        token = self.jwt.encode(payload, 'secret')
        self.jwt.decode(token, 'secret', options={'verify_exp': False})

    def test_skip_check_signature(self):
        token = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                 ".eyJzb21lIjoicGF5bG9hZCJ9"
                 ".4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZA")
        self.jwt.decode(token, 'secret', options={'verify_signature': False})

    def test_skip_check_iat(self):
        payload = {
            'some': 'payload',
            'iat': datetime.utcnow() + timedelta(days=1)
        }
        token = self.jwt.encode(payload, 'secret')
        self.jwt.decode(token, 'secret', options={'verify_iat': False})

    def test_skip_check_nbf(self):
        payload = {
            'some': 'payload',
            'nbf': datetime.utcnow() + timedelta(days=1)
        }
        token = self.jwt.encode(payload, 'secret')
        self.jwt.decode(token, 'secret', options={'verify_nbf': False})

    def test_decode_options_must_be_dict(self):
        payload = {
            'some': 'payload',
        }
        token = self.jwt.encode(payload, 'secret')

        with pytest.raises(TypeError):
            self.jwt.decode(token, 'secret', options=object())

        with pytest.raises(TypeError):
            self.jwt.decode(token, 'secret', options='something')

    def test_custom_json_encoder(self):

        class CustomJSONEncoder(json.JSONEncoder):

            def default(self, o):
                if isinstance(o, Decimal):
                    return 'it worked'
                return super(CustomJSONEncoder, self).default(o)

        data = {
            'some_decimal': Decimal('2.2')
        }

        with pytest.raises(TypeError):
            self.jwt.encode(data, 'secret')

        token = self.jwt.encode(data, 'secret', json_encoder=CustomJSONEncoder)
        payload = self.jwt.decode(token, 'secret')

        assert payload == {'some_decimal': 'it worked'}


    def test_encode_headers_parameter_adds_headers(self):
        headers = {'testheader': True}
        token = self.jwt.encode({'msg': 'hello world'}, 'secret', headers=headers)

        if not isinstance(token, string_types):
            token = token.decode()

        header = token[0:token.index('.')].encode()
        header = base64url_decode(header)

        if not isinstance(header, text_type):
            header = header.decode()

        header_obj = json.loads(header)

        assert 'testheader' in header_obj
        assert header_obj['testheader'] == headers['testheader']
