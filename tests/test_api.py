
import json
import time

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

from .compat import string_types, text_type
from .utils import ensure_bytes, utc_timestamp

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key, load_pem_public_key, load_ssh_public_key
    )

    has_crypto = True
except ImportError:
    has_crypto = False


@pytest.fixture
def jwt():
    return PyJWT()


@pytest.fixture
def payload():
    """ Creates a sample JWT claimset for use as a payload during tests """
    return {
        'iss': 'jeff',
        'exp': utc_timestamp() + 15,
        'claim': 'insanity'
    }


class TestAPI:
    def test_register_algorithm_does_not_allow_duplicate_registration(self, jwt):
        jwt.register_algorithm('AAA', Algorithm())

        with pytest.raises(ValueError):
            jwt.register_algorithm('AAA', Algorithm())

    def test_register_algorithm_rejects_non_algorithm_obj(self, jwt):
        with pytest.raises(TypeError):
            jwt.register_algorithm('AAA123', {})

    def test_unregister_algorithm_removes_algorithm(self, jwt):
        supported = jwt.get_algorithms()
        assert 'none' in supported
        assert 'HS256' in supported

        jwt.unregister_algorithm('HS256')

        supported = jwt.get_algorithms()
        assert 'HS256' not in supported

    def test_unregister_algorithm_throws_error_if_not_registered(self, jwt):
        with pytest.raises(KeyError):
            jwt.unregister_algorithm('AAA')

    def test_algorithms_parameter_removes_alg_from_algorithms_list(self, jwt):
        assert 'none' in jwt.get_algorithms()
        assert 'HS256' in jwt.get_algorithms()

        jwt = PyJWT(algorithms=['HS256'])
        assert 'none' not in jwt.get_algorithms()
        assert 'HS256' in jwt.get_algorithms()

    def test_override_options(self):
        jwt = PyJWT(options={'verify_exp': False, 'verify_nbf': False})

        assert not jwt.options['verify_exp']
        assert not jwt.options['verify_nbf']

    def test_non_object_options_dont_persist(self, jwt):
        token = jwt.encode({'hello': 'world'}, 'secret')

        jwt.decode(token, 'secret', options={'verify_iat': False})

        assert jwt.options['verify_iat']

    def test_options_must_be_dict(self, jwt):
        pytest.raises(TypeError, PyJWT, options=object())
        pytest.raises(TypeError, PyJWT, options=('something'))

    def test_encode_decode(self, jwt, payload):
        secret = 'secret'
        jwt_message = jwt.encode(payload, secret)
        decoded_payload = jwt.decode(jwt_message, secret)

        assert decoded_payload == payload

    def test_decode_fails_when_alg_is_not_on_method_algorithms_param(self, jwt, payload):
        secret = 'secret'
        jwt_token = jwt.encode(payload, secret, algorithm='HS256')
        jwt.decode(jwt_token, secret)

        with pytest.raises(InvalidAlgorithmError):
            jwt.decode(jwt_token, secret, algorithms=['HS384'])

    def test_decode_works_with_unicode_token(self, jwt):
        secret = 'secret'
        unicode_jwt = text_type(
            'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')

        jwt.decode(unicode_jwt, secret)

    def test_decode_missing_segments_throws_exception(self, jwt):
        secret = 'secret'
        example_jwt = ('eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
                       '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
                       '')  # Missing segment

        with pytest.raises(DecodeError) as context:
            jwt.decode(example_jwt, secret)

        exception = context.value
        assert str(exception) == 'Not enough segments'

    def test_decode_with_non_mapping_header_throws_exception(self, jwt):
        secret = 'secret'
        example_jwt = ('MQ'  # == 1
                       '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
                       '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')

        with pytest.raises(DecodeError) as context:
            jwt.decode(example_jwt, secret)

        exception = context.value
        assert str(exception) == 'Invalid header string: must be a json object'

    def test_decode_with_non_mapping_payload_throws_exception(self, jwt):
        secret = 'secret'
        example_jwt = ('eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
                       '.MQ'  # == 1
                       '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')

        with pytest.raises(DecodeError) as context:
            jwt.decode(example_jwt, secret)

        exception = context.value
        assert str(exception) == 'Invalid payload string: must be a json object'

    def test_decode_with_invalid_audience_param_throws_exception(self, jwt):
        secret = 'secret'
        example_jwt = ('eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
                       '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
                       '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')

        with pytest.raises(TypeError) as context:
            jwt.decode(example_jwt, secret, audience=1)

        exception = context.value
        assert str(exception) == 'audience must be a string or None'

    def test_decode_with_nonlist_aud_claim_throws_exception(self, jwt):
        secret = 'secret'
        example_jwt = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
                       '.eyJoZWxsbyI6IndvcmxkIiwiYXVkIjoxfQ'  # aud = 1
                       '.Rof08LBSwbm8Z_bhA2N3DFY-utZR1Gi9rbIS5Zthnnc')

        with pytest.raises(InvalidAudienceError) as context:
            jwt.decode(example_jwt, secret, audience='my_audience')

        exception = context.value
        assert str(exception) == 'Invalid claim format in token'

    def test_decode_with_invalid_aud_list_member_throws_exception(self, jwt):
        secret = 'secret'
        example_jwt = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
                       '.eyJoZWxsbyI6IndvcmxkIiwiYXVkIjpbMV19'
                       '.iQgKpJ8shetwNMIosNXWBPFB057c2BHs-8t1d2CCM2A')

        with pytest.raises(InvalidAudienceError) as context:
            jwt.decode(example_jwt, secret, audience='my_audience')

        exception = context.value
        assert str(exception) == 'Invalid claim format in token'

    def test_encode_bad_type(self, jwt):

        types = ['string', tuple(), list(), 42, set()]

        for t in types:
            pytest.raises(TypeError, lambda: jwt.encode(t, 'secret'))

    def test_encode_algorithm_param_should_be_case_sensitive(self, jwt):
        payload = {'hello': 'world'}

        jwt.encode(payload, 'secret', algorithm='HS256')

        with pytest.raises(NotImplementedError) as context:
            jwt.encode(payload, None, algorithm='hs256')

        exception = context.value
        assert str(exception) == 'Algorithm not supported'

    def test_decode_algorithm_param_should_be_case_sensitive(self, jwt):
        example_jwt = ('eyJhbGciOiJoczI1NiIsInR5cCI6IkpXVCJ9'  # alg = hs256
                       '.eyJoZWxsbyI6IndvcmxkIn0'
                       '.5R_FEPE7SW2dT9GgIxPgZATjFGXfUDOSwo7TtO_Kd_g')

        with pytest.raises(InvalidAlgorithmError) as context:
            jwt.decode(example_jwt, 'secret')

        exception = context.value
        assert str(exception) == 'Algorithm not supported'

    def test_decode_raises_exception_if_exp_is_not_int(self, jwt):
        # >>> jwt.encode({'exp': 'not-an-int'}, 'secret')
        example_jwt = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
                       'eyJleHAiOiJub3QtYW4taW50In0.'
                       'P65iYgoHtBqB07PMtBSuKNUEIPPPfmjfJG217cEE66s')

        with pytest.raises(DecodeError) as exc:
            jwt.decode(example_jwt, 'secret')

        assert 'exp' in str(exc.value)

    def test_decode_raises_exception_if_iat_is_not_int(self, jwt):
        # >>> jwt.encode({'iat': 'not-an-int'}, 'secret')
        example_jwt = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
                       'eyJpYXQiOiJub3QtYW4taW50In0.'
                       'H1GmcQgSySa5LOKYbzGm--b1OmRbHFkyk8pq811FzZM')

        with pytest.raises(DecodeError):
            jwt.decode(example_jwt, 'secret')

    def test_decode_raises_exception_if_nbf_is_not_int(self, jwt):
        # >>> jwt.encode({'nbf': 'not-an-int'}, 'secret')
        example_jwt = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
                       'eyJuYmYiOiJub3QtYW4taW50In0.'
                       'c25hldC8G2ZamC8uKpax9sYMTgdZo3cxrmzFHaAAluw')

        with pytest.raises(DecodeError):
            jwt.decode(example_jwt, 'secret')

    def test_decode_raises_exception_if_iat_in_the_future(self, jwt):
        now = datetime.utcnow()
        token = jwt.encode({'iat': now + timedelta(days=1)}, key='secret')

        with pytest.raises(InvalidIssuedAtError):
            jwt.decode(token, 'secret')

    def test_encode_datetime(self, jwt):
        secret = 'secret'
        current_datetime = datetime.utcnow()
        payload = {
            'exp': current_datetime,
            'iat': current_datetime,
            'nbf': current_datetime
        }
        jwt_message = jwt.encode(payload, secret)
        decoded_payload = jwt.decode(jwt_message, secret, leeway=1)

        assert (decoded_payload['exp'] ==
                timegm(current_datetime.utctimetuple()))
        assert (decoded_payload['iat'] ==
                timegm(current_datetime.utctimetuple()))
        assert (decoded_payload['nbf'] ==
                timegm(current_datetime.utctimetuple()))

    def test_bad_secret(self, jwt, payload):
        right_secret = 'foo'
        bad_secret = 'bar'
        jwt_message = jwt.encode(payload, right_secret)

        with pytest.raises(DecodeError):
            jwt.decode(jwt_message, bad_secret)

    def test_decodes_valid_jwt(self, jwt):
        example_payload = {'hello': 'world'}
        example_secret = 'secret'
        example_jwt = (
            b'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            b'.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            b'.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        decoded_payload = jwt.decode(example_jwt, example_secret)

        assert decoded_payload == example_payload

    # 'Control' Elliptic Curve JWT created by another library.
    # Used to test for regressions that could affect both
    # encoding / decoding operations equally (causing tests
    # to still pass).
    @pytest.mark.skipif(not has_crypto, reason="Can't run without cryptography library")
    def test_decodes_valid_es384_jwt(self, jwt):
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
        decoded_payload = jwt.decode(example_jwt, example_pubkey)

        assert decoded_payload == example_payload

    # 'Control' RSA JWT created by another library.
    # Used to test for regressions that could affect both
    # encoding / decoding operations equally (causing tests
    # to still pass).
    @pytest.mark.skipif(not has_crypto, reason="Can't run without cryptography library")
    def test_decodes_valid_rs384_jwt(self, jwt):
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
        decoded_payload = jwt.decode(example_jwt, example_pubkey)

        assert decoded_payload == example_payload

    def test_load_verify_valid_jwt(self, jwt):
        example_payload = {'hello': 'world'}
        example_secret = 'secret'
        example_jwt = (
            b'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            b'.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            b'.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')

        decoded_payload = jwt.decode(example_jwt, key=example_secret)

        assert decoded_payload == example_payload

    def test_allow_skip_verification(self, jwt, payload):
        right_secret = 'foo'
        jwt_message = jwt.encode(payload, right_secret)
        decoded_payload = jwt.decode(jwt_message, verify=False)

        assert decoded_payload == payload

    def test_verify_false_deprecated(self, jwt, recwarn):
        example_jwt = (
            b'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            b'.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            b'.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')

        pytest.deprecated_call(jwt.decode, example_jwt, verify=False)

    def test_load_no_verification(self, jwt, payload):
        right_secret = 'foo'
        jwt_message = jwt.encode(payload, right_secret)

        decoded_payload = jwt.decode(jwt_message, key=None, verify=False)

        assert decoded_payload == payload

    def test_no_secret(self, jwt, payload):
        right_secret = 'foo'
        jwt_message = jwt.encode(payload, right_secret)

        with pytest.raises(DecodeError):
            jwt.decode(jwt_message)

    def test_verify_signature_with_no_secret(self, jwt, payload):
        right_secret = 'foo'
        jwt_message = jwt.encode(payload, right_secret)

        with pytest.raises(DecodeError) as exc:
            jwt.decode(jwt_message)

        assert 'Signature verification' in str(exc.value)

    def test_invalid_crypto_alg(self, jwt, payload):
        with pytest.raises(NotImplementedError):
            jwt.encode(payload, 'secret', algorithm='HS1024')

    def test_unicode_secret(self, jwt, payload):
        secret = '\xc2'
        jwt_message = jwt.encode(payload, secret)
        decoded_payload = jwt.decode(jwt_message, secret)

        assert decoded_payload == payload

    def test_nonascii_secret(self, jwt, payload):
        secret = '\xc2'  # char value that ascii codec cannot decode
        jwt_message = jwt.encode(payload, secret)

        decoded_payload = jwt.decode(jwt_message, secret)

        assert decoded_payload == payload

    def test_bytes_secret(self, jwt, payload):
        secret = b'\xc2'  # char value that ascii codec cannot decode
        jwt_message = jwt.encode(payload, secret)

        decoded_payload = jwt.decode(jwt_message, secret)

        assert decoded_payload == payload

    def test_decode_unicode_value(self, jwt):
        example_payload = {'hello': 'world'}
        example_secret = 'secret'
        example_jwt = (
            'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        decoded_payload = jwt.decode(example_jwt, example_secret)

        assert decoded_payload == example_payload

    def test_decode_invalid_header_padding(self, jwt):
        example_jwt = (
            'aeyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        example_secret = 'secret'

        with pytest.raises(DecodeError) as exc:
            jwt.decode(example_jwt, example_secret)

        assert 'header padding' in str(exc.value)

    def test_decode_invalid_header_string(self, jwt):
        example_jwt = (
            'eyJhbGciOiAiSFMyNTbpIiwgInR5cCI6ICJKV1QifQ=='
            '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        example_secret = 'secret'

        with pytest.raises(DecodeError) as exc:
            jwt.decode(example_jwt, example_secret)

        assert 'Invalid header' in str(exc.value)

    def test_decode_invalid_payload_padding(self, jwt):
        example_jwt = (
            'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            '.aeyJoZWxsbyI6ICJ3b3JsZCJ9'
            '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        example_secret = 'secret'

        with pytest.raises(DecodeError) as exc:
            jwt.decode(example_jwt, example_secret)

        assert 'Invalid payload padding' in str(exc.value)

    def test_decode_invalid_payload_string(self, jwt):
        example_jwt = (
            'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            '.eyJoZWxsb-kiOiAid29ybGQifQ=='
            '.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        example_secret = 'secret'

        with pytest.raises(DecodeError) as exc:
            jwt.decode(example_jwt, example_secret)

        assert 'Invalid payload string' in str(exc.value)

    def test_decode_invalid_crypto_padding(self, jwt):
        example_jwt = (
            'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            '.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            '.aatvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        example_secret = 'secret'

        with pytest.raises(DecodeError) as exc:
            jwt.decode(example_jwt, example_secret)

        assert 'Invalid crypto padding' in str(exc.value)

    def test_decode_with_expiration(self, jwt, payload):
        payload['exp'] = utc_timestamp() - 1
        secret = 'secret'
        jwt_message = jwt.encode(payload, secret)

        with pytest.raises(ExpiredSignatureError):
            jwt.decode(jwt_message, secret)

    def test_decode_with_notbefore(self, jwt, payload):
        payload['nbf'] = utc_timestamp() + 10
        secret = 'secret'
        jwt_message = jwt.encode(payload, secret)

        with pytest.raises(ImmatureSignatureError):
            jwt.decode(jwt_message, secret)

    def test_decode_skip_expiration_verification(self, jwt, payload):
        payload['exp'] = time.time() - 1
        secret = 'secret'
        jwt_message = jwt.encode(payload, secret)

        jwt.decode(jwt_message, secret, options={'verify_exp': False})

    def test_decode_skip_notbefore_verification(self, jwt, payload):
        payload['nbf'] = time.time() + 10
        secret = 'secret'
        jwt_message = jwt.encode(payload, secret)

        jwt.decode(jwt_message, secret, options={'verify_nbf': False})

    def test_decode_with_expiration_with_leeway(self, jwt, payload):
        payload['exp'] = utc_timestamp() - 2
        secret = 'secret'
        jwt_message = jwt.encode(payload, secret)

        decoded_payload, signing, header, signature = jwt._load(jwt_message)

        # With 3 seconds leeway, should be ok
        for leeway in (3, timedelta(seconds=3)):
            jwt.decode(jwt_message, secret, leeway=leeway)

        # With 1 seconds, should fail
        for leeway in (1, timedelta(seconds=1)):
            with pytest.raises(ExpiredSignatureError):
                jwt.decode(jwt_message, secret, leeway=leeway)

    def test_decode_with_notbefore_with_leeway(self, jwt, payload):
        payload['nbf'] = utc_timestamp() + 10
        secret = 'secret'
        jwt_message = jwt.encode(payload, secret)

        # With 13 seconds leeway, should be ok
        jwt.decode(jwt_message, secret, leeway=13)

        with pytest.raises(ImmatureSignatureError):
            jwt.decode(jwt_message, secret, leeway=1)

    def test_decode_with_algo_none_should_fail(self, jwt, payload):
        jwt_message = jwt.encode(payload, key=None, algorithm=None)

        with pytest.raises(DecodeError):
            jwt.decode(jwt_message)

    def test_decode_with_algo_none_and_verify_false_should_pass(self, jwt, payload):
        jwt_message = jwt.encode(payload, key=None, algorithm=None)
        jwt.decode(jwt_message, verify=False)

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_encode_decode_with_rsa_sha256(self, jwt, payload):
        # PEM-formatted RSA key
        with open('tests/keys/testkey_rsa', 'r') as rsa_priv_file:
            priv_rsakey = load_pem_private_key(ensure_bytes(rsa_priv_file.read()),
                                               password=None, backend=default_backend())
            jwt_message = jwt.encode(payload, priv_rsakey, algorithm='RS256')

        with open('tests/keys/testkey_rsa.pub', 'r') as rsa_pub_file:
            pub_rsakey = load_ssh_public_key(ensure_bytes(rsa_pub_file.read()),
                                             backend=default_backend())

            jwt.decode(jwt_message, pub_rsakey)

        # string-formatted key
        with open('tests/keys/testkey_rsa', 'r') as rsa_priv_file:
            priv_rsakey = rsa_priv_file.read()
            jwt_message = jwt.encode(payload, priv_rsakey, algorithm='RS256')

        with open('tests/keys/testkey_rsa.pub', 'r') as rsa_pub_file:
            pub_rsakey = rsa_pub_file.read()
            jwt.decode(jwt_message, pub_rsakey)

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_encode_decode_with_rsa_sha384(self, jwt, payload):
        # PEM-formatted RSA key
        with open('tests/keys/testkey_rsa', 'r') as rsa_priv_file:
            priv_rsakey = load_pem_private_key(ensure_bytes(rsa_priv_file.read()),
                                               password=None, backend=default_backend())
            jwt_message = jwt.encode(payload, priv_rsakey, algorithm='RS384')

        with open('tests/keys/testkey_rsa.pub', 'r') as rsa_pub_file:
            pub_rsakey = load_ssh_public_key(ensure_bytes(rsa_pub_file.read()),
                                             backend=default_backend())
            jwt.decode(jwt_message, pub_rsakey)

        # string-formatted key
        with open('tests/keys/testkey_rsa', 'r') as rsa_priv_file:
            priv_rsakey = rsa_priv_file.read()
            jwt_message = jwt.encode(payload, priv_rsakey, algorithm='RS384')

        with open('tests/keys/testkey_rsa.pub', 'r') as rsa_pub_file:
            pub_rsakey = rsa_pub_file.read()
            jwt.decode(jwt_message, pub_rsakey)

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_encode_decode_with_rsa_sha512(self, jwt, payload):
        # PEM-formatted RSA key
        with open('tests/keys/testkey_rsa', 'r') as rsa_priv_file:
            priv_rsakey = load_pem_private_key(ensure_bytes(rsa_priv_file.read()),
                                               password=None, backend=default_backend())
            jwt_message = jwt.encode(payload, priv_rsakey, algorithm='RS512')

        with open('tests/keys/testkey_rsa.pub', 'r') as rsa_pub_file:
            pub_rsakey = load_ssh_public_key(ensure_bytes(rsa_pub_file.read()),
                                             backend=default_backend())
            jwt.decode(jwt_message, pub_rsakey)

        # string-formatted key
        with open('tests/keys/testkey_rsa', 'r') as rsa_priv_file:
            priv_rsakey = rsa_priv_file.read()
            jwt_message = jwt.encode(payload, priv_rsakey, algorithm='RS512')

        with open('tests/keys/testkey_rsa.pub', 'r') as rsa_pub_file:
            pub_rsakey = rsa_pub_file.read()
            jwt.decode(jwt_message, pub_rsakey)

    def test_rsa_related_algorithms(self, jwt):
        jwt = PyJWT()
        jwt_algorithms = jwt.get_algorithms()

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
    def test_encode_decode_with_ecdsa_sha256(self, jwt, payload):
        # PEM-formatted EC key
        with open('tests/keys/testkey_ec', 'r') as ec_priv_file:
            priv_eckey = load_pem_private_key(ensure_bytes(ec_priv_file.read()),
                                              password=None, backend=default_backend())
            jwt_message = jwt.encode(payload, priv_eckey, algorithm='ES256')

        with open('tests/keys/testkey_ec.pub', 'r') as ec_pub_file:
            pub_eckey = load_pem_public_key(ensure_bytes(ec_pub_file.read()),
                                            backend=default_backend())
            jwt.decode(jwt_message, pub_eckey)

        # string-formatted key
        with open('tests/keys/testkey_ec', 'r') as ec_priv_file:
            priv_eckey = ec_priv_file.read()
            jwt_message = jwt.encode(payload, priv_eckey, algorithm='ES256')

        with open('tests/keys/testkey_ec.pub', 'r') as ec_pub_file:
            pub_eckey = ec_pub_file.read()
            jwt.decode(jwt_message, pub_eckey)

    @pytest.mark.skipif(not has_crypto, reason="Can't run without cryptography library")
    def test_encode_decode_with_ecdsa_sha384(self, jwt, payload):

        # PEM-formatted EC key
        with open('tests/keys/testkey_ec', 'r') as ec_priv_file:
            priv_eckey = load_pem_private_key(ensure_bytes(ec_priv_file.read()),
                                              password=None, backend=default_backend())
            jwt_message = jwt.encode(payload, priv_eckey, algorithm='ES384')

        with open('tests/keys/testkey_ec.pub', 'r') as ec_pub_file:
            pub_eckey = load_pem_public_key(ensure_bytes(ec_pub_file.read()),
                                            backend=default_backend())
            jwt.decode(jwt_message, pub_eckey)

        # string-formatted key
        with open('tests/keys/testkey_ec', 'r') as ec_priv_file:
            priv_eckey = ec_priv_file.read()
            jwt_message = jwt.encode(payload, priv_eckey, algorithm='ES384')

        with open('tests/keys/testkey_ec.pub', 'r') as ec_pub_file:
            pub_eckey = ec_pub_file.read()
            jwt.decode(jwt_message, pub_eckey)

    @pytest.mark.skipif(not has_crypto, reason="Can't run without cryptography library")
    def test_encode_decode_with_ecdsa_sha512(self, jwt, payload):
        # PEM-formatted EC key
        with open('tests/keys/testkey_ec', 'r') as ec_priv_file:
            priv_eckey = load_pem_private_key(ensure_bytes(ec_priv_file.read()),
                                              password=None, backend=default_backend())
            jwt_message = jwt.encode(payload, priv_eckey, algorithm='ES512')

        with open('tests/keys/testkey_ec.pub', 'r') as ec_pub_file:
            pub_eckey = load_pem_public_key(ensure_bytes(ec_pub_file.read()), backend=default_backend())
            jwt.decode(jwt_message, pub_eckey)

        # string-formatted key
        with open('tests/keys/testkey_ec', 'r') as ec_priv_file:
            priv_eckey = ec_priv_file.read()
            jwt_message = jwt.encode(payload, priv_eckey, algorithm='ES512')

        with open('tests/keys/testkey_ec.pub', 'r') as ec_pub_file:
            pub_eckey = ec_pub_file.read()
            jwt.decode(jwt_message, pub_eckey)

    def test_ecdsa_related_algorithms(self, jwt):
        jwt = PyJWT()
        jwt_algorithms = jwt.get_algorithms()

        if has_crypto:
            assert 'ES256' in jwt_algorithms
            assert 'ES384' in jwt_algorithms
            assert 'ES512' in jwt_algorithms
        else:
            assert 'ES256' not in jwt_algorithms
            assert 'ES384' not in jwt_algorithms
            assert 'ES512' not in jwt_algorithms

    def test_check_audience_when_valid(self, jwt):
        payload = {
            'some': 'payload',
            'aud': 'urn:me'
        }
        token = jwt.encode(payload, 'secret')
        jwt.decode(token, 'secret', audience='urn:me')

    def test_check_audience_in_array_when_valid(self, jwt):
        payload = {
            'some': 'payload',
            'aud': ['urn:me', 'urn:someone-else']
        }
        token = jwt.encode(payload, 'secret')
        jwt.decode(token, 'secret', audience='urn:me')

    def test_raise_exception_invalid_audience(self, jwt):
        payload = {
            'some': 'payload',
            'aud': 'urn:someone-else'
        }

        token = jwt.encode(payload, 'secret')

        with pytest.raises(InvalidAudienceError):
            jwt.decode(token, 'secret', audience='urn-me')

    def test_raise_exception_invalid_audience_in_array(self, jwt):
        payload = {
            'some': 'payload',
            'aud': ['urn:someone', 'urn:someone-else']
        }

        token = jwt.encode(payload, 'secret')

        with pytest.raises(InvalidAudienceError):
            jwt.decode(token, 'secret', audience='urn:me')

    def test_raise_exception_token_without_audience(self, jwt):
        payload = {
            'some': 'payload',
        }
        token = jwt.encode(payload, 'secret')

        with pytest.raises(InvalidAudienceError):
            jwt.decode(token, 'secret', audience='urn:me')

    def test_check_issuer_when_valid(self, jwt):
        issuer = 'urn:foo'
        payload = {
            'some': 'payload',
            'iss': 'urn:foo'
        }
        token = jwt.encode(payload, 'secret')
        jwt.decode(token, 'secret', issuer=issuer)

    def test_raise_exception_invalid_issuer(self, jwt):
        issuer = 'urn:wrong'

        payload = {
            'some': 'payload',
            'iss': 'urn:foo'
        }

        token = jwt.encode(payload, 'secret')

        with pytest.raises(InvalidIssuerError):
            jwt.decode(token, 'secret', issuer=issuer)

    def test_raise_exception_token_without_issuer(self, jwt):
        issuer = 'urn:wrong'

        payload = {
            'some': 'payload',
        }

        token = jwt.encode(payload, 'secret')

        with pytest.raises(InvalidIssuerError):
            jwt.decode(token, 'secret', issuer=issuer)

    def test_skip_check_audience(self, jwt):
        payload = {
            'some': 'payload',
            'aud': 'urn:me',
        }
        token = jwt.encode(payload, 'secret')
        jwt.decode(token, 'secret', options={'verify_aud': False})

    def test_skip_check_exp(self, jwt):
        payload = {
            'some': 'payload',
            'exp': datetime.utcnow() - timedelta(days=1)
        }
        token = jwt.encode(payload, 'secret')
        jwt.decode(token, 'secret', options={'verify_exp': False})

    def test_skip_check_signature(self, jwt):
        token = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                 ".eyJzb21lIjoicGF5bG9hZCJ9"
                 ".4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZA")
        jwt.decode(token, 'secret', options={'verify_signature': False})

    def test_skip_check_iat(self, jwt):
        payload = {
            'some': 'payload',
            'iat': datetime.utcnow() + timedelta(days=1)
        }
        token = jwt.encode(payload, 'secret')
        jwt.decode(token, 'secret', options={'verify_iat': False})

    def test_skip_check_nbf(self, jwt):
        payload = {
            'some': 'payload',
            'nbf': datetime.utcnow() + timedelta(days=1)
        }
        token = jwt.encode(payload, 'secret')
        jwt.decode(token, 'secret', options={'verify_nbf': False})

    def test_decode_options_must_be_dict(self, jwt):
        payload = {
            'some': 'payload',
        }
        token = jwt.encode(payload, 'secret')

        with pytest.raises(TypeError):
            jwt.decode(token, 'secret', options=object())

        with pytest.raises(TypeError):
            jwt.decode(token, 'secret', options='something')

    def test_custom_json_encoder(self, jwt):

        class CustomJSONEncoder(json.JSONEncoder):

            def default(self, o):
                if isinstance(o, Decimal):
                    return 'it worked'
                return super(CustomJSONEncoder, self).default(o)

        data = {
            'some_decimal': Decimal('2.2')
        }

        with pytest.raises(TypeError):
            jwt.encode(data, 'secret')

        token = jwt.encode(data, 'secret', json_encoder=CustomJSONEncoder)
        payload = jwt.decode(token, 'secret')

        assert payload == {'some_decimal': 'it worked'}

    def test_encode_headers_parameter_adds_headers(self, jwt):
        headers = {'testheader': True}
        token = jwt.encode({'msg': 'hello world'}, 'secret', headers=headers)

        if not isinstance(token, string_types):
            token = token.decode()

        header = token[0:token.index('.')].encode()
        header = base64url_decode(header)

        if not isinstance(header, text_type):
            header = header.decode()

        header_obj = json.loads(header)

        assert 'testheader' in header_obj
        assert header_obj['testheader'] == headers['testheader']
