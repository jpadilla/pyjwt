
import json
import time
from calendar import timegm
from datetime import datetime, timedelta
from decimal import Decimal

from jwt.api_jwt import PyJWT
from jwt.exceptions import (
    DecodeError, ExpiredSignatureError, ImmatureSignatureError,
    InvalidAudienceError, InvalidIssuedAtError, InvalidIssuerError,
    MissingRequiredClaimError
)

import pytest

from .test_api_jws import has_crypto
from .utils import utc_timestamp


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


class TestJWT:
    def test_decodes_valid_jwt(self, jwt):
        example_payload = {'hello': 'world'}
        example_secret = 'secret'
        example_jwt = (
            b'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9'
            b'.eyJoZWxsbyI6ICJ3b3JsZCJ9'
            b'.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8')
        decoded_payload = jwt.decode(example_jwt, example_secret)

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

    def test_decode_invalid_payload_string(self, jwt):
        example_jwt = (
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aGVsb'
            'G8gd29ybGQ.SIr03zM64awWRdPrAM_61QWsZchAtgDV'
            '3pphfHPPWkI')
        example_secret = 'secret'

        with pytest.raises(DecodeError) as exc:
            jwt.decode(example_jwt, example_secret)

        assert 'Invalid payload string' in str(exc.value)

    def test_decode_with_non_mapping_payload_throws_exception(self, jwt):
        secret = 'secret'
        example_jwt = ('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.'
                       'MQ.'  # == 1
                       'AbcSR3DWum91KOgfKxUHm78rLs_DrrZ1CrDgpUFFzls')

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
        assert str(exception) == 'audience must be a string, iterable, or None'

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

        with pytest.raises(InvalidIssuedAtError):
            jwt.decode(example_jwt, 'secret')

    def test_decode_raises_exception_if_nbf_is_not_int(self, jwt):
        # >>> jwt.encode({'nbf': 'not-an-int'}, 'secret')
        example_jwt = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
                       'eyJuYmYiOiJub3QtYW4taW50In0.'
                       'c25hldC8G2ZamC8uKpax9sYMTgdZo3cxrmzFHaAAluw')

        with pytest.raises(DecodeError):
            jwt.decode(example_jwt, 'secret')

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
            b'.AddMgkmRhzqptDYqlmy_f2dzM6O9YZmVo-txs_CeAJD'
            b'NoD8LN7YiPeLmtIhkO5_VZeHHKvtQcGc4lsq-Y72c4dK'
            b'pANr1f6HEYhjpBc03u_bv06PYMcr5N2-9k97-qf-JCSb'
            b'zqW6R250Q7gNCX5R7NrCl7MTM4DTBZkGbUlqsFUleiGlj')
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

    def test_check_audience_when_valid(self, jwt):
        payload = {
            'some': 'payload',
            'aud': 'urn:me'
        }
        token = jwt.encode(payload, 'secret')
        jwt.decode(token, 'secret', audience='urn:me')

    def test_check_audience_list_when_valid(self, jwt):
        payload = {
            'some': 'payload',
            'aud': 'urn:me'
        }
        token = jwt.encode(payload, 'secret')
        jwt.decode(token, 'secret', audience=['urn:you', 'urn:me'])

    def test_check_audience_none_specified(self, jwt):
        payload = {
            'some': 'payload',
            'aud': 'urn:me'
        }
        token = jwt.encode(payload, 'secret')
        with pytest.raises(InvalidAudienceError):
            jwt.decode(token, 'secret')

    def test_raise_exception_invalid_audience_list(self, jwt):
        payload = {
            'some': 'payload',
            'aud': 'urn:me'
        }
        token = jwt.encode(payload, 'secret')
        with pytest.raises(InvalidAudienceError):
            jwt.decode(token, 'secret', audience=['urn:you', 'urn:him'])

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

    def test_raise_exception_token_without_issuer(self, jwt):
        issuer = 'urn:wrong'

        payload = {
            'some': 'payload'
        }

        token = jwt.encode(payload, 'secret')

        with pytest.raises(MissingRequiredClaimError) as exc:
            jwt.decode(token, 'secret', issuer=issuer)

        assert exc.value.claim == 'iss'

    def test_raise_exception_token_without_audience(self, jwt):
        payload = {
            'some': 'payload',
        }
        token = jwt.encode(payload, 'secret')

        with pytest.raises(MissingRequiredClaimError) as exc:
            jwt.decode(token, 'secret', audience='urn:me')

        assert exc.value.claim == 'aud'

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

    def test_decode_should_raise_error_if_exp_required_but_not_present(self, jwt):
        payload = {
            'some': 'payload',
            # exp not present
        }
        token = jwt.encode(payload, 'secret')

        with pytest.raises(MissingRequiredClaimError) as exc:
            jwt.decode(token, 'secret', options={'require_exp': True})

        assert exc.value.claim == 'exp'

    def test_decode_should_raise_error_if_iat_required_but_not_present(self, jwt):
        payload = {
            'some': 'payload',
            # iat not present
        }
        token = jwt.encode(payload, 'secret')

        with pytest.raises(MissingRequiredClaimError) as exc:
            jwt.decode(token, 'secret', options={'require_iat': True})

        assert exc.value.claim == 'iat'

    def test_decode_should_raise_error_if_nbf_required_but_not_present(self, jwt):
        payload = {
            'some': 'payload',
            # nbf not present
        }
        token = jwt.encode(payload, 'secret')

        with pytest.raises(MissingRequiredClaimError) as exc:
            jwt.decode(token, 'secret', options={'require_nbf': True})

        assert exc.value.claim == 'nbf'

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

    def test_decode_with_verify_expiration_kwarg(self, jwt, payload):
        payload['exp'] = utc_timestamp() - 1
        secret = 'secret'
        jwt_message = jwt.encode(payload, secret)

        pytest.deprecated_call(
            jwt.decode,
            jwt_message,
            secret,
            verify_expiration=False
        )

        with pytest.raises(ExpiredSignatureError):
            pytest.deprecated_call(
                jwt.decode,
                jwt_message,
                secret,
                verify_expiration=True
            )

    def test_decode_with_optional_algorithms(self, jwt, payload):
        secret = 'secret'
        jwt_message = jwt.encode(payload, secret)

        pytest.deprecated_call(
            jwt.decode,
            jwt_message,
            secret
        )

    def test_decode_no_algorithms_verify_false(self, jwt, payload):
        secret = 'secret'
        jwt_message = jwt.encode(payload, secret)

        try:
            pytest.deprecated_call(
                jwt.decode, jwt_message, secret, verify=False,
            )
        except pytest.fail.Exception:
            pass
        else:
            assert False, "Unexpected DeprecationWarning raised."
