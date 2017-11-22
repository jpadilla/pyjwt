import json

from jwt import decode, encode
from jwt.api_jwk_set import PyJWKSet
from jwt.exceptions import (
    InvalidAlgorithmError, InvalidKeySetError, InvalidTokenError
)

import pytest

try:
    from .keys import load_rsa_pub_key
    has_crypto = True
except ImportError:
    has_crypto = False

from .keys import load_hmac_key
from .utils import key_path, utc_timestamp


@pytest.fixture
def jwks():
    with open(key_path('jwk_set.json'), 'r') as jwks_file:
        return PyJWKSet(key_set=jwks_file.read())


@pytest.fixture
def payload():
    """ Creates a sample JWT claimset for use as a payload during tests """
    return {
        'iss': 'jeff',
        'exp': utc_timestamp() + 15,
        'claim': 'insanity'
    }


class TestJWKSet:
    def test_dumps_jwk_set(self, jwks):
        assert 'keys' in json.loads(jwks.dump())

    def test_loads_jwk_set(self):
        jwks = PyJWKSet()
        with open(key_path('jwk_set.json'), 'r') as jwks_file:
            jwks.load(jwks_file.read())

        assert len(jwks._keys) == 2

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_jwk_set_adds_new_jwk(self, jwks):
        jwks.add_key(load_rsa_pub_key(), 'new_kid', algorithm='RS256')

        assert jwks.get_jwk('new_kid')

    def test_jwk_set_removes_jwk(self, jwks):
        jwks.remove_key('rsa_pub_1')

        try:
            jwk = jwks.get_jwk('rsa_pub_1')
        except InvalidKeySetError:
            pass
        else:
            assert not jwk

    def test_jwk_set_encodes_by_kid(self, jwks, payload):
        jwt = jwks.encode(payload, headers={'kid': 'hmac_1'})

        assert decode(jwt, load_hmac_key()) == payload

    def test_jwk_set_decodes_by_kid(self, jwks, payload):
        jwt = encode(payload, load_hmac_key(), headers={'kid': 'hmac_1'})

        assert jwks.decode(jwt, algorithms=['HS256']) == payload

    def test_jwk_set_get_non_existant_jwk(self, jwks):
        with pytest.raises(InvalidKeySetError):
            jwks.get_jwk('not_here')

    def test_jwk_encode_algorithm_mismatch(self, jwks, payload):
        with pytest.raises(InvalidAlgorithmError):
            jwks.encode(payload, algorithm='RS256', headers={'kid': 'hmac_1'})

    def test_jwk_decode_algorithms_missing(self, jwks, payload):
        with pytest.raises(TypeError):
            jwks.decode('foo', headers={'kid': 'rsa_pub_1'})

    def test_jwk_decode_kid_missing(self, jwks, payload):
        token = (
            b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9'
            b'.eyJpc3MiOiJqZWZmIiwiZXhwIjoxNTExMzYwODc5LCJjbGFpbSI6Imluc2FuaXR5In0'
            b'.FeQY_aWhriMjsCt7dDTtKqh83jpmEjJpvDtoCflD69M')

        with pytest.raises(InvalidTokenError):
            jwks.decode(token, algorithms=['HS256'], headers={'kid': 'hmac_1'})

    def test_jwk_decode_algorithm_tampered_with(self, jwks, payload):
        token = (
            b'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIiwia2lkIjoiaG1hY18xIn0='
            b'.eyJpc3MiOiJqZWZmIiwiZXhwIjoxNTExMzYwODc5LCJjbGFpbSI6Imluc2FuaXR5In0'
            b'.FeQY_aWhriMjsCt7dDTtKqh83jpmEjJpvDtoCflD69M')

        with pytest.raises(InvalidAlgorithmError):
            jwks.decode(token, algorithms=['RS256'], headers={'kid': 'rsa_pub_1'})
