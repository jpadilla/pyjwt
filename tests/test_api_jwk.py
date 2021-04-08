import json

import pytest

from jwt.algorithms import has_crypto
from jwt.api_jwk import PyJWK, PyJWKSet
from jwt.exceptions import InvalidKeyError, PyJWKError

from .utils import crypto_required, key_path

if has_crypto:
    from jwt.algorithms import (
        ECAlgorithm,
        Ed25519Algorithm,
        HMACAlgorithm,
        RSAAlgorithm,
    )


class TestPyJWK:
    @crypto_required
    def test_should_load_key_from_jwk_data_dict(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        key_data_str = algo.to_jwk(pub_key)
        key_data = json.loads(key_data_str)

        # TODO Should `to_jwk` set these?
        key_data["alg"] = "RS256"
        key_data["use"] = "sig"
        key_data["kid"] = "keyid-abc123"

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "RSA"
        assert jwk.key_id == "keyid-abc123"
        assert jwk.public_key_use == "sig"

    @crypto_required
    def test_should_load_key_from_jwk_data_json_string(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        key_data_str = algo.to_jwk(pub_key)
        key_data = json.loads(key_data_str)

        # TODO Should `to_jwk` set these?
        key_data["alg"] = "RS256"
        key_data["use"] = "sig"
        key_data["kid"] = "keyid-abc123"

        jwk = PyJWK.from_json(json.dumps(key_data))

        assert jwk.key_type == "RSA"
        assert jwk.key_id == "keyid-abc123"
        assert jwk.public_key_use == "sig"

    @crypto_required
    def test_should_load_key_without_alg_from_dict(self):

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "RSA"
        assert isinstance(jwk.Algorithm, RSAAlgorithm)
        assert jwk.Algorithm.hash_alg == RSAAlgorithm.SHA256

    @crypto_required
    def test_should_load_key_from_dict_with_algorithm(self):

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data, algorithm="RS256")

        assert jwk.key_type == "RSA"
        assert isinstance(jwk.Algorithm, RSAAlgorithm)
        assert jwk.Algorithm.hash_alg == RSAAlgorithm.SHA256

    @crypto_required
    def test_should_load_key_ec_p256_from_dict(self):

        with open(key_path("jwk_ec_pub_P-256.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "EC"
        assert isinstance(jwk.Algorithm, ECAlgorithm)
        assert jwk.Algorithm.hash_alg == ECAlgorithm.SHA256

    @crypto_required
    def test_should_load_key_ec_p384_from_dict(self):

        with open(key_path("jwk_ec_pub_P-384.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "EC"
        assert isinstance(jwk.Algorithm, ECAlgorithm)
        assert jwk.Algorithm.hash_alg == ECAlgorithm.SHA384

    @crypto_required
    def test_should_load_key_ec_p521_from_dict(self):

        with open(key_path("jwk_ec_pub_P-521.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "EC"
        assert isinstance(jwk.Algorithm, ECAlgorithm)
        assert jwk.Algorithm.hash_alg == ECAlgorithm.SHA512

    @crypto_required
    def test_should_load_key_ec_secp256k1_from_dict(self):

        with open(key_path("jwk_ec_pub_secp256k1.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "EC"
        assert isinstance(jwk.Algorithm, ECAlgorithm)
        assert jwk.Algorithm.hash_alg == ECAlgorithm.SHA256

    @crypto_required
    def test_should_load_key_hmac_from_dict(self):

        with open(key_path("jwk_hmac.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "oct"
        assert isinstance(jwk.Algorithm, HMACAlgorithm)
        assert jwk.Algorithm.hash_alg == HMACAlgorithm.SHA256

    @crypto_required
    def test_should_load_key_hmac_without_alg_from_dict(self):

        with open(key_path("jwk_hmac.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        del key_data["alg"]
        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "oct"
        assert isinstance(jwk.Algorithm, HMACAlgorithm)
        assert jwk.Algorithm.hash_alg == HMACAlgorithm.SHA256

    @crypto_required
    def test_should_load_key_okp_without_alg_from_dict(self):

        with open(key_path("jwk_okp_pub_Ed25519.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "OKP"
        assert isinstance(jwk.Algorithm, Ed25519Algorithm)

    @crypto_required
    def test_from_dict_should_throw_exception_if_arg_is_invalid(self):

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            valid_rsa_pub = json.loads(keyfile.read())
        with open(key_path("jwk_ec_pub_P-256.json")) as keyfile:
            valid_ec_pub = json.loads(keyfile.read())
        with open(key_path("jwk_okp_pub_Ed25519.json")) as keyfile:
            valid_okp_pub = json.loads(keyfile.read())

        # Unknown algorithm
        with pytest.raises(PyJWKError):
            PyJWK.from_dict(valid_rsa_pub, algorithm="unknown")

        # Missing kty
        v = valid_rsa_pub.copy()
        del v["kty"]
        with pytest.raises(InvalidKeyError):
            PyJWK.from_dict(v)

        # Unknown kty
        v = valid_rsa_pub.copy()
        v["kty"] = "unknown"
        with pytest.raises(InvalidKeyError):
            PyJWK.from_dict(v)

        # Unknown EC crv
        v = valid_ec_pub.copy()
        v["crv"] = "unknown"
        with pytest.raises(InvalidKeyError):
            PyJWK.from_dict(v)

        # Unknown OKP crv
        v = valid_okp_pub.copy()
        v["crv"] = "unknown"
        with pytest.raises(InvalidKeyError):
            PyJWK.from_dict(v)

        # Missing OKP crv
        v = valid_okp_pub.copy()
        del v["crv"]
        with pytest.raises(InvalidKeyError):
            PyJWK.from_dict(v)


class TestPyJWKSet:
    @crypto_required
    def test_should_load_keys_from_jwk_data_dict(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        key_data_str = algo.to_jwk(pub_key)
        key_data = json.loads(key_data_str)

        # TODO Should `to_jwk` set these?
        key_data["alg"] = "RS256"
        key_data["use"] = "sig"
        key_data["kid"] = "keyid-abc123"

        jwk_set = PyJWKSet.from_dict({"keys": [key_data]})
        jwk = jwk_set.keys[0]

        assert jwk.key_type == "RSA"
        assert jwk.key_id == "keyid-abc123"
        assert jwk.public_key_use == "sig"

    @crypto_required
    def test_should_load_keys_from_jwk_data_json_string(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        key_data_str = algo.to_jwk(pub_key)
        key_data = json.loads(key_data_str)

        # TODO Should `to_jwk` set these?
        key_data["alg"] = "RS256"
        key_data["use"] = "sig"
        key_data["kid"] = "keyid-abc123"

        jwk_set = PyJWKSet.from_json(json.dumps({"keys": [key_data]}))
        jwk = jwk_set.keys[0]

        assert jwk.key_type == "RSA"
        assert jwk.key_id == "keyid-abc123"
        assert jwk.public_key_use == "sig"
