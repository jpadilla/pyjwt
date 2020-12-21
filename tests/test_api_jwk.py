import json

from jwt.algorithms import has_crypto
from jwt.api_jwk import PyJWK, PyJWKSet

from .utils import crypto_required, key_path

if has_crypto:
    from jwt.algorithms import RSAAlgorithm


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
