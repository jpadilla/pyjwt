import json

from .algorithms import get_default_algorithms
from .exceptions import PyJWKError, PyJWKSetError


class PyJWK:
    def __init__(self, jwk_data, algorithm=None):
        self._algorithms = get_default_algorithms()
        self._jwk_data = jwk_data

        if not algorithm and isinstance(self._jwk_data, dict):
            algorithm = self._jwk_data.get("alg", None)

        if not algorithm:
            raise PyJWKError("Unable to find a algorithm for key: %s" % self._jwk_data)

        self.Algorithm = self._algorithms.get(algorithm)

        if not self.Algorithm:
            raise PyJWKError("Unable to find a algorithm for key: %s" % self._jwk_data)

        self.key = self.Algorithm.from_jwk(self._jwk_data)

    @staticmethod
    def from_dict(obj, algorithm=None):
        return PyJWK(obj, algorithm)

    @staticmethod
    def from_json(data, algorithm=None):
        obj = json.loads(data)
        return PyJWK.from_dict(obj, algorithm)

    @property
    def key_type(self):
        return self._jwk_data.get("kty", None)

    @property
    def key_id(self):
        return self._jwk_data.get("kid", None)

    @property
    def public_key_use(self):
        return self._jwk_data.get("use", None)


class PyJWKSet:
    def __init__(self, keys):
        self.keys = []

        if not keys or not isinstance(keys, list):
            raise PyJWKSetError("Invalid JWK Set value")

        if len(keys) == 0:
            raise PyJWKSetError("The JWK Set did not contain any keys")

        for key in keys:
            self.keys.append(PyJWK(key))

    @staticmethod
    def from_dict(obj):
        keys = obj.get("keys", [])
        return PyJWKSet(keys)

    @staticmethod
    def from_json(data):
        obj = json.loads(data)
        return PyJWKSet.from_dict(obj)
