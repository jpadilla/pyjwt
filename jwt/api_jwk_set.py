import json

from .api_jwt import PyJWT, get_unverified_header
from .algorithms import Algorithm, get_default_algorithms  # NOQA
from .exceptions import (
    InvalidAlgorithmError, InvalidKeySetError, InvalidTokenError
)


class PyJWKSet(PyJWT):
    def __init__(self, key_set=None, **kwargs):
        super(PyJWKSet, self).__init__(**kwargs)

        self._keys = []

        if key_set:
            self.load(key_set)

    def load(self, key_set):
        try:
            obj = json.loads(key_set)
        except ValueError:
            raise InvalidKeySetError('Key Set is not valid JSON')

        self._keys = obj.get('keys', [])

    def dump(self, **kwargs):
        return json.dumps({'keys': self._keys}, **kwargs)

    def get_key(self, jwk, algorithm='none'):
        algo_obj = self.get_algorithm(algorithm)
        return algo_obj.from_jwk(json.dumps(jwk))

    def get_jwk(self, kid):
        for jwk in self._keys:
            if jwk['kid'] == kid:
                return jwk

        raise InvalidKeySetError("There is no JWK matching this Key ID.")

    def add_key(self, key_obj, kid, algorithm):
        alg_obj = self.get_algorithm(algorithm)

        jwk = json.loads(alg_obj.to_jwk(key_obj, kid))
        jwk['alg'] = algorithm

        self._keys.append(jwk)

    def remove_key(self, kid):
        self._keys = [key for key in self._keys if key['kid'] != kid]

    def encode(self, payload, headers, algorithm=None, **kwargs):
        if 'kid' not in headers:
            raise InvalidTokenError('Key ID header parameter is missing')

        jwk = self.get_jwk(headers['kid'])

        alg = jwk.get('alg')

        if alg is not None:
            if algorithm is not None and alg != algorithm:
                raise InvalidAlgorithmError("algorithm does not match the key")

            algorithm = alg

        key = self.get_key(jwk, algorithm)

        return super(PyJWKSet, self).encode(
            payload, key, algorithm, headers, **kwargs
        )

    def decode(self, jwt, algorithms, **kwargs):
        unverified_header = get_unverified_header(jwt)

        if 'kid' not in unverified_header:
            raise InvalidTokenError('Key ID header parameter is missing')

        jwk = self.get_jwk(unverified_header['kid'])

        alg = jwk['alg'] if 'alg' in jwk else unverified_header.get('alg')

        if alg not in algorithms:
            raise InvalidAlgorithmError('The specified alg value is not allowed')

        key = self.get_key(jwk, alg)

        return super(PyJWKSet, self).decode(jwt, key, **kwargs)


_jwk_set_global_obj = PyJWKSet()
encode = _jwk_set_global_obj.encode
decode = _jwk_set_global_obj.decode
register_algorithm = _jwk_set_global_obj.register_algorithm
unregister_algorithm = _jwk_set_global_obj.unregister_algorithm
