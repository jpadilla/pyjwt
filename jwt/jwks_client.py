import json
import urllib.request

from .api_jwk import PyJWKSet
from .api_jwt import decode as decode_token
from .exceptions import PyJWKClientError


class PyJWKClient:
    def __init__(self, uri):
        self.uri = uri

    def fetch_data(self):
        with urllib.request.urlopen(self.uri) as response:
            return json.load(response)

    def get_jwk_set(self):
        data = self.fetch_data()
        return PyJWKSet.from_dict(data)

    def get_signing_keys(self):
        jwk_set = self.get_jwk_set()
        signing_keys = []

        for jwk_set_key in jwk_set.keys:
            if jwk_set_key.public_key_use == "sig" and jwk_set_key.key_id:
                signing_keys.append(jwk_set_key)

        if len(signing_keys) == 0:
            raise PyJWKClientError(
                "The JWKS endpoint did not contain any signing keys"
            )

        return signing_keys

    def get_signing_key(self, kid):
        signing_keys = self.get_signing_keys()
        signing_key = None

        for key in signing_keys:
            if key.key_id == kid:
                signing_key = key
                break

        if not signing_key:
            raise PyJWKClientError(
                f'Unable to find a signing key that matches: "{kid}"'
            )

        return signing_key

    def get_signing_key_from_jwt(self, token):
        unverified = decode_token(
            token, complete=True, options={"verify_signature": False}
        )
        header = unverified.get("header")
        return self.get_signing_key(header.get("kid"))
