from .api_jwk import PyJWKSet
from .api_jwt import decode as decode_token
from .exceptions import PyJWKClientError

try:
    import requests
except ImportError:
    requests = None


class PyJWKClient:
    def __init__(self, uri):
        if not requests:
            raise PyJWKClientError(
                "Missing dependencies for `PyJWKClient`. Run `pip install pyjwt[jwks-client]` to install dependencies."
            )

        self.uri = uri

    def fetch_data(self):
        r = requests.get(self.uri)
        return r.json()

    def get_jwk_set(self):
        data = self.fetch_data()
        return PyJWKSet.from_dict(data)

    def get_signing_keys(self):
        jwk_set = self.get_jwk_set()
        signing_keys = list(
            filter(
                lambda key: key.public_key_use == "sig" and key.key_id, jwk_set.keys,
            )
        )

        if len(signing_keys) == 0:
            raise PyJWKClientError("The JWKS endpoint did not contain any signing keys")

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
                'Unable to find a signing key that matches: "{kid}"'.format(kid)
            )

        return signing_key

    def get_signing_key_from_jwt(self, token):
        unverified = decode_token(token, verify=False, complete=True)
        header = unverified.get("header")
        return self.get_signing_key(header.get("kid"))
