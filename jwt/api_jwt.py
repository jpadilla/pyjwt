from __future__ import division

import json
import warnings

from calendar import timegm
from collections import Mapping
from datetime import datetime, timedelta

from .api_jws import PyJWS
from .algorithms import Algorithm, get_default_algorithms  # NOQA
from .compat import string_types
from .exceptions import (
    DecodeError, ExpiredSignatureError, ImmatureSignatureError,
    InvalidAccessTokenHashError,
    InvalidAudienceError, InvalidIssuedAtError,
    InvalidIssuerError, MissingRequiredClaimError
)
from .utils import base64url_encode, merge_dict

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    has_crypto = True
except ImportError:
    has_crypto = False


class PyJWT(PyJWS):
    header_type = 'JWT'

    @staticmethod
    def _get_default_options():
        return {
            'verify_signature': True,
            'verify_exp': True,
            'verify_nbf': True,
            'verify_iat': True,
            'verify_aud': True,
            'verify_iss': True,
            # TODO: in v2.0, make this default to True
            'verify_at_hash': False,
            'require_exp': False,
            'require_iat': False,
            'require_nbf': False
        }

    def encode(self, payload, key, algorithm='HS256', headers=None,
               json_encoder=None, access_token=None):
        # Check that we get a mapping
        if not isinstance(payload, Mapping):
            raise TypeError('Expecting a mapping object, as JWT only supports '
                            'JSON objects as payloads.')

        # Payload
        for time_claim in ['exp', 'iat', 'nbf']:
            # Convert datetime to a intDate value in known time-format claims
            if isinstance(payload.get(time_claim), datetime):
                payload[time_claim] = timegm(payload[time_claim].utctimetuple())

        # OIDC ID Token may have at_hash additional claim
        if access_token is not None:
            payload['at_hash'] = self.compute_at_hash(access_token, algorithm)

        json_payload = json.dumps(
            payload,
            separators=(',', ':'),
            cls=json_encoder
        ).encode('utf-8')

        return super(PyJWT, self).encode(
            json_payload, key, algorithm, headers, json_encoder
        )

    def decode(self, jwt, key='', verify=True, algorithms=None, options=None,
               **kwargs):

        if verify and not algorithms:
            warnings.warn(
                'It is strongly recommended that you pass in a ' +
                'value for the "algorithms" argument when calling decode(). ' +
                'This argument will be mandatory in a future version.',
                DeprecationWarning
            )

        payload, signing_input, header, signature = self._load(jwt)

        if options is None:
            options = {'verify_signature': verify}
        else:
            options.setdefault('verify_signature', verify)

        decoded = super(PyJWT, self).decode(
            jwt, key=key, algorithms=algorithms, options=options, **kwargs
        )

        try:
            payload = json.loads(decoded.decode('utf-8'))
        except ValueError as e:
            raise DecodeError('Invalid payload string: %s' % e)
        if not isinstance(payload, Mapping):
            raise DecodeError('Invalid payload string: must be a json object')

        if verify:
            merged_options = merge_dict(self.options, options)
            self._validate_claims(payload, header, merged_options, **kwargs)

        return payload

    def compute_at_hash(self, access_token, algorithm='HS256'):
        """
        Computes the at_hash claim for JWTs used in OpenID Connect.

        The at_hash is based on the hashing algorithm used to sign the JWT, and
        is specified here:
        http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken

        :return: at_hash of the access_token as a string

        **Parameters**
          ``access_token`` (string)
            The access token to hash

          ``algorithm``
            An algorithm object from jwt.algorithms. Its expected behavior is
            determined by has_crypto.

            If has_crypto=False, it must have a callable hash_alg member which
            provides digest(), like the hashlib variants
            If has_crypto=True, it *may* be a hashlib style hashing function,
            or it may be a cryptography hashing algorithm
        """
        alg_obj = self.get_algo_by_name(algorithm)
        hash_alg = alg_obj.hash_alg

        def get_digest(bytestr):
            if has_crypto and (
                    isinstance(hash_alg, type) and
                    issubclass(hash_alg, hashes.HashAlgorithm)):
                digest = hashes.Hash(hash_alg(), backend=default_backend())
                digest.update(bytestr)
                return digest.finalize()
            else:
                return hash_alg(bytestr).digest()

        digest = get_digest(access_token.encode('utf-8'))
        truncated = digest[:(len(digest) // 2)]
        return base64url_encode(truncated).decode('utf-8')

    def _validate_claims(self, payload, header, options, audience=None,
                         issuer=None, leeway=0, access_token=None, **kwargs):

        if 'verify_expiration' in kwargs:
            options['verify_exp'] = kwargs.get('verify_expiration', True)
            warnings.warn('The verify_expiration parameter is deprecated. '
                          'Please use verify_exp in options instead.',
                          DeprecationWarning)

        if isinstance(leeway, timedelta):
            leeway = leeway.total_seconds()

        if not isinstance(audience, (string_types, type(None))):
            raise TypeError('audience must be a string or None')

        self._validate_required_claims(payload, options)

        now = timegm(datetime.utcnow().utctimetuple())

        if 'iat' in payload and options.get('verify_iat'):
            self._validate_iat(payload, now, leeway)

        if 'nbf' in payload and options.get('verify_nbf'):
            self._validate_nbf(payload, now, leeway)

        if 'exp' in payload and options.get('verify_exp'):
            self._validate_exp(payload, now, leeway)

        if options.get('verify_at_hash'):
            self._validate_at_hash(payload, header, access_token)

        if options.get('verify_iss'):
            self._validate_iss(payload, issuer)

        if options.get('verify_aud'):
            self._validate_aud(payload, audience)

    def _validate_required_claims(self, payload, options):
        if options.get('require_exp') and payload.get('exp') is None:
            raise MissingRequiredClaimError('exp')

        if options.get('require_iat') and payload.get('iat') is None:
            raise MissingRequiredClaimError('iat')

        if options.get('require_nbf') and payload.get('nbf') is None:
            raise MissingRequiredClaimError('nbf')

    def _validate_iat(self, payload, now, leeway):
        try:
            int(payload['iat'])
        except ValueError:
            raise InvalidIssuedAtError('Issued At claim (iat) must be an integer.')

    def _validate_nbf(self, payload, now, leeway):
        try:
            nbf = int(payload['nbf'])
        except ValueError:
            raise DecodeError('Not Before claim (nbf) must be an integer.')

        if nbf > (now + leeway):
            raise ImmatureSignatureError('The token is not yet valid (nbf)')

    def _validate_exp(self, payload, now, leeway):
        try:
            exp = int(payload['exp'])
        except ValueError:
            raise DecodeError('Expiration Time claim (exp) must be an'
                              ' integer.')

        if exp < (now - leeway):
            raise ExpiredSignatureError('Signature has expired')

    def _validate_aud(self, payload, audience):
        if audience is None and 'aud' not in payload:
            return

        if audience is not None and 'aud' not in payload:
            # Application specified an audience, but it could not be
            # verified since the token does not contain a claim.
            raise MissingRequiredClaimError('aud')

        audience_claims = payload['aud']

        if isinstance(audience_claims, string_types):
            audience_claims = [audience_claims]
        if not isinstance(audience_claims, list):
            raise InvalidAudienceError('Invalid claim format in token')
        if any(not isinstance(c, string_types) for c in audience_claims):
            raise InvalidAudienceError('Invalid claim format in token')
        if audience not in audience_claims:
            raise InvalidAudienceError('Invalid audience')

    def _validate_iss(self, payload, issuer):
        if issuer is None:
            return

        if 'iss' not in payload:
            raise MissingRequiredClaimError('iss')

        if payload['iss'] != issuer:
            raise InvalidIssuerError('Invalid issuer')

    def _validate_at_hash(self, payload, header, access_token):
        if 'at_hash' not in payload:
            if access_token is None:
                return
            else:
                raise MissingRequiredClaimError('at_hash')
        elif access_token is None:
            raise InvalidAccessTokenHashError(
                "access_token=None can't be hashed")

        at_hash = payload['at_hash']
        alg = header.get('alg')

        if at_hash != self.compute_at_hash(access_token, alg):
            raise InvalidAccessTokenHashError("at_hash doesn't match")


_jwt_global_obj = PyJWT()
encode = _jwt_global_obj.encode
decode = _jwt_global_obj.decode
register_algorithm = _jwt_global_obj.register_algorithm
unregister_algorithm = _jwt_global_obj.unregister_algorithm
get_unverified_header = _jwt_global_obj.get_unverified_header
