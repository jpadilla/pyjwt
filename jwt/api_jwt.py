import json

from calendar import timegm
from collections import Mapping
from datetime import datetime, timedelta

from .api_jws import PyJWS
from .algorithms import Algorithm, get_default_algorithms  # NOQA
from .compat import string_types, timedelta_total_seconds
from .exceptions import (
    DecodeError, ExpiredSignatureError, ImmatureSignatureError,
    InvalidAudienceError, InvalidIssuedAtError,
    InvalidIssuerError
)
from .utils import merge_dict


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
        }

    def encode(self, payload, key, algorithm='HS256', headers=None, json_encoder=None):
        # Check that we get a mapping
        if not isinstance(payload, Mapping):
            raise TypeError('Expecting a mapping object, as json web token only'
                            'support json objects.')

        # Payload
        for time_claim in ['exp', 'iat', 'nbf']:
            # Convert datetime to a intDate value in known time-format claims
            if isinstance(payload.get(time_claim), datetime):
                payload[time_claim] = timegm(payload[time_claim].utctimetuple())

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
        payload, signing_input, header, signature = self._load(jwt)

        decoded = super(PyJWT, self).decode(jwt, key, verify, algorithms,
                                            options, **kwargs)

        try:
            payload = json.loads(decoded.decode('utf-8'))
        except ValueError as e:
            raise DecodeError('Invalid payload string: %s' % e)
        if not isinstance(payload, Mapping):
            raise DecodeError('Invalid payload string: must be a json object')

        if verify:
            merged_options = merge_dict(self.options, options)
            self._validate_claims(payload, options=merged_options, **kwargs)

        return payload

    def _validate_claims(self, payload, audience=None, issuer=None, leeway=0,
                         options=None, **kwargs):
        if isinstance(leeway, timedelta):
            leeway = timedelta_total_seconds(leeway)

        if not isinstance(audience, (string_types, type(None))):
            raise TypeError('audience must be a string or None')

        now = timegm(datetime.utcnow().utctimetuple())

        if 'iat' in payload and options.get('verify_iat'):
            try:
                iat = int(payload['iat'])
            except ValueError:
                raise DecodeError('Issued At claim (iat) must be an integer.')

            if iat > (now + leeway):
                raise InvalidIssuedAtError('Issued At claim (iat) cannot be in'
                                           ' the future.')

        if 'nbf' in payload and options.get('verify_nbf'):
            try:
                nbf = int(payload['nbf'])
            except ValueError:
                raise DecodeError('Not Before claim (nbf) must be an integer.')

            if nbf > (now + leeway):
                raise ImmatureSignatureError('The token is not yet valid (nbf)')

        if 'exp' in payload and options.get('verify_exp'):
            try:
                exp = int(payload['exp'])
            except ValueError:
                raise DecodeError('Expiration Time claim (exp) must be an'
                                  ' integer.')

            if exp < (now - leeway):
                raise ExpiredSignatureError('Signature has expired')

        if 'aud' in payload and options.get('verify_aud'):
            audience_claims = payload['aud']
            if isinstance(audience_claims, string_types):
                audience_claims = [audience_claims]
            if not isinstance(audience_claims, list):
                raise InvalidAudienceError('Invalid claim format in token')
            if any(not isinstance(c, string_types) for c in audience_claims):
                raise InvalidAudienceError('Invalid claim format in token')
            if audience not in audience_claims:
                raise InvalidAudienceError('Invalid audience')
        elif audience is not None:
            # Application specified an audience, but it could not be
            # verified since the token does not contain a claim.
            raise InvalidAudienceError('No audience claim in token')

        if issuer is not None:
            if payload.get('iss') != issuer:
                raise InvalidIssuerError('Invalid issuer')


_jwt_global_obj = PyJWT()
encode = _jwt_global_obj.encode
decode = _jwt_global_obj.decode
register_algorithm = _jwt_global_obj.register_algorithm
unregister_algorithm = _jwt_global_obj.unregister_algorithm
