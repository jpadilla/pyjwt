import binascii
import json
import warnings

from calendar import timegm
from collections import Mapping
from datetime import datetime, timedelta

from .algorithms import Algorithm, get_default_algorithms  # NOQA
from .compat import string_types, text_type, timedelta_total_seconds
from .exceptions import (
    DecodeError, ExpiredSignatureError, ImmatureSignatureError,
    InvalidAlgorithmError, InvalidAudienceError, InvalidIssuedAtError,
    InvalidIssuerError
)
from .utils import base64url_decode, base64url_encode, merge_dict


class PyJWT(object):
    def __init__(self, algorithms=None, options=None):
        self._algorithms = get_default_algorithms()
        self._valid_algs = set(algorithms) if algorithms is not None else set(self._algorithms)

        # Remove algorithms that aren't on the whitelist
        for key in list(self._algorithms.keys()):
            if key not in self._valid_algs:
                del self._algorithms[key]

        if not options:
            options = {}

        default_options = {
            'verify_signature': True,
            'verify_exp': True,
            'verify_nbf': True,
            'verify_iat': True,
            'verify_aud': True,
        }

        self.options = merge_dict(default_options, options)

    def register_algorithm(self, alg_id, alg_obj):
        """
        Registers a new Algorithm for use when creating and verifying tokens.
        """
        if alg_id in self._algorithms:
            raise ValueError('Algorithm already has a handler.')

        if not isinstance(alg_obj, Algorithm):
            raise TypeError('Object is not of type `Algorithm`')

        self._algorithms[alg_id] = alg_obj
        self._valid_algs.add(alg_id)

    def unregister_algorithm(self, alg_id):
        """
        Unregisters an Algorithm for use when creating and verifying tokens
        Throws KeyError if algorithm is not registered.
        """
        if alg_id not in self._algorithms:
            raise KeyError('The specified algorithm could not be removed because it is not registered.')

        del self._algorithms[alg_id]
        self._valid_algs.remove(alg_id)

    def get_algorithms(self):
        """
        Returns a list of supported values for the 'alg' parameter.
        """
        return list(self._valid_algs)

    def encode(self, payload, key, algorithm='HS256', headers=None, json_encoder=None):
        segments = []

        if algorithm is None:
            algorithm = 'none'

        if algorithm not in self._valid_algs:
            pass

        # Check that we get a mapping
        if not isinstance(payload, Mapping):
            raise TypeError('Expecting a mapping object, as json web token only'
                            'support json objects.')

        # Header
        header = {'typ': 'JWT', 'alg': algorithm}

        if headers:
            header.update(headers)

        json_header = json.dumps(
            header,
            separators=(',', ':'),
            cls=json_encoder
        ).encode('utf-8')

        segments.append(base64url_encode(json_header))

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

        segments.append(base64url_encode(json_payload))

        # Segments
        signing_input = b'.'.join(segments)
        try:
            alg_obj = self._algorithms[algorithm]
            key = alg_obj.prepare_key(key)
            signature = alg_obj.sign(signing_input, key)

        except KeyError:
            raise NotImplementedError('Algorithm not supported')

        segments.append(base64url_encode(signature))

        return b'.'.join(segments)

    def decode(self, jwt, key='', verify=True, algorithms=None, options=None, **kwargs):
        payload, signing_input, header, signature = self._load(jwt)

        if verify:
            merged_options = merge_dict(self.options, options)
            if merged_options.get('verify_signature'):
                self._verify_signature(payload, signing_input, header, signature,
                                       key, algorithms)

            self._validate_claims(payload, options=merged_options, **kwargs)
        else:
            warnings.warn("The verify parameter is deprecated. Please use options instead.", DeprecationWarning)

        return payload

    def _load(self, jwt):
        if isinstance(jwt, text_type):
            jwt = jwt.encode('utf-8')
        try:
            signing_input, crypto_segment = jwt.rsplit(b'.', 1)
            header_segment, payload_segment = signing_input.split(b'.', 1)
        except ValueError:
            raise DecodeError('Not enough segments')

        try:
            header_data = base64url_decode(header_segment)
        except (TypeError, binascii.Error):
            raise DecodeError('Invalid header padding')
        try:
            header = json.loads(header_data.decode('utf-8'))
        except ValueError as e:
            raise DecodeError('Invalid header string: %s' % e)
        if not isinstance(header, Mapping):
            raise DecodeError('Invalid header string: must be a json object')

        try:
            payload_data = base64url_decode(payload_segment)
        except (TypeError, binascii.Error):
            raise DecodeError('Invalid payload padding')
        try:
            payload = json.loads(payload_data.decode('utf-8'))
        except ValueError as e:
            raise DecodeError('Invalid payload string: %s' % e)
        if not isinstance(payload, Mapping):
            raise DecodeError('Invalid payload string: must be a json object')

        try:
            signature = base64url_decode(crypto_segment)
        except (TypeError, binascii.Error):
            raise DecodeError('Invalid crypto padding')

        return (payload, signing_input, header, signature)

    def _verify_signature(self, payload, signing_input, header, signature,
                          key='', algorithms=None):

        alg = header['alg']

        if algorithms is not None and alg not in algorithms:
            raise InvalidAlgorithmError('The specified alg value is not allowed')

        try:
            alg_obj = self._algorithms[alg]
            key = alg_obj.prepare_key(key)

            if not alg_obj.verify(signing_input, key, signature):
                raise DecodeError('Signature verification failed')

        except KeyError:
            raise InvalidAlgorithmError('Algorithm not supported')

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
                raise InvalidIssuedAtError('Issued At claim (iat) cannot be in the future.')

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
                raise DecodeError('Expiration Time claim (exp) must be an integer.')

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
