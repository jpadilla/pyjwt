import binascii
import json

from calendar import timegm
from collections import Mapping
from datetime import datetime, timedelta

from .compat import string_types, text_type, timedelta_total_seconds
from .exceptions import (
    DecodeError, ExpiredSignatureError,
    InvalidAudienceError, InvalidIssuerError
)
from .utils import base64url_decode, base64url_encode


_algorithms = {}


def register_algorithm(alg_id, alg_obj):
    """
    Registers a new Algorithm for use when creating and verifying tokens.
    """
    if alg_id in _algorithms:
        raise ValueError('Algorithm already has a handler.')

    if not isinstance(alg_obj, Algorithm):
        raise TypeError('Object is not of type `Algorithm`')

    _algorithms[alg_id] = alg_obj

from jwt.algorithms import Algorithm, _register_default_algorithms  # NOQA
_register_default_algorithms()


def encode(payload, key, algorithm='HS256', headers=None, json_encoder=None):
    segments = []

    if algorithm is None:
        algorithm = 'none'

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
        alg_obj = _algorithms[algorithm]
        key = alg_obj.prepare_key(key)
        signature = alg_obj.sign(signing_input, key)

    except KeyError:
        raise NotImplementedError('Algorithm not supported')

    segments.append(base64url_encode(signature))

    return b'.'.join(segments)


def decode(jwt, key='', verify=True, **kwargs):
    payload, signing_input, header, signature = load(jwt)

    if verify:
        verify_signature(payload, signing_input, header, signature, key,
                         **kwargs)

    return payload


def load(jwt):
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


def verify_signature(payload, signing_input, header, signature, key='',
                     verify_expiration=True, leeway=0, audience=None,
                     issuer=None):

    if isinstance(leeway, timedelta):
        leeway = timedelta_total_seconds(leeway)

    if not isinstance(audience, (string_types, type(None))):
        raise TypeError('audience must be a string or None')

    try:
        alg_obj = _algorithms[header['alg']]
        key = alg_obj.prepare_key(key)

        if not alg_obj.verify(signing_input, key, signature):
            raise DecodeError('Signature verification failed')

    except KeyError:
        raise DecodeError('Algorithm not supported')

    if 'nbf' in payload and verify_expiration:
        utc_timestamp = timegm(datetime.utcnow().utctimetuple())

        if payload['nbf'] > (utc_timestamp + leeway):
            raise ExpiredSignatureError('Signature not yet valid')

    if 'exp' in payload and verify_expiration:
        utc_timestamp = timegm(datetime.utcnow().utctimetuple())

        if payload['exp'] < (utc_timestamp - leeway):
            raise ExpiredSignatureError('Signature has expired')

    if 'aud' in payload:
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
