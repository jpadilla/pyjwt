"""
JSON Web Token implementation

Minimum implementation based on this spec:
http://self-issued.info/docs/draft-jones-json-web-token-01.html
"""
from __future__ import unicode_literals

import base64
import binascii
import hashlib
import hmac
from datetime import datetime, timedelta
from calendar import timegm
from collections import Mapping

from .compat import (json, string_types, text_type, constant_time_compare,
                     timedelta_total_seconds)


__version__ = '0.4.1'
__all__ = [
    # Functions
    'encode',
    'decode',

    # Exceptions
    'InvalidTokenError',
    'DecodeError',
    'ExpiredSignatureError',
    'InvalidAudienceError',
    'InvalidIssuerError',

    # Deprecated aliases
    'ExpiredSignature',
    'InvalidAudience',
    'InvalidIssuer',
]


class InvalidTokenError(Exception):
    pass


class DecodeError(InvalidTokenError):
    pass


class ExpiredSignatureError(InvalidTokenError):
    pass


class InvalidAudienceError(InvalidTokenError):
    pass


class InvalidIssuerError(InvalidTokenError):
    pass


# Compatibility aliases (deprecated)
ExpiredSignature = ExpiredSignatureError
InvalidAudience = InvalidAudienceError
InvalidIssuer = InvalidIssuerError

signing_methods = {
    'none': lambda msg, key: b'',
    'HS256': lambda msg, key: hmac.new(key, msg, hashlib.sha256).digest(),
    'HS384': lambda msg, key: hmac.new(key, msg, hashlib.sha384).digest(),
    'HS512': lambda msg, key: hmac.new(key, msg, hashlib.sha512).digest()
}

verify_methods = {
    'HS256': lambda msg, key: hmac.new(key, msg, hashlib.sha256).digest(),
    'HS384': lambda msg, key: hmac.new(key, msg, hashlib.sha384).digest(),
    'HS512': lambda msg, key: hmac.new(key, msg, hashlib.sha512).digest()
}


def prepare_HS_key(key):
    if not isinstance(key, string_types) and not isinstance(key, bytes):
        raise TypeError('Expecting a string- or bytes-formatted key.')

    if isinstance(key, text_type):
        key = key.encode('utf-8')

    return key

prepare_key_methods = {
    'none': lambda key: None,
    'HS256': prepare_HS_key,
    'HS384': prepare_HS_key,
    'HS512': prepare_HS_key
}

try:
    from cryptography.hazmat.primitives import interfaces, hashes
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key, load_pem_public_key, load_ssh_public_key
    )
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature

    def sign_rsa(msg, key, hashalg):
        signer = key.signer(
            padding.PKCS1v15(),
            hashalg
        )

        signer.update(msg)
        return signer.finalize()

    def verify_rsa(msg, key, hashalg, sig):
        verifier = key.verifier(
            sig,
            padding.PKCS1v15(),
            hashalg
        )

        verifier.update(msg)

        try:
            verifier.verify()
            return True
        except InvalidSignature:
            return False

    signing_methods.update({
        'RS256': lambda msg, key: sign_rsa(msg, key, hashes.SHA256()),
        'RS384': lambda msg, key: sign_rsa(msg, key, hashes.SHA384()),
        'RS512': lambda msg, key: sign_rsa(msg, key, hashes.SHA512())
    })

    verify_methods.update({
        'RS256': lambda msg, key, sig: verify_rsa(msg, key, hashes.SHA256(), sig),
        'RS384': lambda msg, key, sig: verify_rsa(msg, key, hashes.SHA384(), sig),
        'RS512': lambda msg, key, sig: verify_rsa(msg, key, hashes.SHA512(), sig)
    })

    def prepare_RS_key(key):
        if isinstance(key, interfaces.RSAPrivateKey) or \
           isinstance(key, interfaces.RSAPublicKey):
            return key

        if isinstance(key, string_types):
            if isinstance(key, text_type):
                key = key.encode('utf-8')

            try:
                if key.startswith(b'ssh-rsa'):
                    key = load_ssh_public_key(key, backend=default_backend())
                else:
                    key = load_pem_private_key(key, password=None, backend=default_backend())
            except ValueError:
                key = load_pem_public_key(key, backend=default_backend())
        else:
            raise TypeError('Expecting a PEM-formatted key.')

        return key

    prepare_key_methods.update({
        'RS256': prepare_RS_key,
        'RS384': prepare_RS_key,
        'RS512': prepare_RS_key
    })

    def sign_ecdsa(msg, key, hashalg):
        signer = key.signer(ec.ECDSA(hashalg))

        signer.update(msg)
        return signer.finalize()

    def verify_ecdsa(msg, key, hashalg, sig):
        verifier = key.verifier(sig, ec.ECDSA(hashalg))

        verifier.update(msg)

        try:
            verifier.verify()
            return True
        except InvalidSignature:
            return False

    signing_methods.update({
        'ES256': lambda msg, key: sign_ecdsa(msg, key, hashes.SHA256()),
        'ES384': lambda msg, key: sign_ecdsa(msg, key, hashes.SHA384()),
        'ES512': lambda msg, key: sign_ecdsa(msg, key, hashes.SHA512()),
    })

    verify_methods.update({
        'ES256': lambda msg, key, sig: verify_ecdsa(msg, key, hashes.SHA256(), sig),
        'ES384': lambda msg, key, sig: verify_ecdsa(msg, key, hashes.SHA384(), sig),
        'ES512': lambda msg, key, sig: verify_ecdsa(msg, key, hashes.SHA512(), sig),
    })

    def prepare_ES_key(key):
        if isinstance(key, interfaces.EllipticCurvePrivateKey) or \
           isinstance(key, interfaces.EllipticCurvePublicKey):
            return key

        if isinstance(key, string_types):
            if isinstance(key, text_type):
                key = key.encode('utf-8')

            # Attempt to load key. We don't know if it's
            # a Signing Key or a Verifying Key, so we try
            # the Verifying Key first.
            try:
                key = load_pem_public_key(key, backend=default_backend())
            except ValueError:
                key = load_pem_private_key(key, password=None, backend=default_backend())

        else:
            raise TypeError('Expecting a PEM-formatted key.')

        return key

    prepare_key_methods.update({
        'ES256': prepare_ES_key,
        'ES384': prepare_ES_key,
        'ES512': prepare_ES_key
    })

except ImportError:
    pass


def base64url_decode(input):
    rem = len(input) % 4

    if rem > 0:
        input += b'=' * (4 - rem)

    return base64.urlsafe_b64decode(input)


def base64url_encode(input):
    return base64.urlsafe_b64encode(input).replace(b'=', b'')


def header(jwt):
    if isinstance(jwt, text_type):
        jwt = jwt.encode('utf-8')
    header_segment = jwt.split(b'.', 1)[0]
    try:
        header_data = base64url_decode(header_segment)
        return json.loads(header_data.decode('utf-8'))
    except (ValueError, TypeError):
        raise DecodeError('Invalid header encoding')


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
        key = prepare_key_methods[algorithm](key)
        signature = signing_methods[algorithm](signing_input, key)
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
        algorithm = header['alg'].upper()
        key = prepare_key_methods[algorithm](key)

        if algorithm.startswith('HS'):
            expected = verify_methods[algorithm](signing_input, key)

            if not constant_time_compare(signature, expected):
                raise DecodeError('Signature verification failed')
        else:
            if not verify_methods[algorithm](signing_input, key, signature):
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
