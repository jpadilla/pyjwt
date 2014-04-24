""" JSON Web Token implementation

Minimum implementation based on this spec:
http://self-issued.info/docs/draft-jones-json-web-token-01.html
"""
from __future__ import unicode_literals
import base64
import binascii
import hashlib
import hmac
import sys

from datetime import datetime
from calendar import timegm
from collections import Mapping

try:
    import json
except ImportError:
    import simplejson as json

__all__ = ['encode', 'decode', 'DecodeError']


if sys.version_info >= (3, 0, 0):
    unicode = str
    basestring = str


class DecodeError(Exception):
    pass


class ExpiredSignature(Exception):
    pass


signing_methods = {
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
    if isinstance(key, basestring):
        if isinstance(key, unicode):
            key = key.encode('utf-8')
    else:
        raise TypeError("Expecting a string-formatted key.")
    return key

prepare_key_methods = {
    'HS256': prepare_HS_key,
    'HS384': prepare_HS_key,
    'HS512': prepare_HS_key
}

try:
    from Crypto.Signature import PKCS1_v1_5
    from Crypto.Hash import SHA256
    from Crypto.Hash import SHA384
    from Crypto.Hash import SHA512
    from Crypto.PublicKey import RSA

    signing_methods.update({
        'RS256': lambda msg, key: PKCS1_v1_5.new(key).sign(SHA256.new(msg)),
        'RS384': lambda msg, key: PKCS1_v1_5.new(key).sign(SHA384.new(msg)),
        'RS512': lambda msg, key: PKCS1_v1_5.new(key).sign(SHA512.new(msg))
    })

    verify_methods.update({
        'RS256': lambda msg, key, sig: PKCS1_v1_5.new(key).verify(SHA256.new(msg), sig),
        'RS384': lambda msg, key, sig: PKCS1_v1_5.new(key).verify(SHA384.new(msg), sig),
        'RS512': lambda msg, key, sig: PKCS1_v1_5.new(key).verify(SHA512.new(msg), sig)
    })

    def prepare_RS_key(key):
        if isinstance(key, basestring):
            if isinstance(key, unicode):
                key = key.encode('utf-8')
            key = RSA.importKey(key)
        elif isinstance(key, RSA._RSAobj):
            pass
        else:
            raise TypeError("Expecting a PEM- or RSA-formatted key.")
        return key

    prepare_key_methods.update({
        'RS256': prepare_RS_key,
        'RS384': prepare_RS_key,
        'RS512': prepare_RS_key
    })

except ImportError:
    pass


def constant_time_compare(val1, val2):
    """
    Returns True if the two strings are equal, False otherwise.

    The time taken is independent of the number of characters that match.
    """
    if len(val1) != len(val2):
        return False
    result = 0
    if sys.version_info >= (3, 0, 0):  # bytes are numbers
        for x, y in zip(val1, val2):
            result |= x ^ y
    else:
        for x, y in zip(val1, val2):
            result |= ord(x) ^ ord(y)
    return result == 0


def base64url_decode(input):
    rem = len(input) % 4
    if rem > 0:
        input += b'=' * (4 - rem)
    return base64.urlsafe_b64decode(input)


def base64url_encode(input):
    return base64.urlsafe_b64encode(input).replace(b'=', b'')


def header(jwt):
    header_segment = jwt.split(b'.', 1)[0]
    try:
        header_data = base64url_decode(header_segment).decode('utf-8')
        return json.loads(header_data)
    except (ValueError, TypeError):
        raise DecodeError("Invalid header encoding")


def encode(payload, key, algorithm='HS256', headers=None):
    segments = []

    # Check that we get a mapping
    if not isinstance(payload, Mapping):
        raise TypeError("Expecting a mapping object, as json web token only"
                        "support json objects.")

    # Header
    header = {"typ": "JWT", "alg": algorithm}
    if headers:
        header.update(headers)
    json_header = json.dumps(header, separators=(',', ':')).encode('utf-8')
    segments.append(base64url_encode(json_header))

    # Payload
    for time_claim in ['exp', 'iat', 'nbf']:    # convert datetime to a intDate value in known time-format claims
        if isinstance(payload.get(time_claim), datetime):
            payload[time_claim] = timegm(payload[time_claim].utctimetuple())
    json_payload = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    segments.append(base64url_encode(json_payload))

    # Segments
    signing_input = b'.'.join(segments)
    try:
        key = prepare_key_methods[algorithm](key)
        signature = signing_methods[algorithm](signing_input, key)
    except KeyError:
        raise NotImplementedError("Algorithm not supported")
    segments.append(base64url_encode(signature))
    return b'.'.join(segments)


def decode(jwt, key='', verify=True, verify_expiration=True, leeway=0):
    payload, signing_input, header, signature = load(jwt)

    if verify:
        verify_signature(payload, signing_input, header, signature, key,
                verify_expiration, leeway)

    return payload


def load(jwt):
    if isinstance(jwt, unicode):
        jwt = jwt.encode('utf-8')
    try:
        signing_input, crypto_segment = jwt.rsplit(b'.', 1)
        header_segment, payload_segment = signing_input.split(b'.', 1)
    except ValueError:
        raise DecodeError("Not enough segments")

    try:
        header_data = base64url_decode(header_segment)
    except (TypeError, binascii.Error):
        raise DecodeError("Invalid header padding")
    try:
        header = json.loads(header_data.decode('utf-8'))
    except ValueError as e:
        raise DecodeError("Invalid header string: %s" % e)

    try:
        payload_data = base64url_decode(payload_segment)
    except (TypeError, binascii.Error):
        raise DecodeError("Invalid payload padding")
    try:
        payload = json.loads(payload_data.decode('utf-8'))
    except ValueError as e:
        raise DecodeError("Invalid payload string: %s" % e)

    try:
        signature = base64url_decode(crypto_segment)
    except (TypeError, binascii.Error):
        raise DecodeError("Invalid crypto padding")

    return (payload, signing_input, header, signature)


def verify_signature(payload, signing_input, header, signature, key='',
            verify_expiration=True, leeway=0):
    try:
        key = prepare_key_methods[header['alg']](key)
        if header['alg'].startswith('HS'):
            expected = verify_methods[header['alg']](signing_input, key)
            if not constant_time_compare(signature, expected):
                raise DecodeError("Signature verification failed")
        else:
            if not verify_methods[header['alg']](signing_input, key, signature):
                raise DecodeError("Signature verification failed")
    except KeyError:
        raise DecodeError("Algorithm not supported")

    if 'exp' in payload and verify_expiration:
        utc_timestamp = timegm(datetime.utcnow().utctimetuple())
        if payload['exp'] < (utc_timestamp - leeway):
            raise ExpiredSignature("Signature has expired")
