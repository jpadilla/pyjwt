""" JSON Web Token implementation

Minimum implementation based on this spec:
http://self-issued.info/docs/draft-jones-json-web-token-01.html
"""
import base64
import hashlib
import hmac

from datetime import datetime
from calendar import timegm
from collections import Mapping

try:
    import json
except ImportError:
    import simplejson as json

__all__ = ['encode', 'decode', 'DecodeError']


class DecodeError(Exception):
    pass


class ExpiredSignature(Exception):
    pass


signing_methods = {
    'HS256': lambda msg, key: hmac.new(key, msg, hashlib.sha256).digest(),
    'HS384': lambda msg, key: hmac.new(key, msg, hashlib.sha384).digest(),
    'HS512': lambda msg, key: hmac.new(key, msg, hashlib.sha512).digest(),
}


def constant_time_compare(val1, val2):
    """
    Returns True if the two strings are equal, False otherwise.

    The time taken is independent of the number of characters that match.
    """
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0


def base64url_decode(input):
    rem = len(input) % 4
    if rem > 0:
        input += '=' * (4 - rem)
    return base64.urlsafe_b64decode(input)


def base64url_encode(input):
    return base64.urlsafe_b64encode(input).replace('=', '')


def header(jwt):
    header_segment = jwt.split('.', 1)[0]
    try:
        return json.loads(base64url_decode(header_segment))
    except (ValueError, TypeError):
        raise DecodeError("Invalid header encoding")


def encode(payload, key, algorithm='HS256'):
    segments = []

    # Check that we get a mapping
    if not isinstance(payload, Mapping):
        raise TypeError("Expecting a mapping object, as json web token only"
                        "support json objects.")

    # Header
    header = {"typ": "JWT", "alg": algorithm}
    segments.append(base64url_encode(json.dumps(header)))

    # Payload
    if isinstance(payload.get('exp'), datetime):
        payload['exp'] = timegm(payload['exp'].utctimetuple())
    segments.append(base64url_encode(json.dumps(payload)))

    # Segments
    signing_input = '.'.join(segments)
    try:
        if isinstance(key, unicode):
            key = key.encode('utf-8')
        signature = signing_methods[algorithm](signing_input, key)
    except KeyError:
        raise NotImplementedError("Algorithm not supported")
    segments.append(base64url_encode(signature))
    return '.'.join(segments)


def decode(jwt, key='', verify=True, verify_expiration=True, leeway=0):
    try:
        signing_input, crypto_segment = str(jwt).rsplit('.', 1)
        header_segment, payload_segment = signing_input.split('.', 1)
    except ValueError:
        raise DecodeError("Not enough segments")

    try:
        header = json.loads(base64url_decode(header_segment))
    except TypeError:
        raise DecodeError("Invalid header padding")
    except ValueError as e:
        raise DecodeError("Invalid header string: %s" % e)

    try:
        payload = json.loads(base64url_decode(payload_segment))
    except TypeError:
        raise DecodeError("Invalid payload padding")
    except ValueError as e:
        raise DecodeError("Invalid payload string: %s" % e)

    try:
        signature = base64url_decode(crypto_segment)
    except TypeError:
        raise DecodeError("Invalid crypto padding")

    if verify:
        try:
            if isinstance(key, unicode):
                key = key.encode('utf-8')
            expected = signing_methods[header['alg']](signing_input, key)
            if not constant_time_compare(signature, expected):
                raise DecodeError("Signature verification failed")
        except KeyError:
            raise DecodeError("Algorithm not supported")

        if 'exp' in payload and verify_expiration:
            utc_timestamp = timegm(datetime.utcnow().utctimetuple())
            if payload['exp'] < (utc_timestamp - leeway):
                raise ExpiredSignature("Signature has expired")
    return payload
