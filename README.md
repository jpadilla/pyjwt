# PyJWT [![Build Status](https://travis-ci.org/progrium/pyjwt.png?branch=master)](https://travis-ci.org/progrium/pyjwt)

A Python implementation of [JSON Web Token draft 01](http://self-issued.info/docs/draft-jones-json-web-token-01.html).

## Installing

```
$ pip install PyJWT
```

**A Note on Dependencies**:

The RSASSA-PKCS1-v1_5 algorithms depend on PyCrypto. If you plan on
using any of those algorithms, you'll need to install it as well.

```
$ pip install PyCrypto
```

The Elliptic Curve Digital Signature algorithms depend on Python-ECDSA. If
you plan on using any of those algorithms, you'll need to install it as well.

```
$ pip install ecdsa
```

## Usage

```python
import jwt
jwt.encode({'some': 'payload'}, 'secret')
```

Additional headers may also be specified.

```python
jwt.encode({'some': 'payload'}, 'secret', headers={'kid': '230498151c214b788dd97f22b85410a5'})
```

Note the resulting JWT will not be encrypted, but verifiable with a secret key.

```python
jwt.decode('someJWTstring', 'secret')
```

If the secret is wrong, it will raise a `jwt.DecodeError` telling you as such.
You can still get the payload by setting the `verify` argument to `False`.

```python
jwt.decode('someJWTstring', verify=False)
```

## Algorithms

The JWT spec supports several algorithms for cryptographic signing. This library
currently supports:

* HS256 - HMAC using SHA-256 hash algorithm (default)
* HS384 - HMAC using SHA-384 hash algorithm
* HS512 - HMAC using SHA-512 hash algorithm
* ES256 - ECDSA signature algorithm using SHA-256 hash algorithm
* ES384 - ECDSA signature algorithm using SHA-384 hash algorithm
* ES512 - ECDSA signature algorithm using SHA-512 hash algorithm
* RS256 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-256 hash algorithm
* RS384 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-384 hash algorithm
* RS512 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-512 hash algorithm

Change the algorithm with by setting it in encode:

```python
jwt.encode({'some': 'payload'}, 'secret', 'HS512')
```

When using the RSASSA-PKCS1-v1_5 algorithms, the `key` argument in both
`jwt.encode()` and `jwt.decode()` (`"secret"` in the examples) is expected to
be an RSA public or private key as imported with `Crypto.PublicKey.RSA.importKey()`.

When using the ECDSA algorithms, the `key` argument is expected to
be an Elliptic Curve private key as imported with `ecdsa.SigningKey.from_pem()`,
or a public key as imported with `ecdsa.VerifyingKey.from_pem()`.

## Tests

You can run tests from the project root after cloning with:

```
$ python tests/test_jwt.py
```

## Support of reserved claim names

JSON Web Token defines some reserved claim names and defines how they should be
used. PyJWT supports these reserved claim names:

 - "exp" (Expiration Time) Claim
 - "nbf" (Not Before Time) Claim

### Expiration Time Claim

From [draft 01 of the JWT spec](http://self-issued.info/docs/draft-jones-json-web-token-01.html#ReservedClaimName):

> The exp (expiration time) claim identifies the expiration time on or after
> which the JWT MUST NOT be accepted for processing. The processing of the exp
> claim requires that the current date/time MUST be before the expiration
> date/time listed in the exp claim. Implementers MAY provide for some small
> leeway, usually no more than a few minutes, to account for clock skew. Its
> value MUST be a number containing an IntDate value. Use of this claim is
> OPTIONAL.

You can pass the expiration time as a UTC UNIX timestamp (an int) or as a
datetime, which will be converted into an int. For example:

```python
jwt.encode({'exp': 1371720939}, 'secret')

jwt.encode({'exp': datetime.utcnow()}, 'secret')
```

Expiration time is automatically verified in `jwt.decode()` and raises
`jwt.ExpiredSignature` if the expiration time is in the past:

```python
import jwt

try:
    jwt.decode('JWT_STRING', 'secret')
except jwt.ExpiredSignature:
    # Signature has expired
```

Expiration time will be compared to the current UTC time (as given by
`timegm(datetime.utcnow().utctimetuple())`), so be sure to use a UTC timestamp
or datetime in encoding.

You can turn off expiration time verification with the `verify_expiration` argument.

PyJWT also supports the leeway part of the expiration time definition, which
means you can validate a expiration time which is in the past but not very far.
For example, if you have a JWT payload with a expiration time set to 30 seconds
after creation but you know that sometimes you will process it after 30 seconds,
you can set a leeway of 10 seconds in order to have some margin:

```python
import datetime
import time
import jwt

jwt_payload = jwt.encode({
    'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=30)
}, 'secret')

time.sleep(32)

# JWT payload is now expired
# But with some leeway, it will still validate
jwt.decode(jwt_payload, 'secret', leeway=10)
```

PyJWT also supports not-before validation via the [`nbf` claim](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-27#section-4.1.5) in a similar fashion.

## License

MIT
