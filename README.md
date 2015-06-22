# PyJWT

[![travis-status-image]][travis]
[![appveyor-status-image]][appveyor]
[![pypi-version-image]][pypi]
[![coveralls-status-image]][coveralls]

A Python implementation of [JSON Web Token draft 32][jwt-spec].
Original implementation was written by [@progrium][progrium].

## Installing

```
$ pip install PyJWT
```

**A Note on Dependencies**:

RSA and ECDSA signatures depend on the recommended `cryptography` package (0.8+). If you plan on
using any of those algorithms, you'll need to install it as well.

```
$ pip install cryptography
```

If your system doesn't allow installing `cryptography` like on Google App Engine, you can install `PyCrypto` for RSA signatures and `ecdsa` for ECDSA signatures.

## Usage

```python
>>> import jwt
>>> encoded = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256')
'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg'
```

Additional headers may also be specified.

```python
>>> jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256', headers={'kid': '230498151c214b788dd97f22b85410a5'})
'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjIzMDQ5ODE1MWMyMTRiNzg4ZGQ5N2YyMmI4NTQxMGE1In0.eyJzb21lIjoicGF5bG9hZCJ9.DogbDGmMHgA_bU05TAB-R6geQ2nMU2BRM-LnYEtefwg'
```

Note the resulting JWT will not be encrypted, but verifiable with a secret key.

```python
>>> jwt.decode(encoded, 'secret', algorithms=['HS256'])
{u'some': u'payload'}
```

If the secret is wrong, it will raise a `jwt.DecodeError` telling you as such.
You can still get the payload by setting the `verify` argument to `False`.

```python
>>> jwt.decode(encoded, verify=False)
{u'some': u'payload'}
```

## Validation
Exceptions can be raised during `decode()` for other errors besides an
invalid signature (e.g. for invalid issuer or audience (see below). All
exceptions that signify that the token is invalid extend from the base
`InvalidTokenError` exception class, so applications can use this approach to
catch any issues relating to invalid tokens:

```python
try:
     payload = jwt.decode(encoded)
except jwt.InvalidTokenError:
     pass  # do something sensible here, e.g. return HTTP 403 status code
```

### Skipping Claim Verification
You may also override claim verification via the `options` dictionary.  The
default options are:

```python
options = {
   'verify_signature': True,
   'verify_exp': True,
   'verify_nbf': True,
   'verify_iat': True,
   'verify_aud': True
   'require_exp': False,
   'require_iat': False,
   'require_nbf': False
}
```

You can skip validation of individual claims by passing an `options` dictionary
with the "verify_<claim_name>" key set to `False` when you call `jwt.decode()`.
For example, if you want to verify the signature of a JWT that has already
expired, you could do so by setting `verify_exp` to `False`.

```python
>>> options = {
>>>    'verify_exp': False,
>>> }

>>> encoded = '...' # JWT with an expired exp claim
>>> jwt.decode(encoded, 'secret', options=options)
{u'some': u'payload'}
```

**NOTE**: *Changing the default behavior is done at your own risk, and almost
certainly will make your application less secure.  Doing so should only be done
with a very clear understanding of what you are doing.*

### Requiring Optional Claims
In addition to skipping certain validations, you may also specify that certain
optional claims are required by setting the appropriate `require_<claim_name>`
option to True. If the claim is not present, PyJWT will raise a
`jwt.exceptions.MissingRequiredClaimError`.

For instance, the following code would require that the token has a 'exp'
claim and raise an error if it is not present:

```python
>>> options = {
>>>     'require_exp': True
>>> }

>>> encoded =  '...' # JWT without an exp claim
>>> jwt.decode(encoded, 'secret', options=options)
jwt.exceptions.MissingRequiredClaimError: Token is missing the "exp" claim
```

## Tests

You can run tests from the project root after cloning with:

```
$ python setup.py test
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
* PS256 - RSASSA-PSS signature using SHA-256 and MGF1 padding with SHA-256
* PS384 - RSASSA-PSS signature using SHA-384 and MGF1 padding with SHA-384
* PS512 - RSASSA-PSS signature using SHA-512 and MGF1 padding with SHA-512

### Encoding
You can specify which algorithm you would like to use to sign the JWT
by using the `algorithm` parameter:

```python
>>> encoded = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS512')
'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.WTzLzFO079PduJiFIyzrOah54YaM8qoxH9fLMQoQhKtw3_fMGjImIOokijDkXVbyfBqhMo2GCNu4w9v7UXvnpA'
```

### Decoding
When decoding, you can specify which algorithms you would like to permit
when validating the JWT by using the `algorithms` parameter which takes a list
of allowed algorithms:

```python
>>> jwt.decode(encoded, 'secret', algorithms=['HS512', 'HS256'])
{u'some': u'payload'}
```

In the above case, if the JWT has any value for its alg header other than
HS512 or HS256, the claim will be rejected with an `InvalidAlgorithmError`.

### Asymmetric (Public-key) Algorithms
Usage of RSA (RS\*) and EC (EC\*) algorithms require a basic understanding
of how public-key cryptography is used with regards to digital signatures.
If you are unfamiliar, you may want to read
[this article](http://en.wikipedia.org/wiki/Public-key_cryptography).

When using the RSASSA-PKCS1-v1_5 algorithms, the `key` argument in both
`jwt.encode()` and `jwt.decode()` (`"secret"` in the examples) is expected to
be either an RSA public or private key in PEM or SSH format. The type of key
(private or public) depends on whether you are signing or verifying.

When using the ECDSA algorithms, the `key` argument is expected to
be an Elliptic Curve public or private key in PEM format. The type of key
(private or public) depends on whether you are signing or verifying.


## Support of registered claim names

JSON Web Token defines some registered claim names and defines how they should
be used. PyJWT supports these registered claim names:

 - "exp" (Expiration Time) Claim
 - "nbf" (Not Before Time) Claim
 - "iss" (Issuer) Claim
 - "aud" (Audience) Claim
 - "iat" (Issued At) Claim

### Expiration Time Claim

From [the JWT spec][jwt-spec-reg-claims]:

> The "exp" (expiration time) claim identifies the expiration time on
> or after which the JWT MUST NOT be accepted for processing.  The
> processing of the "exp" claim requires that the current date/time
> MUST be before the expiration date/time listed in the "exp" claim.
> Implementers MAY provide for some small leeway, usually no more than
> a few minutes, to account for clock skew.  Its value MUST be a number
> containing a NumericDate value.  Use of this claim is OPTIONAL.

You can pass the expiration time as a UTC UNIX timestamp (an int) or as a
datetime, which will be converted into an int. For example:

```python
jwt.encode({'exp': 1371720939}, 'secret')

jwt.encode({'exp': datetime.utcnow()}, 'secret')
```

Expiration time is automatically verified in `jwt.decode()` and raises
`jwt.ExpiredSignatureError` if the expiration time is in the past:

```python
import jwt

try:
    jwt.decode('JWT_STRING', 'secret')
except jwt.ExpiredSignatureError:
    # Signature has expired
```

Expiration time will be compared to the current UTC time (as given by
`timegm(datetime.utcnow().utctimetuple())`), so be sure to use a UTC timestamp
or datetime in encoding.

You can turn off expiration time verification with the `verify_exp` parameter in the options argument.

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

Instead of specifying the leeway as a number of seconds, a `datetime.timedelta`
instance can be used. The last line in the example above is equivalent to:

```python
jwt.decode(jwt_payload, 'secret', leeway=datetime.timedelta(seconds=10))
```


### Not Before Time Claim

> The "nbf" (not before) claim identifies the time before which the JWT
> MUST NOT be accepted for processing.  The processing of the "nbf"
> claim requires that the current date/time MUST be after or equal to
> the not-before date/time listed in the "nbf" claim.  Implementers MAY
> provide for some small leeway, usually no more than a few minutes, to
> account for clock skew.  Its value MUST be a number containing a
> NumericDate value.  Use of this claim is OPTIONAL.

The `nbf` claim works similarly to the `exp` claim above.

```python
jwt.encode({'nbf': 1371720939}, 'secret')

jwt.encode({'nbf': datetime.utcnow()}, 'secret')
```

### Issuer Claim

> The "iss" (issuer) claim identifies the principal that issued the
> JWT.  The processing of this claim is generally application specific.
> The "iss" value is a case-sensitive string containing a StringOrURI
> value.  Use of this claim is OPTIONAL.

```python
import jwt


payload = {
    'some': 'payload',
    'iss': 'urn:foo'
}

token = jwt.encode(payload, 'secret')
decoded = jwt.decode(token, 'secret', issuer='urn:foo')
```

If the issuer claim is incorrect, `jwt.InvalidIssuerError` will be raised.


### Audience Claim

> The "aud" (audience) claim identifies the recipients that the JWT is
> intended for.  Each principal intended to process the JWT MUST
> identify itself with a value in the audience claim.  If the principal
> processing the claim does not identify itself with a value in the
> "aud" claim when this claim is present, then the JWT MUST be
> rejected.  In the general case, the "aud" value is an array of case-
> sensitive strings, each containing a StringOrURI value.  In the
> special case when the JWT has one audience, the "aud" value MAY be a
> single case-sensitive string containing a StringOrURI value.  The
> interpretation of audience values is generally application specific.
> Use of this claim is OPTIONAL.

```python
import jwt


payload = {
    'some': 'payload',
    'aud': 'urn:foo'
}

token = jwt.encode(payload, 'secret')
decoded = jwt.decode(token, 'secret', audience='urn:foo')
```

If the audience claim is incorrect, `jwt.InvalidAudienceError` will be raised.

### Issued At Claim

> The iat (issued at) claim identifies the time at which the JWT was issued.
> This claim can be used to determine the age of the JWT. Its value MUST be a
> number containing a NumericDate value. Use of this claim is OPTIONAL.

If the `iat` claim is in the future, an `jwt.InvalidIssuedAtError` exception
will be raised.

```python
jwt.encode({'iat': 1371720939}, 'secret')

jwt.encode({'iat': datetime.utcnow()}, 'secret')
```

## Frequently Asked Questions

**How can I extract a public / private key from a x509 certificate?**

The `load_pem_x509_certificate()` function from `cryptography` can be used to
extract the public or private keys from a x509 certificate in PEM format.

```python
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

cert_str = "-----BEGIN CERTIFICATE-----MIIDETCCAfm..."
cert_obj = load_pem_x509_certificate(cert_str, default_backend())
public_key = cert_obj.public_key()
private_key = cert_obj.private_key()
```

[travis-status-image]: https://secure.travis-ci.org/jpadilla/pyjwt.svg?branch=master
[travis]: http://travis-ci.org/jpadilla/pyjwt?branch=master
[appveyor-status-image]: https://ci.appveyor.com/api/projects/status/h8nt70aqtwhht39t?svg=true
[appveyor]: https://ci.appveyor.com/project/jpadilla/pyjwt
[pypi-version-image]: https://img.shields.io/pypi/v/pyjwt.svg
[pypi]: https://pypi.python.org/pypi/pyjwt
[coveralls-status-image]: https://coveralls.io/repos/jpadilla/pyjwt/badge.svg?branch=master
[coveralls]: https://coveralls.io/r/jpadilla/pyjwt?branch=master
[jwt-spec]: https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32
[jwt-spec-reg-claims]: http://self-issued.info/docs/draft-jones-json-web-token-01.html#ReservedClaimName
[progrium]: https://github.com/progrium
