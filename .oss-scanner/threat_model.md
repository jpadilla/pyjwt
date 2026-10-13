# Threat model

The authoritative threat model for PyJWT is the "Threat Model" section of
[`SECURITY.md`](../SECURITY.md) at the repository root (`/src/SECURITY.md` in
the scanner image). Read it first; this file only adds scanner-specific notes.
Anything SECURITY.md lists under "What Is Not Considered a PyJWT
Vulnerability" should not be reported.

## What this project does and where untrusted input enters

PyJWT is a pure-Python library implementing JWT (RFC 7519), JWS (RFC 7515),
JWK (RFC 7517) and JWA (RFC 7518). It has no network-facing server of its own.
Untrusted input enters through:

- the compact token string passed to `jwt.decode`, `jwt.decode_complete`,
  `jwt.api_jws.PyJWS.decode*` and `jwt.get_unverified_header`
- JWK / JWKS JSON passed to `PyJWK`, `PyJWKSet` and `PyJWKClient`, including
  JWKS responses fetched over HTTP by `PyJWKClient`
- the `kid` and other header values that select keys

Keys, algorithm allowlists, and validation options are supplied by the
application and are trusted.

## Components that matter most / least

- Most important: `jwt/api_jws.py`, `jwt/api_jwt.py` (signature verification,
  algorithm selection, claim validation), `jwt/algorithms.py` (key parsing and
  sign/verify for HMAC, RSA, RSA-PSS, EC, EdDSA), `jwt/api_jwk.py` and
  `jwt/jwks_client.py` (key set parsing, key selection by `kid`, caching).
- Less important: `jwt/help.py`, `jwt/warnings.py`, `docs/`.
- Out of scope: `tests/`, and bugs that exist solely in `cryptography`,
  OpenSSL or CPython.

## How to exercise it

- The package is installed in editable mode with the `crypto` extra, so
  `import jwt` uses the code in `/src/jwt`.
- Run the test suite with `python -m pytest` from `/src`. Tests in
  `tests/test_jwks_client.py` mock the network.
- A reproducer should be a short Python script that calls the public API
  (`jwt.encode`, `jwt.decode`, `PyJWK`, `PyJWKClient`, ...) with realistic,
  application-chosen arguments and shows the security property being broken.

## How you rate severity

- Critical: forging a token that `jwt.decode` accepts as verified when the
  application passed a trusted key and an explicit `algorithms` allowlist
  (or a `PyJWK` with a bound algorithm) — e.g. signature bypass, algorithm
  confusion, `none` accepted, key-type confusion between HMAC and asymmetric
  keys.
- High: a registered claim check (`exp`, `nbf`, `iat`, `aud`, `iss`, `sub`,
  `jti`, required claims) that the application explicitly enabled is skipped
  or evaluated incorrectly; selecting a key outside the configured JWKS;
  disclosure of key material.
- Medium: disproportionate CPU or memory use from small attacker-controlled
  input (e.g. super-linear parsing, decompression bombs) where PyJWT does
  unnecessary work; incorrect rejection/acceptance of malformed input that
  has a plausible security impact.
- Low / informational: hardening suggestions, missing warnings, behaviour that
  only matters with insecure application configuration.

Reports must show the issue under a correct application configuration as
described in SECURITY.md. Findings that require `verify_signature=False`,
an algorithm list derived from the token, attacker-supplied keys, or a
compromised runtime are not vulnerabilities.

## Anything to leave alone

- Timing side channels that exist only in `cryptography`/OpenSSL or the
  Python runtime.
- Resource exhaustion that is purely proportional to input size.
- Lack of key-size enforcement beyond what SECURITY.md promises.
