# Threat model

This file is self-contained. It summarises the "Threat Model" section of
`SECURITY.md` at the repository root (`/src/SECURITY.md` in the scanner
image), which is the authoritative version and has more detail.

## Trust assumptions

- The attacker can supply arbitrary JWTs, JWSs, JWKs, JWKS responses, key
  identifiers, headers, claims, signatures and payloads.
- The application's keys, algorithm allowlist, validation options, JWKS URL,
  runtime, network and caches are trusted and not compromised.
- The application picks the allowed algorithms independently of the token's
  `alg` header: an explicit `algorithms` list for raw keys, or the algorithm
  bound to a `PyJWK` obtained from trusted configuration.
- PyJWT validates only the claims the application asked it to validate.
- `cryptography`, OpenSSL and the Python standard library are assumed to
  implement their primitives correctly.
- PyJWT does not impose hard size limits on input; applications limit input
  size and request rates. PyJWT is still responsible for not doing
  unnecessary or disproportionate work.

## What PyJWT guarantees when configured correctly

- Correct implementation of the supported JWT, JWS, JWK and JWA operations.
- Signature verification with trusted keys and either an explicit algorithm
  allowlist or the algorithm bound to a `PyJWK`.
- Validation of `exp`, `nbf`, `iat`, `aud`, `iss`, `sub` and `jti` according
  to the arguments and options the application supplies.
- Rejection of malformed or unsupported input where safe processing needs it.

## Not a PyJWT vulnerability (do not report)

Unless PyJWT violates a check the application explicitly configured, or uses
an underlying primitive incorrectly:

- Authentication or authorization failures caused by application policy,
  including claims the application did not require or validate.
- Treating unverified headers or payloads as authenticated, including data
  decoded with `verify_signature=False` or read with `get_unverified_header`.
- Choosing allowed algorithms, keys or trust anchors from attacker-controlled
  token data.
- Weak, exposed, badly generated or mismanaged keys and secrets supplied by
  the application.
- Failures caused by an untrusted JWKS source, insecure transport, a
  user-configured proxy, or a writable cache.
- Treating the original JWT string as a canonical identity (more than one
  encoding can decode to the same content).
- Missing replay prevention, revocation, nonce validation, session binding,
  rate limiting or resource controls in the application.
- Resource exhaustion caused only by input volume or size, where PyJWT does
  no unnecessary or disproportionate work.
- Reading secrets via a debugger, process memory, heap or core dumps, or any
  other runtime compromise; no secure memory erasure is promised.
- Bugs in a compromised or malicious runtime, OS, dependency, crypto library
  or hardware, and side channels that exist only in those components.

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
described above. Findings that require `verify_signature=False`,
an algorithm list derived from the token, attacker-supplied keys, or a
compromised runtime are not vulnerabilities.

## Anything to leave alone

- Timing side channels that exist only in `cryptography`/OpenSSL or the
  Python runtime.
- Resource exhaustion that is purely proportional to input size.
- Lack of key-size enforcement: PyJWT and its dependencies may reject some
  weak keys, but enforcing every key-size recommendation is not promised.
