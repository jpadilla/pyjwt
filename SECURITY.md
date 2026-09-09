# Security Policy

This policy was adapted from the
[`panva/jose` security policy](https://github.com/panva/jose/security), with
thanks to its maintainers for documenting a clear threat model and disclosure
process.

## Supported Versions

The following major version is currently supported with security updates.

| Version | End of life |
| ------- | ----------- |
| 2.x     | TBD         |

End of life for the current major version will be determined before its
successor is released.

## Reporting a Vulnerability

Report vulnerabilities through the project's
[private vulnerability reporting workflow](https://github.com/jpadilla/pyjwt/security/advisories/new).

All vulnerability reports must use this channel so that the maintainers can
privately assess the report, collaborate on a fix, and coordinate disclosure.
Do not open a public issue for a suspected vulnerability.

Only the maintainers, or reporters who have received the maintainers' explicit
consent, may request or coordinate CVE identifiers for PyJWT. This applies to
confirmed, rejected, disputed, and untriaged reports. Submitting a private
report does not authorize a reporter to contact a third-party CVE Numbering
Authority on the project's behalf.

A report rejected through the documented channel remains subject to this
disclosure process. Rejection does not authorize a reporter to seek a CVE from
a third-party CNA. The maintainers may request the rejection, withdrawal, or
dispute of CVE records coordinated without their prior explicit consent.

## Threat Model

PyJWT is a Python implementation of JSON Web Token (JWT) and JSON Web Signature
(JWS) standards, including
[RFC 7519](https://www.rfc-editor.org/rfc/rfc7519),
[RFC 7515](https://www.rfc-editor.org/rfc/rfc7515), and the related JSON Web Key
(JWK) and JSON Web Algorithms (JWA) specifications.

### Purpose and Intended Users

PyJWT provides JWT and JWS protocol primitives for Python applications. It is
not a complete authentication, authorization, identity, session-management, or
application-security framework. Applications decide what verified claims mean
and whether they authorize an operation.

### Trust Assumptions

#### Cryptographic Implementations

PyJWT relies on Python's standard library and, for asymmetric algorithms, the
`cryptography` package and its underlying cryptographic implementations. PyJWT
assumes those implementations correctly perform their documented operations.
Vulnerabilities in those dependencies are outside PyJWT's threat model unless
PyJWT uses them incorrectly or bypasses their security properties.

#### Runtime Environment

PyJWT assumes a trusted Python process and operating environment. An attacker
who can alter imported modules, inspect or modify process memory, attach a
debugger, replace dependencies, or otherwise control the runtime has already
crossed this trust boundary.

#### Application Policy

Applications are responsible for defining and enforcing their authentication
and authorization policy. This includes choosing trusted signing algorithms and
keys; accepted issuers, audiences, subjects, and token types; required claims;
maximum token age; clock-skew allowances; replay prevention; nonce and `jti`
handling; revocation; session binding; custom-claim validation; and every
authorization decision.

PyJWT validates claims according to the arguments and options supplied by the
application. A claim that the application did not require or validate is an
application-policy concern unless PyJWT was instructed to validate it and
failed to do so correctly.

#### Algorithm and Key Selection

JWT headers and claims are untrusted until verified. Applications must establish
a trusted algorithm policy independently of the token's `alg` header and must
not derive that policy from untrusted token data. For raw keys, this means
passing an explicit `algorithms` allowlist. When using a `PyJWK`, the key's bound
algorithm provides that policy, so the application must obtain the key from a
trusted configuration or key set. Applications must also ensure that symmetric
and asymmetric algorithms are not confused.

#### Unverified Data

Data returned with signature verification disabled, or by an API whose purpose
is to inspect unverified headers, is not authenticated. Applications must not
use that data for security decisions before completing signature verification
and all required claim validation.

#### Token String Identity

Applications should not assume that the original compact JWT string is a
canonical security identity. JWT processing operates on decoded bytes and JSON
values, and more than one textual representation can decode to equivalent
content. Authentication, authorization, replay detection, revocation, caching,
and session binding should use validated claims, trusted keys, protected header
values, decoded bytes, or an application-defined canonical representation.

#### JWKS Sources

When `PyJWKClient` retrieves a JSON Web Key Set, the application is responsible
for trusting the configured URL and its transport, controlling access to the
destination, and protecting any surrounding proxy or cache. Applications must
confine key selection based on an attacker-controlled `kid` to a JWKS they have
independently chosen to trust.

#### Key Material

PyJWT assumes that keys and secrets supplied by the application are authentic,
appropriate for the selected algorithm, and handled securely. Generating,
storing, rotating, distributing, and revoking key material are application
responsibilities.

#### Key and Secret Sizes

Applications must choose key and secret sizes that meet their security
requirements. PyJWT and its dependencies may reject some inadequate keys, but
PyJWT does not promise to enforce every current or future key-size
recommendation for every supported algorithm.

#### Input and Resource Limits

PyJWT does not generally impose hard size or complexity limits on tokens,
payloads, headers, keys, or JWKS documents. Applications must limit
attacker-controlled input sizes, request rates, remote-response sizes, and
resource consumption as appropriate for their environment. PyJWT remains
responsible for avoiding unnecessary or disproportionate work while processing
those inputs.

#### Side Channels

Resistance to timing, cache, memory, and other side-channel attacks depends on
Python, PyJWT's dependencies, the operating system, and the hardware. Problems
caused solely by those underlying components are outside PyJWT's threat model.

### Security Guarantees

PyJWT aims to provide the following properties when its APIs are configured
correctly:

- Correct implementation of the supported JWT, JWS, JWK, and JWA operations.
- Signature verification using trusted key material and either an explicit
  algorithm allowlist or the algorithm bound to a `PyJWK`.
- Validation of registered claims such as `exp`, `nbf`, `iat`, `aud`, `iss`,
  `sub`, and `jti` according to application-supplied arguments and options.
- Rejection of malformed or unsupported inputs where required for safe protocol
  processing.

### Out of Scope

#### Authentication and Authorization Policy

PyJWT does not decide whether a token grants access to an application resource.
User and session state, token revocation, replay prevention, nonce storage,
custom-claim rules, required-claim policy, and authorization remain the
application's responsibility.

#### Key Management

PyJWT does not provide secure key storage or a complete key-management system.

#### Secure Memory Erasure

PyJWT does not guarantee that keys, token contents, or other sensitive data are
removed from process memory after use. Memory-management guarantees depend on
Python, dependencies, and the runtime environment.

### Threat Actors and Security Properties

The primary in-scope attacker can provide arbitrary JWTs, JWSs, JWKs, JWKS
responses, key identifiers, headers, claims, signatures, and payloads to an
application using PyJWT. The threat model assumes the application's trusted
keys, configured algorithms, validation options, JWKS locations, runtime,
network controls, and caches have not been compromised.

For the underlying protocol security properties, see the Security
Considerations sections of
[RFC 7515](https://www.rfc-editor.org/rfc/rfc7515#section-10),
[RFC 7517](https://www.rfc-editor.org/rfc/rfc7517#section-9),
[RFC 7518](https://www.rfc-editor.org/rfc/rfc7518#section-8), and
[RFC 7519](https://www.rfc-editor.org/rfc/rfc7519#section-11).

### What Is Not Considered a PyJWT Vulnerability

The following are not vulnerabilities in PyJWT unless PyJWT violates an
explicitly configured security check or incorrectly uses an underlying
primitive:

- Authentication or authorization failures caused by application policy,
  including claims the application did not require or validate.
- Use of unverified headers or payloads as authenticated data, including data
  decoded with signature verification disabled.
- Selection of allowed algorithms, keys, or trust anchors from
  attacker-controlled token data.
- Use of weak, exposed, incorrectly generated, or incorrectly managed keys and
  secrets supplied by the application.
- Security failures caused by an untrusted JWKS source, insecure transport,
  user-configured proxy, or writable cache.
- Treating the original JWT string as a canonical identity without defining
  and enforcing an application-specific canonical representation.
- Missing replay prevention, revocation, nonce validation, session binding,
  rate limiting, or resource controls in the application.
- Ordinary resource exhaustion caused solely by input volume or size where
  PyJWT performs no unnecessary or disproportionate work and the application
  did not enforce suitable limits.
- Inspection of secrets through debugger access, process-memory access, heap or
  core dumps, or other runtime-level compromise.
- Vulnerabilities in a compromised or malicious Python runtime, operating
  system, dependency, cryptographic library, or hardware implementation.
- Side-channel weaknesses that exist solely in an underlying cryptographic
  implementation or execution environment.
