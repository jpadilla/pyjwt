Change Log
=========================================================================

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

[v1.4][1.4.0]
-------------------------------------------------------------------------
### Fixed
- Exclude Python cache files from PyPI releases.

### Added
- Added new options to require certain claims
  (require_nbf, require_iat, require_exp) and raise `MissingRequiredClaimError`
  if they are not present.
- If `audience=` or `issuer=` is specified but the claim is not present,
  `MissingRequiredClaimError` is now raised instead of `InvalidAudienceError`
  and `InvalidIssuerError`

[v1.3][1.3.0]
-------------------------------------------------------------------------
### Fixed
- ECDSA (ES256, ES384, ES512) signatures are now being properly serialized [#158][158]
- RSA-PSS (PS256, PS384, PS512) signatures now use the proper salt length for PSS padding. [#163][163]

### Added
- Added a new `jwt.get_unverified_header()` to parse and return the header portion of a token prior to signature verification.

### Removed
- Python 3.2 is no longer a supported platform. This version of Python is
rarely used. Users affected by this should upgrade to 3.3+.

[v1.2.0][1.2.0]
-------------------------------------------------------------------------
### Fixed
- Added back `verify_expiration=` argument to `jwt.decode()` that was erroneously removed in [v1.1.0][1.1.0].


### Changed
- Refactored JWS-specific logic out of PyJWT and into PyJWS superclass. [#141][141]

### Deprecated
- `verify_expiration=` argument to `jwt.decode()` is now deprecated and will be removed in a future version. Use the `option=` argument instead.

[v1.1.0][1.1.0]
-------------------------------------------------------------------------
### Added
- Added support for PS256, PS384, and PS512 algorithms. [#132][132]
- Added flexible and complete verification options during decode. [#131][131]
- Added this CHANGELOG.md file.


### Deprecated
- Deprecated usage of the .decode(..., verify=False) parameter.


### Fixed
- Fixed command line encoding. [#128][128]

[v1.0.1][1.0.1]
-------------------------------------------------------------------------
### Fixed
- Include jwt/contrib' and jwt/contrib/algorithms` in setup.py so that they will
  actually be included when installing. [882524d][882524d]
- Fix bin/jwt after removing jwt.header(). [bd57b02][bd57b02]

[v1.0.0][1.0.0]
-------------------------------------------------------------------------
### Changed
- Moved `jwt.api.header` out of the public API. [#85][85]
- Added README details how to extract public / private keys from an x509 certificate. [#100][100]
- Refactor api.py functions into an object (`PyJWT`). [#101][101]
- Added support for PyCrypto and ecdsa when cryptography isn't available. [#101][103]

### Fixed
- Fixed a security vulnerability where `alg=None` header could bypass signature verification. [#109][109]
- Fixed a security vulnerability by adding support for a whitelist of allowed `alg` values `jwt.decode(algorithms=[])`. [#110][110]


[unreleased]: https://github.com/jpadilla/pyjwt/compare/1.3.0...HEAD
[1.0.0]: https://github.com/jpadilla/pyjwt/compare/0.4.3...1.0.0
[1.0.1]: https://github.com/jpadilla/pyjwt/compare/1.0.0...1.0.1
[1.0.1]: https://github.com/jpadilla/pyjwt/compare/1.0.0...1.0.1
[1.0.1]: https://github.com/jpadilla/pyjwt/compare/1.0.0...1.0.1
[1.1.0]: https://github.com/jpadilla/pyjwt/compare/1.0.1...1.1.0
[1.2.0]: https://github.com/jpadilla/pyjwt/compare/1.1.0...1.2.0
[1.3.0]: https://github.com/jpadilla/pyjwt/compare/1.2.0...1.3.0
[1.4.0]: https://github.com/jpadilla/pyjwt/compare/1.3.0...1.4.0


[109]: https://github.com/jpadilla/pyjwt/pull/109
[110]: https://github.com/jpadilla/pyjwt/pull/110
[100]: https://github.com/jpadilla/pyjwt/pull/100
[101]: https://github.com/jpadilla/pyjwt/pull/101
[103]: https://github.com/jpadilla/pyjwt/pull/103
[85]: https://github.com/jpadilla/pyjwt/pull/85
[882524d]: https://github.com/jpadilla/pyjwt/commit/882524d
[bd57b02]: https://github.com/jpadilla/pyjwt/commit/bd57b02
[131]: https://github.com/jpadilla/pyjwt/pull/131
[132]: https://github.com/jpadilla/pyjwt/pull/132
[128]: https://github.com/jpadilla/pyjwt/pull/128
[141]: https://github.com/jpadilla/pyjwt/pull/141
[158]: https://github.com/jpadilla/pyjwt/pull/158
[163]: https://github.com/jpadilla/pyjwt/pull/163
