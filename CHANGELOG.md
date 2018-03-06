Change Log
=========================================================================

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

[Unreleased][unreleased]
-------------------------------------------------------------------------
### Changed

### Fixed

### Added

[v1.6.0][1.6.0]
-------------------------------------------------------------------------
### Changed

- Dropped support for python 2.6 and 3.3 [#301][301]
- An invalid signature now raises an `InvalidSignatureError` instead of `DecodeError` [#316][316]

### Fixed

- Fix over-eager fallback to stdin [#304][304]

### Added

- Audience parameter now supports iterables [#306][306]

[v1.5.3][1.5.3]
-------------------------------------------------------------------------
### Changed

- Increase required version of the cryptography package to >=1.4.0.

### Fixed

- Remove uses of deprecated functions from the cryptography package.
- Warn about missing `algorithms` param to `decode()` only when `verify` param is `True` [#281][281]

[v1.5.2][1.5.2]
-------------------------------------------------------------------------
### Fixed

- Ensure correct arguments order in decode super call [7c1e61d][7c1e61d]

[v1.5.1][1.5.1]
-------------------------------------------------------------------------
### Changed

- Change optparse for argparse. [#238][238]

### Fixed

- Guard against PKCS1 PEM encododed public keys [#277][277]
- Add deprecation warning when decoding without specifying `algorithms` [#277][277]
- Improve deprecation messages [#270][270]
- PyJWT.decode: move verify param into options [#271][271]

### Added

- Support for Python 3.6 [#262][262]
- Expose jwt.InvalidAlgorithmError [#264][264]

[v1.5.0][1.5.0]
-------------------------------------------------------------------------
### Changed
- Add support for ECDSA public keys in RFC 4253 (OpenSSH) format [#244][244]
- Renamed commandline script `jwt` to `jwt-cli` to avoid issues with the script clobbering the `jwt` module in some circumstances. [#187][187]
- Better error messages when using an algorithm that requires the cryptography package, but it isn't available [#230][230]
- Tokens with future 'iat' values are no longer rejected [#190][190]
- Non-numeric 'iat' values now raise InvalidIssuedAtError instead of DecodeError
- Remove rejection of future 'iat' claims [#252][252]

### Fixed
- Add back 'ES512' for backward compatibility (for now) [#225][225]
- Fix incorrectly named ECDSA algorithm [#219][219]
- Fix rpm build [#196][196]

### Added
- Add JWK support for HMAC and RSA keys [#202][202]

[v1.4.2][1.4.2]
-------------------------------------------------------------------------
### Fixed
- A PEM-formatted key encoded as bytes could cause a `TypeError` to be raised [#213][213]

[v1.4.1][1.4.1]
-------------------------------------------------------------------------
### Fixed
- Newer versions of Pytest could not detect warnings properly [#182][182]
- Non-string 'kid' value now raises `InvalidTokenError` [#174][174]
- `jwt.decode(None)` now gracefully fails with `InvalidTokenError` [#183][183]

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


[unreleased]: https://github.com/jpadilla/pyjwt/compare/1.4.2...HEAD
[1.0.0]: https://github.com/jpadilla/pyjwt/compare/0.4.3...1.0.0
[1.0.1]: https://github.com/jpadilla/pyjwt/compare/1.0.0...1.0.1
[1.0.1]: https://github.com/jpadilla/pyjwt/compare/1.0.0...1.0.1
[1.0.1]: https://github.com/jpadilla/pyjwt/compare/1.0.0...1.0.1
[1.1.0]: https://github.com/jpadilla/pyjwt/compare/1.0.1...1.1.0
[1.2.0]: https://github.com/jpadilla/pyjwt/compare/1.1.0...1.2.0
[1.3.0]: https://github.com/jpadilla/pyjwt/compare/1.2.0...1.3.0
[1.4.0]: https://github.com/jpadilla/pyjwt/compare/1.3.0...1.4.0
[1.4.1]: https://github.com/jpadilla/pyjwt/compare/1.4.0...1.4.1
[1.4.2]: https://github.com/jpadilla/pyjwt/compare/1.4.1...1.4.2
[1.5.0]: https://github.com/jpadilla/pyjwt/compare/1.4.2...1.5.0
[1.5.1]: https://github.com/jpadilla/pyjwt/compare/1.5.0...1.5.1
[1.5.2]: https://github.com/jpadilla/pyjwt/compare/1.5.1...1.5.2
[1.5.3]: https://github.com/jpadilla/pyjwt/compare/1.5.2...1.5.3
[1.6.0]: https://github.com/jpadilla/pyjwt/compare/1.5.3...1.6.0

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
[174]: https://github.com/jpadilla/pyjwt/pull/174
[182]: https://github.com/jpadilla/pyjwt/pull/182
[183]: https://github.com/jpadilla/pyjwt/pull/183
[190]: https://github.com/jpadilla/pyjwt/pull/190
[213]: https://github.com/jpadilla/pyjwt/pull/214
[244]: https://github.com/jpadilla/pyjwt/pull/244
[202]: https://github.com/jpadilla/pyjwt/pull/202
[252]: https://github.com/jpadilla/pyjwt/pull/252
[225]: https://github.com/jpadilla/pyjwt/pull/225
[219]: https://github.com/jpadilla/pyjwt/pull/219
[196]: https://github.com/jpadilla/pyjwt/pull/196
[187]: https://github.com/jpadilla/pyjwt/pull/187
[230]: https://github.com/jpadilla/pyjwt/pull/230
[238]: https://github.com/jpadilla/pyjwt/pull/238
[262]: https://github.com/jpadilla/pyjwt/pull/262
[264]: https://github.com/jpadilla/pyjwt/pull/264
[270]: https://github.com/jpadilla/pyjwt/pull/270
[271]: https://github.com/jpadilla/pyjwt/pull/271
[277]: https://github.com/jpadilla/pyjwt/pull/277
[281]: https://github.com/jpadilla/pyjwt/pull/281
[301]: https://github.com/jpadilla/pyjwt/pull/301
[304]: https://github.com/jpadilla/pyjwt/pull/304
[306]: https://github.com/jpadilla/pyjwt/pull/306
[315]: https://github.com/jpadilla/pyjwt/pull/315
[316]: https://github.com/jpadilla/pyjwt/pull/316
[7c1e61d]: https://github.com/jpadilla/pyjwt/commit/7c1e61dde27bafe16e7d1bb6e35199e778962742
