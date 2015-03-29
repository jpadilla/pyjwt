Change Log
=========================================================================

[Unreleased][unreleased]
-------------------------------------------------------------------------
### Changed
- Added this CHANGELOG.md file

### Fixed
- Placeholder

[v1.0.1][1.0.1]
-------------------------------------------------------------------------
### Fixed
- Include jwt/contrib' andjwt/contrib/algorithms` in setup.py so that they will
  actually be included when installing. Ref 882524d
- Fix bin/jwt after removing jwt.header() Ref bd57b02

[v1.0.0][1.0.0]
-------------------------------------------------------------------------
### Changed
- Moved `jwt.api.header` out of the public API #85
- Added README details how to extract public / private keys from an x509 certificate. #100
- Refactor api.py functions into an object (`PyJWT`). #101
- Added support for PyCrypto and ecdsa when cryptography isn't available. #103

### Fixed
- Fixed a security vulnerability where `alg=None` header could bypass signature verification #109
- Fixed a security vulnerability by adding support for a whitelist of allowed `alg` values `jwt.decode(algorithms=[])` #110


[unreleased]: https://github.com/jpadilla/pyjwt/compare/1.0.1...HEAD
[1.0.1]: https://github.com/jpadilla/pyjwt/compare/1.0.0...1.0.1
[1.0.0]: https://github.com/jpadilla/pyjwt/compare/0.4.3...1.0.0
