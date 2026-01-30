Changelog
=========

All notable changes to this project will be documented in this file.
This project adheres to `Semantic Versioning <https://semver.org/>`__.

`Unreleased <https://github.com/jpadilla/pyjwt/compare/2.11.0...HEAD>`__
------------------------------------------------------------------------

Fixed
~~~~~

Added
~~~~~

`v2.11.0 <https://github.com/jpadilla/pyjwt/compare/2.10.1...2.11.0>`__
-----------------------------------------------------------------------

Fixed
~~~~~

- Enforce ECDSA curve validation per RFC 7518 Section 3.4.
- Fix build system warnings by @kurtmckee in `#1105 <https://github.com/jpadilla/pyjwt/pull/1105>`__
- Validate key against allowed types for Algorithm family in `#964 <https://github.com/jpadilla/pyjwt/pull/964>`__
- Add iterator for JWKSet in `#1041 <https://github.com/jpadilla/pyjwt/pull/1041>`__
- Validate `iss` claim is a string during encoding and decoding by @pachewise in `#1040 <https://github.com/jpadilla/pyjwt/pull/1040>`__
- Improve typing/logic for `options` in decode, decode_complete by @pachewise in `#1045 <https://github.com/jpadilla/pyjwt/pull/1045>`__
- Declare float supported type for lifespan and timeout by @nikitagashkov in `#1068 <https://github.com/jpadilla/pyjwt/pull/1068>`__
- Fix ``SyntaxWarning``\s/``DeprecationWarning``\s caused by invalid escape sequences by @kurtmckee in `#1103 <https://github.com/jpadilla/pyjwt/pull/1103>`__
- Development: Build a shared wheel once to speed up test suite setup times by @kurtmckee in `#1114 <https://github.com/jpadilla/pyjwt/pull/1114>`__
- Development: Test type annotations across all supported Python versions,
  increase the strictness of the type checking, and remove the mypy pre-commit hook
  by @kurtmckee in `#1112 <https://github.com/jpadilla/pyjwt/pull/1112>`__

Added
~~~~~

- Support Python 3.14, and test against PyPy 3.10 and 3.11 by @kurtmckee in `#1104 <https://github.com/jpadilla/pyjwt/pull/1104>`__
- Development: Migrate to ``build`` to test package building in CI by @kurtmckee in `#1108 <https://github.com/jpadilla/pyjwt/pull/1108>`__
- Development: Improve coverage config and eliminate unused test suite code by @kurtmckee in `#1115 <https://github.com/jpadilla/pyjwt/pull/1115>`__
- Docs: Standardize CHANGELOG links to PRs by @kurtmckee in `#1110 <https://github.com/jpadilla/pyjwt/pull/1110>`__
- Docs: Fix Read the Docs builds by @kurtmckee in `#1111 <https://github.com/jpadilla/pyjwt/pull/1111>`__
- Docs: Add example of using leeway with nbf by @djw8605 in `#1034 <https://github.com/jpadilla/pyjwt/pull/1034>`__
- Docs: Refactored docs with ``autodoc``; added ``PyJWS`` and ``jwt.algorithms`` docs by @pachewise in `#1045 <https://github.com/jpadilla/pyjwt/pull/1045>`__
- Docs: Documentation improvements for "sub" and "jti" claims by @cleder in `#1088 <https://github.com/jpadilla/pyjwt/pull/1088>`__
- Development: Add pyupgrade as a pre-commit hook by @kurtmckee in `#1109 <https://github.com/jpadilla/pyjwt/pull/1109>`__
- Add minimum key length validation for HMAC and RSA keys (CWE-326).
  Warns by default via ``InsecureKeyLengthWarning`` when keys are below
  minimum recommended lengths per RFC 7518 Section 3.2 (HMAC) and
  NIST SP 800-131A (RSA). Pass ``enforce_minimum_key_length=True`` in
  options to ``PyJWT`` or ``PyJWS`` to raise ``InvalidKeyError`` instead.
- Refactor ``PyJWT`` to own an internal ``PyJWS`` instance instead of
  calling global ``api_jws`` functions.

`v2.10.1 <https://github.com/jpadilla/pyjwt/compare/2.10.0...2.10.1>`__
-----------------------------------------------------------------------


Fixed
~~~~~

- Prevent partial matching of `iss` claim by @fabianbadoi in `GHSA-75c5-xw7c-p5pm <https://github.com/jpadilla/pyjwt/security/advisories/GHSA-75c5-xw7c-p5pm>`__


`v2.10.0 <https://github.com/jpadilla/pyjwt/compare/2.9.0...2.10.0>`__
-----------------------------------------------------------------------


Changed
~~~~~~~

- Remove algorithm requirement from JWT API, instead relying on JWS API for enforcement, by @luhn in `#975 <https://github.com/jpadilla/pyjwt/pull/975>`__
- Use ``Sequence`` for parameter types rather than ``List`` where applicable by @imnotjames in `#970 <https://github.com/jpadilla/pyjwt/pull/970>`__
- Add JWK support to JWT encode by @luhn in `#979 <https://github.com/jpadilla/pyjwt/pull/979>`__
- Encoding and decoding payloads using the `none` algorithm by @jpadilla in `#c2629f6 <https://github.com/jpadilla/pyjwt/commit/c2629f66c593459e02616048443231ccbe18be16>`__

  Before:

  .. code-block:: pycon

   >>> import jwt
   >>> jwt.encode({"payload": "abc"}, key=None, algorithm=None)

  After:

  .. code-block:: pycon

   >>> import jwt
   >>> jwt.encode({"payload": "abc"}, key=None, algorithm="none")

- Added validation for 'sub' (subject) and 'jti' (JWT ID) claims in tokens by @Divan009 in `#1005 <https://github.com/jpadilla/pyjwt/pull/1005>`__
- Refactor project configuration files from ``setup.cfg`` to ``pyproject.toml`` by @cleder in `#995 <https://github.com/jpadilla/pyjwt/pull/995>`__
- Ruff linter and formatter changes by @gagandeepp in `#1001 <https://github.com/jpadilla/pyjwt/pull/1001>`__
- Drop support for Python 3.8 (EOL) by @kkirsche in `#1007 <https://github.com/jpadilla/pyjwt/pull/1007>`__


Fixed
~~~~~

- Encode EC keys with a fixed bit length by @etianen in `#990 <https://github.com/jpadilla/pyjwt/pull/990>`__
- Add an RTD config file to resolve Read the Docs build failures by @kurtmckee in `#977 <https://github.com/jpadilla/pyjwt/pull/977>`__
- Docs: Update ``iat`` exception docs by @pachewise in `#974 <https://github.com/jpadilla/pyjwt/pull/974>`__
- Docs: Fix ``decode_complete`` scope and algorithms by @RbnRncn in `#982 <https://github.com/jpadilla/pyjwt/pull/982>`__
- Fix doctest for ``docs/usage.rst`` by @pachewise in `#986 <https://github.com/jpadilla/pyjwt/pull/986>`__
- Fix ``test_utils.py`` not to xfail by @pachewise in `#987 <https://github.com/jpadilla/pyjwt/pull/987>`__
- Docs: Correct `jwt.decode` audience param doc expression by @peter279k in `#994 <https://github.com/jpadilla/pyjwt/pull/994>`__

Added
~~~~~


- Add support for python 3.13 by @hugovk in `#972 <https://github.com/jpadilla/pyjwt/pull/972>`__
- Create SECURITY.md by @auvipy and @jpadilla in `#973 <https://github.com/jpadilla/pyjwt/pull/973>`__
- Docs: Add PS256 encoding and decoding usage by @peter279k in `#992 <https://github.com/jpadilla/pyjwt/pull/992>`__
- Docs: Add API docs for PyJWK by @luhn in `#980 <https://github.com/jpadilla/pyjwt/pull/980>`__
- Docs: Add EdDSA algorithm encoding/decoding usage by @peter279k in `#993 <https://github.com/jpadilla/pyjwt/pull/993>`__
- Include checkers and linters for ``pyproject.toml`` in ``pre-commit`` by @cleder in `#1002 <https://github.com/jpadilla/pyjwt/pull/1002>`__
- Docs: Add ES256 decoding usage by @Gautam-Hegde in `#1003 <https://github.com/jpadilla/pyjwt/pull/1003>`__

`v2.9.0 <https://github.com/jpadilla/pyjwt/compare/2.8.0...2.9.0>`__
-----------------------------------------------------------------------

Changed
~~~~~~~

- Drop support for Python 3.7 (EOL) by @hugovk in `#910 <https://github.com/jpadilla/pyjwt/pull/910>`__
- Allow JWT issuer claim validation to accept a list of strings too by @mattpollak in `#913 <https://github.com/jpadilla/pyjwt/pull/913>`__

Fixed
~~~~~

- Fix unnecessary string concatenation by @sirosen in `#904 <https://github.com/jpadilla/pyjwt/pull/904>`__
- Fix docs for ``jwt.decode_complete`` to include ``strict_aud`` option by @woodruffw in `#923 <https://github.com/jpadilla/pyjwt/pull/923>`__
- Fix docs step by @jpadilla in `#950 <https://github.com/jpadilla/pyjwt/pull/950>`__
- Fix: Remove an unused variable from example code block by @kenkoooo in `#958 <https://github.com/jpadilla/pyjwt/pull/958>`__

Added
~~~~~

- Add support for Python 3.12 by @hugovk in `#910 <https://github.com/jpadilla/pyjwt/pull/910>`__
- Improve performance of ``is_ssh_key`` + add unit test by @bdraco in `#940 <https://github.com/jpadilla/pyjwt/pull/940>`__
- Allow ``jwt.decode()`` to accept a PyJWK object by @luhn in `#886 <https://github.com/jpadilla/pyjwt/pull/886>`__
- Make ``algorithm_name`` attribute available on PyJWK by @luhn in `#886 <https://github.com/jpadilla/pyjwt/pull/886>`__
- Raise ``InvalidKeyError`` on invalid PEM keys to be compatible with cryptography 42.x.x by @CollinEMac in `#952 <https://github.com/jpadilla/pyjwt/pull/952>`__
- Raise an exception when required cryptography dependency is missing by @tobloef in `<https://github.com/jpadilla/pyjwt/pull/963>`__

`v2.8.0 <https://github.com/jpadilla/pyjwt/compare/2.7.0...2.8.0>`__
-----------------------------------------------------------------------

Changed
~~~~~~~

- Update python version test matrix by @auvipy in `#895 <https://github.com/jpadilla/pyjwt/pull/895>`__

Fixed
~~~~~

Added
~~~~~

- Add ``strict_aud`` as an option to ``jwt.decode`` by @woodruffw in `#902 <https://github.com/jpadilla/pyjwt/pull/902>`__
- Export PyJWKClientConnectionError class by @daviddavis in `#887 <https://github.com/jpadilla/pyjwt/pull/887>`__
- Allows passing of ssl.SSLContext to PyJWKClient by @juur in `#891 <https://github.com/jpadilla/pyjwt/pull/891>`__

`v2.7.0 <https://github.com/jpadilla/pyjwt/compare/2.6.0...2.7.0>`__
-----------------------------------------------------------------------

Changed
~~~~~~~

- Changed the error message when the token audience doesn't match the expected audience by @irdkwmnsb `#809 <https://github.com/jpadilla/pyjwt/pull/809>`__
- Improve error messages when cryptography isn't installed by @Viicos in `#846 <https://github.com/jpadilla/pyjwt/pull/846>`__
- Make `Algorithm` an abstract base class by @Viicos in `#845 <https://github.com/jpadilla/pyjwt/pull/845>`__
- ignore invalid keys in a jwks by @timw6n in `#863 <https://github.com/jpadilla/pyjwt/pull/863>`__

Fixed
~~~~~

- Add classifier for Python 3.11 by @eseifert in `#818 <https://github.com/jpadilla/pyjwt/pull/818>`__
- Fix ``_validate_iat`` validation by @Viicos in `#847 <https://github.com/jpadilla/pyjwt/pull/847>`__
- fix: use datetime.datetime.timestamp function to have a milliseconds by @daillouf `#821 <https://github.com/jpadilla/pyjwt/pull/821>`__
- docs: correct mistake in the changelog about verify param by @gbillig in `#866 <https://github.com/jpadilla/pyjwt/pull/866>`__

Added
~~~~~

- Add ``compute_hash_digest`` as a method of ``Algorithm`` objects, which uses
  the underlying hash algorithm to compute a digest. If there is no appropriate
  hash algorithm, a ``NotImplementedError`` will be raised in `#775 <https://github.com/jpadilla/pyjwt/pull/775>`__
- Add optional ``headers`` argument to ``PyJWKClient``. If provided, the headers
  will be included in requests that the client uses when fetching the JWK set by @thundercat1 in `#823 <https://github.com/jpadilla/pyjwt/pull/823>`__
- Add PyJWT._{de,en}code_payload hooks by @akx in `#829 <https://github.com/jpadilla/pyjwt/pull/829>`__
- Add `sort_headers` parameter to `api_jwt.encode` by @evroon in `#832 <https://github.com/jpadilla/pyjwt/pull/832>`__
- Make mypy configuration stricter and improve typing by @akx in `#830 <https://github.com/jpadilla/pyjwt/pull/830>`__
- Add more types by @Viicos in `#843 <https://github.com/jpadilla/pyjwt/pull/843>`__
- Add a timeout for PyJWKClient requests by @daviddavis in `#875 <https://github.com/jpadilla/pyjwt/pull/875>`__
- Add client connection error exception by @daviddavis in `#876 <https://github.com/jpadilla/pyjwt/pull/876>`__
- Add complete types to take all allowed keys into account by @Viicos in `#873 <https://github.com/jpadilla/pyjwt/pull/873>`__
- Add `as_dict` option to `Algorithm.to_jwk` by @fluxth in `#881 <https://github.com/jpadilla/pyjwt/pull/881>`__


`v2.6.0 <https://github.com/jpadilla/pyjwt/compare/2.5.0...2.6.0>`__
-----------------------------------------------------------------------

Changed
~~~~~~~

- bump up cryptography >= 3.4.0 by @jpadilla in `#807 <https://github.com/jpadilla/pyjwt/pull/807>`__
- Remove `types-cryptography` from `crypto` extra by @lautat in `#805 <https://github.com/jpadilla/pyjwt/pull/805>`__

Fixed
~~~~~

- Invalidate token on the exact second the token expires `#797 <https://github.com/jpadilla/pyjwt/pull/797>`__
- fix: version 2.5.0 heading typo by @c0state in `#803 <https://github.com/jpadilla/pyjwt/pull/803>`__

Added
~~~~~
- Adding validation for `issued_at` when `iat > (now + leeway)` as `ImmatureSignatureError` by @sriharan16 in `#794 <https://github.com/jpadilla/pyjwt/pull/794>`__

`v2.5.0 <https://github.com/jpadilla/pyjwt/compare/2.4.0...2.5.0>`__
-----------------------------------------------------------------------

Changed
~~~~~~~

- Skip keys with incompatible alg when loading JWKSet by @DaGuich in `#762 <https://github.com/jpadilla/pyjwt/pull/762>`__
- Remove support for python3.6 by @sirosen in `#777 <https://github.com/jpadilla/pyjwt/pull/777>`__
- Emit a deprecation warning for unsupported kwargs by @sirosen in `#776 <https://github.com/jpadilla/pyjwt/pull/776>`__
- Remove redundant wheel dep from pyproject.toml by @mgorny in `#765 <https://github.com/jpadilla/pyjwt/pull/765>`__
- Do not fail when an unusable key occurs by @DaGuich in `#762 <https://github.com/jpadilla/pyjwt/pull/762>`__
- Update audience typing by @JulianMaurin in `#782 <https://github.com/jpadilla/pyjwt/pull/782>`__
- Improve PyJWKSet error accuracy by @JulianMaurin in `#786 <https://github.com/jpadilla/pyjwt/pull/786>`__
- Mypy as pre-commit check + api_jws typing by @JulianMaurin in `#787 <https://github.com/jpadilla/pyjwt/pull/787>`__

Fixed
~~~~~

- Adjust expected exceptions in option merging tests for PyPy3 by @mgorny in `#763 <https://github.com/jpadilla/pyjwt/pull/763>`__
- Fixes for pyright on strict mode by @brandon-leapyear in `#747 <https://github.com/jpadilla/pyjwt/pull/747>`__
- docs: fix simple typo, iinstance -> isinstance by @timgates42 in `#774 <https://github.com/jpadilla/pyjwt/pull/774>`__
- Fix typo: priot -> prior by @jdufresne in `#780 <https://github.com/jpadilla/pyjwt/pull/780>`__
- Fix for headers disorder issue by @kadabusha in `#721 <https://github.com/jpadilla/pyjwt/pull/721>`__

Added
~~~~~

- Add to_jwk static method to ECAlgorithm by @leonsmith in `#732 <https://github.com/jpadilla/pyjwt/pull/732>`__
- Expose get_algorithm_by_name as new method by @sirosen in `#773 <https://github.com/jpadilla/pyjwt/pull/773>`__
- Add type hints to jwt/help.py and add missing types dependency by @kkirsche in `#784 <https://github.com/jpadilla/pyjwt/pull/784>`__
- Add cacheing functionality for JWK set by @wuhaoyujerry in `#781 <https://github.com/jpadilla/pyjwt/pull/781>`__

`v2.4.0 <https://github.com/jpadilla/pyjwt/compare/2.3.0...2.4.0>`__
-----------------------------------------------------------------------

Security
~~~~~~~~

- [CVE-2022-29217] Prevent key confusion through non-blocklisted public key formats. https://github.com/jpadilla/pyjwt/security/advisories/GHSA-ffqj-6fqr-9h24

Changed
~~~~~~~

- Explicit check the key for ECAlgorithm by @estin in `#713 <https://github.com/jpadilla/pyjwt/pull/713>`__
- Raise DeprecationWarning for jwt.decode(verify=...) by @akx in `#742 <https://github.com/jpadilla/pyjwt/pull/742>`__

Fixed
~~~~~

- Don't use implicit optionals by @rekyungmin in `#705 <https://github.com/jpadilla/pyjwt/pull/705>`__
- documentation fix: show correct scope for decode_complete() by @sseering in `#661 <https://github.com/jpadilla/pyjwt/pull/661>`__
- fix: Update copyright information by @kkirsche in `#729 <https://github.com/jpadilla/pyjwt/pull/729>`__
- Don't mutate options dictionary in .decode_complete() by @akx in `#743 <https://github.com/jpadilla/pyjwt/pull/743>`__

Added
~~~~~

- Add support for Python 3.10 by @hugovk in `#699 <https://github.com/jpadilla/pyjwt/pull/699>`__
- api_jwk: Add PyJWKSet.__getitem__ by @woodruffw in `#725 <https://github.com/jpadilla/pyjwt/pull/725>`__
- Update usage.rst by @guneybilen in `#727 <https://github.com/jpadilla/pyjwt/pull/727>`__
- Docs: mention performance reasons for reusing RSAPrivateKey when encoding by @dmahr1 in `#734 <https://github.com/jpadilla/pyjwt/pull/734>`__
- Fixed typo in usage.rst by @israelabraham in `#738 <https://github.com/jpadilla/pyjwt/pull/738>`__
- Add detached payload support for JWS encoding and decoding by @fviard in `#723 <https://github.com/jpadilla/pyjwt/pull/723>`__
- Replace various string interpolations with f-strings by @akx in `#744 <https://github.com/jpadilla/pyjwt/pull/744>`__
- Update CHANGELOG.rst by @hipertracker in `#751 <https://github.com/jpadilla/pyjwt/pull/751>`__

`v2.3.0 <https://github.com/jpadilla/pyjwt/compare/2.2.0...2.3.0>`__
-----------------------------------------------------------------------

Fixed
~~~~~

- Revert "Remove arbitrary kwargs." `#701 <https://github.com/jpadilla/pyjwt/pull/701>`__

Added
~~~~~

- Add exception chaining `#702 <https://github.com/jpadilla/pyjwt/pull/702>`__

`v2.2.0 <https://github.com/jpadilla/pyjwt/compare/2.1.0...2.2.0>`__
-----------------------------------------------------------------------

Changed
~~~~~~~

- Remove arbitrary kwargs. `#657 <https://github.com/jpadilla/pyjwt/pull/657>`__
- Use timezone package as Python 3.5+ is required. `#694 <https://github.com/jpadilla/pyjwt/pull/694>`__

Fixed
~~~~~
- Assume JWK without the "use" claim is valid for signing as per RFC7517 `#668 <https://github.com/jpadilla/pyjwt/pull/668>`__
- Prefer `headers["alg"]` to `algorithm` in `jwt.encode()`. `#673 <https://github.com/jpadilla/pyjwt/pull/673>`__
- Fix aud validation to support {'aud': null} case. `#670 <https://github.com/jpadilla/pyjwt/pull/670>`__
- Make `typ` optional in JWT to be compliant with RFC7519. `#644 <https://github.com/jpadilla/pyjwt/pull/644>`__
-  Remove upper bound on cryptography version. `#693 <https://github.com/jpadilla/pyjwt/pull/693>`__

Added
~~~~~

- Add support for Ed448/EdDSA. `#675 <https://github.com/jpadilla/pyjwt/pull/675>`__

`v2.1.0 <https://github.com/jpadilla/pyjwt/compare/2.0.1...2.1.0>`__
--------------------------------------------------------------------

Changed
~~~~~~~

- Allow claims validation without making JWT signature validation mandatory. `#608 <https://github.com/jpadilla/pyjwt/pull/608>`__

Fixed
~~~~~

- Remove padding from JWK test data. `#628 <https://github.com/jpadilla/pyjwt/pull/628>`__
- Make `kty` mandatory in JWK to be compliant with RFC7517. `#624 <https://github.com/jpadilla/pyjwt/pull/624>`__
- Allow JWK without `alg` to be compliant with RFC7517. `#624 <https://github.com/jpadilla/pyjwt/pull/624>`__
- Allow to verify with private key on ECAlgorithm, as well as on Ed25519Algorithm. `#645 <https://github.com/jpadilla/pyjwt/pull/645>`__

Added
~~~~~

- Add caching by default to PyJWKClient `#611 <https://github.com/jpadilla/pyjwt/pull/611>`__
- Add missing exceptions.InvalidKeyError to jwt module __init__ imports `#620 <https://github.com/jpadilla/pyjwt/pull/620>`__
- Add support for ES256K algorithm `#629 <https://github.com/jpadilla/pyjwt/pull/629>`__
- Add `from_jwk()` to Ed25519Algorithm `#621 <https://github.com/jpadilla/pyjwt/pull/621>`__
- Add `to_jwk()` to Ed25519Algorithm `#643 <https://github.com/jpadilla/pyjwt/pull/643>`__
- Export `PyJWK` and `PyJWKSet` `#652 <https://github.com/jpadilla/pyjwt/pull/652>`__

`v2.0.1 <https://github.com/jpadilla/pyjwt/compare/2.0.0...2.0.1>`__
--------------------------------------------------------------------

Changed
~~~~~~~

- Rename CHANGELOG.md to CHANGELOG.rst and include in docs `#597 <https://github.com/jpadilla/pyjwt/pull/597>`__

Fixed
~~~~~

- Fix `from_jwk()` for all algorithms `#598 <https://github.com/jpadilla/pyjwt/pull/598>`__

Added
~~~~~

`v2.0.0 <https://github.com/jpadilla/pyjwt/compare/1.7.1...2.0.0>`__
--------------------------------------------------------------------

Changed
~~~~~~~

Drop support for Python 2 and Python 3.0-3.5
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Python 3.5 is EOL so we decide to drop its support. Version ``1.7.1`` is
the last one supporting Python 3.0-3.5.

Require cryptography >= 3
^^^^^^^^^^^^^^^^^^^^^^^^^

Drop support for PyCrypto and ECDSA
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We've kept this around for a long time, mostly for environments that
didn't allow installing cryptography.

Drop CLI
^^^^^^^^

Dropped the included cli entry point.

Improve typings
^^^^^^^^^^^^^^^

We no longer need to use mypy Python 2 compatibility mode (comments)

``jwt.encode(...)`` return type
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Tokens are returned as string instead of a byte string

Dropped deprecated errors
^^^^^^^^^^^^^^^^^^^^^^^^^

Removed ``ExpiredSignature``, ``InvalidAudience``, and
``InvalidIssuer``. Use ``ExpiredSignatureError``,
``InvalidAudienceError``, and ``InvalidIssuerError`` instead.

Dropped deprecated ``verify_expiration`` param in ``jwt.decode(...)``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use
``jwt.decode(encoded, key, algorithms=["HS256"], options={"verify_exp": False})``
instead.

Dropped deprecated ``verify`` param in ``jwt.decode(...)``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use ``jwt.decode(encoded, key, options={"verify_signature": False})``
instead.

Require explicit ``algorithms`` in ``jwt.decode(...)`` by default
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Example: ``jwt.decode(encoded, key, algorithms=["HS256"])``.

Dropped deprecated ``require_*`` options in ``jwt.decode(...)``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For example, instead of
``jwt.decode(encoded, key, algorithms=["HS256"], options={"require_exp": True})``,
use
``jwt.decode(encoded, key, algorithms=["HS256"], options={"require": ["exp"]})``.

And the old v1.x syntax
``jwt.decode(token, verify=False)``
is now:
``jwt.decode(jwt=token, key='secret', algorithms=['HS256'], options={"verify_signature": False})``

Added
~~~~~

Introduce better experience for JWKs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Introduce ``PyJWK``, ``PyJWKSet``, and ``PyJWKClient``.

.. code:: python

    import jwt
    from jwt import PyJWKClient

    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5FRTFRVVJCT1RNNE16STVSa0ZETlRZeE9UVTFNRGcyT0Rnd1EwVXpNVGsxUWpZeVJrUkZRdyJ9.eyJpc3MiOiJodHRwczovL2Rldi04N2V2eDlydS5hdXRoMC5jb20vIiwic3ViIjoiYVc0Q2NhNzl4UmVMV1V6MGFFMkg2a0QwTzNjWEJWdENAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vZXhwZW5zZXMtYXBpIiwiaWF0IjoxNTcyMDA2OTU0LCJleHAiOjE1NzIwMDY5NjQsImF6cCI6ImFXNENjYTc5eFJlTFdVejBhRTJINmtEME8zY1hCVnRDIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIn0.PUxE7xn52aTCohGiWoSdMBZGiYAHwE5FYie0Y1qUT68IHSTXwXVd6hn02HTah6epvHHVKA2FqcFZ4GGv5VTHEvYpeggiiZMgbxFrmTEY0csL6VNkX1eaJGcuehwQCRBKRLL3zKmA5IKGy5GeUnIbpPHLHDxr-GXvgFzsdsyWlVQvPX2xjeaQ217r2PtxDeqjlf66UYl6oY6AqNS8DH3iryCvIfCcybRZkc_hdy-6ZMoKT6Piijvk_aXdm7-QQqKJFHLuEqrVSOuBqqiNfVrG27QzAPuPOxvfXTVLXL2jek5meH6n-VWgrBdoMFH93QEszEDowDAEhQPHVs0xj7SIzA"
    kid = "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw"
    url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

    jwks_client = PyJWKClient(url)
    signing_key = jwks_client.get_signing_key_from_jwt(token)

    data = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience="https://expenses-api",
        options={"verify_exp": False},
    )
    print(data)

Support for JWKs containing ECDSA keys
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Add support for Ed25519 / EdDSA
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Pull Requests
~~~~~~~~~~~~~

-  Add PyPy3 to the test matrix (#550) by @jdufresne
-  Require tweak (#280) by @psafont
-  Decode return type is dict[str, Any] (#393) by @jacopofar
-  Fix linter error in test\_cli (#414) by @jaraco
-  Run mypy with tox (#421) by @jpadilla
-  Document (and prefer) pyjwt[crypto] req format (#426) by @gthb
-  Correct type for json\_encoder argument (#438) by @jdufresne
-  Prefer https:// links where available (#439) by @jdufresne
-  Pass python\_requires argument to setuptools (#440) by @jdufresne
-  Rename [wheel] section to [bdist\_wheel] as the former is legacy
   (#441) by @jdufresne
-  Remove setup.py test command in favor of pytest and tox (#442) by
   @jdufresne
-  Fix mypy errors (#449) by @jpadilla
-  DX Tweaks (#450) by @jpadilla
-  Add support of python 3.8 (#452) by @Djailla
-  Fix 406 (#454) by @justinbaur
-  Add support for Ed25519 / EdDSA, with unit tests (#455) by
   @Someguy123
-  Remove Python 2.7 compatibility (#457) by @Djailla
-  Fix simple typo: encododed -> encoded (#462) by @timgates42
-  Enhance tracebacks. (#477) by @JulienPalard
-  Simplify ``python_requires`` (#478) by @michael-k
-  Document top-level .encode and .decode to close #459 (#482) by
   @dimaqq
-  Improve documentation for audience usage (#484) by @CorreyL
-  Correct README on how to run tests locally (#489) by @jdufresne
-  Fix ``tox -e lint`` warnings and errors (#490) by @jdufresne
-  Run pyupgrade across project to use modern Python 3 conventions
   (#491) by @jdufresne
-  Add Python-3-only trove classifier and remove "universal" from wheel
   (#492) by @jdufresne
-  Emit warnings about user code, not pyjwt code (#494) by @mgedmin
-  Move setup information to declarative setup.cfg (#495) by @jdufresne
-  CLI options for verifying audience and issuer (#496) by
   @GeoffRichards
-  Specify the target Python version for mypy (#497) by @jdufresne
-  Remove unnecessary compatibility shims for Python 2 (#498) by
   @jdufresne
-  Setup GH Actions (#499) by @jpadilla
-  Implementation of ECAlgorithm.from\_jwk (#500) by @jpadilla
-  Remove cli entry point (#501) by @jpadilla
-  Expose InvalidKeyError on jwt module (#503) by @russellcardullo
-  Avoid loading token twice in pyjwt.decode (#506) by @CaselIT
-  Default links to stable version of documentation (#508) by @salcedo
-  Update README.md badges (#510) by @jpadilla
-  Introduce better experience for JWKs (#511) by @jpadilla
-  Fix tox conditional extras (#512) by @jpadilla
-  Return tokens as string not bytes (#513) by @jpadilla
-  Drop support for legacy contrib algorithms (#514) by @jpadilla
-  Drop deprecation warnings (#515) by @jpadilla
-  Update Auth0 sponsorship link (#519) by @Sambego
-  Update return type for jwt.encode (#521) by @moomoolive
-  Run tests against Python 3.9 and add trove classifier (#522) by
   @michael-k
-  Removed redundant ``default_backend()`` (#523) by @rohitkg98
-  Documents how to use private keys with passphrases (#525) by @rayluo
-  Update version to 2.0.0a1 (#528) by @jpadilla
-  Fix usage example (#530) by @nijel
-  add EdDSA to docs (#531) by @CircleOnCircles
-  Remove support for EOL Python 3.5 (#532) by @jdufresne
-  Upgrade to isort 5 and adjust configurations (#533) by @jdufresne
-  Remove unused argument "verify" from PyJWS.decode() (#534) by
   @jdufresne
-  Update typing syntax and usage for Python 3.6+ (#535) by @jdufresne
-  Run pyupgrade to simplify code and use Python 3.6 syntax (#536) by
   @jdufresne
-  Drop unknown pytest config option: strict (#537) by @jdufresne
-  Upgrade black version and usage (#538) by @jdufresne
-  Remove "Command line" sections from docs (#539) by @jdufresne
-  Use existing key\_path() utility function throughout tests (#540) by
   @jdufresne
-  Replace force\_bytes()/force\_unicode() in tests with literals (#541)
   by @jdufresne
-  Remove unnecessary Unicode decoding before json.loads() (#542) by
   @jdufresne
-  Remove unnecessary force\_bytes() calls prior to base64url\_decode()
   (#543) by @jdufresne
-  Remove deprecated arguments from docs (#544) by @jdufresne
-  Update code blocks in docs (#545) by @jdufresne
-  Refactor jwt/jwks\_client.py without requests dependency (#546) by
   @jdufresne
-  Tighten bytes/str boundaries and remove unnecessary coercing (#547)
   by @jdufresne
-  Replace codecs.open() with builtin open() (#548) by @jdufresne
-  Replace int\_from\_bytes() with builtin int.from\_bytes() (#549) by
   @jdufresne
-  Enforce .encode() return type using mypy (#551) by @jdufresne
-  Prefer direct indexing over options.get() (#552) by @jdufresne
-  Cleanup "noqa" comments (#553) by @jdufresne
-  Replace merge\_dict() with builtin dict unpacking generalizations
   (#555) by @jdufresne
-  Do not mutate the input payload in PyJWT.encode() (#557) by
   @jdufresne
-  Use direct indexing in PyJWKClient.get\_signing\_key\_from\_jwt()
   (#558) by @jdufresne
-  Split PyJWT/PyJWS classes to tighten type interfaces (#559) by
   @jdufresne
-  Simplify mocked\_response test utility function (#560) by @jdufresne
-  Autoupdate pre-commit hooks and apply them (#561) by @jdufresne
-  Remove unused argument "payload" from PyJWS.\ *verify*\ signature()
   (#562) by @jdufresne
-  Add utility functions to assist test skipping (#563) by @jdufresne
-  Type hint jwt.utils module (#564) by @jdufresne
-  Prefer ModuleNotFoundError over ImportError (#565) by @jdufresne
-  Fix tox "manifest" environment to pass (#566) by @jdufresne
-  Fix tox "docs" environment to pass (#567) by @jdufresne
-  Simplify black configuration to be closer to upstream defaults (#568)
   by @jdufresne
-  Use generator expressions (#569) by @jdufresne
-  Simplify from\_base64url\_uint() (#570) by @jdufresne
-  Drop lint environment from GitHub actions in favor of pre-commit.ci
   (#571) by @jdufresne
-  [pre-commit.ci] pre-commit autoupdate (#572)
-  Simplify tox configuration (#573) by @jdufresne
-  Combine identical test functions using pytest.mark.parametrize()
   (#574) by @jdufresne
-  Complete type hinting of jwks\_client.py (#578) by @jdufresne

`v1.7.1 <https://github.com/jpadilla/pyjwt/compare/1.7.0...1.7.1>`__
--------------------------------------------------------------------

Fixed
~~~~~

-  Update test dependencies with pinned ranges
-  Fix pytest deprecation warnings

`v1.7.0 <https://github.com/jpadilla/pyjwt/compare/1.6.4...1.7.0>`__
--------------------------------------------------------------------

Changed
~~~~~~~

-  Remove CRLF line endings
   `#353 <https://github.com/jpadilla/pyjwt/pull/353>`__

Fixed
~~~~~

-  Update usage.rst
   `#360 <https://github.com/jpadilla/pyjwt/pull/360>`__

Added
~~~~~

-  Support for Python 3.7
   `#375 <https://github.com/jpadilla/pyjwt/pull/375>`__
   `#379 <https://github.com/jpadilla/pyjwt/pull/379>`__
   `#384 <https://github.com/jpadilla/pyjwt/pull/384>`__

`v1.6.4 <https://github.com/jpadilla/pyjwt/compare/1.6.3...1.6.4>`__
--------------------------------------------------------------------

Fixed
~~~~~

-  Reverse an unintentional breaking API change to .decode()
   `#352 <https://github.com/jpadilla/pyjwt/pull/352>`__

`v1.6.3 <https://github.com/jpadilla/pyjwt/compare/1.6.1...1.6.3>`__
--------------------------------------------------------------------

Changed
~~~~~~~

-  All exceptions inherit from PyJWTError
   `#340 <https://github.com/jpadilla/pyjwt/pull/340>`__

Added
~~~~~

-  Add type hints `#344 <https://github.com/jpadilla/pyjwt/pull/344>`__
-  Add help module
   `7ca41e <https://github.com/jpadilla/pyjwt/commit/7ca41e53b3d7d9f5cd31bdd8a2b832d192006239>`__

Docs
~~~~

-  Added section to usage docs for jwt.get\_unverified\_header()
   `#350 <https://github.com/jpadilla/pyjwt/pull/350>`__
-  Update legacy instructions for using pycrypto
   `#337 <https://github.com/jpadilla/pyjwt/pull/337>`__

`v1.6.1 <https://github.com/jpadilla/pyjwt/compare/1.6.0...1.6.1>`__
--------------------------------------------------------------------

Fixed
~~~~~

-  Audience parameter throws ``InvalidAudienceError`` when application
   does not specify an audience, but the token does.
   `#336 <https://github.com/jpadilla/pyjwt/pull/336>`__

`v1.6.0 <https://github.com/jpadilla/pyjwt/compare/1.5.3...1.6.0>`__
--------------------------------------------------------------------

Changed
~~~~~~~

-  Dropped support for python 2.6 and 3.3
   `#301 <https://github.com/jpadilla/pyjwt/pull/301>`__
-  An invalid signature now raises an ``InvalidSignatureError`` instead
   of ``DecodeError``
   `#316 <https://github.com/jpadilla/pyjwt/pull/316>`__

Fixed
~~~~~

-  Fix over-eager fallback to stdin
   `#304 <https://github.com/jpadilla/pyjwt/pull/304>`__

Added
~~~~~

-  Audience parameter now supports iterables
   `#306 <https://github.com/jpadilla/pyjwt/pull/306>`__

`v1.5.3 <https://github.com/jpadilla/pyjwt/compare/1.5.2...1.5.3>`__
--------------------------------------------------------------------

Changed
~~~~~~~

-  Increase required version of the cryptography package to >=1.4.0.

Fixed
~~~~~

-  Remove uses of deprecated functions from the cryptography package.
-  Warn about missing ``algorithms`` param to ``decode()`` only when
   ``verify`` param is ``True``
   `#281 <https://github.com/jpadilla/pyjwt/pull/281>`__

`v1.5.2 <https://github.com/jpadilla/pyjwt/compare/1.5.1...1.5.2>`__
--------------------------------------------------------------------

Fixed
~~~~~

-  Ensure correct arguments order in decode super call
   `7c1e61d <https://github.com/jpadilla/pyjwt/commit/7c1e61dde27bafe16e7d1bb6e35199e778962742>`__

`v1.5.1 <https://github.com/jpadilla/pyjwt/compare/1.5.0...1.5.1>`__
--------------------------------------------------------------------

Changed
~~~~~~~

-  Change optparse for argparse.
   `#238 <https://github.com/jpadilla/pyjwt/pull/238>`__

Fixed
~~~~~

-  Guard against PKCS1 PEM encoded public keys
   `#277 <https://github.com/jpadilla/pyjwt/pull/277>`__
-  Add deprecation warning when decoding without specifying
   ``algorithms`` `#277 <https://github.com/jpadilla/pyjwt/pull/277>`__
-  Improve deprecation messages
   `#270 <https://github.com/jpadilla/pyjwt/pull/270>`__
-  PyJWT.decode: move verify param into options
   `#271 <https://github.com/jpadilla/pyjwt/pull/271>`__

Added
~~~~~

-  Support for Python 3.6
   `#262 <https://github.com/jpadilla/pyjwt/pull/262>`__
-  Expose jwt.InvalidAlgorithmError
   `#264 <https://github.com/jpadilla/pyjwt/pull/264>`__

`v1.5.0 <https://github.com/jpadilla/pyjwt/compare/1.4.2...1.5.0>`__
--------------------------------------------------------------------

Changed
~~~~~~~

-  Add support for ECDSA public keys in RFC 4253 (OpenSSH) format
   `#244 <https://github.com/jpadilla/pyjwt/pull/244>`__
-  Renamed commandline script ``jwt`` to ``jwt-cli`` to avoid issues
   with the script clobbering the ``jwt`` module in some circumstances.
   `#187 <https://github.com/jpadilla/pyjwt/pull/187>`__
-  Better error messages when using an algorithm that requires the
   cryptography package, but it isn't available
   `#230 <https://github.com/jpadilla/pyjwt/pull/230>`__
-  Tokens with future 'iat' values are no longer rejected
   `#190 <https://github.com/jpadilla/pyjwt/pull/190>`__
-  Non-numeric 'iat' values now raise InvalidIssuedAtError instead of
   DecodeError
-  Remove rejection of future 'iat' claims
   `#252 <https://github.com/jpadilla/pyjwt/pull/252>`__

Fixed
~~~~~

-  Add back 'ES512' for backward compatibility (for now)
   `#225 <https://github.com/jpadilla/pyjwt/pull/225>`__
-  Fix incorrectly named ECDSA algorithm
   `#219 <https://github.com/jpadilla/pyjwt/pull/219>`__
-  Fix rpm build `#196 <https://github.com/jpadilla/pyjwt/pull/196>`__

Added
~~~~~

-  Add JWK support for HMAC and RSA keys
   `#202 <https://github.com/jpadilla/pyjwt/pull/202>`__

`v1.4.2 <https://github.com/jpadilla/pyjwt/compare/1.4.1...1.4.2>`__
--------------------------------------------------------------------

Fixed
~~~~~

-  A PEM-formatted key encoded as bytes could cause a ``TypeError`` to
   be raised `#213 <https://github.com/jpadilla/pyjwt/pull/214>`__

`v1.4.1 <https://github.com/jpadilla/pyjwt/compare/1.4.0...1.4.1>`__
--------------------------------------------------------------------

Fixed
~~~~~

-  Newer versions of Pytest could not detect warnings properly
   `#182 <https://github.com/jpadilla/pyjwt/pull/182>`__
-  Non-string 'kid' value now raises ``InvalidTokenError``
   `#174 <https://github.com/jpadilla/pyjwt/pull/174>`__
-  ``jwt.decode(None)`` now gracefully fails with ``InvalidTokenError``
   `#183 <https://github.com/jpadilla/pyjwt/pull/183>`__

`v1.4 <https://github.com/jpadilla/pyjwt/compare/1.3.0...1.4.0>`__
------------------------------------------------------------------

Fixed
~~~~~

-  Exclude Python cache files from PyPI releases.

Added
~~~~~

-  Added new options to require certain claims (require\_nbf,
   require\_iat, require\_exp) and raise ``MissingRequiredClaimError``
   if they are not present.
-  If ``audience=`` or ``issuer=`` is specified but the claim is not
   present, ``MissingRequiredClaimError`` is now raised instead of
   ``InvalidAudienceError`` and ``InvalidIssuerError``

`v1.3 <https://github.com/jpadilla/pyjwt/compare/1.2.0...1.3.0>`__
------------------------------------------------------------------

Fixed
~~~~~

-  ECDSA (ES256, ES384, ES512) signatures are now being properly
   serialized `#158 <https://github.com/jpadilla/pyjwt/pull/158>`__
-  RSA-PSS (PS256, PS384, PS512) signatures now use the proper salt
   length for PSS padding.
   `#163 <https://github.com/jpadilla/pyjwt/pull/163>`__

Added
~~~~~

-  Added a new ``jwt.get_unverified_header()`` to parse and return the
   header portion of a token prior to signature verification.

Removed
~~~~~~~

-  Python 3.2 is no longer a supported platform. This version of Python
   is rarely used. Users affected by this should upgrade to 3.3+.

`v1.2.0 <https://github.com/jpadilla/pyjwt/compare/1.1.0...1.2.0>`__
--------------------------------------------------------------------

Fixed
~~~~~

-  Added back ``verify_expiration=`` argument to ``jwt.decode()`` that
   was erroneously removed in
   `v1.1.0 <https://github.com/jpadilla/pyjwt/compare/1.0.1...1.1.0>`__.

Changed
~~~~~~~

-  Refactored JWS-specific logic out of PyJWT and into PyJWS superclass.
   `#141 <https://github.com/jpadilla/pyjwt/pull/141>`__

Deprecated
~~~~~~~~~~

-  ``verify_expiration=`` argument to ``jwt.decode()`` is now deprecated
   and will be removed in a future version. Use the ``option=`` argument
   instead.

`v1.1.0 <https://github.com/jpadilla/pyjwt/compare/1.0.1...1.1.0>`__
--------------------------------------------------------------------

Added
~~~~~

-  Added support for PS256, PS384, and PS512 algorithms.
   `#132 <https://github.com/jpadilla/pyjwt/pull/132>`__
-  Added flexible and complete verification options during decode.
   `#131 <https://github.com/jpadilla/pyjwt/pull/131>`__
-  Added this CHANGELOG.md file.

Deprecated
~~~~~~~~~~

-  Deprecated usage of the .decode(..., verify=False) parameter.

Fixed
~~~~~

-  Fixed command line encoding.
   `#128 <https://github.com/jpadilla/pyjwt/pull/128>`__

`v1.0.1 <https://github.com/jpadilla/pyjwt/compare/1.0.0...1.0.1>`__
--------------------------------------------------------------------

Fixed
~~~~~

-  Include jwt/contrib' and jwt/contrib/algorithms\` in setup.py so that
   they will actually be included when installing.
   `882524d <https://github.com/jpadilla/pyjwt/commit/882524d>`__
-  Fix bin/jwt after removing jwt.header().
   `bd57b02 <https://github.com/jpadilla/pyjwt/commit/bd57b02>`__

`v1.0.0 <https://github.com/jpadilla/pyjwt/compare/0.4.3...1.0.0>`__
--------------------------------------------------------------------

Changed
~~~~~~~

-  Moved ``jwt.api.header`` out of the public API.
   `#85 <https://github.com/jpadilla/pyjwt/pull/85>`__
-  Added README details how to extract public / private keys from an
   x509 certificate.
   `#100 <https://github.com/jpadilla/pyjwt/pull/100>`__
-  Refactor api.py functions into an object (``PyJWT``).
   `#101 <https://github.com/jpadilla/pyjwt/pull/101>`__
-  Added support for PyCrypto and ecdsa when cryptography isn't
   available. `#101 <https://github.com/jpadilla/pyjwt/pull/103>`__

Fixed
~~~~~

-  Fixed a security vulnerability where ``alg=None`` header could bypass
   signature verification.
   `#109 <https://github.com/jpadilla/pyjwt/pull/109>`__
-  Fixed a security vulnerability by adding support for a whitelist of
   allowed ``alg`` values ``jwt.decode(algorithms=[])``.
   `#110 <https://github.com/jpadilla/pyjwt/pull/110>`__
