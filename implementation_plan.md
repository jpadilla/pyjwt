# Refactoring `test_algorithms.py`

Now that `jwt/algorithms.py` has been split into a subpackage (`base.py`, `hmac.py`, `rsa.py`, `ec.py`, `okp.py`), it makes perfect architectural sense to refactor the test suite to mirror this new structure.

The current `tests/test_algorithms.py` is a monolithic file (~1600 lines) containing tests for all algorithms, including general tests and RFC 7520 test vectors.

## Open Questions
- Would you like the RFC 7520 test vectors (currently residing in `TestAlgorithmsRFC7520`) to be grouped alongside the standard unit tests in their respective files (e.g. putting the HMAC RFC vector test inside `test_algorithms_hmac.py`), or would you prefer a separate `test_algorithms_rfc7520.py` file to keep them strictly separated?
*(Grouping them by algorithm is usually best for maintainability!)*

## Proposed Changes

We will split the monolithic test file into the following module-specific test files:

### `tests/`

#### [NEW] `test_algorithms_base.py`
Will contain tests related to the `Algorithm` ABC, `NoneAlgorithm`, and the `has_crypto` module checks.

#### [NEW] `test_algorithms_hmac.py`
Will contain tests specifically for `HMACAlgorithm`, including its RFC 7520 vector tests.

#### [NEW] `test_algorithms_rsa.py`
Will contain tests for `RSAAlgorithm` and `RSAPSSAlgorithm`, including parsing, signing, verifying, and RSA-related RFC 7520 vector tests.

#### [NEW] `test_algorithms_ec.py`
Will contain tests for `ECAlgorithm`, curve lookups, and EC-related RFC 7520 vector tests.

#### [NEW] `test_algorithms_okp.py`
Will contain tests for `OKPAlgorithm` (EdDSA, Ed25519, Ed448).

#### [DELETE] `test_algorithms.py`
The original monolithic file will be safely deleted after all its tests are correctly migrated.

## Verification Plan

### Automated Tests
Run `pytest` to ensure the exact same number of tests are collected and executed successfully without any regressions.
