# PyJWT Refactoring Analysis

A deep analysis of the [PyJWT](file:///c:/Users/User/Documents/GitHub/pyjwt) codebase identifying refactoring opportunities, organized by impact and effort.

---

## 1. Split the Monolithic `algorithms.py` (999 Lines)

**Priority: High** · **Impact: High** · **Effort: Medium**

[algorithms.py](file:///c:/Users/User/Documents/GitHub/pyjwt/jwt/algorithms.py) is by far the largest file at **999 lines** and contains **7 classes** (`Algorithm`, `NoneAlgorithm`, `HMACAlgorithm`, `RSAAlgorithm`, `ECAlgorithm`, `RSAPSSAlgorithm`, `OKPAlgorithm`), all type aliases, and the conditional `has_crypto` guard.

### Proposed Split

| New Module | Contents | Lines (approx) |
|---|---|---|
| `algorithms/base.py` | `Algorithm` ABC, `NoneAlgorithm`, `get_default_algorithms()`, `requires_cryptography` set | ~170 |
| `algorithms/hmac.py` | `HMACAlgorithm` | ~80 |
| `algorithms/rsa.py` | `RSAAlgorithm`, `RSAPSSAlgorithm` | ~230 |
| `algorithms/ec.py` | `ECAlgorithm` | ~210 |
| `algorithms/okp.py` | `OKPAlgorithm` | ~175 |
| `algorithms/_types.py` | All `TypeAlias` definitions (`AllowedRSAKeys`, `AllowedECKeys`, etc.) | ~40 |
| `algorithms/__init__.py` | Re-exports everything for backward compatibility | ~30 |

### Why

- Single Responsibility: each algorithm family gets its own module
- Easier navigation, code review, and testing
- The conditional `if has_crypto:` block (line 391–999) would become natural module-level guards

---

## 2. Extract Duplicated JWK Parsing Boilerplate

**Priority: High** · **Impact: Medium** · **Effort: Low**

Every `from_jwk()` method repeats the **exact same** JSON deserialization + validation preamble:

```python
# Repeated in RSAAlgorithm.from_jwk (L500-508), ECAlgorithm.from_jwk (L722-731),
# OKPAlgorithm.from_jwk (L966-975), HMACAlgorithm.from_jwk (L357-366)
try:
    if isinstance(jwk, str):
        obj = json.loads(jwk)
    elif isinstance(jwk, dict):
        obj = jwk
    else:
        raise ValueError
except ValueError:
    raise InvalidKeyError("Key is not valid JSON") from None
```

### Refactoring

Extract a shared utility:

```python
# utils.py or algorithms/base.py
def _parse_jwk_input(jwk: str | JWKDict) -> JWKDict:
    """Parse a JWK from string or dict, raising InvalidKeyError on failure."""
    try:
        if isinstance(jwk, str):
            return json.loads(jwk)
        elif isinstance(jwk, dict):
            return jwk
        raise ValueError
    except ValueError:
        raise InvalidKeyError("Key is not valid JSON") from None
```

Similarly, every `to_jwk()` ends with the same `as_dict` conditional:

```python
if as_dict:
    return obj
else:
    return json.dumps(obj)
```

This can be a shared `_finalize_jwk(obj, as_dict)` helper.

---

## 3. Eliminate Duplicated `prepare_key()` Logic

**Priority: Medium** · **Impact: Medium** · **Effort: Medium**

`RSAAlgorithm.prepare_key()` (L421–449) and `ECAlgorithm.prepare_key()` (L615–645) follow an almost identical pattern:

1. Check if the key is already a cryptography key type → return early
2. Check `isinstance(key, (bytes, str))` → raise `TypeError`
3. `force_bytes(key)`
4. Try SSH key loading → Try PEM private → Fallback to PEM public
5. Call `self.check_crypto_key_type()`
6. Cast and return

### Refactoring

Create a base method in `Algorithm` (or a mixin) like `_prepare_crypto_key()` that handles the common PEM/SSH loading flow and let subclasses provide:
- The SSH key prefix (e.g. `b"ssh-rsa"`, `b"ecdsa-sha2-"`)
- Post-load validation (curve checking for EC)

---

## 4. Replace `if has_crypto:` Class Nesting with Lazy Imports

**Priority: Medium** · **Impact: Medium** · **Effort: Medium**

Currently, **four full classes** (RSA, EC, RSAPSS, OKP) are defined inside an `if has_crypto:` block (lines 391–999). This creates:

- Unusual indentation for ~600 lines of code
- Difficulty for IDE tools to index and navigate
- Tight coupling between the availability check and class definition

### Alternatives

1. **Separate modules** (see item 1): each module does its own `try/except` at import time
2. **Factory pattern**: `get_default_algorithms()` already handles registration — the classes don't need to be conditionally defined if they're only instantiated conditionally

---

## 5. Curve Mapping Tables for ECAlgorithm

**Priority: Medium** · **Impact: Low** · **Effort: Low**

[ECAlgorithm.to_jwk()](file:///c:/Users/User/Documents/GitHub/pyjwt/jwt/algorithms.py#L678-L719) and [ECAlgorithm.from_jwk()](file:///c:/Users/User/Documents/GitHub/pyjwt/jwt/algorithms.py#L722-L793) have large `if/elif` chains for curve mapping:

```python
# to_jwk: curve object → JWK crv string
if isinstance(key_obj.curve, SECP256R1):
    crv = "P-256"
elif isinstance(key_obj.curve, SECP384R1):
    crv = "P-384"
# ...

# from_jwk: JWK crv string → curve object + byte length validation
if curve == "P-256":
    if len(x) == len(y) == 32:
        curve_obj = SECP256R1()
# ...
```

### Refactoring

Use a lookup table:

```python
_EC_CURVES: dict[str, tuple[type[EllipticCurve], int]] = {
    "P-256":     (SECP256R1, 32),
    "P-384":     (SECP384R1, 48),
    "P-521":     (SECP521R1, 66),
    "secp256k1": (SECP256K1, 32),
}
_EC_CURVE_NAMES: dict[type[EllipticCurve], str] = {
    v[0]: k for k, v in _EC_CURVES.items()
}
```

This eliminates ~40 lines of repetitive branching and makes adding new curves trivial.

---

## 6. Consolidate `_merge_options` / Options Handling

**Priority: Medium** · **Impact: Low** · **Effort: Low**

In [api_jwt.py](file:///c:/Users/User/Documents/GitHub/pyjwt/jwt/api_jwt.py#L75-L88), `_merge_options()` manually sets 7 individual `verify_*` keys to `False`:

```python
if not options.get("verify_signature", True):
    options["verify_exp"] = options.get("verify_exp", False)
    options["verify_nbf"] = options.get("verify_nbf", False)
    options["verify_iat"] = options.get("verify_iat", False)
    options["verify_aud"] = options.get("verify_aud", False)
    options["verify_iss"] = options.get("verify_iss", False)
    options["verify_sub"] = options.get("verify_sub", False)
    options["verify_jti"] = options.get("verify_jti", False)
```

### Refactoring

```python
_VERIFY_CLAIMS = ("verify_exp", "verify_nbf", "verify_iat", "verify_aud",
                   "verify_iss", "verify_sub", "verify_jti")

if not options.get("verify_signature", True):
    for claim in _VERIFY_CLAIMS:
        options[claim] = options.get(claim, False)
```

---

## 7. Simplify `PyJWTSetWithTimestamp` Wrapper

**Priority: Low** · **Impact: Low** · **Effort: Low**

[PyJWTSetWithTimestamp](file:///c:/Users/User/Documents/GitHub/pyjwt/jwt/api_jwk.py#L179-L188) is a simple wrapper with just two attributes and trivial getters:

```python
class PyJWTSetWithTimestamp:
    def __init__(self, jwk_set: PyJWKSet):
        self.jwk_set = jwk_set
        self.timestamp = time.monotonic()

    def get_jwk_set(self) -> PyJWKSet:
        return self.jwk_set

    def get_timestamp(self) -> float:
        return self.timestamp
```

### Options

- **`dataclass`** or **`NamedTuple`** would be more idiomatic and remove the boilerplate getters
- The `get_jwk_set()` / `get_timestamp()` methods are Java-style getters — in Python, direct attribute access is preferred (they're already public)

> [!NOTE]
> The class name `PyJWTSetWithTimestamp` uses **JWT** instead of **JWK** — likely a typo. Should be `PyJWKSetWithTimestamp`.

---

## 8. Modernize Type Annotations

**Priority: Low** · **Impact: Low** · **Effort: Low**

[utils.py](file:///c:/Users/User/Documents/GitHub/pyjwt/jwt/utils.py) and [jwk_set_cache.py](file:///c:/Users/User/Documents/GitHub/pyjwt/jwt/jwk_set_cache.py) still use legacy `typing.Optional` and `typing.Union`:

```python
# utils.py, line 4
from typing import Optional, Union

# jwk_set_cache.py, line 9
self.jwk_set_with_timestamp: Optional[PyJWTSetWithTimestamp] = None
```

The rest of the codebase already uses `X | Y` syntax (via `from __future__ import annotations`). These files should be updated for consistency:

```python
# Before
from typing import Optional, Union
def func(val: Union[bytes, str]) -> bytes:
def func2(val: int, *, bit_length: Optional[int] = None) -> bytes:

# After
from __future__ import annotations
def func(val: bytes | str) -> bytes:
def func2(val: int, *, bit_length: int | None = None) -> bytes:
```

---

## 9. `_validate_claims()` — Strategy or Dispatch Pattern

**Priority: Low** · **Impact: Medium** · **Effort: Medium**

[_validate_claims()](file:///c:/Users/User/Documents/GitHub/pyjwt/jwt/api_jwt.py#L379-L419) is a long method that dispatches to individual validators with an `if claim in payload and options[key]` pattern:

```python
if "iat" in payload and options["verify_iat"]:
    self._validate_iat(payload, now, leeway)
if "nbf" in payload and options["verify_nbf"]:
    self._validate_nbf(payload, now, leeway)
if "exp" in payload and options["verify_exp"]:
    self._validate_exp(payload, now, leeway)
# ... etc
```

### Refactoring Option

A validator registry pattern would make this extensible and reduce the sequential `if` chain:

```python
_CLAIM_VALIDATORS = {
    "iat": ("verify_iat", "_validate_iat"),
    "nbf": ("verify_nbf", "_validate_nbf"),
    "exp": ("verify_exp", "_validate_exp"),
}
```

> [!TIP]
> This becomes especially valuable if users want to register custom claim validators.

---

## 10. Test Code Quality

**Priority: Low** · **Impact: Medium** · **Effort: Medium**

The test files are proportionally large ([test_algorithms.py](file:///c:/Users/User/Documents/GitHub/pyjwt/tests/test_algorithms.py) = 63KB, [test_api_jws.py](file:///c:/Users/User/Documents/GitHub/pyjwt/tests/test_api_jws.py) = 41KB, [test_api_jwt.py](file:///c:/Users/User/Documents/GitHub/pyjwt/tests/test_api_jwt.py) = 39KB). If algorithms are split into separate modules, tests should follow the same structure:

| Current | Proposed |
|---|---|
| `test_algorithms.py` (63KB) | `test_hmac.py`, `test_rsa.py`, `test_ec.py`, `test_okp.py` |

---

## Summary Matrix

| # | Refactoring | Priority | Impact | Effort | Risk |
|---|---|---|---|---|---|
| 1 | Split `algorithms.py` into subpackage | 🔴 High | High | Medium | Low (backward-compat re-exports) |
| 2 | Extract JWK parse/serialize boilerplate | 🔴 High | Medium | Low | Very Low |
| 3 | Consolidate `prepare_key()` logic | 🟡 Medium | Medium | Medium | Low |
| 4 | Replace `if has_crypto:` nesting | 🟡 Medium | Medium | Medium | Low |
| 5 | EC curve lookup tables | 🟡 Medium | Low | Low | Very Low |
| 6 | Loop-based options merge | 🟡 Medium | Low | Low | Very Low |
| 7 | Simplify timestamp wrapper / fix typo | 🟢 Low | Low | Low | Very Low |
| 8 | Modernize type annotations in utils | 🟢 Low | Low | Low | Very Low |
| 9 | Claim validator registry | 🟢 Low | Medium | Medium | Low |
| 10 | Split test files to match modules | 🟢 Low | Medium | Medium | Very Low |

> [!IMPORTANT]
> Items 1, 2, and 5 are the highest-value, lowest-risk changes. They reduce file size, eliminate code duplication, and improve maintainability without changing any public API.
