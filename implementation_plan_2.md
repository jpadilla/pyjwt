# Refactoring `api_jwt.py` — Parameter Lists & Validation Complexity

Addresses items **#6** (loop-based options merge), **#9** (claim validator dispatch), and the **Long Parameter List** code smell identified in previous analysis of [api_jwt.py](file:///c:/Users/User/Documents/GitHub/pyjwt/jwt/api_jwt.py).

---

## Problem Summary

Three interrelated smells in `api_jwt.py`:

| # | Smell | Location | Details |
|---|---|---|---|
| 1 | **Long Parameter List** | `decode()` (11 params), `decode_complete()` (11 params) | `audience`, `issuer`, `subject`, `leeway` are pass-through args to `_validate_claims` — the source code itself has a comment saying *"consider putting in options"* |
| 2 | **Repetitive defaults** | `_merge_options()` L80-87 | 7 identical `options.get(key, False)` lines when `verify_signature` is off |
| 3 | **Sequential if-chain** | `_validate_claims()` L398-419 | 7 near-identical `if options[key]: self._validate_X()` blocks |

---

## Proposed Changes

### 1. Move validation parameters into the `Options` TypedDict

#### [MODIFY] [types.py](file:///c:/Users/User/Documents/GitHub/pyjwt/jwt/types.py)

Add four new optional keys to `Options` and `FullOptions`:

```python
class Options(TypedDict, total=False):
    # ... existing keys ...
    audience: str | Iterable[str] | None
    issuer: str | Container[str] | None
    subject: str | None
    leeway: float | timedelta
```

```python
class FullOptions(TypedDict):
    # ... existing keys ...
    audience: str | Iterable[str] | None
    issuer: str | Container[str] | None
    subject: str | None
    leeway: float | timedelta
```

> [!NOTE]
> These are typed as optional in `Options` (since `total=False`) but required in `FullOptions` — matching the existing pattern. Defaults will be set in `_get_default_options()`.

---

#### [MODIFY] [api_jwt.py](file:///c:/Users/User/Documents/GitHub/pyjwt/jwt/api_jwt.py)

**a) Update `_get_default_options()`** — add defaults for the new keys:

```python
@staticmethod
def _get_default_options() -> FullOptions:
    return {
        # ... existing ...
        "audience": None,
        "issuer": None,
        "subject": None,
        "leeway": 0,
    }
```

**b) Simplify `decode_complete()` signature** — remove the 4 pass-through params, read them from merged options instead:

```python
def decode_complete(
    self,
    jwt: str | bytes,
    key: AllowedPublicKeyTypes = "",
    algorithms: Sequence[str] | None = None,
    options: Options | None = None,
    # deprecated arg, remove in pyjwt3
    verify: bool | None = None,
    # passthrough to api_jws
    detached_payload: bytes | None = None,
    # kwargs for backward compat
    **kwargs: Any,
) -> dict[str, Any]:
```

Inside the method body, extract values from merged options and handle backward compatibility:

```python
# Backward compatibility: if old-style kwargs were passed, emit deprecation
# warning and merge them into options
for param_name in ("audience", "issuer", "subject", "leeway"):
    if param_name in kwargs:
        warnings.warn(
            f"Passing '{param_name}' as a keyword argument to decode_complete() is "
            "deprecated. Use the 'options' dictionary instead. "
            "This will be removed in PyJWT 3.",
            RemovedInPyjwt3Warning,
            stacklevel=2,
        )
        # kwargs value takes precedence if options didn't specify it
        if options is None:
            options = {}
        options.setdefault(param_name, kwargs.pop(param_name))
```

Then validation uses merged options directly:

```python
self._validate_claims(payload, merged_options)
```

**c) Simplify `decode()` signature** — same treatment.

**d) Simplify `_validate_claims()` signature** — remove the 4 extra params, read everything from `options`:

```python
def _validate_claims(
    self,
    payload: dict[str, Any],
    options: FullOptions,
) -> None:
    leeway = options["leeway"]
    if isinstance(leeway, timedelta):
        leeway = leeway.total_seconds()
    audience = options["audience"]
    issuer = options["issuer"]
    subject = options["subject"]
    # ... rest of validation logic ...
```

> [!IMPORTANT]
> **Backward compatibility**: Tests currently pass `audience=`, `issuer=`, `subject=`, `leeway=` as keyword arguments to `decode()` / `decode_complete()`. The `**kwargs` catch + deprecation warning approach ensures these continue to work while guiding users to migrate. No existing tests need to change for the code to pass — only new deprecation warnings will appear.

---

### 2. Loop-based `_merge_options()`

Replace the 7-line repetition in [_merge_options()](file:///c:/Users/User/Documents/GitHub/pyjwt/jwt/api_jwt.py#L75-L88) with a loop:

```python
_VERIFY_CLAIMS = (
    "verify_exp", "verify_nbf", "verify_iat",
    "verify_aud", "verify_iss", "verify_sub", "verify_jti",
)

def _merge_options(self, options: Options | None = None) -> FullOptions:
    if options is None:
        return self.options

    if not options.get("verify_signature", True):
        for claim in _VERIFY_CLAIMS:
            options[claim] = options.get(claim, False)

    return {**self.options, **options}
```

---

### 3. Validator registry in `_validate_claims()`

Replace the sequential if-chain in [_validate_claims()](file:///c:/Users/User/Documents/GitHub/pyjwt/jwt/api_jwt.py#L379-L419) with a data-driven dispatch:

```python
# Validators that check a specific claim in the payload
# (claim_key, option_flag, validator_method_name)
_CLAIM_VALIDATORS: tuple[tuple[str, str, str], ...] = (
    ("iat", "verify_iat", "_validate_iat"),
    ("nbf", "verify_nbf", "_validate_nbf"),
    ("exp", "verify_exp", "_validate_exp"),
)

# Validators that always run when their option flag is set
# (option_flag, validator_method_name)
_OPTION_VALIDATORS: tuple[tuple[str, str], ...] = (
    ("verify_iss", "_validate_iss"),
    ("verify_aud", "_validate_aud"),
    ("verify_sub", "_validate_sub"),
    ("verify_jti", "_validate_jti"),
)
```

Then `_validate_claims` becomes:

```python
def _validate_claims(self, payload: dict[str, Any], options: FullOptions) -> None:
    leeway = options["leeway"]
    if isinstance(leeway, timedelta):
        leeway = leeway.total_seconds()

    audience = options["audience"]
    if audience is not None and not isinstance(audience, (str, Iterable)):
        raise TypeError("audience must be a string, iterable or None")

    self._validate_required_claims(payload, options["require"])
    now = datetime.now(tz=timezone.utc).timestamp()

    # Time-based claim validators (only run if claim is present)
    for claim, flag, method_name in self._CLAIM_VALIDATORS:
        if claim in payload and options[flag]:
            getattr(self, method_name)(payload, now, leeway)

    # Option-based validators (always run when flag is set)
    if options["verify_iss"]:
        self._validate_iss(payload, options["issuer"])
    if options["verify_aud"]:
        self._validate_aud(payload, audience, strict=options.get("strict_aud", False))
    if options["verify_sub"]:
        self._validate_sub(payload, options["subject"])
    if options["verify_jti"]:
        self._validate_jti(payload)
```

> [!NOTE]
> The time-based validators (`iat`, `nbf`, `exp`) share the same `(payload, now, leeway)` signature, so they map cleanly to the registry. The non-time validators (`iss`, `aud`, `sub`, `jti`) have different signatures, so they remain explicit but now read their values from `options` instead of function parameters.

---

## Open Questions

> [!IMPORTANT]
> **Q1: Should we update existing tests to use the new `options` style now, or keep them using the old kwargs style to serve as backward-compatibility regression tests?**
> 
> My recommendation: Keep existing tests as-is (they'll exercise the deprecation path) and add a small number of new tests that use the `options`-based API to verify the new style works.

> [!IMPORTANT]
> **Q2: The `_CLAIM_VALIDATORS` and `_OPTION_VALIDATORS` tuples are defined as class attributes. Should they be module-level constants instead?**
> 
> Either approach works. Class-level makes them available for subclass customization; module-level is simpler.

---

## Verification Plan

### Automated Tests

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_api_jwt.py -v
```

- All existing tests pass unchanged (backward compat via `**kwargs` + deprecation warnings)
- Deprecation warnings are correctly emitted when old-style params are used
- New `options`-based API works for `audience`, `issuer`, `subject`, `leeway`
