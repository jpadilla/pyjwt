# Update `test_api_jwt.py` — Migrate to Options-Based API

Follows up on the `api_jwt.py` refactoring (conversation `e274a6a9`) that moved `audience`, `issuer`, `subject`, and `leeway` from function parameters into the `options` dictionary.

## Problem

All 80 existing tests pass via the backward-compat `**kwargs` shim, but **no tests exercise the new options-based API**. We need to:

1. **Migrate** existing tests to use `options={"audience": ..., "issuer": ..., "subject": ..., "leeway": ...}`
2. **Keep a small set of backward-compat tests** that use the old kwargs style to serve as regression guards
3. **Add new tests** that verify options-based behavior not previously covered

---

## Proposed Changes

### [MODIFY] [test_api_jwt.py](file:///c:/Users/User/Documents/GitHub/pyjwt/tests/test_api_jwt.py)

#### 1. Migrate existing tests to options-based API (35 call sites)

Convert `audience=`, `issuer=`, `subject=`, `leeway=` keyword arguments into `options={}` dict entries. Summary of affected tests:

| Test Method | Old-Style Kwarg(s) | Change |
|---|---|---|
| `test_decode_with_invalid_audience_param_throws_exception` | `audience=1` | → `options={"audience": 1}` |
| `test_decode_with_nonlist_aud_claim_throws_exception` | `audience="my_audience"` | → `options={"audience": "my_audience"}` |
| `test_decode_with_invalid_aud_list_member_throws_exception` | `audience="my_audience"` | → `options={"audience": "my_audience"}` |
| `test_encode_datetime` | `leeway=1` | → `options={"leeway": 1}` |
| `test_decode_with_expiration_with_leeway` | `leeway=5/1` | → `options={"leeway": 5/1}` |
| `test_decode_with_notbefore_with_leeway` | `leeway=13/1` | → `options={"leeway": 13/1}` |
| `test_check_audience_when_valid` | `audience="urn:me"` | → `options={"audience": "urn:me"}` |
| `test_check_audience_list_when_valid` | `audience=[...]` | → `options={"audience": [...]}` |
| `test_raise_exception_invalid_audience_list` | `audience=[...]` | → `options={"audience": [...]}` |
| `test_check_audience_in_array_when_valid` | `audience="urn:me"` | → `options={"audience": "urn:me"}` |
| `test_raise_exception_invalid_audience` | `audience="urn-me"` | → `options={"audience": "urn-me"}` |
| `test_raise_exception_audience_as_bytes` | `audience=b"urn:me"` | → `options={"audience": b"urn:me"}` |
| `test_raise_exception_invalid_audience_in_array` | `audience="urn:me"` | → `options={"audience": "urn:me"}` |
| `test_raise_exception_token_without_issuer` | `issuer="urn:wrong"` | → `options={"issuer": "urn:wrong"}` |
| `test_rasise_exception_on_partial_issuer_match` | `issuer="urn:expected"` | → `options={"issuer": "urn:expected"}` |
| `test_raise_exception_token_without_audience` | `audience="urn:me"` | → `options={"audience": "urn:me"}` |
| `test_raise_exception_token_with_aud_none_and_without_audience` | `audience="urn:me"` | → `options={"audience": "urn:me"}` |
| `test_check_issuer_when_valid` | `issuer="urn:foo"` | → `options={"issuer": "urn:foo"}` |
| `test_check_issuer_list_when_valid` | `issuer=[...]` | → `options={"issuer": [...]}` |
| `test_raise_exception_invalid_issuer` | `issuer="urn:wrong"` | → `options={"issuer": "urn:wrong"}` |
| `test_raise_exception_invalid_issuer_list` | `issuer=[...]` | → `options={"issuer": [...]}` |
| `test_decode_strict_aud_*` (4 tests) | `audience=...` | → merged into `options={"audience": ..., "strict_aud": ...}` |
| `test_decode_with_valid_sub_claim` | `subject="user123"` | → `options={"subject": "user123"}` |
| `test_decode_with_invalid_sub_claim` | `subject="user456"` | → `options={"subject": "user456"}` |
| `test_decode_with_sub_claim_and_none_subject` | `subject=None` | → `options={"subject": None}` |

#### 2. Add backward-compat regression test section

Add a new class `TestBackwardCompatKwargs` (or section within `TestJWT`) with ~4 focused tests exercising the old kwargs pathway, confirming they still work without warning (since we silently absorb them, not yet emitting deprecation):

- `test_decode_audience_kwarg_backward_compat` — `audience="urn:me"` as kwarg
- `test_decode_issuer_kwarg_backward_compat` — `issuer="urn:foo"` as kwarg
- `test_decode_subject_kwarg_backward_compat` — `subject="user123"` as kwarg
- `test_decode_leeway_kwarg_backward_compat` — `leeway=5` as kwarg

#### 3. Add new options-based API tests

Add tests that exercise options-based patterns not previously covered:

- `test_decode_options_audience_takes_precedence_over_kwarg` — When both `options={"audience": "A"}` and `audience="B"` are passed, options wins
- `test_decode_options_leeway_with_timedelta` — `options={"leeway": timedelta(seconds=5)}`
- `test_decode_options_combined_validation` — Multiple validation params in a single options dict

---

## Open Questions

> [!IMPORTANT]
> **Q1: Should the backward-compat regression tests be in a separate test class (`TestBackwardCompatKwargs`) or just grouped at the end of `TestJWT`?**
> 
> My recommendation: Group them at the end of `TestJWT` under a comment section header, consistent with the existing pattern (e.g. `# -------------------- Sub Claim Tests --------------------`).

> [!IMPORTANT]
> **Q2: Should we emit deprecation warnings for the old kwargs-style parameters now?**
> 
> Currently the shim silently absorbs the old kwargs without warning. The implementation plan from the previous conversation deferred this. If we add warnings now, the backward-compat tests would need `pytest.warns()`. My recommendation: **defer warnings** to a separate PR — this task focuses on updating test call sites only.

---

## Verification Plan

### Automated Tests

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_api_jwt.py -v
```

- All migrated tests continue to pass with the new `options={}` style
- Backward-compat regression tests pass using old kwargs style
- New options-based tests pass
- Full suite remains at **80+ tests** (originals + new additions)
