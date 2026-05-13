# Refactor api_jwt.py — Parameter Lists & Validation Complexity

- `[x]` Update `types.py` — add `audience`, `issuer`, `subject`, `leeway` to `Options` and `FullOptions`
- `[x]` Update `api_jwt.py` — `_get_default_options()` with new defaults
- `[x]` Update `api_jwt.py` — loop-based `_merge_options()`
- `[x]` Update `api_jwt.py` — simplify `decode_complete()` signature + backward compat kwargs
- `[x]` Update `api_jwt.py` — simplify `decode()` signature + backward compat kwargs
- `[x]` Update `api_jwt.py` — simplify `_validate_claims()` signature + validator dispatch
- `[x]` Run tests to verify — **80/80 passed**
