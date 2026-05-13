# Algorithms Package: `rsa.py` & `okp.py` Fixes

Corrected both modules to match the original `algorithms.py` behavior that was lost during the initial refactoring extraction.

---

## `rsa.py` — Changes

### 1. Restored `check_key_length()` and `_MIN_KEY_SIZE`

The original RSAAlgorithm enforces a minimum key size of 2048 bits (NIST SP 800-131A). This was dropped entirely.

```diff
     _crypto_key_types = cast(
         tuple[type[AllowedRSAKeys], ...], get_args(AllowedRSAKeys)
     )
+    _MIN_KEY_SIZE: ClassVar[int] = 2048
 
     def __init__(self, hash_alg: type[hashes.HashAlgorithm]) -> None:
         self.hash_alg = hash_alg
 
+    def check_key_length(self, key: AllowedRSAKeys) -> str | None:
+        if key.key_size < self._MIN_KEY_SIZE:
+            return (
+                f"The RSA key is {key.key_size} bits long, which is below "
+                f"the minimum recommended size of {self._MIN_KEY_SIZE} bits. "
+                f"See NIST SP 800-131A."
+            )
+        return None
```

### 2. Fixed `prepare_key()` PEM parsing order

The original tries **private key first** for non-SSH PEM data, then falls back to public. The refactored version had it reversed. Also restores `UnsupportedAlgorithm` catch and proper error message.

```diff
-        try:
-            if key_bytes.startswith(b"ssh-rsa"):
-                public_key = load_ssh_public_key(key_bytes)
-            else:
-                public_key = load_pem_public_key(key_bytes)
-            self.check_crypto_key_type(public_key)
-            return cast(RSAPublicKey, public_key)
-        except ValueError:
-            private_key = load_pem_private_key(key_bytes, password=None)
-            self.check_crypto_key_type(private_key)
-            return cast(RSAPrivateKey, private_key)
+        try:
+            if key_bytes.startswith(b"ssh-rsa"):
+                public_key = load_ssh_public_key(key_bytes)
+                self.check_crypto_key_type(public_key)
+                return cast(RSAPublicKey, public_key)
+            else:
+                private_key = load_pem_private_key(key_bytes, password=None)
+                self.check_crypto_key_type(private_key)
+                return cast(RSAPrivateKey, private_key)
+        except ValueError:
+            try:
+                public_key = load_pem_public_key(key_bytes)
+                self.check_crypto_key_type(public_key)
+                return cast(RSAPublicKey, public_key)
+            except (ValueError, UnsupportedAlgorithm):
+                raise InvalidKeyError(
+                    "Could not parse the provided public key."
+                ) from None
```

### 3. Added `key_ops` to `to_jwk()`

The original includes `"key_ops": ["sign"]` for private keys and `"key_ops": ["verify"]` for public keys. Also restructured to build the full dict in each branch (matching original style).

### 4. Restored full `from_jwk()` validation & prime recovery

Three pieces of logic were missing:

| Feature | Before | After |
|---|---|---|
| Multi-prime (`"oth"`) rejection | ❌ Silently accepted | ✅ Raises `InvalidKeyError` |
| Partial CRT params (e.g. `p` without `q`) | ❌ Used `0` as default | ✅ Raises `InvalidKeyError` |
| Missing CRT params (only `d`) | ❌ Used `0` for p/q/dp/dq/qi | ✅ Uses `rsa_recover_prime_factors()` |

### 5. New imports

```diff
-from cryptography.exceptions import InvalidSignature
+from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
 from cryptography.hazmat.primitives.asymmetric.rsa import (
-    RSAPrivateKey, RSAPrivateNumbers, RSAPublicKey, RSAPublicNumbers,
+    RSAPrivateKey, RSAPrivateNumbers, RSAPublicKey, RSAPublicNumbers,
+    rsa_crt_dmp1, rsa_crt_dmq1, rsa_crt_iqmp, rsa_recover_prime_factors,
 )
```

Also added `from_base64url_uint` from `..utils` for consistency with original.

---

## `okp.py` — Changes

### 1. Added `__init__(**kwargs)`

The original accepts kwargs (instantiated as `OKPAlgorithm()` in `get_default_algorithms`).

```diff
+    def __init__(self, **kwargs: Any) -> None:
+        pass
```

### 2. Restored original `prepare_key()` behavior

The refactored version used a try/except pattern (try public → catch → try private). The original uses explicit PEM prefix matching, which gives clearer errors for unrecognized key formats.

```diff
-    def prepare_key(self, key):
-        if isinstance(key, self._crypto_key_types):
-            return cast(AllowedOKPKeys, key)
-        ...try/except pattern...
+    def prepare_key(self, key):
+        if not isinstance(key, (str, bytes)):
+            self.check_crypto_key_type(key)
+            return cast(AllowedOKPKeys, key)
+        if "-----BEGIN PUBLIC" in key_str:
+            loaded_key = load_pem_public_key(key_bytes)
+        elif "-----BEGIN PRIVATE" in key_str:
+            loaded_key = load_pem_private_key(key_bytes, password=None)
+        elif key_str[0:4] == "ssh-":
+            loaded_key = load_ssh_public_key(key_bytes)
+        else:
+            raise InvalidKeyError("Not a public or private key")
```

### 3. Restored `str | bytes` support in `sign()` and `verify()`

The original OKP methods accept both `str` and `bytes` for messages and signatures. The refactored version only accepted `bytes`.

### 4. Restored explicit `isinstance` check in `verify()`

Changed from `hasattr(key, "public_key")` to `isinstance(key, (Ed25519PrivateKey, Ed448PrivateKey))` — more explicit and type-safe.

### 5. Added `ValueError` catch in `from_jwk()`

The original wraps `from_public_bytes` / `from_private_bytes` in a try/except to convert `ValueError` → `InvalidKeyError("Invalid key parameter")`.

### 6. Moved serialization imports to module level

`Encoding`, `NoEncryption`, `PrivateFormat`, `PublicFormat` are now imported at the top instead of lazily inside `to_jwk()`.

---

## Verification

```
tests/test_algorithms.py — 119 passed ✅
Full suite             — 344 passed, 4 skipped ✅
```

The 4 skips are expected (they test the no-cryptography fallback path).
