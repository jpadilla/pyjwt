# PyJWT Code Smells Analysis

This document provides a categorized shortlist of code smells identified within the PyJWT project, along with their causes, associated metric scores (using `radon`), and recommended treatments.

## 1. Large File / God Class (Bloater)

### **Location:**
`jwt/algorithms.py` (998 Lines of Code)

### **Cause & Metrics:**
This file acts as a centralized "God Class" module, containing the logic for every single supported cryptographic algorithm (`RSAAlgorithm`, `ECAlgorithm`, `RSAPSSAlgorithm`, `OKPAlgorithm`, `HMACAlgorithm`, `NoneAlgorithm`).
- **Maintainability Index (MI):** `B` (The only file in the project that is not an `A`).
- **Cause:** Over time, as more algorithms and features (like JWK support) were added, they were all appended to this single file, leading to low cohesion.

### **Treatment:**
- **Extract Module / Extract Class:** Split the algorithms into a dedicated subpackage (e.g., `jwt/algorithms/`). Create separate files for each family of algorithms, such as `rsa.py`, `ec.py`, `hmac.py`, and `okp.py`. (Note: It appears a partial refactor has already begun with the existence of the `jwt/algorithms/` folder, but the monolithic `algorithms.py` remains the primary entry point).

---

## 2. High Cyclomatic Complexity & Long Methods

### **Location:**
- `jwt/algorithms.py` -> `ECAlgorithm.from_jwk`, `RSAAlgorithm.from_jwk`, `OKPAlgorithm.from_jwk`
- `jwt/api_jwt.py` -> `PyJWT._validate_aud`, `PyJWT._validate_claims`

### **Cause & Metrics:**
- **Cyclomatic Complexity (CC):**
  - `OKPAlgorithm.from_jwk` - Score: **C (High)**
  - `ECAlgorithm.from_jwk` - Score: **C (High)**
  - `RSAAlgorithm.from_jwk` - Score: **C (High)**
  - `PyJWT._validate_aud` - Score: **C (High)**
- **Cause:** These methods contain excessive `if/elif/else` branching. For instance, `from_jwk` methods handle JSON parsing, validation, public/private key distinction, and curve matching all in one block. Similarly, `_validate_aud` handles strict/loose string/list matching in a single method.

### **Treatment:**
- **Extract Method:** Break down `from_jwk` into smaller methods like `_parse_private_key()` and `_parse_public_key()`.
- **Replace Conditional with Polymorphism:** For the EC algorithms, instead of branching based on `crv` (P-256, P-384, etc.) inside the method, delegate the instantiation to curve-specific handler classes.
- **Decompose Conditional:** Split `_validate_aud` into `_validate_aud_strict` and `_validate_aud_loose`.

---

## 3. Duplicated Code (Boilerplate)

### **Location:**
`jwt/algorithms.py` (across all `Algorithm` subclasses)

### **Cause:**
The `to_jwk` and `from_jwk` methods across `RSAAlgorithm`, `ECAlgorithm`, and `HMACAlgorithm` share nearly identical structural boilerplate:
1. Checking if the input is a string or dict.
2. Parsing JSON.
3. Verifying the `kty` (Key Type) field.
4. Handling generic exceptions and re-raising them as `InvalidKeyError`.

### **Treatment:**
- **Form Template Method:** Move the common JSON parsing and basic validation logic into the base `Algorithm` class. Let the subclasses only implement the specific cryptographic extraction logic (e.g., extracting `x` and `y` for EC keys).

---

## 4. Long Parameter List

### **Location:**
`jwt/api_jwt.py` -> `PyJWT.decode_complete` and `PyJWT.decode`

### **Cause:**
The `decode_complete` method accepts up to **11 arguments**:
`(jwt, key, algorithms, options, verify, detached_payload, audience, issuer, subject, leeway, **kwargs)`

### **Treatment:**
- **Introduce Parameter Object:** The method already accepts an `options` dictionary, but several parameters (`audience`, `issuer`, `subject`, `leeway`, `verify`) are still passed individually. These parameters should be consolidated into a unified `DecodeOptions` typed dict or dataclass to reduce the method signature size and improve readability.

---

## 5. Deprecated/Dead Code Maintenance

### **Location:**
`jwt/api_jwt.py` -> Legacy `verify` and `**kwargs` in `decode`

### **Cause:**
To maintain backwards compatibility, the code includes legacy arguments like `verify` and catches stray `**kwargs` just to raise `RemovedInPyjwt3Warning`. While necessary for library evolution, leaving these in the core execution path clutters the logic.

### **Treatment:**
- **Inline/Remove (Eventually):** Once PyJWT v3 is released, these can be safely removed. Until then, the warning logic could be abstracted into a decorator (e.g., `@warn_deprecated_args`) to keep the core `decode` method focused strictly on business logic.
