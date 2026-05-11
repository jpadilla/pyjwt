from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING, Union

try:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePrivateKey,
        EllipticCurvePublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed448 import (
        Ed448PrivateKey, Ed448PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateKey, RSAPublicKey,
    )

    if sys.version_info >= (3, 10):
        from typing import TypeAlias
    else:
        from typing_extensions import TypeAlias

    AllowedRSAKeys: TypeAlias = Union[RSAPrivateKey, RSAPublicKey]
    AllowedECKeys: TypeAlias = Union[EllipticCurvePrivateKey, EllipticCurvePublicKey]
    AllowedOKPKeys: TypeAlias = Union[
        Ed25519PrivateKey, Ed25519PublicKey, Ed448PrivateKey, Ed448PublicKey
    ]
    AllowedKeys: TypeAlias = Union[AllowedRSAKeys, AllowedECKeys, AllowedOKPKeys]
    AllowedPrivateKeys: TypeAlias = Union[
        RSAPrivateKey, EllipticCurvePrivateKey, Ed25519PrivateKey, Ed448PrivateKey
    ]
    AllowedPublicKeys: TypeAlias = Union[
        RSAPublicKey, EllipticCurvePublicKey, Ed25519PublicKey, Ed448PublicKey
    ]

    if TYPE_CHECKING or bool(os.getenv("SPHINX_BUILD", "")):
        from cryptography.hazmat.primitives.asymmetric.types import (
            PrivateKeyTypes, PublicKeyTypes,
        )

    has_crypto = True
except ModuleNotFoundError:
    if sys.version_info >= (3, 11):
        from typing import Never
    else:
        from typing_extensions import Never

    AllowedRSAKeys = Never   # type: ignore[misc]
    AllowedECKeys = Never    # type: ignore[misc]
    AllowedOKPKeys = Never   # type: ignore[misc]
    AllowedKeys = Never      # type: ignore[misc]
    AllowedPrivateKeys = Never  # type: ignore[misc]
    AllowedPublicKeys = Never   # type: ignore[misc]
    has_crypto = False

requires_cryptography = {
    "RS256", "RS384", "RS512", "ES256", "ES256K", "ES384",
    "ES521", "ES512", "PS256", "PS384", "PS512", "EdDSA",
}
