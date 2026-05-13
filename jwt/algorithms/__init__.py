from __future__ import annotations

from ._types import (
    AllowedECKeys,
    AllowedKeys,
    AllowedOKPKeys,
    AllowedPrivateKeys,
    AllowedPublicKeys,
    AllowedRSAKeys,
    has_crypto,
    requires_cryptography,
)
from .base import Algorithm, NoneAlgorithm
from .hmac import HMACAlgorithm

if has_crypto:
    from .ec import ECAlgorithm
    from .okp import OKPAlgorithm
    from .rsa import RSAAlgorithm, RSAPSSAlgorithm

from .ec import _EC_CRV_TO_CURVE  # noqa: for use by api_jwk if needed


def get_default_algorithms() -> dict[str, Algorithm]:
    default_algorithms: dict[str, Algorithm] = {
        "none": NoneAlgorithm(),
        "HS256": HMACAlgorithm(HMACAlgorithm.SHA256),
        "HS384": HMACAlgorithm(HMACAlgorithm.SHA384),
        "HS512": HMACAlgorithm(HMACAlgorithm.SHA512),
    }

    if has_crypto:
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP256K1,
            SECP256R1,
            SECP384R1,
            SECP521R1,
        )

        default_algorithms.update(
            {
                "RS256": RSAAlgorithm(RSAAlgorithm.SHA256),
                "RS384": RSAAlgorithm(RSAAlgorithm.SHA384),
                "RS512": RSAAlgorithm(RSAAlgorithm.SHA512),
                "ES256": ECAlgorithm(ECAlgorithm.SHA256, SECP256R1),
                "ES256K": ECAlgorithm(ECAlgorithm.SHA256, SECP256K1),
                "ES384": ECAlgorithm(ECAlgorithm.SHA384, SECP384R1),
                "ES521": ECAlgorithm(ECAlgorithm.SHA512, SECP521R1),
                "ES512": ECAlgorithm(ECAlgorithm.SHA512, SECP521R1),
                "PS256": RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256),
                "PS384": RSAPSSAlgorithm(RSAPSSAlgorithm.SHA384),
                "PS512": RSAPSSAlgorithm(RSAPSSAlgorithm.SHA512),
                "EdDSA": OKPAlgorithm(),
            }
        )

    return default_algorithms


__all__ = [
    "Algorithm",
    "NoneAlgorithm",
    "HMACAlgorithm",
    "RSAAlgorithm",
    "RSAPSSAlgorithm",
    "ECAlgorithm",
    "OKPAlgorithm",
    "AllowedRSAKeys",
    "AllowedECKeys",
    "AllowedOKPKeys",
    "AllowedKeys",
    "AllowedPrivateKeys",
    "AllowedPublicKeys",
    "has_crypto",
    "requires_cryptography",
    "get_default_algorithms",
]
