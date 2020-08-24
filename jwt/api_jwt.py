import json
from calendar import timegm
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta

from .algorithms import Algorithm, get_default_algorithms  # NOQA
from .api_jws import PyJWS
from .exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    MissingRequiredClaimError,
)
from .utils import merge_dict

try:
    # import required by mypy to perform type checking, not used for normal execution
    from typing import Any, Callable, Dict, List, Optional, Type, Union  # NOQA
except ImportError:
    pass


class PyJWT(PyJWS):
    header_type = "JWT"

    @staticmethod
    def _get_default_options():
        # type: () -> Dict[str, Union[bool, List[str]]]
        return {
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": True,
            "verify_aud": True,
            "verify_iss": True,
            "require": [],
        }

    def encode(
        self,
        payload,  # type: Union[Dict, bytes]
        key,  # type: str
        algorithm="HS256",  # type: str
        headers=None,  # type: Optional[Dict]
        json_encoder=None,  # type: Optional[Type[json.JSONEncoder]]
    ):
        # Check that we get a mapping
        if not isinstance(payload, Mapping):
            raise TypeError(
                "Expecting a mapping object, as JWT only supports "
                "JSON objects as payloads."
            )

        # Payload
        for time_claim in ["exp", "iat", "nbf"]:
            # Convert datetime to a intDate value in known time-format claims
            if isinstance(payload.get(time_claim), datetime):
                payload[time_claim] = timegm(
                    payload[time_claim].utctimetuple()
                )  # type: ignore

        json_payload = json.dumps(
            payload, separators=(",", ":"), cls=json_encoder
        ).encode("utf-8")

        return super().encode(
            json_payload, key, algorithm, headers, json_encoder
        )

    def decode(
        self,
        jwt,  # type: str
        key="",  # type: str
        algorithms=None,  # type: List[str]
        options=None,  # type: Dict
        complete=False,  # type: bool
        **kwargs
    ):  # type: (...) -> Dict[str, Any]

        payload, _, _, _ = self._load(jwt)

        if options is None:
            options = {"verify_signature": True}
        else:
            options.setdefault("verify_signature", True)

        if options["verify_signature"] and not algorithms:
            raise DecodeError(
                'It is required that you pass in a value for the "algorithms" argument when calling decode().'
            )

        decoded = super().decode(
            jwt,
            key=key,
            algorithms=algorithms,
            options=options,
            complete=complete,
            **kwargs
        )

        try:
            if complete:
                payload = json.loads(decoded["payload"].decode("utf-8"))
            else:
                payload = json.loads(decoded.decode("utf-8"))
        except ValueError as e:
            raise DecodeError("Invalid payload string: %s" % e)
        if not isinstance(payload, dict):
            raise DecodeError("Invalid payload string: must be a json object")

        if options["verify_signature"]:
            merged_options = merge_dict(self.options, options)
            self._validate_claims(payload, merged_options, **kwargs)

        if complete:
            decoded["payload"] = payload
            return decoded

        return payload

    def _validate_claims(
        self, payload, options, audience=None, issuer=None, leeway=0, **kwargs
    ):
        if isinstance(leeway, timedelta):
            leeway = leeway.total_seconds()

        if not isinstance(audience, (bytes, str, type(None), Iterable)):
            raise TypeError("audience must be a string, iterable, or None")

        self._validate_required_claims(payload, options)

        now = timegm(datetime.utcnow().utctimetuple())

        if "iat" in payload and options.get("verify_iat"):
            self._validate_iat(payload, now, leeway)

        if "nbf" in payload and options.get("verify_nbf"):
            self._validate_nbf(payload, now, leeway)

        if "exp" in payload and options.get("verify_exp"):
            self._validate_exp(payload, now, leeway)

        if options.get("verify_iss"):
            self._validate_iss(payload, issuer)

        if options.get("verify_aud"):
            self._validate_aud(payload, audience)

    def _validate_required_claims(self, payload, options):
        for claim in options.get("require", []):
            if payload.get(claim) is None:
                raise MissingRequiredClaimError(claim)

    def _validate_iat(self, payload, now, leeway):
        try:
            int(payload["iat"])
        except ValueError:
            raise InvalidIssuedAtError(
                "Issued At claim (iat) must be an integer."
            )

    def _validate_nbf(self, payload, now, leeway):
        try:
            nbf = int(payload["nbf"])
        except ValueError:
            raise DecodeError("Not Before claim (nbf) must be an integer.")

        if nbf > (now + leeway):
            raise ImmatureSignatureError("The token is not yet valid (nbf)")

    def _validate_exp(self, payload, now, leeway):
        try:
            exp = int(payload["exp"])
        except ValueError:
            raise DecodeError(
                "Expiration Time claim (exp) must be an" " integer."
            )

        if exp < (now - leeway):
            raise ExpiredSignatureError("Signature has expired")

    def _validate_aud(self, payload, audience):
        if audience is None and "aud" not in payload:
            return

        if audience is not None and "aud" not in payload:
            # Application specified an audience, but it could not be
            # verified since the token does not contain a claim.
            raise MissingRequiredClaimError("aud")

        if audience is None and "aud" in payload:
            # Application did not specify an audience, but
            # the token has the 'aud' claim
            raise InvalidAudienceError("Invalid audience")

        audience_claims = payload["aud"]

        if isinstance(audience_claims, (bytes, str)):
            audience_claims = [audience_claims]
        if not isinstance(audience_claims, list):
            raise InvalidAudienceError("Invalid claim format in token")
        if any(not isinstance(c, (bytes, str)) for c in audience_claims):
            raise InvalidAudienceError("Invalid claim format in token")

        if isinstance(audience, (bytes, str)):
            audience = [audience]

        if not any(aud in audience_claims for aud in audience):
            raise InvalidAudienceError("Invalid audience")

    def _validate_iss(self, payload, issuer):
        if issuer is None:
            return

        if "iss" not in payload:
            raise MissingRequiredClaimError("iss")

        if payload["iss"] != issuer:
            raise InvalidIssuerError("Invalid issuer")


_jwt_global_obj = PyJWT()
encode = _jwt_global_obj.encode
decode = _jwt_global_obj.decode
register_algorithm = _jwt_global_obj.register_algorithm
unregister_algorithm = _jwt_global_obj.unregister_algorithm
get_unverified_header = _jwt_global_obj.get_unverified_header
