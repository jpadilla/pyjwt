from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any
from unittest.mock import patch

import pytest

import jwt
from jwt.exceptions import (
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidSignatureError,
    MissingRequiredClaimError,
)
from jwt.types import Options

KEY = "test-signing-key-32-characters-long"


@pytest.fixture(
    params=[
        jwt.decode,
        jwt.decode_complete,
        jwt.PyJWT().decode,
        jwt.PyJWT().decode_complete,
    ]
)
def decode(request: pytest.FixtureRequest) -> Callable[..., dict[str, Any]]:
    return request.param  # type: ignore[no-any-return]


def test_supplied_time_checks_all_claims(decode: Callable[..., dict[str, Any]]) -> None:
    payload = {"iat": 100, "nbf": 100, "exp": 101}
    token = jwt.encode(payload, KEY, algorithm="HS256")
    result = decode(token, KEY, algorithms=["HS256"], now=100.5)
    assert result.get("payload", result) == payload


@pytest.mark.parametrize(
    "payload,now,error",
    [
        ({"exp": 100}, 100, ExpiredSignatureError),
        ({"exp": 100}, 100.1, ExpiredSignatureError),
        ({"nbf": 100}, 99.9, ImmatureSignatureError),
        ({"iat": 100}, 99.9, ImmatureSignatureError),
    ],
)
def test_time_boundaries(
    payload: dict[str, int], now: float, error: type[Exception]
) -> None:
    token = jwt.encode(payload, KEY, algorithm="HS256")
    with pytest.raises(error):
        jwt.decode(token, KEY, algorithms=["HS256"], now=now)


@pytest.mark.parametrize("now", [0, -1, 0.75])
def test_epoch_and_fractional_times(now: float) -> None:
    token = jwt.encode({"iat": -1, "nbf": -1, "exp": 1}, KEY, algorithm="HS256")
    assert jwt.decode(token, KEY, algorithms=["HS256"], now=now)["exp"] == 1


@pytest.mark.parametrize("leeway", [0.5, timedelta(seconds=0.5)])
@pytest.mark.parametrize("claim,now", [("exp", 100.25), ("nbf", 99.75), ("iat", 99.75)])
def test_leeway(claim: str, now: float, leeway: float | timedelta) -> None:
    token = jwt.encode({claim: 100}, KEY, algorithm="HS256")
    assert jwt.decode(token, KEY, algorithms=["HS256"], now=now, leeway=leeway) == {
        claim: 100
    }


class NaiveTimezone(tzinfo):
    def utcoffset(self, dt: datetime | None) -> None:
        return None

    def dst(self, dt: datetime | None) -> None:
        return None

    def tzname(self, dt: datetime | None) -> None:
        return None


@pytest.mark.parametrize(
    "now",
    [
        datetime(1970, 1, 1, 0, 1, 40, 500000, tzinfo=timezone.utc),
        datetime(
            1970,
            1,
            1,
            5,
            31,
            40,
            500000,
            tzinfo=timezone(timedelta(hours=5, minutes=30)),
        ),
        datetime(1969, 12, 31, 20, 1, 40, 500000, tzinfo=timezone(timedelta(hours=-4))),
        datetime(1970, 1, 1, 0, 1, 40, 500000),
        datetime(1970, 1, 1, 0, 1, 40, 500000, tzinfo=NaiveTimezone()),
    ],
)
def test_datetime_timezone_and_precision(now: datetime) -> None:
    token = jwt.encode({"nbf": 100, "exp": 101}, KEY, algorithm="HS256")
    assert jwt.decode(token, KEY, algorithms=["HS256"], now=now)["exp"] == 101


@pytest.mark.parametrize("now", ["100", True, False, [], {}, object()])
def test_rejects_invalid_time_type(now: Any) -> None:
    token = jwt.encode({}, KEY, algorithm="HS256")
    with pytest.raises(TypeError, match="now must be"):
        jwt.decode(token, KEY, algorithms=["HS256"], now=now)


@pytest.mark.parametrize(
    "now",
    [float("nan"), float("inf"), float("-inf"), pytest.param(10**1000, id="overflow")],
)
def test_rejects_nonfinite_time(now: float) -> None:
    token = jwt.encode({"exp": 0, "nbf": 100}, KEY, algorithm="HS256")
    with pytest.raises(ValueError, match="now must be finite"):
        jwt.decode(token, KEY, algorithms=["HS256"], now=now)


@pytest.mark.parametrize("claim", ["iat", "nbf", "exp"])
def test_claim_options_are_preserved(claim: str) -> None:
    payload = {claim: 0 if claim == "exp" else 200}
    token = jwt.encode(payload, KEY, algorithm="HS256")
    options: Options = {"verify_exp": False, "verify_iat": False, "verify_nbf": False}
    assert (
        jwt.decode(token, KEY, algorithms=["HS256"], options=options, now=100)
        == payload
    )


def test_other_validation_is_preserved() -> None:
    token = jwt.encode({"exp": 101, "aud": "expected"}, KEY, algorithm="HS256")
    with pytest.raises(InvalidSignatureError):
        jwt.decode(
            token, "other-signing-key-32-characters-long", algorithms=["HS256"], now=100
        )
    with pytest.raises(InvalidAudienceError):
        jwt.decode(token, KEY, algorithms=["HS256"], audience="other", now=100)
    with pytest.raises(MissingRequiredClaimError):
        jwt.decode(
            token, KEY, algorithms=["HS256"], options={"require": ["sub"]}, now=100
        )


def test_unverified_decode_can_explicitly_validate_time() -> None:
    token = jwt.encode({"exp": 100}, KEY, algorithm="HS256")
    assert jwt.decode(token, options={"verify_signature": False}, now=100) == {
        "exp": 100
    }
    with pytest.raises(ExpiredSignatureError):
        jwt.decode(
            token, options={"verify_signature": False, "verify_exp": True}, now=100
        )


def test_default_clock_is_read_once() -> None:
    token = jwt.encode({"iat": 100, "nbf": 100, "exp": 101}, KEY, algorithm="HS256")
    with patch("jwt.api_jwt.datetime") as clock:
        clock.now.return_value.timestamp.return_value = 100.5
        assert jwt.decode(token, KEY, algorithms=["HS256"])["exp"] == 101
        clock.now.assert_called_once_with(tz=timezone.utc)


def test_supplied_time_does_not_change_later_decodes() -> None:
    token = jwt.encode({"exp": 101}, KEY, algorithm="HS256")
    assert jwt.decode(token, KEY, algorithms=["HS256"], now=100)["exp"] == 101
    with pytest.raises(ExpiredSignatureError):
        jwt.decode(token, KEY, algorithms=["HS256"])


@pytest.mark.parametrize("explicit_none", [False, True])
def test_default_time_preserves_legacy_subclass_overrides(explicit_none: bool) -> None:
    class LegacyClaims(jwt.PyJWT):
        def _validate_claims(  # type: ignore[override]
            self,
            payload: dict[str, Any],
            options: Any,
            audience: Any = None,
            issuer: Any = None,
            subject: str | None = None,
            leeway: float | timedelta = 0,
        ) -> None:
            super()._validate_claims(
                payload, options, audience, issuer, subject, leeway
            )

    class LegacyDecode(jwt.PyJWT):
        def decode_complete(  # type: ignore[override]
            self,
            jwt: str | bytes,
            key: Any = "",
            algorithms: Any = None,
            options: Any = None,
            verify: bool | None = None,
            detached_payload: bytes | None = None,
            audience: Any = None,
            issuer: Any = None,
            subject: str | None = None,
            leeway: float | timedelta = 0,
        ) -> dict[str, Any]:
            return super().decode_complete(
                jwt,
                key,
                algorithms,
                options,
                verify,
                detached_payload,
                audience,
                issuer,
                subject,
                leeway,
            )

    payload = {"message": "legacy override"}
    token = jwt.encode(payload, KEY, algorithm="HS256")
    for decoder in (LegacyClaims().decode, LegacyDecode().decode):
        if explicit_none:
            assert decoder(token, KEY, algorithms=["HS256"], now=None) == payload
        else:
            assert decoder(token, KEY, algorithms=["HS256"]) == payload
