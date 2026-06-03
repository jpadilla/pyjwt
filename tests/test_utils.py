import base64
import warnings
from contextlib import nullcontext

import pytest

from contextlib import AbstractContextManager

from jwt.utils import (
    base64url_decode,
    force_bytes,
    from_base64url_uint,
    is_ssh_key,
    to_base64url_uint,
)


@pytest.mark.parametrize(
    "inputval,expected",
    [
        (0, nullcontext(b"AA")),
        (1, nullcontext(b"AQ")),
        (255, nullcontext(b"_w")),
        (65537, nullcontext(b"AQAB")),
        (123456789, nullcontext(b"B1vNFQ")),
        (-1, pytest.raises(ValueError)),
    ],
)
def test_to_base64url_uint(
    inputval: int, expected: AbstractContextManager[bytes]
) -> None:
    with expected as e:
        actual = to_base64url_uint(inputval)
        assert actual == e


@pytest.mark.parametrize(
    "inputval,expected",
    [
        (b"AA", 0),
        (b"AQ", 1),
        (b"_w", 255),
        (b"AQAB", 65537),
        (b"B1vNFQ", 123456789),
    ],
)
def test_from_base64url_uint(inputval: bytes, expected: int) -> None:
    actual = from_base64url_uint(inputval)
    assert actual == expected


def test_base64url_decode_handles_standard_alphabet() -> None:
    # The same bytes encoded with the standard ("+/") and the URL-safe ("-_")
    # alphabets must decode to the same value. ``base64url_decode`` normalises
    # the standard alphabet so historical callers keep working.
    raw = bytes(range(256))
    standard = base64.b64encode(raw)
    urlsafe = base64.urlsafe_b64encode(raw).rstrip(b"=")

    assert b"+" in standard or b"/" in standard
    assert base64url_decode(standard) == raw
    assert base64url_decode(urlsafe) == raw


def test_base64url_decode_does_not_warn_on_urlsafe_input() -> None:
    # Valid URL-safe input must never trigger the Python 3.15+ FutureWarning
    # about "+"/"/" in URL-safe Base64 data (jpadilla/pyjwt#1167).
    raw = bytes(range(256))
    standard = base64.b64encode(raw)
    urlsafe = base64.urlsafe_b64encode(raw).rstrip(b"=")

    with warnings.catch_warnings():
        warnings.simplefilter("error", FutureWarning)
        assert base64url_decode(urlsafe) == raw
        # A standard-alphabet input is normalised first, so it must also be
        # decoded without emitting the FutureWarning.
        assert base64url_decode(standard) == raw


def test_force_bytes_raises_error_on_invalid_object() -> None:
    with pytest.raises(TypeError):
        force_bytes({})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "key_format",
    (
        b"ssh-ed25519",
        b"ssh-rsa",
        b"ssh-dss",
        b"ecdsa-sha2-nistp256",
        b"ecdsa-sha2-nistp384",
        b"ecdsa-sha2-nistp521",
    ),
)
def test_is_ssh_key(key_format: bytes) -> None:
    assert is_ssh_key(key_format + b" any") is True
    assert is_ssh_key(b"not a ssh key") is False
