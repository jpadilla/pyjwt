from contextlib import nullcontext

import pytest

from jwt.utils import force_bytes, from_base64url_uint, is_ssh_key, to_base64url_uint


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
def test_to_base64url_uint(inputval, expected):
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
def test_from_base64url_uint(inputval, expected):
    actual = from_base64url_uint(inputval)
    assert actual == expected


def test_force_bytes_raises_error_on_invalid_object():
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
def test_is_ssh_key(key_format):
    assert is_ssh_key(key_format + b" any") is True
    assert is_ssh_key(b"not a ssh key") is False
