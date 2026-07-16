from jwt.exceptions import MissingRequiredClaimError


def test_missing_required_claim_error_has_proper_str() -> None:
    exc = MissingRequiredClaimError("abc")

    assert str(exc) == 'Token is missing the "abc" claim'


def test_missing_required_claim_error_defaults_claims_to_single_claim() -> None:
    exc = MissingRequiredClaimError("abc")

    assert exc.claim == "abc"
    assert exc.claims == ["abc"]


def test_missing_required_claim_error_with_multiple_claims() -> None:
    exc = MissingRequiredClaimError("abc", ["abc", "def", "ghi"])

    assert exc.claim == "abc"
    assert exc.claims == ["abc", "def", "ghi"]
    assert str(exc) == 'Token is missing the following claims: "abc", "def", "ghi"'
