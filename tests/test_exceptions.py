from jwt.exceptions import MissingRequiredClaimError


def test_missing_required_claim_error_has_proper_str():
    exc = MissingRequiredClaimError('abc')

    assert str(exc) == 'Token is missing the "abc" claim'
