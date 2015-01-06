import base64
import hmac
import sys


def base64url_decode(input):
    rem = len(input) % 4

    if rem > 0:
        input += b'=' * (4 - rem)

    return base64.urlsafe_b64decode(input)


def base64url_encode(input):
    return base64.urlsafe_b64encode(input).replace(b'=', b'')

try:
    constant_time_compare = hmac.compare_digest
except AttributeError:
    # Fallback for Python < 2.7.7 and Python < 3.3
    def constant_time_compare(val1, val2):
        """
        Returns True if the two strings are equal, False otherwise.

        The time taken is independent of the number of characters that match.
        """
        if len(val1) != len(val2):
            return False

        result = 0

        if sys.version_info >= (3, 0, 0):
            # Bytes are numbers
            for x, y in zip(val1, val2):
                result |= x ^ y
        else:
            for x, y in zip(val1, val2):
                result |= ord(x) ^ ord(y)

        return result == 0
