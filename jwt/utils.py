import base64


def base64url_decode(input):
    rem = len(input) % 4

    if rem > 0:
        input += b'=' * (4 - rem)

    return base64.urlsafe_b64decode(input)


def base64url_encode(input):
    return base64.urlsafe_b64encode(input).replace(b'=', b'')


def merge_dict(original, updates):
    if not updates:
        return original

    try:
        merged_options = original.copy()
        merged_options.update(updates)
    except (AttributeError, ValueError) as e:
        raise TypeError('original and updates must be a dictionary: %s' % e)

    return merged_options
