import base64
import hashlib
import hmac
import json


from .compat import constant_time_compare, string_types
from .exceptions import InvalidKeyError
from .utils import (
    base64url_decode, base64url_encode, der_to_raw_signature,
    force_bytes, force_unicode, from_base64url_uint, raw_to_der_signature,
    to_base64url_uint
)

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key, load_pem_public_key, load_ssh_public_key,
        load_der_public_key, load_der_private_key
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateKey, RSAPublicKey, RSAPrivateNumbers, RSAPublicNumbers,
        rsa_recover_prime_factors, rsa_crt_dmp1, rsa_crt_dmq1, rsa_crt_iqmp
    )
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePrivateKey, EllipticCurvePublicKey
    )
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature

    has_crypto = True
except ImportError:
    has_crypto = False

requires_cryptography = set(['RS256', 'RS384', 'RS512', 'ES256', 'ES384',
                             'ES521', 'ES512', 'PS256', 'PS384', 'PS512'])


def get_default_algorithms():
    """
    Returns the algorithms that are implemented by the library.
    """
    default_algorithms = {
        'none': NoneAlgorithm(),
        'HS256': HMACAlgorithm(HMACAlgorithm.SHA256),
        'HS384': HMACAlgorithm(HMACAlgorithm.SHA384),
        'HS512': HMACAlgorithm(HMACAlgorithm.SHA512)
    }

    if has_crypto:
        default_algorithms.update({
            'RS256': RSAAlgorithm(RSAAlgorithm.SHA256),
            'RS384': RSAAlgorithm(RSAAlgorithm.SHA384),
            'RS512': RSAAlgorithm(RSAAlgorithm.SHA512),
            'ES256': ECAlgorithm(ECAlgorithm.SHA256),
            'ES384': ECAlgorithm(ECAlgorithm.SHA384),
            'ES521': ECAlgorithm(ECAlgorithm.SHA512),
            'ES512': ECAlgorithm(ECAlgorithm.SHA512),  # Backward compat for #219 fix
            'PS256': RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256),
            'PS384': RSAPSSAlgorithm(RSAPSSAlgorithm.SHA384),
            'PS512': RSAPSSAlgorithm(RSAPSSAlgorithm.SHA512)
        })

    return default_algorithms


class Algorithm(object):
    """
    The interface for an algorithm used to sign and verify tokens.
    """
    def prepare_key(self, key):
        """
        Performs necessary validation and conversions on the key and returns
        the key value in the proper format for sign() and verify().
        """
        raise NotImplementedError

    def sign(self, msg, key):
        """
        Returns a digital signature for the specified message
        using the specified key value.
        """
        raise NotImplementedError

    def verify(self, msg, key, sig):
        """
        Verifies that the specified digital signature is valid
        for the specified message and key values.
        """
        raise NotImplementedError

    @staticmethod
    def to_jwk(key_obj):
        """
        Serializes a given RSA key into a JWK
        """
        raise NotImplementedError

    @staticmethod
    def from_jwk(jwk):
        """
        Deserializes a given RSA key from JWK back into a PublicKey or PrivateKey object
        """
        raise NotImplementedError


class NoneAlgorithm(Algorithm):
    """
    Placeholder for use when no signing or verification
    operations are required.
    """
    def prepare_key(self, key):
        if key == '':
            key = None

        if key is not None:
            raise InvalidKeyError('When alg = "none", key value must be None.')

        return key

    def sign(self, msg, key):
        return b''

    def verify(self, msg, key, sig):
        return False


class HMACAlgorithm(Algorithm):
    """
    Performs signing and verification operations using HMAC
    and the specified hash function.
    """
    SHA256 = hashlib.sha256
    SHA384 = hashlib.sha384
    SHA512 = hashlib.sha512

    def __init__(self, hash_alg):
        self.hash_alg = hash_alg

    def prepare_key(self, key):
        key = force_bytes(key)

        invalid_strings = [
            b'-----BEGIN PUBLIC KEY-----',
            b'-----BEGIN CERTIFICATE-----',
            b'-----BEGIN RSA PUBLIC KEY-----',
            b'ssh-rsa'
        ]

        if any([string_value in key for string_value in invalid_strings]):
            raise InvalidKeyError(
                'The specified key is an asymmetric key or x509 certificate and'
                ' should not be used as an HMAC secret.')

        return key

    @staticmethod
    def to_jwk(key_obj):
        return json.dumps({
            'k': force_unicode(base64url_encode(force_bytes(key_obj))),
            'kty': 'oct'
        })

    @staticmethod
    def from_jwk(jwk):
        obj = json.loads(jwk)

        if obj.get('kty') != 'oct':
            raise InvalidKeyError('Not an HMAC key')

        return base64url_decode(obj['k'])

    def sign(self, msg, key):
        return hmac.new(key, msg, self.hash_alg).digest()

    def verify(self, msg, key, sig):
        return constant_time_compare(sig, self.sign(msg, key))


if has_crypto:

    class RSAAlgorithm(Algorithm):
        """
        Performs signing and verification operations using
        RSASSA-PKCS-v1_5 and the specified hash function.
        """
        SHA256 = hashes.SHA256
        SHA384 = hashes.SHA384
        SHA512 = hashes.SHA512

        def __init__(self, hash_alg):
            self.hash_alg = hash_alg

        def prepare_key(self, key):
            if isinstance(key, RSAPrivateKey) or \
               isinstance(key, RSAPublicKey):
                return key

            if isinstance(key, string_types):
                key = force_bytes(key)

                try:
                    if key.startswith(b'ssh-rsa'):
                        key = load_ssh_public_key(key, backend=default_backend())
                    else:
                        key = load_pem_private_key(key, password=None, backend=default_backend())
                except ValueError:
                    key = load_pem_public_key(key, backend=default_backend())
            else:
                raise TypeError('Expecting a PEM-formatted key.')

            return key

        @staticmethod
        def to_jwk(key_obj):
            obj = None

            if getattr(key_obj, 'private_numbers', None):
                # Private key
                numbers = key_obj.private_numbers()

                obj = {
                    'kty': 'RSA',
                    'key_ops': ['sign'],
                    'n': force_unicode(to_base64url_uint(numbers.public_numbers.n)),
                    'e': force_unicode(to_base64url_uint(numbers.public_numbers.e)),
                    'd': force_unicode(to_base64url_uint(numbers.d)),
                    'p': force_unicode(to_base64url_uint(numbers.p)),
                    'q': force_unicode(to_base64url_uint(numbers.q)),
                    'dp': force_unicode(to_base64url_uint(numbers.dmp1)),
                    'dq': force_unicode(to_base64url_uint(numbers.dmq1)),
                    'qi': force_unicode(to_base64url_uint(numbers.iqmp))
                }

            elif getattr(key_obj, 'verify', None):
                # Public key
                numbers = key_obj.public_numbers()

                obj = {
                    'kty': 'RSA',
                    'key_ops': ['verify'],
                    'n': force_unicode(to_base64url_uint(numbers.n)),
                    'e': force_unicode(to_base64url_uint(numbers.e))
                }
            else:
                raise InvalidKeyError('Not a public or private key')

            return json.dumps(obj)

        @staticmethod
        def from_jwk(jwk):
            try:
                obj = json.loads(jwk)
            except ValueError:
                raise InvalidKeyError('Key is not valid JSON')

            if obj.get('kty') != 'RSA':
                raise InvalidKeyError('Not an RSA key')

            if 'd' in obj and 'e' in obj and 'n' in obj:
                # Private key
                if 'oth' in obj:
                    raise InvalidKeyError('Unsupported RSA private key: > 2 primes not supported')

                other_props = ['p', 'q', 'dp', 'dq', 'qi']
                props_found = [prop in obj for prop in other_props]
                any_props_found = any(props_found)

                if any_props_found and not all(props_found):
                    raise InvalidKeyError('RSA key must include all parameters if any are present besides d')

                public_numbers = RSAPublicNumbers(
                    from_base64url_uint(obj['e']), from_base64url_uint(obj['n'])
                )

                if any_props_found:
                    numbers = RSAPrivateNumbers(
                        d=from_base64url_uint(obj['d']),
                        p=from_base64url_uint(obj['p']),
                        q=from_base64url_uint(obj['q']),
                        dmp1=from_base64url_uint(obj['dp']),
                        dmq1=from_base64url_uint(obj['dq']),
                        iqmp=from_base64url_uint(obj['qi']),
                        public_numbers=public_numbers
                    )
                else:
                    d = from_base64url_uint(obj['d'])
                    p, q = rsa_recover_prime_factors(
                        public_numbers.n, d, public_numbers.e
                    )

                    numbers = RSAPrivateNumbers(
                        d=d,
                        p=p,
                        q=q,
                        dmp1=rsa_crt_dmp1(d, p),
                        dmq1=rsa_crt_dmq1(d, q),
                        iqmp=rsa_crt_iqmp(p, q),
                        public_numbers=public_numbers
                    )

                return numbers.private_key(default_backend())
            elif 'n' in obj and 'e' in obj:
                # Public key
                numbers = RSAPublicNumbers(
                    from_base64url_uint(obj['e']), from_base64url_uint(obj['n'])
                )

                return numbers.public_key(default_backend())
            else:
                raise InvalidKeyError('Not a public or private key')

        def sign(self, msg, key):
            return key.sign(msg, padding.PKCS1v15(), self.hash_alg())

        def verify(self, msg, key, sig):
            try:
                key.verify(sig, msg, padding.PKCS1v15(), self.hash_alg())
                return True
            except InvalidSignature:
                return False

    class ECAlgorithm(Algorithm):
        """
        Performs signing and verification operations using
        ECDSA and the specified hash function
        """
        SHA256 = hashes.SHA256
        SHA384 = hashes.SHA384
        SHA512 = hashes.SHA512

        def __init__(self, hash_alg):
            self.hash_alg = hash_alg

        def prepare_key(self, key):
            if isinstance(key, EllipticCurvePrivateKey) or \
               isinstance(key, EllipticCurvePublicKey):
                return key

            if isinstance(key, string_types):
                key = force_bytes(key)

                # Attempt to load key. We don't know if it's
                # a Signing Key or a Verifying Key, so we try
                # the Verifying Key first.
                try:
                    if key.startswith(b'ecdsa-sha2-'):
                        key = load_ssh_public_key(key, backend=default_backend())
                    else:
                        key = load_pem_public_key(key, backend=default_backend())
                except ValueError:
                    key = load_pem_private_key(key, password=None, backend=default_backend())

            else:
                raise TypeError('Expecting a PEM-formatted key.')

            return key

        def sign(self, msg, key):
            der_sig = key.sign(msg, ec.ECDSA(self.hash_alg()))

            return der_to_raw_signature(der_sig, key.curve)

        def verify(self, msg, key, sig):
            try:
                der_sig = raw_to_der_signature(sig, key.curve)
            except ValueError:
                return False

            try:
                key.verify(der_sig, msg, ec.ECDSA(self.hash_alg()))
                return True
            except InvalidSignature:
                return False

        @staticmethod
        def from_jwk(jwk):

            ASN1_TAG_SEQUENCE = 0b10000
            ASN1_TAG_OBJECT_IDENTIFIER = 0b110
            ASN1_TAG_INTEGER = 0b10
            ASN1_TAG_BITSTRING = 0b11
            ASN1_TAG_OCTETSTRING = 0b100
            ASN1_CONTEXT_SPECIFIC = 0b10000000
            ASN1_CONSTRUCTED = 0b100000

            # ASN.1 Object Identifiers for EC public key and curves
            ASN1_OID_PUBKEY = b'\x2a\x86\x48\xce\x3d\x02\x01'
            # 1.2.840.10045.2.1
            ASN1_OID_CURVE_P256 = b'\x2a\x86\x48\xce\x3d\x03\x01\x07'
            # 1.2.840.10045.3.1.7
            ASN1_OID_CURVE_P384 = b'\x2b\x81\x04\x00\x22'
            # 1.3.132.0.34
            ASN1_OID_CURVE_P521 = b'\x2b\x81\x04\x00\x23'
            # 1.3.132.0.35

            def encode_length(length):
                """Object length is encoded as a single octet for lengths <=
                127 octets and in max 1 + 127 octets for everything > 127
                octets."""
                res = bytearray()
                if length <= 127:
                    res.append(length)
                else:
                    lengthbytes = bytearray()
                    while length > 0:
                        lengthbytes.append(length & 0xFF)
                        length = length >> 8
                    if len(lengthbytes) > 127:
                        raise Exception("Cannot encode objects this long in ASN.1")
                        # Not sure what to raise here
                    res.append(0b10000000 | len(lengthbytes))
                    res.extend(lengthbytes)
                return bytes(res)

            try:
                obj = json.loads(jwk)
            except ValueError:
                raise InvalidKeyError('Key is not valid JSON')

            if obj.get('kty') != 'EC':
                raise InvalidKeyError('Not an Elliptic curve key')

            if 'x' not in obj or 'y' not in obj:
                raise InvalidKeyError('Not an Elliptic curve key')

            x = base64.urlsafe_b64decode(force_bytes(obj.get('x')))
            y = base64.urlsafe_b64decode(force_bytes(obj.get('y')))

            curve = obj.get('crv')
            if curve == 'P-256':
                if len(x) == len(y) == 32:
                    curve_oid = ASN1_OID_CURVE_P256
                else:
                    raise InvalidKeyError("X should be 32 bytes for curve P-256")
            elif curve == 'P-384':
                if len(x) == len(y) == 48:
                    curve_oid = ASN1_OID_CURVE_P384
                else:
                    raise InvalidKeyError("X should be 48 bytes for curve P-384")
            elif curve == 'P-521':
                if len(x) == len(y) == 66:
                    curve_oid = ASN1_OID_CURVE_P521
                else:
                    raise InvalidKeyError("X should be 66 bytes for curve P-521")
            else:
                raise InvalidKeyError("Invalid curve: {}".format(curve))

            ec_point = bytearray()
            ec_point.append(ASN1_TAG_BITSTRING)
            ec_point.extend(encode_length(2 + len(x)*2))
            ec_point.append(0)  # no unused bits
            ec_point.append(4)  # no compression
            ec_point.extend(x)
            ec_point.extend(y)

            if 'd' in obj:
                # Encode as private key.
                #
                # Format (https://tools.ietf.org/html/rfc5915#section-3):
                #
                #   ECPrivateKey ::= SEQUENCE {
                #     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
                #     privateKey     OCTET STRING,
                #     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
                #     publicKey  [1] BIT STRING OPTIONAL
                #   }
                d = base64.urlsafe_b64decode(force_bytes(obj.get('d')))
                if len(d) != len(x):
                    raise InvalidKeyError(
                        "D should be {} bytes for curve {}", len(x), curve
                    )

                version = bytearray()
                version.append(ASN1_TAG_INTEGER)
                version.extend(encode_length(0x01))
                version.append(1)

                privatekey = bytearray()
                privatekey.append(ASN1_TAG_OCTETSTRING)
                privatekey.extend(encode_length(len(d)))
                privatekey.extend(d)

                parameters = bytearray()
                parameters.append(ASN1_CONTEXT_SPECIFIC | ASN1_CONSTRUCTED)
                # context specific, constructed because OPTIONAL [0]
                parameters.extend(encode_length(len(curve_oid) + 2))
                parameters.append(ASN1_TAG_OBJECT_IDENTIFIER)
                parameters.extend(encode_length(len(curve_oid)))
                parameters.extend(curve_oid)

                publickey = bytearray()
                publickey.append(ASN1_CONTEXT_SPECIFIC | ASN1_CONSTRUCTED | 1)
                # context specific, constructed because OPTIONAL [1]
                publickey.extend(encode_length(len(ec_point)))
                publickey.extend(ec_point)

                sequence_length = len(version) + len(privatekey) + \
                                  len(parameters) + len(publickey)

                ec_privatekey = bytearray()
                ec_privatekey.append(ASN1_CONSTRUCTED | ASN1_TAG_SEQUENCE)
                ec_privatekey.extend(encode_length(sequence_length))
                ec_privatekey.extend(version)
                ec_privatekey.extend(privatekey)
                ec_privatekey.extend(parameters)
                ec_privatekey.extend(publickey)

                return load_der_private_key(
                    bytes(ec_privatekey), None, default_backend()
                )

            # Encode as public key.
            #
            # Format (https://tools.ietf.org/html/rfc5480#section-2):
            #
            #   PublicKeyInfo ::= SEQUENCE {
            #     algorithm       AlgorithmIdentifier,
            #     PublicKey       BIT STRING
            #   }
            #
            #   AlgorithmIdentifier ::= SEQUENCE {
            #     algorithm       OBJECT IDENTIFIER,
            #     parameters      ANY DEFINED BY algorithm OPTIONAL
            #   }
            algorithm_identifier = bytearray()
            algorithm_identifier.append(ASN1_TAG_OBJECT_IDENTIFIER)
            algorithm_identifier.extend(encode_length(len(ASN1_OID_PUBKEY)))
            algorithm_identifier.extend(ASN1_OID_PUBKEY)
            algorithm_identifier.append(ASN1_TAG_OBJECT_IDENTIFIER)
            algorithm_identifier.extend(encode_length(len(curve_oid)))
            algorithm_identifier.extend(curve_oid)

            algorithm = bytearray()
            algorithm.append(ASN1_CONSTRUCTED | ASN1_TAG_SEQUENCE)
            algorithm.extend(encode_length(len(algorithm_identifier)))

            sequence_length = len(algorithm_identifier) + \
                              len(algorithm) + len(ec_point)

            publickey_info = bytearray()
            publickey_info.append(ASN1_CONSTRUCTED | ASN1_TAG_SEQUENCE)
            publickey_info.extend(encode_length(sequence_length))
            publickey_info.extend(algorithm)
            publickey_info.extend(algorithm_identifier)
            publickey_info.extend(ec_point)

            return load_der_public_key(
                bytes(publickey_info), default_backend()
            )


    class RSAPSSAlgorithm(RSAAlgorithm):
        """
        Performs a signature using RSASSA-PSS with MGF1
        """

        def sign(self, msg, key):
            return key.sign(
                msg,
                padding.PSS(
                    mgf=padding.MGF1(self.hash_alg()),
                    salt_length=self.hash_alg.digest_size
                ),
                self.hash_alg()
            )

        def verify(self, msg, key, sig):
            try:
                key.verify(
                    sig,
                    msg,
                    padding.PSS(
                        mgf=padding.MGF1(self.hash_alg()),
                        salt_length=self.hash_alg.digest_size
                    ),
                    self.hash_alg()
                )
                return True
            except InvalidSignature:
                return False
