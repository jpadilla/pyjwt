import binascii
import json
from collections.abc import Mapping

from .algorithms import requires_cryptography  # NOQA
from .algorithms import Algorithm, get_default_algorithms, has_crypto
from .exceptions import (
    DecodeError,
    InvalidAlgorithmError,
    InvalidSignatureError,
    InvalidTokenError,
)
from .utils import base64url_decode, base64url_encode, force_bytes, merge_dict

try:
    # import required by mypy to perform type checking, not used for normal execution
    from typing import Callable, Dict, List, Optional, Type, Union  # NOQA
except ImportError:
    pass


class PyJWS:
    header_typ = "JWT"

    def __init__(self, algorithms=None, options=None):
        self._algorithms = get_default_algorithms()
        self._valid_algs = (
            set(algorithms)
            if algorithms is not None
            else set(self._algorithms)
        )

        # Remove algorithms that aren't on the whitelist
        for key in list(self._algorithms.keys()):
            if key not in self._valid_algs:
                del self._algorithms[key]

        if not options:
            options = {}

        self.options = merge_dict(self._get_default_options(), options)

    @staticmethod
    def _get_default_options():
        return {"verify_signature": True}

    def register_algorithm(self, alg_id, alg_obj):
        """
        Registers a new Algorithm for use when creating and verifying tokens.
        """
        if alg_id in self._algorithms:
            raise ValueError("Algorithm already has a handler.")

        if not isinstance(alg_obj, Algorithm):
            raise TypeError("Object is not of type `Algorithm`")

        self._algorithms[alg_id] = alg_obj
        self._valid_algs.add(alg_id)

    def unregister_algorithm(self, alg_id):
        """
        Unregisters an Algorithm for use when creating and verifying tokens
        Throws KeyError if algorithm is not registered.
        """
        if alg_id not in self._algorithms:
            raise KeyError(
                "The specified algorithm could not be removed"
                " because it is not registered."
            )

        del self._algorithms[alg_id]
        self._valid_algs.remove(alg_id)

    def get_algorithms(self):
        """
        Returns a list of supported values for the 'alg' parameter.
        """
        return list(self._valid_algs)

    def encode(
        self,
        payload,  # type: Union[Dict, bytes]
        key,  # type: str
        algorithm="HS256",  # type: str
        headers=None,  # type: Optional[Dict]
        json_encoder=None,  # type: Optional[Type[json.JSONEncoder]]
    ):
        segments = []

        if algorithm is None:
            algorithm = "none"

        if algorithm not in self._valid_algs:
            pass

        # Header
        header = {"typ": self.header_typ, "alg": algorithm}

        if headers:
            self._validate_headers(headers)
            header.update(headers)

        json_header = force_bytes(
            json.dumps(header, separators=(",", ":"), cls=json_encoder)
        )

        segments.append(base64url_encode(json_header))
        segments.append(base64url_encode(payload))

        # Segments
        signing_input = b".".join(segments)
        try:
            alg_obj = self._algorithms[algorithm]
            key = alg_obj.prepare_key(key)
            signature = alg_obj.sign(signing_input, key)

        except KeyError:
            if not has_crypto and algorithm in requires_cryptography:
                raise NotImplementedError(
                    "Algorithm '%s' could not be found. Do you have cryptography "
                    "installed?" % algorithm
                )
            else:
                raise NotImplementedError("Algorithm not supported")

        segments.append(base64url_encode(signature))

        encoded_string = b".".join(segments)

        return encoded_string.decode("utf-8")

    def decode(
        self,
        jwt,  # type: str
        key="",  # type: str
        verify=True,  # type: bool
        algorithms=None,  # type: List[str]
        options=None,  # type: Dict
        complete=False,  # type: bool
        **kwargs
    ):

        merged_options = merge_dict(self.options, options)
        verify_signature = merged_options["verify_signature"]

        if verify_signature and not algorithms:
            raise DecodeError(
                'It is required that you pass in a value for the "algorithms" argument when calling decode().'
            )

        payload, signing_input, header, signature = self._load(jwt)

        if verify_signature:
            self._verify_signature(
                payload, signing_input, header, signature, key, algorithms
            )

        if complete:
            return {
                "payload": payload,
                "header": header,
                "signature": signature,
            }

        return payload

    def get_unverified_header(self, jwt):
        """Returns back the JWT header parameters as a dict()

        Note: The signature is not verified so the header parameters
        should not be fully trusted until signature verification is complete
        """
        headers = self._load(jwt)[2]
        self._validate_headers(headers)

        return headers

    def _load(self, jwt):
        if isinstance(jwt, str):
            jwt = jwt.encode("utf-8")

        if not isinstance(jwt, bytes):
            raise DecodeError(
                "Invalid token type. Token must be a {}".format(bytes)
            )

        try:
            signing_input, crypto_segment = jwt.rsplit(b".", 1)
            header_segment, payload_segment = signing_input.split(b".", 1)
        except ValueError as err:
            raise DecodeError("Not enough segments") from err

        try:
            header_data = base64url_decode(header_segment)
        except (TypeError, binascii.Error) as err:
            raise DecodeError("Invalid header padding") from err

        try:
            header = json.loads(header_data.decode("utf-8"))
        except ValueError as e:
            raise DecodeError("Invalid header string: %s" % e) from e

        if not isinstance(header, Mapping):
            raise DecodeError("Invalid header string: must be a json object")

        try:
            payload = base64url_decode(payload_segment)
        except (TypeError, binascii.Error) as err:
            raise DecodeError("Invalid payload padding") from err

        try:
            signature = base64url_decode(crypto_segment)
        except (TypeError, binascii.Error) as err:
            raise DecodeError("Invalid crypto padding") from err

        return (payload, signing_input, header, signature)

    def _verify_signature(
        self,
        payload,
        signing_input,
        header,
        signature,
        key="",
        algorithms=None,
    ):

        alg = header.get("alg")

        if algorithms is not None and alg not in algorithms:
            raise InvalidAlgorithmError(
                "The specified alg value is not allowed"
            )

        try:
            alg_obj = self._algorithms[alg]
            key = alg_obj.prepare_key(key)

            if not alg_obj.verify(signing_input, key, signature):
                raise InvalidSignatureError("Signature verification failed")

        except KeyError:
            raise InvalidAlgorithmError("Algorithm not supported")

    def _validate_headers(self, headers):
        if "kid" in headers:
            self._validate_kid(headers["kid"])

    def _validate_kid(self, kid):
        if not isinstance(kid, (bytes, str)):
            raise InvalidTokenError("Key ID header parameter must be a string")


_jws_global_obj = PyJWS()
encode = _jws_global_obj.encode
decode = _jws_global_obj.decode
register_algorithm = _jws_global_obj.register_algorithm
unregister_algorithm = _jws_global_obj.unregister_algorithm
get_unverified_header = _jws_global_obj.get_unverified_header
