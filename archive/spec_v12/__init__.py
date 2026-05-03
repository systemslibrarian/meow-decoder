"""Spec v1.2/v1.3.1 implementation modules for Meow Decoder.

⚠️  QUARANTINED — NOT PRODUCTION-GRADE (Rule #2 non-compliant)

This module uses raw Python key material (os.urandom, HKDF returning bytes)
instead of the opaque Rust handle registry. It is retained for backward
compatibility with spec v1.2 test vectors and should NOT be used for new
encryption operations.

Production code MUST use the main meow_decoder.crypto / crypto_backend
pipeline which routes all secret material through Rust handles.
"""

import warnings as _warnings

_warnings.warn(
    "meow_decoder.spec_v12 is QUARANTINED (Rule #2 non-compliant). "
    "Do not use for new encryption. Use meow_decoder.crypto instead.",
    DeprecationWarning,
    stacklevel=2,
)

from .encode import encode_file
from .decode import decode_file
from .multi_tier import encode_multi_tier, decode_multi_tier
from .key_management import (
    KeyBackend,
    SoftwareBackend,
    get_best_backend,
    ed25519_pk_to_x25519_pk,
    ed25519_sk_to_x25519_sk,
)
from .steganography import find_gif_insertion_point, embed_in_gif, extract_from_gif

__all__ = [
    "encode_file",
    "decode_file",
    "encode_multi_tier",
    "decode_multi_tier",
    "KeyBackend",
    "SoftwareBackend",
    "get_best_backend",
    "ed25519_pk_to_x25519_pk",
    "ed25519_sk_to_x25519_sk",
    "find_gif_insertion_point",
    "embed_in_gif",
    "extract_from_gif",
]
