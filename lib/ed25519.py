# Copyright (c) 2026 OpaqueInfra
# Licensed under the Apache License, Version 2.0.
# See LICENSE file for details.

"""
Ed25519 signature primitives for OpaqueInfra verifier.

Uses raw 32-byte public keys (NOT PKCS8, NOT SPKI).
Spec reference: oi-docs/02_spec/02_receipt_and_signature_spec.md
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def verify(public_key_bytes, signature_bytes, message_bytes):
    """Verify an Ed25519 signature.

    Args:
        public_key_bytes: Raw 32-byte Ed25519 public key
        signature_bytes: 64-byte Ed25519 signature
        message_bytes: The message that was signed

    Returns:
        True if signature is valid, False otherwise
    """
    if len(public_key_bytes) != 32:
        return False
    if len(signature_bytes) != 64:
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        key.verify(signature_bytes, message_bytes)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
