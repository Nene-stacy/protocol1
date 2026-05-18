"""
key derivation 
Primitives
----------
- HKDF-SHA256  (RFC 5869)
- HMAC-SHA256
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
from cryptography.hazmat.backends import default_backend



# Primitive: HKDF


def HKDF(
    input_key_material: bytes,
    salt: bytes,
    info: bytes,
    length: int = 32,
) -> bytes:
    
    """
    RFC 5869 HKDF-SHA256.

    Parameters
    ----------
    input_key_material : the (possibly low-entropy) input secret
    salt               : random or constant salt
    info               : context/application string
    length             : output key length in bytes
    """
    hkdf = _HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend(),
    )
    return hkdf.derive(input_key_material)


def HMAC_SHA256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256."""
    return _hmac.new(key, data, hashlib.sha256).digest()


# root kdf

# Signal spec constant inputs
_RK_INFO = b"DoubleRatchet_RK"

def kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """
    KDF_RK(rk, dh_out) → (new_rk, ck)

    Derives a new root key and chain key from the current root key and a
    Diffie-Hellman output.

    Parameters
    
    rk     : current 32-byte root key
    dh_out : 32-byte DH shared secret from the ratchet step

    Returns
    
    (new_root_key, new_chain_key) both 32 bytes
    """
    output = HKDF(
        input_key_material=dh_out,
        salt=rk,
        info=_RK_INFO,
        length=64,
    )
    return output[:32], output[32:]



# Chain KDF  (KDF_CK)


_CK_MSG_CONSTANT = b"\x01"
_CK_CHAIN_CONSTANT = b"\x02"

def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    """
    KDF_CK(ck) → (new_ck, mk)

    Derives a new chain key and a message key from the current chain key.
    Uses HMAC-SHA256 with constants as per Signal spec.

    Parameters
    ----------
    ck : current 32-byte chain key

    Returns
    -------
    (new_chain_key, message_key) both 32 bytes
    """
    mk = HMAC_SHA256(ck, _CK_MSG_CONSTANT)
    new_ck = HMAC_SHA256(ck, _CK_CHAIN_CONSTANT)
    return new_ck, mk
