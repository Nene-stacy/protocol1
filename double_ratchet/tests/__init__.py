"""
Double Ratchet Algorithm - Signal Protocol Implementation
=========================================================
A complete, advanced Python implementation of the Signal Double Ratchet Algorithm
as specified in https://signal.org/docs/specifications/doubleratchet/

Combines:
  - X3DH-style key agreement (via X25519 ECDH)
  - Symmetric-key ratchet (chain key / message key derivation)
  - Diffie-Hellman ratchet (forward secrecy + break-in recovery)
"""

from .keys import (
    DHKeyPair,
    generate_dh,
    dh,
    generate_x3dh_bundle,
    x3dh_initiator,
    x3dh_responder,
)
from .kdf import (
    kdf_rk,
    kdf_ck,
    HKDF,
)
from .ratchet import (
    RatchetState,
    RatchetSession,
    MessageHeader,
    EncryptedMessage,
)
from .store import (
    SessionStore,
    InMemorySessionStore,
)
from .exceptions import (
    DoubleRatchetError,
    DecryptionError,
    AuthenticationError,
    ReplayAttackError,
    MaxSkipExceededError,
)

__version__ = "1.0.0"
__all__ = [
    # Keys
    "DHKeyPair",
    "generate_dh",
    "dh",
    "generate_x3dh_bundle",
    "x3dh_initiator",
    "x3dh_responder",
    # KDF
    "kdf_rk",
    "kdf_ck",
    "HKDF",
    # Ratchet
    "RatchetState",
    "RatchetSession",
    "MessageHeader",
    "EncryptedMessage",
    # Store
    "SessionStore",
    "InMemorySessionStore",
    # Exceptions
    "DoubleRatchetError",
    "DecryptionError",
    "AuthenticationError",
    "ReplayAttackError",
    "MaxSkipExceededError",
]
