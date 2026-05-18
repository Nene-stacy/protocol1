"""
Key generation and key agreement primitives.

Uses X25519 for Diffie-Hellman and Ed25519 for identity key signing,
matching the Signal protocol's recommended cryptographic primitives.
"""

from __future__ import annotations

import os
import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)

from .exceptions import AuthenticationError




@dataclass
class DHKeyPair:
    """An X25519 Diffie-Hellman key pair."""

    private_key: X25519PrivateKey
    public_key: X25519PublicKey

    # Serialised public key bytes (32 bytes, little-endian Montgomery form)
    public_bytes: bytes = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.public_bytes = self.public_key.public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    """serialization"""

    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "DHKeyPair":
        priv = X25519PrivateKey.from_private_bytes(raw)
        return cls(private_key=priv, public_key=priv.public_key())

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DHKeyPair):
            return NotImplemented
        return self.public_bytes == other.public_bytes

    def __hash__(self) -> int:
        return hash(self.public_bytes)


def generate_dh() -> DHKeyPair:
    """Generate a fresh X25519 key pair."""
    priv = X25519PrivateKey.generate()
    return DHKeyPair(private_key=priv, public_key=priv.public_key())


def dh(our: DHKeyPair, their_public: bytes) -> bytes:
    """
    Perform a Diffie-Hellman exchange.

    Parameters
    ----------
    our:
        Our key pair (private key used for the exchange).
    their_public:
        Peer's raw 32-byte X25519 public key.

    Returns
    -------
    32-byte shared secret.
    """
    their_key = X25519PublicKey.from_public_bytes(their_public)
    return our.private_key.exchange(their_key)



# X3DH (Extended Triple Diffie-Hellman) – Signal-style key agreement


@dataclass
class X3DHBundle:
    """
    A public key bundle published by a recipient for asynchronous session
    establishment (analogous to Signal's PreKeyBundle).

    Fields
    ------
    ik : identity key (long-lived Ed25519 signing key – also used for DH
         via conversion to X25519)
    spk : signed pre-key (X25519)
    spk_sig : Ed25519 signature over spk by ik
    opk : one-time pre-key (X25519, optional – consumed once)
    """

    ik_pub: bytes           # Ed25519 identity public key (raw 32 bytes)
    ik_x25519_pub: bytes    # X25519 version of ik (for DH)
    spk_pub: bytes          # Signed pre-key public bytes
    spk_sig: bytes          # Signature of spk_pub by ik
    opk_pub: Optional[bytes] = None  # One-time pre-key (optional)
    opk_id: Optional[int] = None     # Identifier for the OPK used


@dataclass
class X3DHIdentity:
    """Full X3DH identity with private keys (kept secret by the owner)."""

    ik: DHKeyPair              # X25519 identity key pair
    ik_signing: Ed25519PrivateKey  # Ed25519 key for signing the SPK
    spk: DHKeyPair             # Current signed pre-key
    spk_sig: bytes             # Signature
    opks: dict[int, DHKeyPair] = field(default_factory=dict)  # id -> OPK


def generate_x3dh_bundle(num_opks: int = 10) -> tuple[X3DHIdentity, X3DHBundle]:
    """
    Generate a full X3DH identity + the public bundle to publish.

    Parameters
    ----------
    num_opks : number of one-time pre-keys to generate

    Returns
    -------
    (identity, bundle) tuple
    """
    # Identity key – Ed25519 for signing, X25519 for DH
    ed_priv = Ed25519PrivateKey.generate()
    ed_pub_bytes = ed_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Derive X25519 IK from the Ed25519 seed (first 32 bytes of seed == private scalar)
    ik_seed = ed_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ik = DHKeyPair.from_private_bytes(ik_seed)

    # Signed pre-key
    spk = generate_dh()
    spk_sig = ed_priv.sign(spk.public_bytes)

    # One-time pre-keys
    opks = {i: generate_dh() for i in range(num_opks)}

    # Pick one OPK to include in the bundle (the lowest unused id)
    opk_id, opk_pair = next(iter(opks.items())) if opks else (None, None)

    identity = X3DHIdentity(
        ik=ik,
        ik_signing=ed_priv,
        spk=spk,
        spk_sig=spk_sig,
        opks=opks,
    )

    bundle = X3DHBundle(
        ik_pub=ed_pub_bytes,
        ik_x25519_pub=ik.public_bytes,
        spk_pub=spk.public_bytes,
        spk_sig=spk_sig,
        opk_pub=opk_pair.public_bytes if opk_pair else None,
        opk_id=opk_id,
    )

    return identity, bundle


def x3dh_initiator(
    our_identity: X3DHIdentity,
    their_bundle: X3DHBundle,
    info: bytes = b"DoubleRatchet_X3DH",
) -> tuple[bytes, bytes, Optional[bytes], Optional[int]]:
    """
    Perform X3DH as the initiator (Alice).

    Returns
    -------
    (shared_secret, ek_pub, opk_pub_used, opk_id_used)
    - shared_secret : 32-byte master secret fed into the root KDF
    - ek_pub        : our ephemeral public key (sent in the initial message)
    - opk_pub_used  : the OPK public bytes we used (or None)
    - opk_id_used   : the OPK id we used (or None)
    """
    # Verify recipient's SPK signature
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        their_ed_pub = Ed25519PublicKey.from_public_bytes(their_bundle.ik_pub)
        their_ed_pub.verify(their_bundle.spk_sig, their_bundle.spk_pub)
    except Exception as exc:
        raise AuthenticationError("SPK signature verification failed") from exc

    # Ephemeral key
    ek = generate_dh()

    # DH computations (Signal spec section 3.3)
    dh1 = dh(our_identity.ik, their_bundle.spk_pub)   # DH1 = IKa * SPKb
    dh2 = dh(ek, their_bundle.ik_x25519_pub)           # DH2 = EKa * IKb
    dh3 = dh(ek, their_bundle.spk_pub)                 # DH3 = EKa * SPKb
    dh_material = dh1 + dh2 + dh3

    opk_pub_used = None
    opk_id_used = None
    if their_bundle.opk_pub is not None:
        dh4 = dh(ek, their_bundle.opk_pub)             # DH4 = EKa * OPKb
        dh_material += dh4
        opk_pub_used = their_bundle.opk_pub
        opk_id_used = their_bundle.opk_id

    shared_secret = _x3dh_kdf(dh_material, info)
    return shared_secret, ek.public_bytes, opk_pub_used, opk_id_used


def x3dh_responder(
    our_identity: X3DHIdentity,
    their_ik_x25519: bytes,
    their_ek: bytes,
    opk_id: Optional[int] = None,
    info: bytes = b"DoubleRatchet_X3DH",
) -> bytes:
    """
    Perform X3DH as the responder (Bob).

    Parameters
    ----------
    their_ik_x25519 : initiator's X25519 identity public key bytes
    their_ek        : initiator's ephemeral public key bytes (from initial msg)
    opk_id          : which OPK the initiator used (None if none)

    Returns
    -------
    32-byte shared secret (must match initiator's)
    """
    dh1 = dh(our_identity.spk, their_ik_x25519)        # DH1 = SPKb * IKa
    dh2 = dh(our_identity.ik, their_ek)                 # DH2 = IKb * EKa
    dh3 = dh(our_identity.spk, their_ek)                # DH3 = SPKb * EKa
    dh_material = dh1 + dh2 + dh3

    if opk_id is not None:
        opk = our_identity.opks.get(opk_id)
        if opk is None:
            raise AuthenticationError(f"OPK {opk_id} not found or already consumed")
        dh4 = dh(opk, their_ek)                         # DH4 = OPKb * EKa
        dh_material += dh4
        # Consume the OPK (one-time use)
        del our_identity.opks[opk_id]

    return _x3dh_kdf(dh_material, info)


def _x3dh_kdf(dh_material: bytes, info: bytes) -> bytes:
    """HKDF over concatenated DH outputs as specified by Signal X3DH."""
    from .kdf import HKDF
    salt = b"\x00" * 32  # Signal spec: 32 zero bytes for X3DH KDF salt
    return HKDF(
        input_key_material=b"\xff" * 32 + dh_material,
        salt=salt,
        info=info,
        length=32,
    )
