"""
Double Ratchet (main work).

summary:

- DH Ratchet  : advances on every message direction change; provides
                 forward secrecy and break-in recovery.
- Sending chain ratchet  : symmetric ratchet for outgoing messages.
- Receiving chain ratchet: symmetric ratchet for incoming messages.
- Skipped message keys   : stored for out-of-order delivery.
"""

from __future__ import annotations

import os
import json
import struct
import base64
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keys import DHKeyPair, generate_dh, dh
from .kdf import kdf_rk, kdf_ck, HKDF
from .exceptions import (
    DecryptionError,
    AuthenticationError,
    ReplayAttackError,
    MaxSkipExceededError,
)


# Constants

MAX_SKIP = 1000          # Maximum number of skipped message keys to store
AEAD_INFO = b"DoubleRatchet_AEAD"          
HEADER_KEY_INFO = b"DoubleRatchet_HK"
MSG_KEY_SEED = b"DoubleRatchet_MK"


# Message Header

@dataclass(frozen=True)
class MessageHeader:
    """
    Double Ratchet message header.

    Contains the sender's current ratchet public key, the previous chain
    length (pn), and the message number within the current sending chain (n).
    """

    dh_pub: bytes   # Sender's current ratchet public key (32 bytes)
    pn: int         # Length of the previous sending chain
    n: int          # Message number in current sending chain

    def serialise(self) -> bytes:
        """Encode header to bytes: 32 (dh) + 4 (pn) + 4 (n) = 40 bytes."""
        return self.dh_pub + struct.pack(">II", self.pn, self.n)

    @classmethod
    def deserialise(cls, data: bytes) -> "MessageHeader":
        if len(data) != 40:
            raise DecryptionError(f"Invalid header length: {len(data)}")
        dh_pub = data[:32]
        pn, n = struct.unpack(">II", data[32:40])
        return cls(dh_pub=dh_pub, pn=pn, n=n)


#message encryption

@dataclass
class EncryptedMessage:
    """
    Wire format for a Double Ratchet encrypted message.

    header      : this is in plaintext
    ciphertext  : AEAD-encrypted payload
    """

    header: MessageHeader
    ciphertext: bytes  # AES-256-GCM ciphertext + tag

    def to_dict(self) -> dict:
        return {
            "header": base64.b64encode(self.header.serialise()).decode(),
            "ciphertext": base64.b64encode(self.ciphertext).decode(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "EncryptedMessage":
        header_bytes = base64.b64decode(d["header"])
        header = MessageHeader.deserialise(header_bytes)
        ciphertext = base64.b64decode(d["ciphertext"])
        return cls(header=header, ciphertext=ciphertext)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, s: str) -> "EncryptedMessage":
        return cls.from_dict(json.loads(s))


# AEAD(Authenticated encryption with associated data) Encryption and decryption

def _encrypt(mk: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    
    # AES-256GCM is the specified AEAD  cipher used
    """
    AES-256-GCM AEAD encryption.
    

    here,a random 12-byte nonce is prepended to the ciphertext so 
    that the same message key does not produce thesame nonce.
    The message key mk is HKDF-expanded to a 32-byte AES-256 key.
    Output layout: nonce (12) || GCM-ciphertext+tag
    """
    key = _derive_aead_key(mk)
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, associated_data)
    return nonce + ct


def _decrypt(mk: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
    """AES-256-GCM AEAD decryption. Raises AuthenticationError on tag failure."""
    if len(ciphertext) < 12:
        raise DecryptionError("Ciphertext too short to contain nonce")
    nonce, ct = ciphertext[:12], ciphertext[12:]
    key = _derive_aead_key(mk)
    aes = AESGCM(key)
    try:
        return aes.decrypt(nonce, ct, associated_data)
    except Exception as exc:
        raise AuthenticationError("AEAD authentication failed") from exc


def _derive_aead_key(mk: bytes) -> bytes:
    """Expand message key into a 32-byte AES-256-GCM key via HKDF."""
    return HKDF(
        input_key_material=mk,
        salt=b"\x00" * 32,
        info=AEAD_INFO,
        length=32,
    )


@dataclass
class RatchetState:
    """
    All mutable state for one side of a Double Ratchet session.

    Attributes mirror the specification variables exactly:

    DHs  : our current DH ratchet key pair (sending)
    DHr  : their current DH ratchet public key (receiving)
    RK   : 32-byte root key
    CKs  : 32-byte sending chain key
    CKr  : 32-byte receiving chain key
    Ns   : message counter in current sending chain
    Nr   : message counter in current receiving chain
    PN   : number of messages in previous sending chain
    MKSKIPPED : skipped message keys {(dh_pub, n): mk}
    """

    DHs: DHKeyPair
    DHr: Optional[bytes]         # peer's ratchet public key bytes
    RK: bytes                    # root key
    CKs: Optional[bytes]         # sending chain key
    CKr: Optional[bytes]         # receiving chain key
    Ns: int = 0
    Nr: int = 0
    PN: int = 0
    MKSKIPPED: dict[tuple[bytes, int], bytes] = field(default_factory=dict)

    def serialise(self) -> dict:
        """Convert state to a JSON-serialisable dict for persistence."""
        def b64(x):
            return base64.b64encode(x).decode() if x is not None else None

        return {
            "DHs_priv": b64(self.DHs.private_bytes()),
            "DHr": b64(self.DHr),
            "RK": b64(self.RK),
            "CKs": b64(self.CKs),
            "CKr": b64(self.CKr),
            "Ns": self.Ns,
            "Nr": self.Nr,
            "PN": self.PN,
            "MKSKIPPED": {
                f"{base64.b64encode(k[0]).decode()}:{k[1]}": b64(v)
                for k, v in self.MKSKIPPED.items()
            },
        }

    @classmethod
    def deserialise(cls, d: dict) -> "RatchetState":
        def unb64(x):
            return base64.b64decode(x) if x is not None else None

        DHs = DHKeyPair.from_private_bytes(base64.b64decode(d["DHs_priv"]))
        skipped = {}
        for k_str, v in d["MKSKIPPED"].items():
            pub_b64, n_str = k_str.rsplit(":", 1)
            skipped[(base64.b64decode(pub_b64), int(n_str))] = base64.b64decode(v)

        return cls(
            DHs=DHs,
            DHr=unb64(d["DHr"]),
            RK=base64.b64decode(d["RK"]),
            CKs=unb64(d["CKs"]),
            CKr=unb64(d["CKr"]),
            Ns=d["Ns"],
            Nr=d["Nr"],
            PN=d["PN"],
            MKSKIPPED=skipped,
        )



# RatchetSession – the public API


class RatchetSession:
    """
    A fully initialised Double Ratchet session.

    Usage
    -----
    Initiator (Alice) ::

        session = RatchetSession.init_as_sender(
            shared_secret=sk,
            their_ratchet_public=bob_ratchet_pub,
        )
        msg = session.encrypt(b"Hello Bob")

    Responder (Bob) ::

        session = RatchetSession.init_as_receiver(
            shared_secret=sk,
            our_ratchet_keypair=bob_ratchet_kp,
        )
        plaintext = session.decrypt(msg)

    The session handles:
      - DH ratchet advances on direction changes
      - Symmetric chain ratchet for each message
      - Out-of-order delivery via skipped message key cache
    """

    def __init__(self, state: RatchetState, session_id: Optional[str] = None) -> None:
        self._state = state
        self.session_id = session_id or base64.b64encode(os.urandom(16)).decode()

  
    # Factory constructors


    @classmethod
    def init_as_sender(
        cls,
        shared_secret: bytes,
        their_ratchet_public: bytes,
        session_id: Optional[str] = None,
    ) -> "RatchetSession":
        """
        Initialise a session as the message initiator (Alice).

        The sender immediately performs a DH ratchet step using the
        recipient's ratchet public key so it can derive a sending chain key.

        Parameters
        ----------
        shared_secret       : 32-byte secret from X3DH (or any pre-agreed KDF)
        their_ratchet_public: recipient's ratchet public key bytes (32 bytes)
        """
        DHs = generate_dh()
        # Root KDF step to derive first sending chain
        dh_out = dh(DHs, their_ratchet_public)
        rk, cks = kdf_rk(shared_secret, dh_out)

        state = RatchetState(
            DHs=DHs,
            DHr=their_ratchet_public,
            RK=rk,
            CKs=cks,
            CKr=None,
        )
        return cls(state, session_id)

    @classmethod
    def init_as_receiver(
        cls,
        shared_secret: bytes,
        our_ratchet_keypair: DHKeyPair,
        session_id: Optional[str] = None,
    ) -> "RatchetSession":
        """
        Initialise a session as the message receiver (Bob).

        The receiver waits for the first message to advance its ratchet.

        Parameters
        ----------
        shared_secret       : 32-byte secret from X3DH
        our_ratchet_keypair : our DH ratchet key pair (public key was sent
                              in our X3DH bundle)
        """
        state = RatchetState(
            DHs=our_ratchet_keypair,
            DHr=None,
            RK=shared_secret,
            CKs=None,
            CKr=None,
        )
        return cls(state, session_id)

   
    # Encrypt
   

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> EncryptedMessage:
        """
        Encrypt a message.

        Advances the sending symmetric ratchet and produces an
        EncryptedMessage containing the header and ciphertext.

        Parameters
        
        plaintext       : message bytes to encrypt
        associated_data : optional additional authenticated data (e.g. sender ID)

        Returns
        
        EncryptedMessage
        """
        state = self._state

        if state.CKs is None:
            raise DecryptionError(
                "Sending chain not initialised. "
                "Did you call init_as_sender with their ratchet key?"
            )

        # Advance symmetric ratchet
        state.CKs, mk = kdf_ck(state.CKs)

        # Build header
        header = MessageHeader(
            dh_pub=state.DHs.public_bytes,
            pn=state.PN,
            n=state.Ns,
        )
        state.Ns += 1

        # Authenticated data includes the serialised header
        ad = associated_data + header.serialise()
        ciphertext = _encrypt(mk, plaintext, ad)

        return EncryptedMessage(header=header, ciphertext=ciphertext)

   
    # Decrypt
   

    def decrypt(self, message: EncryptedMessage, associated_data: bytes = b"") -> bytes:
        """
        Decrypt a received message.

        Handles:
        - In-order messages (happy path)
        - Out-of-order messages (uses skipped key cache)
        - DH ratchet steps when a new ratchet key is seen

        Parameters
        
        message         : EncryptedMessage received from the peer
        associated_data : must match what the sender used

        Returns
        
        plaintext bytes

        Raises
        
        ReplayAttackError       : if message was already decrypted
        MaxSkipExceededError    : if too many messages were skipped
        AuthenticationError     : if AEAD tag check fails
        DecryptionError         : other decryption failures
        """
        header = message.header
        ad = associated_data + header.serialise()

        # 1. Try skipped keys first (out-of-order delivery)
        plaintext = self._try_skipped_message(header, message.ciphertext, ad)
        if plaintext is not None:
            return plaintext

        state = self._state

        # 2. DH ratchet step if new ratchet public key
        if header.dh_pub != state.DHr:
            self._skip_message_keys(header.pn)
            self._dh_ratchet(header.dh_pub)

        # 3. Skip any gap in current receiving chain
        self._skip_message_keys(header.n)

        # 4. Advance receiving chain and decrypt
        if state.CKr is None:
            raise DecryptionError("Receiving chain not initialised")

        state.CKr, mk = kdf_ck(state.CKr)
        state.Nr += 1
        return _decrypt(mk, message.ciphertext, ad)

    
    # Internal helpers
   

    def _try_skipped_message(
        self,
        header: MessageHeader,
        ciphertext: bytes,
        ad: bytes,
    ) -> Optional[bytes]:
        """Look up and consume a skipped message key."""
        key = (header.dh_pub, header.n)
        state = self._state

        if key in state.MKSKIPPED:
            mk = state.MKSKIPPED.pop(key)
            try:
                return _decrypt(mk, ciphertext, ad)
            except AuthenticationError:
                raise
        return None

    def _skip_message_keys(self, until: int) -> None:
        """
        Advance the receiving chain up to (but not including) message index
        `until`, storing skipped message keys for future out-of-order delivery.
        """
        state = self._state

        if state.Nr > until:
            return  # nothing to skip

        if until - state.Nr > MAX_SKIP:
            raise MaxSkipExceededError(
                f"Would need to skip {until - state.Nr} keys (max {MAX_SKIP})"
            )

        if state.CKr is not None:
            while state.Nr < until:
                key = (state.DHr, state.Nr)
                if key in state.MKSKIPPED:
                    raise ReplayAttackError(
                        f"Duplicate message index {state.Nr} for ratchet key "
                        f"{state.DHr.hex()[:16]}…"
                    )
                state.CKr, mk = kdf_ck(state.CKr)
                state.MKSKIPPED[key] = mk
                state.Nr += 1

    def _dh_ratchet(self, their_new_pub: bytes) -> None:
        """
        Perform a DH ratchet step.
        
        this step is called when a new message is recieved with a new public key
        this process updates root key, recieving chain and generates a new DH keypair,
        updates root key again, and derives new sending
        
        """
        state = self._state
        state.PN = state.Ns
        state.Ns = 0
        state.Nr = 0
        state.DHr = their_new_pub

        # Receiving chain from their new ratchet key
        dh_recv = dh(state.DHs, their_new_pub)
        state.RK, state.CKr = kdf_rk(state.RK, dh_recv)

        # New DH keypair and sending chain
        state.DHs = generate_dh()
        dh_send = dh(state.DHs, their_new_pub)
        state.RK, state.CKs = kdf_rk(state.RK, dh_send)

 
    # Persistence
    

    def serialise(self) -> dict:
        """Export the full session state as a JSON-serialisable dict."""
        return {
            "session_id": self.session_id,
            "state": self._state.serialise(),
        }

    @classmethod
    def deserialise(cls, d: dict) -> "RatchetSession":
        """Restore a session from a previously serialised dict."""
        state = RatchetState.deserialise(d["state"])
        return cls(state=state, session_id=d.get("session_id"))

    def to_json(self) -> str:
        return json.dumps(self.serialise())

    @classmethod
    def from_json(cls, s: str) -> "RatchetSession":
        return cls.deserialise(json.loads(s))

   
    # Diagnostics
  

    @property
    def send_message_number(self) -> int:
        return self._state.Ns

    @property
    def receive_message_number(self) -> int:
        return self._state.Nr

    @property
    def skipped_keys_count(self) -> int:
        return len(self._state.MKSKIPPED)

    @property
    def our_ratchet_key(self) -> bytes:
        return self._state.DHs.public_bytes

    @property
    def their_ratchet_key(self) -> Optional[bytes]:
        return self._state.DHr

    def __repr__(self) -> str:
        return (
            f"RatchetSession("
            f"id={self.session_id[:8]}…, "
            f"Ns={self._state.Ns}, Nr={self._state.Nr}, "
            f"skipped={len(self._state.MKSKIPPED)})"
        )
