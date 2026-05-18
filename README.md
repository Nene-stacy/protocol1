# Double Ratchet — Python Library

A complete, advanced Python implementation of the **Signal Double Ratchet Algorithm**, combining X3DH key agreement with the Double Ratchet for secure end-to-end encrypted messaging.

## Features

| Feature | Details |
|---|---|
| **Key Agreement** | X3DH (Extended Triple DH) with Ed25519 + X25519 |
| **DH Ratchet** | X25519 — forward secrecy + break-in recovery |
| **Symmetric Ratchet** | HMAC-SHA256 chain/message key derivation |
| **AEAD Encryption** | AES-256-GCM with HKDF-expanded keys |
| **KDF** | HKDF-SHA256 (root & chain), HMAC-SHA256 (chain step) |
| **Out-of-Order** | Skipped message key cache (up to 1000 keys) |
| **Serialisation** | Full session state → JSON (for persistence) |
| **Session Store** | Pluggable interface + in-memory reference impl |

---

## Installation

```bash
pip install cryptography
# or from source:
pip install -e ".[dev]"
```

---

## Quick Start

```python
import os
from double_ratchet import (
    generate_x3dh_bundle, x3dh_initiator, x3dh_responder,
    RatchetSession,
)

# 1. Bob publishes key bundle
bob_identity, bob_bundle = generate_x3dh_bundle()
alice_identity, _         = generate_x3dh_bundle()

# 2. Alice performs X3DH
sk_alice, ek_pub, _, opk_id = x3dh_initiator(alice_identity, bob_bundle)

# 3. Bob recovers shared secret
sk_bob = x3dh_responder(bob_identity, alice_identity.ik.public_bytes, ek_pub, opk_id)

# 4. Initialise Double Ratchet sessions
alice = RatchetSession.init_as_sender(sk_alice, bob_identity.spk.public_bytes)
bob   = RatchetSession.init_as_receiver(sk_bob, bob_identity.spk)

# 5. Encrypt / decrypt
msg = alice.encrypt(b"Hello, Bob!")
print(bob.decrypt(msg))  # b"Hello, Bob!"
```

---

## Architecture

```
double_ratchet/
├── __init__.py       # Public API
├── keys.py           # DHKeyPair, X3DH key agreement
├── kdf.py            # HKDF, KDF_RK, KDF_CK
├── ratchet.py        # RatchetState, RatchetSession (core)
├── store.py          # SessionStore interface + InMemorySessionStore
└── exceptions.py     # Custom exceptions
```

### Double Ratchet state variables (Signal spec names)

| Variable | Description |
|---|---|
| `DHs` | Our current DH ratchet key pair |
| `DHr` | Their current DH ratchet public key |
| `RK` | 32-byte root key |
| `CKs` | Sending chain key |
| `CKr` | Receiving chain key |
| `Ns` | Send message counter |
| `Nr` | Receive message counter |
| `PN` | Previous chain length |
| `MKSKIPPED` | Cache of skipped message keys |

---

## Security Properties

- **Forward secrecy** — Compromise of current keys does not expose past messages.
- **Break-in recovery** — After a DH ratchet step, future messages are secure even if the current state was compromised.
- **Out-of-order delivery** — Up to `MAX_SKIP=1000` skipped message keys stored.
- **Replay protection** — Duplicate message indices cause `ReplayAttackError`.
- **Authentication** — AES-256-GCM provides ciphertext integrity; X3DH SPK is Ed25519-signed.

---

## Running Tests

```bash
pytest double_ratchet/tests/ -v
```

---

## References

- [Signal Double Ratchet Specification](https://signal.org/docs/specifications/doubleratchet/)
- [Signal X3DH Specification](https://signal.org/docs/specifications/x3dh/)
- [RFC 5869 — HKDF](https://www.rfc-editor.org/rfc/rfc5869)
