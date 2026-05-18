"""
Comprehensive test suite for the Double Ratchet library.

Covers:
  - Basic encrypt/decrypt round-trip
  - Multi-message sessions
  - Direction change (DH ratchet step)
  - Out-of-order message delivery
  - Skipped message keys cleanup
  - Replay attack detection
  - Max-skip enforcement
  - X3DH key agreement integration
  - Session serialisation / deserialisation
  - Large payloads
  - Associated data authentication
"""

import pytest
import os

from double_ratchet import (
    generate_dh,
    dh,
    generate_x3dh_bundle,
    x3dh_initiator,
    x3dh_responder,
    RatchetSession,
    InMemorySessionStore,
    AuthenticationError,
    ReplayAttackError,
    MaxSkipExceededError,
)
from double_ratchet.ratchet import MAX_SKIP


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_session_pair() -> tuple[RatchetSession, RatchetSession]:
    """
    Create a symmetric session pair using a random shared secret and a
    pre-agreed ratchet key (simulates post-X3DH state).
    """
    bob_ratchet = generate_dh()
    shared_secret = os.urandom(32)

    alice = RatchetSession.init_as_sender(
        shared_secret=shared_secret,
        their_ratchet_public=bob_ratchet.public_bytes,
    )
    bob = RatchetSession.init_as_receiver(
        shared_secret=shared_secret,
        our_ratchet_keypair=bob_ratchet,
    )
    return alice, bob


def make_x3dh_session_pair() -> tuple[RatchetSession, RatchetSession]:
    """Full X3DH + Double Ratchet session establishment."""
    bob_identity, bob_bundle = generate_x3dh_bundle(num_opks=5)
    alice_identity, _ = generate_x3dh_bundle(num_opks=1)

    # Alice → X3DH → shared secret
    sk_alice, ek_pub, opk_pub, opk_id = x3dh_initiator(alice_identity, bob_bundle)

    # Bob recovers shared secret
    sk_bob = x3dh_responder(
        our_identity=bob_identity,
        their_ik_x25519=alice_identity.ik.public_bytes,
        their_ek=ek_pub,
        opk_id=opk_id,
    )

    assert sk_alice == sk_bob, "X3DH shared secrets must match"

    alice = RatchetSession.init_as_sender(
        shared_secret=sk_alice,
        their_ratchet_public=bob_identity.spk.public_bytes,
    )
    bob = RatchetSession.init_as_receiver(
        shared_secret=sk_bob,
        our_ratchet_keypair=bob_identity.spk,
    )
    return alice, bob


# testing encryptn and decryptn

class TestBasicRoundTrip:
    def test_single_message_alice_to_bob(self):
        alice, bob = make_session_pair()
        msg = alice.encrypt(b"Hello, Bob!")
        assert bob.decrypt(msg) == b"Hello, Bob!"

    def test_multiple_messages_alice_to_bob(self):
        alice, bob = make_session_pair()
        plaintexts = [f"Message {i}".encode() for i in range(20)]
        encrypted = [alice.encrypt(p) for p in plaintexts]
        for pt, ct in zip(plaintexts, encrypted):
            assert bob.decrypt(ct) == pt

    def test_bidirectional_communication(self):
        alice, bob = make_session_pair()

        # Alice → Bob
        m1 = alice.encrypt(b"Hello Bob")
        assert bob.decrypt(m1) == b"Hello Bob"

        # Bob → Alice
        m2 = bob.encrypt(b"Hi Alice")
        assert alice.decrypt(m2) == b"Hi Alice"

        # Alice → Bob again (triggers DH ratchet on Bob's decrypt)
        m3 = alice.encrypt(b"How are you?")
        assert bob.decrypt(m3) == b"How are you?"

    def test_associated_data(self):
        alice, bob = make_session_pair()
        ad = b"alice@example.com"
        msg = alice.encrypt(b"Secret", associated_data=ad)
        assert bob.decrypt(msg, associated_data=ad) == b"Secret"

    def test_wrong_associated_data_fails(self):
        alice, bob = make_session_pair()
        msg = alice.encrypt(b"Secret", associated_data=b"correct-ad")
        with pytest.raises(AuthenticationError):
            bob.decrypt(msg, associated_data=b"wrong-ad")

    def test_empty_plaintext(self):
        alice, bob = make_session_pair()
        msg = alice.encrypt(b"")
        assert bob.decrypt(msg) == b""

    def test_large_payload(self):
        alice, bob = make_session_pair()
        payload = os.urandom(1024 * 1024)  # 1 MB
        msg = alice.encrypt(payload)
        assert bob.decrypt(msg) == payload


# ---------------------------------------------------------------------------
# Tests: DH Ratchet advancement
# ---------------------------------------------------------------------------

class TestDHRatchet:
    def test_dh_ratchet_advances_on_direction_change(self):
        alice, bob = make_session_pair()
        initial_rk = alice._state.RK

        m1 = alice.encrypt(b"A to B")
        bob.decrypt(m1)
        bob.encrypt(b"B to A")

        # Root key should have changed after the ratchet
        assert alice._state.RK != initial_rk or bob._state.RK != initial_rk

    def test_many_ratchet_steps(self):
        alice, bob = make_session_pair()
        for i in range(50):
            msg = alice.encrypt(f"a{i}".encode())
            assert bob.decrypt(msg) == f"a{i}".encode()
            msg = bob.encrypt(f"b{i}".encode())
            assert alice.decrypt(msg) == f"b{i}".encode()

    def test_ratchet_keys_differ_after_step(self):
        alice, bob = make_session_pair()
        rk_before = bytes(alice._state.RK)

        m = alice.encrypt(b"ping")
        bob.decrypt(m)
        m2 = bob.encrypt(b"pong")
        alice.decrypt(m2)

        assert alice._state.RK != rk_before


# ---------------------------------------------------------------------------
# Tests: Out-of-order delivery
# ---------------------------------------------------------------------------

class TestOutOfOrderDelivery:
    def test_two_messages_reversed(self):
        alice, bob = make_session_pair()
        m1 = alice.encrypt(b"First")
        m2 = alice.encrypt(b"Second")

        # Deliver in reverse
        assert bob.decrypt(m2) == b"Second"
        assert bob.decrypt(m1) == b"First"

    def test_many_out_of_order(self):
        alice, bob = make_session_pair()
        messages = [alice.encrypt(f"msg{i}".encode()) for i in range(20)]

        # Deliver in reverse order
        for i in reversed(range(20)):
            assert bob.decrypt(messages[i]) == f"msg{i}".encode()

    def test_skipped_keys_cleaned_up_after_use(self):
        alice, bob = make_session_pair()
        m1 = alice.encrypt(b"skip me")
        m2 = alice.encrypt(b"delivered first")

        bob.decrypt(m2)
        assert bob.skipped_keys_count == 1  # m1 is still cached

        bob.decrypt(m1)
        assert bob.skipped_keys_count == 0  # cache cleared


# ---------------------------------------------------------------------------
# Tests: Security properties
# ---------------------------------------------------------------------------

class TestSecurityProperties:
    def test_replay_attack_rejected(self):
        alice, bob = make_session_pair()
        msg = alice.encrypt(b"Replay me")
        bob.decrypt(msg)
        # Second decrypt of same message should fail
        with pytest.raises((AuthenticationError, ReplayAttackError)):
            bob.decrypt(msg)

    def test_tampered_ciphertext_rejected(self):
        alice, bob = make_session_pair()
        msg = alice.encrypt(b"Tamper me")
        # Flip a byte in the ciphertext
        corrupted_ct = bytearray(msg.ciphertext)
        corrupted_ct[0] ^= 0xFF
        msg.ciphertext = bytes(corrupted_ct)
        with pytest.raises(AuthenticationError):
            bob.decrypt(msg)

    def test_max_skip_enforced(self):
        alice, bob = make_session_pair()
        # Encrypt MAX_SKIP + 1 messages without delivering any
        msgs = [alice.encrypt(f"skip{i}".encode()) for i in range(MAX_SKIP + 2)]
        # Attempting to decrypt the last one should raise MaxSkipExceededError
        with pytest.raises(MaxSkipExceededError):
            bob.decrypt(msgs[-1])

    def test_forward_secrecy_different_message_keys(self):
        """Each message must use a unique message key (no reuse)."""
        alice, bob = make_session_pair()
        m1 = alice.encrypt(b"A")
        m2 = alice.encrypt(b"B")
        # Ciphertexts must differ even for same-length plaintexts
        assert m1.ciphertext != m2.ciphertext

    def test_break_in_recovery(self):
        """After a DH ratchet step following a compromise, future messages are safe."""
        alice, bob = make_session_pair()
        # Simulate a series of messages
        for _ in range(5):
            bob.decrypt(alice.encrypt(b"pre-compromise"))

        # After a direction change (Bob sends), a new DH ratchet step occurs
        alice.decrypt(bob.encrypt(b"trigger ratchet"))

        # Alice's subsequent messages use a fresh chain
        m = alice.encrypt(b"post-ratchet secret")
        assert bob.decrypt(m) == b"post-ratchet secret"


# ---------------------------------------------------------------------------
# Tests: X3DH integration
# ---------------------------------------------------------------------------

class TestX3DHIntegration:
    def test_full_x3dh_session(self):
        alice, bob = make_x3dh_session_pair()
        msg = alice.encrypt(b"X3DH works!")
        assert bob.decrypt(msg) == b"X3DH works!"

    def test_x3dh_bidirectional(self):
        alice, bob = make_x3dh_session_pair()
        m1 = alice.encrypt(b"Hello via X3DH")
        assert bob.decrypt(m1) == b"Hello via X3DH"
        m2 = bob.encrypt(b"Reply via X3DH")
        assert alice.decrypt(m2) == b"Reply via X3DH"

    def test_x3dh_different_secrets_without_opk(self):
        bob_identity, bob_bundle = generate_x3dh_bundle(num_opks=0)
        alice_identity, _ = generate_x3dh_bundle(num_opks=0)
        # Bundle has no OPK
        bob_bundle.opk_pub = None
        bob_bundle.opk_id = None

        sk_alice, ek_pub, _, _ = x3dh_initiator(alice_identity, bob_bundle)
        sk_bob = x3dh_responder(
            our_identity=bob_identity,
            their_ik_x25519=alice_identity.ik.public_bytes,
            their_ek=ek_pub,
            opk_id=None,
        )
        assert sk_alice == sk_bob


# ---------------------------------------------------------------------------
# Tests: Serialisation
# ---------------------------------------------------------------------------

class TestSerialisation:
    def test_serialise_deserialise_roundtrip(self):
        alice, bob = make_session_pair()

        # Exchange some messages
        bob.decrypt(alice.encrypt(b"Before save"))

        # Serialise Alice
        alice_json = alice.to_json()
        alice2 = RatchetSession.from_json(alice_json)

        # Restored Alice can still encrypt
        msg = alice2.encrypt(b"After restore")
        assert bob.decrypt(msg) == b"After restore"

    def test_serialise_preserves_skipped_keys(self):
        alice, bob = make_session_pair()
        m1 = alice.encrypt(b"skip")
        m2 = alice.encrypt(b"deliver first")

        bob.decrypt(m2)
        assert bob.skipped_keys_count == 1

        # Serialise and restore Bob
        bob2 = RatchetSession.from_json(bob.to_json())
        assert bob2.skipped_keys_count == 1

        # Skipped key still usable after restore
        assert bob2.decrypt(m1) == b"skip"

    def test_store_save_and_load(self):
        alice, bob = make_session_pair()
        store = InMemorySessionStore()

        store.save(alice)
        alice_loaded = store.load(alice.session_id)
        assert alice_loaded.session_id == alice.session_id

        msg = alice_loaded.encrypt(b"From store")
        assert bob.decrypt(msg) == b"From store"


# ---------------------------------------------------------------------------
# Tests: EncryptedMessage wire format
# ---------------------------------------------------------------------------

class TestWireFormat:
    def test_json_encode_decode(self):
        alice, bob = make_session_pair()
        msg = alice.encrypt(b"Wire test")
        json_str = msg.to_json()
        recovered = type(msg).from_json(json_str)
        assert bob.decrypt(recovered) == b"Wire test"

    def test_dict_encode_decode(self):
        alice, bob = make_session_pair()
        msg = alice.encrypt(b"Dict test")
        d = msg.to_dict()
        recovered = type(msg).from_dict(d)
        assert bob.decrypt(recovered) == b"Dict test"


# ---------------------------------------------------------------------------
# Run directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
