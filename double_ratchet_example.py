
# session chat between alice and bob using X3DH for initial key 
# agreement followed by double rachet for message encryption

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from double_ratchet import (
    generate_x3dh_bundle,
    x3dh_initiator,
    x3dh_responder,
    RatchetSession,
    InMemorySessionStore,
)


def separator(title=""):
    print(f"\n{'─' * 60}")
    if title:
        print(f"  {title}")
        print(f"{'─' * 60}")


def main():
    separator("1. Key Generation (X3DH)")

    # Bob generates his identity and publishes a key bundle
    bob_identity, bob_bundle = generate_x3dh_bundle(num_opks=10)
    print(f"  Bob's identity key (X25519): {bob_identity.ik.public_bytes.hex()[:32]}…")
    print(f"  Bob's signed pre-key:        {bob_bundle.spk_pub.hex()[:32]}…")
    print(f"  One-time pre-keys available: {len(bob_identity.opks)}")

    # Alice also has an identity
    alice_identity, _ = generate_x3dh_bundle(num_opks=1)
    print(f"  Alice's identity key:        {alice_identity.ik.public_bytes.hex()[:32]}…")

    separator("2. X3DH Key Agreement")

    # Alice performs X3DH using Bob's published bundle
    sk_alice, ek_pub, opk_pub_used, opk_id_used = x3dh_initiator(alice_identity, bob_bundle)
    print(f"  Alice computed shared secret: {sk_alice.hex()[:32]}…")
    print(f"  Alice's ephemeral key:        {ek_pub.hex()[:32]}…")
    print(f"  OPK used:                     id={opk_id_used}")

    # Bob recovers the same shared secret (offline / async)
    sk_bob = x3dh_responder(
        our_identity=bob_identity,
        their_ik_x25519=alice_identity.ik.public_bytes,
        their_ek=ek_pub,
        opk_id=opk_id_used,
    )
    print(f"  Bob recovered shared secret:  {sk_bob.hex()[:32]}…")
    assert sk_alice == sk_bob
    print(" Shared secrets match!")

    separator("3. Double Ratchet Session Initialisation")

    alice_session = RatchetSession.init_as_sender(
        shared_secret=sk_alice,
        their_ratchet_public=bob_identity.spk.public_bytes,
        session_id="alice-bob-session",
    )
    bob_session = RatchetSession.init_as_receiver(
        shared_secret=sk_bob,
        our_ratchet_keypair=bob_identity.spk,
        session_id="alice-bob-session",
    )
    print(f"  Alice session: {alice_session}")
    print(f"  Bob session:   {bob_session}")

    separator("4. Message Exchange (Alice → Bob)")

    messages_ab = [
        b"Hey Bob! Can you hear me?",
        b"This message is end-to-end encrypted.",
        b"Each message advances the symmetric ratchet.",
    ]

    for pt in messages_ab:
        enc = alice_session.encrypt(pt)
        dec = bob_session.decrypt(enc)
        status = "successful" if dec == pt else "failed"
        print(f"  {status} Alice: {pt.decode()!r}")

    separator("5. Reply (Bob → Alice)  triggers DH ratchet")

    replies = [b"Loud and clear, Alice!", b"Forward secrecy is great."]
    for pt in replies:
        enc = bob_session.encrypt(pt)
        dec = alice_session.decrypt(enc)
        status = "sucessful" if dec == pt else "failed"
        print(f"  {status} Bob: {pt.decode()!r}")

    separator("6. Out-of-Order Delivery")

    m1 = alice_session.encrypt(b"Message 1 (sent first)")
    m2 = alice_session.encrypt(b"Message 2 (sent second)")
    m3 = alice_session.encrypt(b"Message 3 (sent third)")

    # Deliver out of order: 3, 1, 2
    dec3 = bob_session.decrypt(m3)
    dec1 = bob_session.decrypt(m1)
    dec2 = bob_session.decrypt(m2)

    print(f"  Delivered: {dec3.decode()!r}")
    print(f"  Delivered: {dec1.decode()!r}")
    print(f"  Delivered: {dec2.decode()!r}")
    print(f"  All out-of-order messages decrypted correctly")

    separator("7. Session Serialisation")

    store = InMemorySessionStore()
    store.save(alice_session)
    alice_restored = store.load(alice_session.session_id)

    enc = alice_restored.encrypt(b"Message after restore from store")
    dec = bob_session.decrypt(enc)
    print(f"  Restored session works: {dec.decode()!r}")

    separator("8. Associated Data (Sender Authentication)")

    # Fresh session pair to cleanly demo AD
    alice2, bob2 = [RatchetSession.init_as_sender(sk_alice, bob_identity.spk.public_bytes),
                    RatchetSession.init_as_receiver(sk_bob, bob_identity.spk)]
    ad = alice_identity.ik.public_bytes  # bind message to Alice's identity
    enc2 = alice2.encrypt(b"Authenticated message", associated_data=ad)
    dec2 = bob2.decrypt(enc2, associated_data=ad)
    print(f"   Authenticated decryption: {dec2.decode()!r}")

    # Wrong AD must fail
    import contextlib
    from double_ratchet import AuthenticationError
    alice3, bob3 = [RatchetSession.init_as_sender(sk_alice, bob_identity.spk.public_bytes),
                    RatchetSession.init_as_receiver(sk_bob, bob_identity.spk)]
    enc3 = alice3.encrypt(b"Tamper AD", associated_data=b"correct")
    try:
        bob3.decrypt(enc3, associated_data=b"wrong")
        print("   Should have raised AuthenticationError!")
    except AuthenticationError:
        print("   Wrong AD correctly rejected")

    separator("Session Statistics")
    print(f"  Alice: Ns={alice_session.send_message_number}, "
          f"Nr={alice_session.receive_message_number}")
    print(f"  Bob:   Ns={bob_session.send_message_number}, "
          f"Nr={bob_session.receive_message_number}")
    print(f"  Skipped keys in Bob's cache: {bob_session.skipped_keys_count}")
    print()


if __name__ == "__main__":
    main()
