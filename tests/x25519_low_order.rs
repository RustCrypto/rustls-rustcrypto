//! RFC 8446 §4.2.8.2 for the provider's X25519 group: a peer key of low order
//! makes the Diffie-Hellman result the identity — a shared secret the peer knows —
//! and `x25519-dalek` only *reports* that through `was_contributory()`, so the
//! group is the only place the rejection can be made. The trait asks for exactly
//! that ("must return an error if `peer_pub_key` is invalid: ... such as, but not
//! limited to, being in a small order subgroup"), and the `ring` and `aws-lc-rs`
//! providers do it.

use rustls::crypto::SupportedKxGroup;
use rustls::{Error, NamedGroup, PeerMisbehaved};
use rustls_rustcrypto::provider;

/// The seven encodings of a low-order point, from libsodium's `has_small_order`
/// table: the points of order 1, 2, 4 and 8, and the three non-canonical encodings
/// at or above the field prime that reduce to them. Each of them is a valid
/// Curve25519 public key whose shared secret is the identity, so a check that only
/// rejected the all-zero key would still accept a key of order 2.
const LOW_ORDER_PEER_KEYS: [[u8; 32]; 7] = [
    // 0 (order 4)
    [0; 32],
    // 1 (order 1)
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    // order 8
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    // order 8
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    // p - 1 (order 2)
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p (order 4), non-canonical
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p + 1 (order 1), non-canonical
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

fn x25519() -> &'static dyn SupportedKxGroup {
    provider()
        .kx_groups
        .into_iter()
        .find(|group| group.name() == NamedGroup::X25519)
        .expect("the provider offers X25519")
}

/// Every low-order peer key aborts, with the key-share error `complete` documents.
#[test]
fn x25519_rejects_a_low_order_peer_key() {
    for peer_key in LOW_ORDER_PEER_KEYS {
        let active = x25519().start().expect("a key exchange starts");
        match active.complete(&peer_key) {
            Ok(secret) => panic!(
                "a low-order peer key was accepted: {peer_key:02x?} -> {} bytes",
                secret.secret_bytes().len()
            ),
            Err(err) => assert!(
                matches!(err, Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)),
                "unexpected error for {peer_key:02x?}: {err:?}"
            ),
        }
    }
}

/// A peer key that is not 32 bytes is the same key-share error, not a panic.
#[test]
fn x25519_rejects_a_peer_key_of_the_wrong_length() {
    let active = x25519().start().expect("a key exchange starts");
    assert!(matches!(
        active.complete(&[0u8; 31]),
        Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))
    ));
}

/// The control for the two tests above: a real peer key completes, with a 32-byte
/// secret that is not the identity. Without it, a group that rejected every key
/// would pass them too.
#[test]
fn x25519_completes_for_a_real_peer_key() {
    let active = x25519().start().expect("a key exchange starts");
    let peer = x25519().start().expect("a key exchange starts");
    let peer_key = peer.pub_key().to_vec();
    let secret = active
        .complete(&peer_key)
        .expect("a real peer key completes");
    assert_eq!(secret.secret_bytes().len(), 32);
    assert!(
        secret.secret_bytes().iter().any(|byte| *byte != 0),
        "the identity is not a completed key exchange"
    );
}
