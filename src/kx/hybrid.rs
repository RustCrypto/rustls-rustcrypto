//! Implement the hybrid postquantum key exchanges from
//! https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/ .
//!
//! These key exchanges work by combining the key_exchange shares from
//! an elliptic curve key exchange and an MLKEM key exchange, and
//! simply concatenating them.
//!
//! Since all of the encodings are constant-length, concatenation and
//! splitting is trivial.

use alloc::{boxed::Box, vec::Vec};
use crypto::SupportedKxGroup as _;
use paste::paste;
use rustls::{crypto, NamedGroup};

use super::mlkem::{MLKEM1024, MLKEM768};
use super::{SecP256R1, SecP384R1, X25519};

const SECP256R1MLKEM768_ID: u16 = 4587;
const X25519MLKEM768_ID: u16 = 4588;
const SECP384R1MLKEM1024_ID: u16 = 4589;

/// Make a new vector by concatenating two slices.
///
/// Only allocates once. (This is important, since reallocating would
/// imply that secret data could be left on the heap by the realloc
/// call.)
fn concat(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(b1.len() + b2.len());
    v.extend_from_slice(b1);
    v.extend_from_slice(b2);
    v
}

/// Replacement for slice::split_at_checked, which is not available
/// at the current MSRV.
fn split_at_checked(slice: &[u8], mid: usize) -> Option<(&[u8], &[u8])> {
    if mid <= slice.len() {
        Some(slice.split_at(mid))
    } else {
        None
    }
}

fn first<A>(tup: (A, A)) -> A {
    tup.0
}
fn second<A>(tup: (A, A)) -> A {
    tup.1
}

// Positions to split the client and server keyshare components respectively
// in the X25519MLKEM768 handshake.
const X25519MLKEM768_CKE_SPLIT: usize = 1184;
const X25519MLKEM768_SKE_SPLIT: usize = 1088;

// Positions to split the client and server keyshare components respectively
// in the SecP256r1MLKEM768 handshake.
const SECP256R1MLKEM768_CKE_SPLIT: usize = 65;
const SECP256R1MLKEM768_SKE_SPLIT: usize = 65;

// Positions to split the client and server keyshare components respectively
// in the SecP384r1MLKEM1024 handshake.
const SECP384R1MLKEM1024_CKE_SPLIT: usize = 97;
const SECP384R1MLKEM1024_SKE_SPLIT: usize = 97;

macro_rules! hybrid_kex {
    ($name:ident, $kex1:ty, $kex2:ty, $kex_ec:ty, $ec_member:expr) => {
        paste! {
            #[derive(Debug)]
            pub struct $name;

            struct [< $name KeyExchange >] {
                // Note: This is redundant with pub_key in kx1 and kx2.
                pub_key: Box<[u8]>,
                kx1: Box<dyn crypto::ActiveKeyExchange>,
                kx2: Box<dyn crypto::ActiveKeyExchange>,
            }

            impl crypto::SupportedKxGroup for $name {
                fn name(&self) -> NamedGroup {
                    NamedGroup::from([< $name:upper _ID >])
                }

                fn usable_for_version(&self, version: rustls::ProtocolVersion) -> bool {
                    version == rustls::ProtocolVersion::TLSv1_3
                }

                fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
                    let kx1 = $kex1.start()?;
                    let kx2 = $kex2.start()?;
                    Ok(Box::new([< $name KeyExchange >] {
                        pub_key: concat(kx1.pub_key(), kx2.pub_key()).into(),
                        kx1,
                        kx2,
                    }))
                }

                fn start_and_complete(
                    &self,
                    peer: &[u8],
                ) -> Result<crypto::CompletedKeyExchange, rustls::Error> {
                    let (kx1_pubkey, kx2_pubkey) =
                        split_at_checked(peer, [< $name:upper _CKE_SPLIT >])
                        .ok_or_else(|| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
                    let kx1_completed = $kex1.start_and_complete(kx1_pubkey)?;
                    let kx2_completed = $kex2.start_and_complete(kx2_pubkey)?;

                    Ok(crypto::CompletedKeyExchange {
                        group: self.name(),
                        pub_key: concat(&kx1_completed.pub_key, &kx2_completed.pub_key).into(),
                        secret: concat(
                            kx1_completed.secret.secret_bytes(),
                            kx2_completed.secret.secret_bytes(),
                        )
                            .into(),
                    })
                }
            }

            impl crypto::ActiveKeyExchange for [< $name KeyExchange >] {
                fn group(&self) -> NamedGroup {
                    NamedGroup::from([< $name:upper _ID >])
                }

                fn pub_key(&self) -> &[u8] {
                    &self.pub_key
                }

                fn complete(self: Box<Self>, peer: &[u8]) -> Result<crypto::SharedSecret, rustls::Error> {
                    let (kx1_pubkey, kx2_pubkey) =
                        split_at_checked(peer, [< $name:upper _SKE_SPLIT >])
                        .ok_or_else(|| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
                    let secret1 = self.kx1.complete(kx1_pubkey)?;
                    let secret2 = self.kx2.complete(kx2_pubkey)?;
                    Ok(concat(secret1.secret_bytes(), secret2.secret_bytes()).into())
                }

                fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
                    let pk = self.pub_key.split_at([< $name:upper _CKE_SPLIT >]);
                    let ec_pk = ($ec_member)(pk);
                    Some((
                        $kex_ec.name(),
                        ec_pk,
                    ))
                }

                fn complete_hybrid_component(
                    self: Box<Self>,
                    peer: &[u8],
                ) -> Result<crypto::SharedSecret, rustls::Error> {
                    let ec_kx = ($ec_member)((self.kx1, self.kx2));
                    ec_kx.complete(peer)
                }
            }
        }
    }
}

// Note: The EC key appears first in the SecP* groups,
// but (for historical reasons) appears second in X25519MLKEM768.

hybrid_kex! { X25519MLKEM768, MLKEM768, X25519, X25519, second }
hybrid_kex! { SecP256r1MLKEM768, SecP256R1, MLKEM768, SecP256R1, first }
hybrid_kex! { SecP384r1MLKEM1024, SecP384R1, MLKEM1024, SecP384R1, first }
