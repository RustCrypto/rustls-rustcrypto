use rustls::crypto::SupportedKxGroup;

pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    #[cfg(feature = "x25519")]
    &x25519::X25519,
    #[cfg(feature = "p256")]
    &nist::SecP256R1,
    #[cfg(feature = "p384")]
    &nist::SecP384R1,
];

#[cfg(feature = "nist")]
pub mod nist;

#[cfg(feature = "x25519")]
pub mod x25519;
