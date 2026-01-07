use rustls::crypto::SupportedKxGroup;

pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    #[cfg(feature = "kx-x448")]
    &x448::X448,
    #[cfg(feature = "kx-x25519")]
    &x25519::X25519,
    #[cfg(feature = "kx-p256")]
    &nist::SEC_P256_R1,
    #[cfg(feature = "kx-p384")]
    &nist::SEC_P384_R1,
    #[cfg(feature = "kx-p521")]
    &nist::SEC_P521_R1,
];

#[cfg(feature = "kx-nist")]
pub mod nist;

#[cfg(feature = "kx-x25519")]
pub mod x25519;

#[cfg(feature = "kx-x448")]
pub mod x448;
