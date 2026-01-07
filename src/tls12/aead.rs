#[cfg(feature = "chacha20poly1305")]
pub mod chacha20;

#[cfg(feature = "gcm")]
pub mod gcm;

#[cfg(feature = "ccm")]
pub mod ccm;

#[cfg(any(feature = "aes-gcm", feature = "aes-ccm"))]
pub(crate) mod explicit_nonce;
