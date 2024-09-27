const CHACHAPOLY1305_OVERHEAD: usize = 16;

pub struct ChaCha20Poly1305;

#[cfg(feature = "tls12")]
pub mod tls12;

pub mod tls13;
