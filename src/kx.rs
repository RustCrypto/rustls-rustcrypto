use rustls::crypto::SupportedKxGroup;

pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&X25519, &SecP256R1, &SecP384R1];

mod nist;
mod x25519;

pub use nist::*;
pub use x25519::*;
