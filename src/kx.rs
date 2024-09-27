use nist::{SecP256R1, SecP384R1};
use rustls::crypto::SupportedKxGroup;
use x25519::X25519;

pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&X25519, &SecP256R1, &SecP384R1];

pub mod nist;
pub mod x25519;
