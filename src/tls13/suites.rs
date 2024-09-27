use crate::const_concat_slices;
use rustls::SupportedCipherSuite;

pub const TLS13_SUITES: &[SupportedCipherSuite] = const_concat_slices!(
    SupportedCipherSuite,
    {
        #[cfg(feature = "aes-gcm")]
        {
            aes::TLS13_AES_SUITES
        }

        #[cfg(not(feature = "aes-gcm"))]
        {
            &[]
        }
    },
    {
        #[cfg(feature = "chacha20poly1305")]
        {
            &[chacha20::TLS13_CHACHA20_POLY1305_SHA256]
        }

        #[cfg(not(feature = "chacha20poly1305"))]
        {
            &[]
        }
    },
    &[]
);

#[cfg(feature = "aes-gcm")]
pub mod aes;

#[cfg(feature = "chacha20poly1305")]
pub mod chacha20;
