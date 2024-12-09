use crate::const_concat_slices;
use rustls::SupportedCipherSuite;

pub const TLS13_SUITES: &[SupportedCipherSuite] = const_concat_slices!(
    SupportedCipherSuite,
    {
        #[cfg(feature = "aes")]
        {
            aes::TLS13_AES_SUITES
        }

        #[cfg(not(feature = "aes"))]
        {
            &[]
        }
    },
    {
        #[cfg(feature = "chacha20poly1305")]
        {
            &[
                #[cfg(feature = "hash-sha256")]
                chacha20::TLS13_CHACHA20_POLY1305_SHA256,
            ]
        }

        #[cfg(not(feature = "chacha20poly1305"))]
        {
            &[]
        }
    },
    &[]
);

#[cfg(feature = "aes")]
pub mod aes;

#[cfg(feature = "chacha20poly1305")]
pub mod chacha20;
