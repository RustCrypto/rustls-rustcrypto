use crate::misc::const_concat_slices;
use rustls::SupportedCipherSuite;

pub const TLS12_SUITES: &[SupportedCipherSuite] = const_concat_slices!(
    SupportedCipherSuite,
    {
        #[cfg(feature = "ecdsa")]
        {
            ecdsa::TLS_ECDHE_ECDSA_SUITES
        }

        #[cfg(not(feature = "ecdsa"))]
        {
            &[]
        }
    },
    {
        #[cfg(feature = "rsa")]
        {
            rsa::TLS_ECDHE_RSA_SUITES
        }

        #[cfg(not(feature = "rsa"))]
        {
            &[]
        }
    }
);

#[cfg(feature = "ecdsa")]
pub mod ecdsa;
#[cfg(feature = "rsa")]
pub mod rsa;
pub mod schemes;
