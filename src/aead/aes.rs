use ::aes::{Aes128, Aes256};

#[cfg(feature = "gcm")]
use aes_gcm::AesGcm;

#[cfg(feature = "ccm")]
use {
    ccm::Ccm,
    typenum::{U8, U16},
};

#[cfg(any(feature = "gcm", feature = "ccm"))]
use typenum::U12;

// The AEAD_AES_128_CCM authenticated encryption algorithm works as
// specified in [CCM], using AES-128 as the block cipher, by providing
// the key, nonce, associated data, and plaintext to that mode of
// operation.  The formatting and counter generation function are as
// specified in Appendix A of that reference, and the values of the
// parameters identified in that appendix are as follows:
//    the nonce length n is 12,
//    the tag length t is 16, and
//    the value of q is 3.
#[cfg(feature = "ccm")]
pub type Aes128Ccm = Ccm<Aes128, U16, U12>;
#[cfg(feature = "ccm")]
pub type Aes256Ccm = Ccm<Aes256, U16, U12>;

// The AEAD_AES_128_CCM_8 authenticated encryption algorithm is
// identical to the AEAD_AES_128_CCM algorithm (see Section 5.3 of
// [RFC5116]), except that it uses 8 octets for authentication, instead
// of the full 16 octets used by AEAD_AES_128_CCM.
#[cfg(feature = "ccm")]
pub type Aes128Ccm8 = Ccm<Aes128, U8, U12>;
#[cfg(feature = "ccm")]
pub type Aes256Ccm8 = Ccm<Aes256, U8, U12>;

#[cfg(feature = "gcm")]
pub type Aes128Gcm = AesGcm<Aes128, U12>;

#[cfg(feature = "gcm")]
pub type Aes256Gcm = AesGcm<Aes256, U12>;
