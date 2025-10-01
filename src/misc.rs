#[macro_export]
macro_rules! const_concat_slices {
    ($ty:ty, $($s:expr),* $(,)*) => {
        const {
            use ::core::mem::{MaybeUninit, transmute};
            const TOTAL_LEN: usize = $(const {const VALUE: &[$ty] = $s; VALUE.len()} + )* 0;
            const SLICES: &[&[$ty]] = &[$($s),*];

            let mut out: [MaybeUninit<$ty>; TOTAL_LEN] = unsafe { MaybeUninit::uninit().assume_init() };
            let mut offset = 0;
            let mut slice_idx = 0;
            while slice_idx < SLICES.len() {
                let slice = SLICES[slice_idx];
                let mut i = 0;
                while i < slice.len() {
                    out[offset] = MaybeUninit::new(slice[i]);
                    offset += 1;
                    i += 1;
                }
                slice_idx += 1;
            }
            &unsafe { transmute::<[MaybeUninit<$ty>; TOTAL_LEN], [$ty; TOTAL_LEN]>(out) }
        }
    };
}

#[macro_export]
macro_rules! feature_eval_expr {
    (
        [$($cfg:tt)*],
        $on_true:expr,
        else $on_false:expr
    ) => {
        {
            #[cfg($($cfg)*)]
            {
                $on_true
            }
            #[cfg(not($($cfg)*))]
            {
                $on_false
            }
        }
    };
}

#[macro_export]
macro_rules! feature_slice {
    (
        [$($cfg:tt)*],
        $slice:expr
    ) => { $crate::feature_eval_expr!([$($cfg)*], $slice, else &[]) };
}

#[macro_export]
macro_rules! tls13_cipher_suite {
    ($name:ident, $suite:expr, $hash:expr, $hkdf:expr, $aead:expr, $quic:expr) => {
        pub const $name: Tls13CipherSuite = Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: $suite,
                hash_provider: $hash,
                confidentiality_limit: u64::MAX,
            },
            hkdf_provider: &$hkdf,
            aead_alg: $aead,
            quic: $quic,
        };
    };
}

#[macro_export]
macro_rules! tls12_ecdhe_cipher_suite {
    ($name:ident, $suite:expr, $hash:expr, $prf:expr, $sign:expr, $aead:expr) => {
        pub const $name: Tls12CipherSuite = Tls12CipherSuite {
            common: CipherSuiteCommon {
                suite: $suite,
                hash_provider: $hash,
                confidentiality_limit: u64::MAX,
            },
            kx: KeyExchangeAlgorithm::ECDHE,
            sign: $sign,
            aead_alg: $aead,
            prf_provider: &$prf,
        };
    };
}

pub(crate) use const_concat_slices;
