#[macro_export]
macro_rules! const_concat_slices {
    ($ty:ty, $a:expr, $b:expr $(,)*) => {{
        const A: &[$ty] = $a;
        const B: &[$ty] = $b;
        const __LEN: usize = A.len() + B.len();
        const __CONCATENATED: &[$ty; __LEN] = &{
            let mut out: [$ty; __LEN] = if __LEN == 0 {
                unsafe {
                    core::mem::transmute::<[u8; core::mem::size_of::<$ty>() * __LEN], [$ty; __LEN]>(
                        [0u8; core::mem::size_of::<$ty>() * __LEN],
                    )
                }
            } else if A.len() == 0 {
                [B[0]; __LEN]
            } else {
                [A[0]; __LEN]
            };
            let mut i = 0;
            while i < A.len() {
                out[i] = A[i];
                i += 1;
            }
            i = 0;
            while i < B.len() {
                out[i + A.len()] = B[i];
                i += 1;
            }
            out
        };

        __CONCATENATED
    }};
    ($ty:ty, $a:expr, $b:expr, $($c:expr), + $(,)* ) => {{
        const CON: &[$ty] = const_concat_slices!($ty, $a, $b);
        const_concat_slices!($ty, CON, $($c), +)
    }}
}

pub(crate) use const_concat_slices;

/// A tiny RNG adapter that uses `getrandom` directly and implements the
/// `rand_core::RngCore` and `rand_core::CryptoRng` traits so it can be used
/// in places that expect those traits without pulling in the `rand` crate.
pub struct TinyRng;

impl rand_core::CryptoRng for TinyRng {}

impl rand_core::RngCore for TinyRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_ne_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_ne_bytes(b)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        getrandom::getrandom(dst).expect("getrandom failure");
    }
}
