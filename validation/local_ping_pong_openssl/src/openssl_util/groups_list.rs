//! Sets the context’s supported elliptic curve groups.
//! https://docs.rs/openssl/latest/openssl/ssl/struct.SslContextBuilder.html#method.set_groups_list
//! https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set1_groups_list.html

#[derive(Debug)]
#[allow(non_snake_case)]
pub struct GroupsList {
    pub P256: bool,
    pub P384: bool,
    pub X25519: bool,
    pub X448: bool,
    pub brainpoolP256r1tls13: bool,
    pub brainpoolP384r1tls13: bool,
    pub brainpoolP512r1tls13: bool,
    pub ffdhe2048: bool,
    pub ffdhe3072: bool,
    pub ffdhe4096: bool,
    pub ffdhe6144: bool,
    pub ffdhe8192: bool,
}

impl GroupsList {
    pub fn all_false() -> Self {
        GroupsList {
            P256: false,
            P384: false,
            X25519: false,
            X448: false,
            brainpoolP256r1tls13: false,
            brainpoolP384r1tls13: false,
            brainpoolP512r1tls13: false,
            ffdhe2048: false,
            ffdhe3072: false,
            ffdhe4096: false,
            ffdhe6144: false,
            ffdhe8192: false,
        }
    }
}

impl Default for GroupsList {
    fn default() -> Self {
        GroupsList {
            P256: true,
            P384: true,
            X25519: true,
            X448: false,
            brainpoolP256r1tls13: false,
            brainpoolP384r1tls13: false,
            brainpoolP512r1tls13: false,
            ffdhe2048: false,
            ffdhe3072: false,
            ffdhe4096: false,
            ffdhe6144: false,
            ffdhe8192: false,
        }
    }
}

impl core::fmt::Display for GroupsList {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        let mut vec_groups: Vec<&str> = vec![];

        if self.P256 {
            vec_groups.push("P-256");
        }
        if self.P384 {
            vec_groups.push("P-384");
        }
        if self.X25519 {
            vec_groups.push("X25519");
        }
        if self.X448 {
            vec_groups.push("X448");
        }
        if self.brainpoolP256r1tls13 {
            vec_groups.push("brainpoolP256r1tls13");
        }
        if self.brainpoolP384r1tls13 {
            vec_groups.push("brainpoolP384r1tls13");
        }
        if self.brainpoolP512r1tls13 {
            vec_groups.push("brainpoolP512r1tls13");
        }
        if self.ffdhe2048 {
            vec_groups.push("ffdhe2048");
        }
        if self.ffdhe3072 {
            vec_groups.push("ffdhe3072");
        }
        if self.ffdhe4096 {
            vec_groups.push("ffdhe4096");
        }
        if self.ffdhe6144 {
            vec_groups.push("ffdhe6144");
        }
        if self.ffdhe8192 {
            vec_groups.push("ffdhe8192");
        }
        write!(f, "{}", vec_groups.join(":"))
    }
}
