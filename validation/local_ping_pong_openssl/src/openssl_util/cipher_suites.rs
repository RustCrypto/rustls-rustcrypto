#[derive(Debug)]
#[allow(non_snake_case)]
pub struct CipherSuites {
    pub TLS_AES_128_GCM_SHA256: bool,
    pub TLS_AES_256_GCM_SHA384: bool,
    pub TLS_CHACHA20_POLY1305_SHA256: bool,
    pub TLS_AES_128_CCM_SHA256: bool,
    pub TLS_AES_128_CCM_8_SHA256: bool,
}

impl core::fmt::Display for CipherSuites {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        let mut vec_suites: Vec<&str> = vec![];
        if self.TLS_AES_128_GCM_SHA256 {
            vec_suites.push("TLS_AES_128_GCM_SHA256");
        }
        if self.TLS_AES_256_GCM_SHA384 {
            vec_suites.push("TLS_AES_256_GCM_SHA384");
        }
        if self.TLS_CHACHA20_POLY1305_SHA256 {
            vec_suites.push("TLS_CHACHA20_POLY1305_SHA256");
        }
        if self.TLS_AES_128_CCM_SHA256 {
            vec_suites.push("TLS_AES_128_CCM_SHA256");
        }
        if self.TLS_AES_128_CCM_8_SHA256 {
            vec_suites.push("TLS_AES_128_CCM_8_SHA256");
        }
        write!(f, "{}", vec_suites.join(":"))
    }
}

impl Default for CipherSuites {
    fn default() -> Self {
        CipherSuites {
            TLS_AES_128_GCM_SHA256: true,
            TLS_AES_256_GCM_SHA384: true,
            TLS_CHACHA20_POLY1305_SHA256: true,
            TLS_AES_128_CCM_SHA256: false,
            TLS_AES_128_CCM_8_SHA256: false,
        }
    }
}
