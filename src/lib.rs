#[cfg(feature = "hjiayz-p12")]
pub mod hjiayz_p12;
#[cfg(feature = "pem")]
pub mod pem;
#[cfg(feature = "qthree-p12")]
pub mod qthree_p12;
#[cfg(feature = "rustcrypto-pkcs12")]
pub mod rustcrypto_pkcs12;
#[cfg(feature = "rustls-pki-types")]
pub mod rustls;

#[cfg(feature = "rustls-21")]
pub mod rustls_21;

#[derive(Debug)]
pub struct P12 {
    pub key_bags: Vec<Vec<u8>>,
    pub cert_bags: Vec<Vec<u8>>,
}

impl P12 {
    #[cfg(any(
        feature = "pem",
        feature = "rustls-pki-types",
        feature = "rustls-21",
    ))]
    fn take_single_key(&mut self) -> Result<Vec<u8>, usize> {
        if self.key_bags.len() != 1 {
            return Err(self.key_bags.len());
        }
        Ok(self.key_bags.remove(0))
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    #[derive(Clone, Copy)]
    pub struct TestKey(&'static str);
    
    impl TestKey {
        pub fn key_p12(&self) -> Vec<u8> {
            std::fs::read(format!("{}/key.p12", self.0)).unwrap()
        }

        pub fn key_pem(&self) -> String {
            std::fs::read_to_string(format!("{}/key.pem", self.0)).unwrap()
        }

        pub fn cert_pem(&self) -> String {
            std::fs::read_to_string(format!("{}/cert.pem", self.0)).unwrap()
        }
    }

    pub const PBE: TestKey = TestKey("tests/pbeWithSHA1And40BitRC2-CBC");
    pub const PBES2: TestKey = TestKey("tests/PBES2");
}
