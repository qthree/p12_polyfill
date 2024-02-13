#[cfg(feature = "hjiayz-p12")]
pub mod hjiayz_p12;
#[cfg(feature = "pem")]
pub mod pem;
#[cfg(feature = "rustcrypto-pkcs12")]
pub mod rustcrypto_pkcs12;
#[cfg(feature = "rustls-pki-types")]
pub mod rustls;

#[derive(Debug)]
pub struct P12 {
    pub key_bags: Vec<Vec<u8>>,
    pub cert_bags: Vec<Vec<u8>>,
}

impl P12 {
    #[cfg(any(feature = "rustls-pki-types", feature = "pem"))]
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
    pub fn key_p12() -> Vec<u8> {
        std::fs::read("tests/examples/key.p12").unwrap()
    }

    pub fn key_pem() -> String {
        std::fs::read_to_string("tests/examples/key.pem").unwrap()
    }

    pub fn cert_pem() -> String {
        std::fs::read_to_string("tests/examples/cert.pem").unwrap()
    }
}
