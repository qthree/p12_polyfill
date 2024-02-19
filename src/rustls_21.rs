use ::rustls_21::{Certificate, PrivateKey};

use crate::P12;

#[derive(Debug)]
pub enum Error {
    WrongPrivateKeysNumber(usize),
}

pub struct SingleCert {
    pub cert_chain: Vec<Certificate>,
    pub key_der: PrivateKey,
}

impl P12 {
    /// Can be used with with rustls::ConfigBuilder::with_single_cert or with_client_auth_cert
    pub fn rustls_21_single_cert(mut self) -> Result<SingleCert, Error> {
        let single_key = self
            .take_single_key()
            .map_err(Error::WrongPrivateKeysNumber)?;
        let key_der = PrivateKey(single_key);
        let cert_chain = self.cert_bags.into_iter().map(Certificate).collect();
        Ok(SingleCert {
            key_der,
            cert_chain,
        })
    }
}
