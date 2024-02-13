use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::P12;

#[derive(Debug)]
pub enum Error {
    WrongPrivateKeysNumber(usize),
}

pub struct SingleCert {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub key_der: PrivateKeyDer<'static>,
}

impl P12 {
    /// Can be used with with rustls::ConfigBuilder::with_single_cert
    pub fn rustls_single_cert(mut self) -> Result<SingleCert, Error> {
        let single_key = self
            .take_single_key()
            .map_err(Error::WrongPrivateKeysNumber)?;
        let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(single_key));
        let cert_chain = self
            .cert_bags
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        Ok(SingleCert {
            key_der,
            cert_chain,
        })
    }
}
