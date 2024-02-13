use crate::P12;

#[derive(Debug)]
pub enum Error {
    WrongPrivateKeysNumber(usize),
}

#[derive(Debug)]
pub struct Pem {
    pub key: String,
    pub certs: String,
}

impl P12 {
    /// Can be used with native_tls::Identity::from_pkcs8
    pub fn into_pem(mut self) -> Result<Pem, Error> {
        let single_key = self
            .take_single_key()
            .map_err(Error::WrongPrivateKeysNumber)?;
        let key = pem::Pem::new("PRIVATE KEY", single_key);
        let key = pem::encode(&key);
        let certs: Vec<_> = self
            .cert_bags
            .into_iter()
            .map(|cert| pem::Pem::new("CERTIFICATE", cert))
            .collect();
        let certs = pem::encode_many(&certs);
        Ok(Pem { key, certs })
    }
}

#[cfg(test)]
mod tests {
    use crate::hjiayz_p12::tests::parse;

    #[test]
    fn test_parse() {
        let p12 = parse();
        let pem = p12.into_pem().unwrap();

        let key_pem = crate::tests::key_pem();
        let cert_pem = crate::tests::cert_pem();

        let normalize = |str: &str| str.trim().replace("\r\n", "\n");

        assert_eq!(normalize(&pem.key), normalize(&key_pem));
        assert_eq!(normalize(&pem.certs), normalize(&cert_pem));

        eprintln!("{pem:?}")
    }
}
