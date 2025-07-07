use crate::P12;

#[derive(Debug)]
pub enum ParseError {
    ParsePFX(yasna::ASN1Error),
    KeyBags(yasna::ASN1Error),
    CertBags(yasna::ASN1Error),
    VerifyMac,
}

impl P12 {
    pub fn parse_with_p12(
        p12: &[u8],
        password: &str,
    ) -> Result<P12, ParseError> {
        let pfx = p12::PFX::parse(p12).map_err(ParseError::ParsePFX)?;
        if !pfx.verify_mac(password) {
            return Err(ParseError::VerifyMac);
        }

        let key_bags = pfx.key_bags(password).map_err(ParseError::KeyBags)?;
        let cert_bags =
            pfx.cert_bags(password).map_err(ParseError::CertBags)?;
        Ok(P12 {
            key_bags,
            cert_bags,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::tests::TestKey;

    use super::*;

    pub fn parse(test_key: TestKey) -> P12 {
        let bytes = test_key.key_p12();
        P12::parse_with_p12(&bytes, "").unwrap()
    }

    #[test]
    fn test_parse_pbe_with_p12() {
        eprintln!("{:?}", parse(crate::tests::PBE));
    }

    #[test]
    fn test_parse_pbes2_with_p12() {
        eprintln!("{:?}", parse(crate::tests::PBES2));
    }
}
