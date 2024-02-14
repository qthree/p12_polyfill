use p12_q3::{BmpString, PFX};

use crate::P12;

#[derive(Debug)]
pub enum ParseError {
    ParsePFX(yasna::ASN1Error),
    KeyBags(yasna::ASN1Error),
    CertBags(yasna::ASN1Error),
    VerifyMac,
}

impl P12 {
    fn guess_password(
        pfx: &PFX,
        password: &str,
    ) -> Result<BmpString, ParseError> {
        let mut bmp_password = BmpString::with_two_trailing_zeros(password);
        let mut res = pfx.verify_mac(&bmp_password);
        if !res && password.is_empty() {
            bmp_password = BmpString::empty_without_trailing_zeros();
            res = pfx.verify_mac(&bmp_password);
        }
        if res {
            Ok(bmp_password)
        } else {
            Err(ParseError::VerifyMac)
        }
    }

    pub fn parse_with_p12_q3(
        p12: &[u8],
        password: &str,
    ) -> Result<P12, ParseError> {
        let pfx = PFX::parse(p12).map_err(ParseError::ParsePFX)?;

        let password = Self::guess_password(&pfx, password)?;

        let key_bags = pfx.key_bags(&password).map_err(ParseError::KeyBags)?;
        let cert_bags =
            pfx.cert_bags(&password).map_err(ParseError::CertBags)?;
        Ok(P12 {
            key_bags,
            cert_bags,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn parse() -> P12 {
        let bytes = crate::tests::key_p12();
        P12::parse_with_p12_q3(&bytes, "").unwrap()
    }

    #[test]
    fn test_parse_with_p12() {
        eprintln!("{:?}", parse());
    }
}
