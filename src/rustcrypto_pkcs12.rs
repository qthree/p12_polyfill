use der::Decode;

use crate::P12;

#[derive(Debug)]
pub enum ParseError {}

impl P12 {
    pub fn parse_with_pkcs12(
        p12: &[u8],
        _password: &str,
    ) -> Result<P12, ParseError> {
        let _pfx = pkcs12::pfx::Pfx::from_der(p12).unwrap();
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn parse() -> P12 {
        let bytes = crate::tests::key_p12();
        P12::parse_with_pkcs12(&bytes, "").unwrap()
    }

    #[test]
    fn test_parse_with_pkcs12() {
        eprintln!("{:?}", parse());
    }
}
