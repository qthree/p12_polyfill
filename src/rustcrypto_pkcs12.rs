use cms::encrypted_data::EncryptedData;
use der::{
    asn1::OctetString,
    oid::db::rfc5911::{ID_DATA, ID_ENCRYPTED_DATA},
    Decode, Encode as _,
};
use pkcs12::{authenticated_safe::AuthenticatedSafe, pfx::Version};
use pkcs8::pkcs5::pbes2::PBES2_OID;

use crate::P12;

#[derive(Debug)]
pub enum ParseError {}

impl P12 {
    pub fn parse_with_pkcs12(
        p12: &[u8],
        _password: &str,
    ) -> Result<P12, ParseError> {
        let pfx = pkcs12::pfx::Pfx::from_der(p12).unwrap();
        println!("pfx: {pfx:?}");
        assert_eq!(Version::V3, pfx.version);
        assert_eq!(ID_DATA, pfx.auth_safe.content_type);
        let auth_safes_os =
            OctetString::from_der(&pfx.auth_safe.content.to_der().unwrap())
                .unwrap();
        let auth_safes =
            AuthenticatedSafe::from_der(auth_safes_os.as_bytes()).unwrap();
        println!("auth_safes: {auth_safes:?}");

        // Process first auth safe (from offset 34)
        let auth_safe0 = auth_safes.first().unwrap();
        assert_eq!(ID_ENCRYPTED_DATA, auth_safe0.content_type);
        let enc_data_os = &auth_safe0.content.to_der().unwrap();
        let enc_data = EncryptedData::from_der(enc_data_os.as_slice()).unwrap();

        println!("enc_data: {enc_data:?}");

        assert_eq!(ID_DATA, enc_data.enc_content_info.content_type);
        //ObjectIdentifier(1.2.840.113549.1.12.1.6)
        assert_eq!(todo!(), enc_data.enc_content_info.content_enc_alg.oid);
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
