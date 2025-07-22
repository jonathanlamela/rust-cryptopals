use crate::enums::MODE;

pub struct Hex(pub String);
pub struct Base64(pub String);

#[derive(Debug)]
pub struct SingleXorRow {
    pub key: u8,
    pub xor_value: Vec<u8>,
}

pub struct OracleBase {
    pub key: Vec<u8>,
    pub prefix: Option<Vec<u8>>,
    pub suffix: Option<Vec<u8>>,
    pub iv: Option<Vec<u8>>,
    pub mode: MODE,
}

pub struct CustomCrypter11 {
    pub base: OracleBase,
}

pub struct CustomCrypter12 {
    pub base: OracleBase,
}

pub struct CustomCrypter13 {
    pub base: OracleBase,
}

pub struct CustomCrypter14 {
    pub base: OracleBase,
}

pub struct CustomCrypter16 {}

pub struct CustomCrypter17 {
    pub picked_token: String,
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
}
