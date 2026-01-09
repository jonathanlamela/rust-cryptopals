#[derive(Copy, Clone, Eq, PartialEq)]
pub enum MODE {
    ECB,
    CBC,
    CTR,
}

pub mod custom_crypter_11;
pub mod custom_crypter_12;
pub mod custom_crypter_13;
pub mod custom_crypter_14;
pub mod custom_crypter_16;
pub mod custom_crypter_17;

pub use custom_crypter_11::CustomCrypter11;
pub use custom_crypter_12::CustomCrypter12;
pub use custom_crypter_13::CustomCrypter13;
pub use custom_crypter_14::CustomCrypter14;
pub use custom_crypter_16::CustomCrypter16;
pub use custom_crypter_17::CustomCrypter17;
