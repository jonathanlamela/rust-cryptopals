#[derive(Debug)]
pub enum JlmCryptoErrors {
    InvalidHEXValue,
    InvalidHEXToBase64Conversion,
    InvalidHEXToBytesConversion,
    InvalidBytesToHEX,
    InvalidBase64ToBytes,
    UnableFindKs,
    BreakRepeatingKeyAttackFailed,
    PKCS7PaddingFailed,
    BadKeySize,
    BadIvSize,
    CBCEncryptionFailed,
    ECBEncryptionFailed,
    NoDifferentBlocks,
    NoOutputLengthChange,
    InvalidSet2Challenge13Chars,
    InvalidPadding,
    InvalidEncryptionMode,
    BadEncryptionMode,
    FailedAesCtrEncrypt,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum MODE {
    ECB,
    CBC,
    CTR,
}
