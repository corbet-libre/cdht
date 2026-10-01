use std::fmt;

/// `cdht` errors. Coarse on purpose: never carry record data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Malformed input or stored data.
    Encoding,
    /// Invalid schema.
    InvalidSchema,
    /// A signature did not verify.
    BadSignature,
    /// The writer may not write this subkey.
    WrongWriter,
    /// The subkey is outside the schema.
    SubkeyOutOfRange,
    /// The value exceeds the schema's size limit.
    ValueTooLarge,
    /// No more sequence numbers.
    SeqExhausted,
    /// A descriptor does not belong to the record key, or a different descriptor exists.
    WrongRecord,
    /// The backend does not know the record.
    UnknownRecord,
    /// The record was not opened in this client.
    NotOpen,
    /// The watch does not exist.
    UnknownWatch,
    /// The backend is unreachable (writes are queued).
    Unavailable,
    /// A concurrent write disagrees with the proposed value.
    Conflict,
    /// Encrypted data did not decrypt (wrong key or modified).
    Decrypt,
    /// Signing failed in the signer port.
    Signer,
    /// The platform random number generator failed.
    Randomness,
    /// A cryptographic operation failed unexpectedly.
    Crypto,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Encoding => "malformed data",
            Error::InvalidSchema => "invalid schema",
            Error::BadSignature => "signature did not verify",
            Error::WrongWriter => "writer not allowed for this subkey",
            Error::SubkeyOutOfRange => "subkey out of range",
            Error::ValueTooLarge => "value too large",
            Error::SeqExhausted => "sequence numbers exhausted",
            Error::WrongRecord => "descriptor does not match the record",
            Error::UnknownRecord => "unknown record",
            Error::NotOpen => "record not open",
            Error::UnknownWatch => "unknown watch",
            Error::Unavailable => "backend unavailable",
            Error::Conflict => "concurrent write won",
            Error::Decrypt => "decryption failed",
            Error::Signer => "signing failed",
            Error::Randomness => "randomness unavailable",
            Error::Crypto => "cryptographic failure",
        })
    }
}

impl std::error::Error for Error {}
