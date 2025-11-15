use thiserror::Error;

/// Result alias for public APIs.
pub type DexResult<T> = Result<T, DexError>;

/// Errors that can be emitted while parsing or modeling a DEX file.
#[derive(Debug, Error)]
pub enum DexError {
    /// The provided file was too small to contain a valid header.
    #[error("buffer too small: expected at least {expected} bytes, got {actual}")]
    BufferTooSmall {
        /// Expected byte count.
        expected: usize,
        /// Actual byte count.
        actual: usize,
    },
    /// The header magic did not match a known DEX version.
    #[error("invalid magic bytes {magic:?}")]
    InvalidMagic {
        /// The raw magic bytes found in the file.
        magic: [u8; 8],
    },
    /// The parser encountered a DEX version newer than it understands.
    #[error("unsupported dex version {version}")]
    UnsupportedVersion {
        /// Reported version string, e.g. 041.
        version: u16,
    },
    /// A header field pointed outside the main buffer.
    #[error("section {section} (offset {offset}, size {size}) is out of bounds")]
    SectionOutOfBounds {
        /// Section description.
        section: &'static str,
        /// Requested start offset.
        offset: usize,
        /// Requested size in bytes.
        size: usize,
    },
    /// Malformed structured data.
    #[error("{context} is malformed: {message}")]
    Malformed {
        /// Context string.
        context: &'static str,
        /// Explanation.
        message: &'static str,
    },
    /// Attempted to access an index outside of its table.
    #[error("index {index} is out of range for {table}")]
    InvalidIndex {
        /// Table name.
        table: &'static str,
        /// Requested index.
        index: u32,
    },
    /// Variable-length integer decoding failed.
    #[error("invalid leb128 encoding while parsing {context}")]
    Leb128 {
        /// Context string.
        context: &'static str,
    },
    /// Modified UTF-8 decoding failed.
    #[error("invalid mutf8 data in string at offset {offset}")]
    Mutf8 {
        /// Offset of the string data.
        offset: u32,
    },
    /// Encountered an unknown opcode while decoding bytecode.
    #[error("unknown opcode {opcode:#04x} at pc {pc}")]
    UnknownOpcode {
        /// Raw opcode byte.
        opcode: u8,
        /// Program counter where the opcode appeared.
        pc: u32,
    },
    /// Any other parsing failure.
    #[error("{0}")]
    Message(&'static str),
    /// I/O error while reading fixtures or archives.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Zip archive error.
    #[error("zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
}
