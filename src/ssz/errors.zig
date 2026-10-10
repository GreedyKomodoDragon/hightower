//! Canonical SSZ error set.
//!
//! Public SSZ functions annotate their signatures with
//! `(std.Io.Reader.Error || std.mem.Allocator.Error || SszError)`
//! (or the Writer counterpart) so callers see the full contract.
//! I/O and allocation errors come from their own modules; everything
//! SSZ-specific lives here.

pub const SszError = error{
    InvalidBoolean,
    InvalidLength,
    InvalidOffset,
    TrailingBytes,
    EndOfStream,
    ListTooLong,
    SszNotImplemented,
    BitListTooLong,
    ByteListTooLong,
    NoDelimiterBit,
    /// A bounded read overflowed its limit (`Reader.allocRemaining`).
    StreamTooLong,
    /// Merkleization met more chunks than the type limit allows.
    MerkleizeLimit,
    /// Fixed BitVector had non-zero padding bits beyond its length.
    NonZeroPaddingBits,
    /// Lazy view element index outside the validated length.
    IndexOutOfBounds,
};
