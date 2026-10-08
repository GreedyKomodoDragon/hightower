//! SSZ (Simple Serialize) public API.
//!
//! Serialization format used in the Ethereum consensus layer.
//! Supported types: bool, uint8/16/32/64/128/256, fixed arrays,
//! BitVector, BitList, ByteVector, ByteList, List and Containers
//! (plain and progressive).
//!
//! Layout of this module:
//! - `serialize` / `serializeAlloc` / `deserialize` / `freeDecoded`
//!   are thin kind-dispatchers (see `serialize.zig`, `deserialize.zig`)
//! - per-type codecs live in `basic`, `bitlist`, `bitvector`,
//!   `bytelist`, `bytevector`, `list`, `array`, `container`
//! - `size` computes serialized lengths, `offset` handles offset
//!   tables, `free` releases owned decode output
//! - `type_descriptor.SszType(T)` is the single source of truth for
//!   type metadata; `ssz_errors.SszError` is the canonical error set
//!
//! Ownership: `deserialize` takes an allocator but only touches it
//! for variable-size types (fixed types decode without allocating).
//! Owned output must be released with `freeDecoded`.

const serialize_mod = @import("serialize.zig");
const deserialize_mod = @import("deserialize.zig");
const free_mod = @import("free.zig");
const desc_mod = @import("type_descriptor");
const errors = @import("ssz_errors");

pub const serialize = serialize_mod.serialize;
pub const serializeAlloc = serialize_mod.serializeAlloc;
pub const deserialize = deserialize_mod.deserialize;
pub const freeDecoded = free_mod.freeDecoded;

pub const SszError = errors.SszError;
pub const SszType = desc_mod.SszType;
pub const Kind = desc_mod.Kind;
pub const Descriptor = desc_mod.Descriptor;
