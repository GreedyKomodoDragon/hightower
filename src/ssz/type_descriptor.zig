//! Single source of truth for SSZ type metadata.
//!
//! Every SSZ-eligible Zig type maps to one `Descriptor` computed at
//! compile time by `SszType(T)`. Dispatch code (serialize,
//! deserialize, size, merkleization) switches on `desc.kind`
//! instead of repeating `@typeInfo` / `@hasDecl("ssz_kind")` logic.
//!
//! Usage pattern (compute once per generic instantiation, reuse):
//!
//! ```zig
//! const desc = comptime SszType(T);
//! if (comptime desc.is_variable) { ... }
//! ```

pub const Kind = enum {
    Bool,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Uint128,
    Uint256,
    BitVector,
    BitList,
    ByteVector,
    ByteList,
    List,
    Array,
    Container,
    ProgressiveContainer,
};

pub const Descriptor = struct {
    kind: Kind,
    /// Serialized byte size, or null when variable-size.
    fixed_size: ?usize,
    /// True for List, BitList, ByteList, variable Arrays/Containers.
    is_variable: bool,
    max_bits: ?usize = null,
    max_bytes: ?usize = null,
    max_length: ?usize = null,
    bit_length: ?usize = null,
    byte_length: ?usize = null,
    /// Element type for List and Array, else null.
    element: ?type = null,
};

/// Compute the SSZ descriptor for `T`. Compile-errors on
/// non-SSZ types (signed ints, unsupported widths, unknown kinds).
pub fn SszType(comptime T: type) Descriptor {
    return switch (@typeInfo(T)) {
        .bool => .{
            .kind = .Bool,
            .fixed_size = 1,
            .is_variable = false,
        },
        .int => |info| {
            if (info.signedness != .unsigned) {
                @compileError("SSZ does not support signed int: " ++ @typeName(T));
            }
            return switch (info.bits) {
                8 => .{ .kind = .Uint8, .fixed_size = 1, .is_variable = false },
                16 => .{ .kind = .Uint16, .fixed_size = 2, .is_variable = false },
                32 => .{ .kind = .Uint32, .fixed_size = 4, .is_variable = false },
                64 => .{ .kind = .Uint64, .fixed_size = 8, .is_variable = false },
                128 => .{ .kind = .Uint128, .fixed_size = 16, .is_variable = false },
                256 => .{ .kind = .Uint256, .fixed_size = 32, .is_variable = false },
                else => @compileError("SSZ does not support uint size: " ++ @typeName(T)),
            };
        },
        .array => |array_info| {
            const elem = comptime SszType(array_info.child);
            if (elem.is_variable) {
                return .{
                    .kind = .Array,
                    .fixed_size = null,
                    .is_variable = true,
                    .element = array_info.child,
                };
            }
            return .{
                .kind = .Array,
                .fixed_size = array_info.len * elem.fixed_size.?,
                .is_variable = false,
                .element = array_info.child,
            };
        },
        .@"struct" => {
            if (@hasDecl(T, "ssz_kind")) {
                return switch (T.ssz_kind) {
                    .bitvector => .{
                        .kind = .BitVector,
                        .fixed_size = (T.bit_length + 7) / 8,
                        .is_variable = false,
                        .bit_length = T.bit_length,
                    },
                    .bitlist => .{
                        .kind = .BitList,
                        .fixed_size = null,
                        .is_variable = true,
                        .max_bits = T.max_bits,
                        .element = bool,
                    },
                    .bytevector => .{
                        .kind = .ByteVector,
                        .fixed_size = T.byte_length,
                        .is_variable = false,
                        .byte_length = T.byte_length,
                    },
                    .bytelist => .{
                        .kind = .ByteList,
                        .fixed_size = null,
                        .is_variable = true,
                        .max_bytes = T.max_bytes,
                        .element = u8,
                    },
                    .list => .{
                        .kind = .List,
                        // Lists are always variable-size (length varies).
                        .fixed_size = null,
                        .is_variable = true,
                        .max_length = T.max_length,
                        .element = T.Element,
                    },
                    else => @compileError("unknown ssz_kind: " ++ @typeName(T)),
                };
            }

            if (@hasDecl(T, "ssz_active_fields")) {
                // Progressive containers (EIP-7495) serialize exactly like
                // plain containers (fixed fields inline, offsets for
                // variable fields). Only Merkleization differs (spine +
                // layout word), hence the distinct kind.
                const section = comptime containerFixedSize(T);
                return .{
                    .kind = .ProgressiveContainer,
                    .fixed_size = section,
                    .is_variable = section == null,
                };
            }

            // Plain container: fixed iff every field is fixed.
            const total = comptime containerFixedSize(T);
            return .{
                .kind = .Container,
                .fixed_size = total,
                .is_variable = total == null,
            };
        },
        else => @compileError("SSZ type descriptor not implemented for: " ++ @typeName(T)),
    };
}

/// Comptime fixed-size check. Prefer binding
/// `const desc = comptime SszType(T);` once and reading
/// `desc.is_variable` in hot generic code.
pub fn isFixedSize(comptime T: type) bool {
    return (comptime SszType(T).is_variable) == false;
}

/// Fixed byte size, or a compile error for variable-size types.
pub fn fixedSize(comptime T: type) usize {
    const desc = comptime SszType(T);
    if (desc.fixed_size) |size| return size;
    @compileError("fixedSize called on variable-size SSZ type: " ++ @typeName(T));
}

/// Total serialized size of a fixed container, or null when any
/// field is variable-size. Shared by Container and
/// ProgressiveContainer, which lay out bytes identically.
fn containerFixedSize(comptime T: type) ?usize {
    comptime var all_fixed = true;
    comptime var total: usize = 0;
    inline for (@typeInfo(T).@"struct".fields) |field| {
        const field_desc = comptime SszType(field.type);
        if (field_desc.is_variable) {
            all_fixed = false;
        } else {
            total += field_desc.fixed_size.?;
        }
    }
    return if (all_fixed) total else null;
}
