//! Serialized-size computation. Sizes depend on values for
//! variable-size types (List lengths, BitList lengths, container
//! payloads), so this cannot live in the descriptor.

const desc_mod = @import("type_descriptor");

/// Full serialized byte length of `value`.
pub fn serializedSize(value: anytype) usize {
    const T = @TypeOf(value);
    const desc = comptime desc_mod.SszType(T);

    switch (desc.kind) {
        .Bool => return 1,
        .Uint8, .Uint16, .Uint32, .Uint64, .Uint128, .Uint256 => {
            return desc.fixed_size.?;
        },
        .BitVector => return (desc.bit_length.? + 7) / 8,
        .BitList => {
            // +1 bit for the delimiter.
            return (value.data.len + 1 + 7) / 8;
        },
        .ByteVector => return desc.byte_length.?,
        .ByteList => return value.data.len,
        .List => {
            const elem = comptime desc_mod.SszType(desc.element.?);
            if (comptime !elem.is_variable) {
                return value.data.len * elem.fixed_size.?;
            }
            var size: usize = value.data.len * 4;
            for (value.data) |item| {
                size += serializedSize(item);
            }
            return size;
        },
        .Array => {
            if (comptime !desc.is_variable) {
                return desc.fixed_size.?;
            }
            // Vector of variable-size elements: offsets then payloads.
            var size: usize = value.len * 4;
            for (value) |item| {
                size += serializedSize(item);
            }
            return size;
        },
        .Container, .ProgressiveContainer => {
            if (comptime !desc.is_variable) {
                return desc.fixed_size.?;
            }
            var size = containerFixedSectionSize(T);
            inline for (@typeInfo(T).@"struct".fields) |field| {
                const field_desc = comptime desc_mod.SszType(field.type);
                if (comptime field_desc.is_variable) {
                    size += serializedSize(@field(value, field.name));
                }
            }
            return size;
        },
    }
}

/// Fixed-section byte length of a container: fixed fields inline,
/// 4-byte offset slots for variable-size fields.
pub fn containerFixedSectionSize(comptime T: type) usize {
    var size: usize = 0;
    inline for (@typeInfo(T).@"struct".fields) |field| {
        const field_desc = comptime desc_mod.SszType(field.type);
        if (comptime field_desc.is_variable) {
            size += 4;
        } else {
            size += field_desc.fixed_size.?;
        }
    }
    return size;
}
