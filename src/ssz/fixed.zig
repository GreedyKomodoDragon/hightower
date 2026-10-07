pub fn fixedSize(comptime T: type) usize {
    switch (@typeInfo(T)) {
        .int => |info| {
            return info.bits / 8;
        },

        .bool => {
            return 1;
        },

        .array => |info| {
            return info.len * fixedSize(info.child);
        },

        .@"struct" => |info| {
            if (@hasDecl(T, "ssz_kind")) {
                switch (T.ssz_kind) {
                    .bitvector => {
                        return (T.bit_length + 7) / 8;
                    },

                    .bytevector => {
                        return T.byte_length;
                    },

                    .bitlist,
                    .bytelist,
                    => {
                        @compileError(
                            "fixedSize called on variable-size SSZ type: " ++
                                @typeName(T),
                        );
                    },

                    else => {
                        @compileError(
                            "fixedSize not implemented for SSZ type: " ++
                                @typeName(T),
                        );
                    },
                }
            }

            var total: usize = 0;

            if (comptime !isFixedSize(T)) {
                @compileError(
                    "fixedSize called on variable-size container: " ++
                        @typeName(T),
                );
            }

            inline for (info.fields) |field| {
                total += fixedSize(field.type);
            }

            return total;
        },

        else => {
            @compileError(
                "fixedSize unsupported for type: " ++ @typeName(T),
            );
        },
    }
}

pub fn isFixedSize(comptime T: type) bool {
    switch (@typeInfo(T)) {
        .int => return true,
        .bool => return true,

        .array => |info| {
            return isFixedSize(info.child);
        },

        .@"struct" => |info| {
            if (@hasDecl(T, "ssz_kind")) {
                switch (T.ssz_kind) {
                    .bitlist => return false,
                    .bitvector => return true,
                    .bytelist => return false,
                    .bytevector => return true,
                    .list => return false,

                    else => @compileError(
                        "isFixedSize not implemented for SSZ type: " ++
                            @typeName(T),
                    ),
                }
            }

            inline for (info.fields) |field| {
                if (!isFixedSize(field.type)) {
                    return false;
                }
            }

            return true;
        },

        else => return false,
    }
}
