//! Legacy fixed-size helpers, now thin delegates over
//! `type_descriptor.SszType(T)`. Kept so existing call sites
//! (`ssz.zig`, tests) keep working during the incremental refactor.
//! New code should use `type_descriptor` directly.

const desc = @import("type_descriptor");

pub fn fixedSize(comptime T: type) usize {
    return desc.fixedSize(T);
}

pub fn isFixedSize(comptime T: type) bool {
    return desc.isFixedSize(T);
}
