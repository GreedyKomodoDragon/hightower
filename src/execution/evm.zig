// The transaction-scoped EVM executes call frames in opcode order. Gas, warm
// accesses, logs, and storage changes are committed or reverted with each frame.
// The public API stays here while implementation and tests live in the evm package.
const core = @import("evm/machine.zig");

pub const Environment = core.Environment;
pub const Access = core.Access;
pub const Log = core.Log;
pub const Input = core.Input;
pub const Fault = core.Fault;
pub const Status = core.Status;
pub const Result = core.Result;
pub const Machine = core.Machine;

test {
    _ = @import("evm/tests.zig");
}
