// A precompile call spends its supplied gas before returning bytes or failure.
// This runner compares that frame boundary with Geth across London, Cancun,
// and Osaka; Fulu uses Osaka's precompile rules. Inputs are at most 512 bytes.
//
// JSON case -> fork/address/data -> EVM frame -> compare -> reproducer
const std = @import("std");
const execution = @import("execution");
const evm = execution.evm;
const state = execution.state;
const ckzg = @import("ckzg");

const Outcome = struct { success: bool, output: []const u8, gas_used: u64 };
const Case = struct { seed: i64, fork: []const u8, address: u8, input: []const u8, gas: u64, geth: Outcome };
const max_cases_bytes = 16 * 1024 * 1024;

/// Decodes a bounded even-length hexadecimal input from the generator.
fn decode(a: std.mem.Allocator, raw: []const u8) ![]u8 {
    if (raw.len > 1024 or raw.len % 2 != 0) return error.InvalidInput;
    const result = try a.alloc(u8, raw.len / 2);
    errdefer a.free(result);
    _ = try std.fmt.hexToBytes(result, raw);
    return result;
}

/// Maps Fulu to Osaka's precompile schedule.
fn forkOf(name: []const u8) !evm.Fork {
    if (std.mem.eql(u8, name, "london")) return .london;
    if (std.mem.eql(u8, name, "cancun")) return .cancun;
    if (std.mem.eql(u8, name, "osaka")) return .osaka;
    if (std.mem.eql(u8, name, "fulu")) return .fulu;
    return error.InvalidFork;
}

/// Runs one real EVM call frame and records its output and spent gas.
fn compare(a: std.mem.Allocator, item: Case, settings: *const ckzg.Settings) !Outcome {
    if (item.address < 1 or item.address > 10) return error.InvalidAddress;
    const input = try decode(a, item.input);
    defer a.free(input);
    var world = state.State.init(a);
    defer world.deinit();
    var machine = evm.Machine.init(a, &world);
    defer machine.deinit();
    machine.environment = .{
        .fork = try forkOf(item.fork),
        .origin = .{0} ** 20,
        .gas_price = 0,
        .coinbase = .{0} ** 20,
        .timestamp = 0,
        .number = 0,
        .prev_randao = 0,
        .gas_limit = item.gas,
        .chain_id = 1,
        .base_fee = 0,
        .blob_base_fee = 0,
        .kzg_settings = settings,
    };
    var target: state.Address = .{0} ** 20;
    target[19] = item.address;
    var result = try machine.run(.{ .code = &.{}, .data = input, .gas = item.gas, .callee = target });
    defer result.deinit(a);
    const hex = try a.alloc(u8, result.output.len * 2);
    const digits = "0123456789abcdef";
    for (result.output, 0..) |byte, i| {
        hex[i * 2] = digits[byte >> 4];
        hex[i * 2 + 1] = digits[byte & 15];
    }
    return .{
        .success = result.status == .success,
        .output = hex,
        .gas_used = item.gas - result.gas_remaining,
    };
}

/// Compares a case and writes a standalone JSON reproducer on mismatch.
fn check(a: std.mem.Allocator, io: std.Io, item: Case, settings: *const ckzg.Settings, path: []const u8) !void {
    const actual = try compare(a, item, settings);
    if (actual.success == item.geth.success and actual.gas_used == item.geth.gas_used and std.mem.eql(u8, actual.output, item.geth.output)) return;
    const report = try std.json.Stringify.valueAlloc(a, .{ .case = item, .hightower = actual }, .{});
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = report });
    const message = try std.fmt.allocPrint(a, "precompile mismatch seed={d} fork={s} address=0x{x:0>2} input={s} gas={d}\nGeth: {f}\nHightower: {f}\nreproducer: {s}\n", .{ item.seed, item.fork, item.address, item.input, item.gas, std.json.fmt(item.geth, .{}), std.json.fmt(actual, .{}), path });
    try std.Io.File.stderr().writeStreamingAll(io, message);
    return error.DifferentialMismatch;
}

/// Reads a generated case array or a single saved case and compares it with Geth.
pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len < 2 or args.len > 3) return error.ExpectedCasesFileAndOptionalReproducerPath;
    const path = if (args.len == 3) args[2] else "precompile-mismatch.json";
    const bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, args[1], a, .limited(max_cases_bytes));
    var settings = try ckzg.Settings.loadTrustedSetupFile("src/execution/trusted_setup.txt", 0);
    defer settings.deinit();
    if (bytes.len > 0 and bytes[0] == '[') {
        const parsed = try std.json.parseFromSlice([]Case, a, bytes, .{ .allocate = .alloc_always });
        for (parsed.value) |item| try check(a, init.io, item, &settings, path);
        try std.Io.File.stdout().writeStreamingAll(init.io, try std.fmt.allocPrint(a, "precompile comparisons passed: {d} cases\n", .{parsed.value.len}));
        return;
    }
    const parsed = try std.json.parseFromSlice(struct { case: Case }, a, bytes, .{ .allocate = .alloc_always });
    try check(a, init.io, parsed.value.case, &settings, path);
    try std.Io.File.stdout().writeStreamingAll(init.io, "precompile comparison passed: 1 case\n");
}
