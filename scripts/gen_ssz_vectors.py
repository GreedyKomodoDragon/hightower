#!/usr/bin/env python3
"""Generate one Zig test file per ssz-specs fixture.

Reads  testdata/ssz-test-vectors/fixtures/ssz/ssz/*/*.json
Writes  src/ssz/vectors/<fixture-stem>.zig + src/ssz/vectors/tests.zig

Fixture types the current implementation supports (bool, fixed uints,
fixed BytesN, fixed uint vectors) get a real serialize/deserialize/
hash-tree-root test. Everything else (lists, bitlists, unions,
progressive types, decode-failure cases) gets a failing stub that
embeds the expected bytes, ready to implement.

Rerun with:  just gen-vectors   (or: python3 scripts/gen_ssz_vectors.py)
"""

import glob
import json
import os
import re
import sys

FIXTURES_GLOB = "testdata/ssz-test-vectors/fixtures/ssz/ssz/*/*.json"
OUT_DIR = "src/ssz/vectors"

SUPPORTED_UINTS = {
    "Uint8": "u8",
    "Uint16": "u16",
    "Uint32": "u32",
    "Uint64": "u64",
    "Uint128": "u128",
    "Uint256": "u256",
}
SUPPORTED_BYTES = {"Bytes4": 4, "Bytes32": 32, "Bytes52": 52, "Bytes64": 64}


def sanitize(name):
    stem = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if stem[:1].isdigit():
        stem = "_" + stem
    return stem


def load_fixtures():
    files = sorted(glob.glob(FIXTURES_GLOB))
    if not files:
        sys.exit(f"no fixtures found at {FIXTURES_GLOB} (run `just ssz-vectors` first)")
    cases = []
    for path in files:
        with open(path) as f:
            data = json.load(f)
        assert len(data) == 1, f"expected 1 case per file: {path}"
        test_id, case = next(iter(data.items()))
        stem = sanitize(os.path.splitext(os.path.basename(path))[0])
        cases.append((stem, path, test_id, case))
    stems = [c[0] for c in cases]
    assert len(set(stems)) == len(stems), "duplicate file stems"
    return cases


def zig_value_literal(type_name, value):
    """Return (zig_type, zig_value_expr, needs_hex_decode)."""
    if type_name == "Boolean":
        return "bool", "true" if value else "false", None
    if type_name in SUPPORTED_UINTS:
        t = SUPPORTED_UINTS[type_name]
        return t, f"@as({t}, {value})", None
    if type_name in SUPPORTED_BYTES:
        n = SUPPORTED_BYTES[type_name]
        assert value.startswith("0x") and len(value) == 2 + 2 * n, value
        return f"[{n}]u8", value[2:], n
    if type_name == "SampleUint16Vector3":
        elems = ", ".join(str(int(x)) for x in value["data"])
        assert len(value["data"]) == 3
        return "[3]u16", f"[_]u16{{ {elems} }}", None
    if type_name == "SampleUint64Vector4":
        elems = ", ".join(str(int(x)) for x in value["data"])
        assert len(value["data"]) == 4
        return "[4]u64", f"[_]u64{{ {elems} }}", None
    return None, None, None


def render_supported(stem, test_id, case, zig_type, value_expr, hex_n):
    serialized = case["serialized"]
    root = case["root"]
    assert serialized.startswith("0x") and root.startswith("0x")
    assert len(root) == 66, root
    ser_hex, root_hex = serialized[2:], root[2:]

    if hex_n is not None:
        value_block = (
            f"    var value: {zig_type} = undefined;\n"
            f'    _ = try std.fmt.hexToBytes(&value, "{value_expr}");'
        )
    else:
        value_block = f"    const value: {zig_type} = {value_expr};"

    return f"""const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const merkle = @import("merkle");

// {test_id}
// typeName: {case["typeName"]}

test "vectors.{stem}" {{
    const allocator = testing.allocator;
{value_block}

    const expected_serialized_hex = "{ser_hex}";
    var expected_serialized: [expected_serialized_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_serialized, expected_serialized_hex);

    const expected_root_hex = "{root_hex}";
    var expected_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_root, expected_root_hex);

    var out: [expected_serialized.len]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out);
    try ssz.serialize(&writer, value);
    try testing.expectEqualSlices(u8, &expected_serialized, writer.buffered());

    const root = try merkle.HashTreeRoot(allocator, value);
    try testing.expectEqualSlices(u8, &expected_root, &root);

    var reader: std.Io.Reader = .fixed(&expected_serialized);
    const decoded = try ssz.deserialize({zig_type}, &reader);
    try testing.expectEqual(value, decoded);
}}
"""


def render_stub(stem, test_id, case):
    serialized = case["serialized"]
    root = case.get("root", "")
    value_json = json.dumps(case["value"])
    if len(value_json) > 400:
        value_json = value_json[:400] + "… (truncated)"
    return f"""// {test_id}
// typeName: {case["typeName"]}
// value: {value_json}
// serialized: {serialized}
// root: {root}
// TODO: {case["typeName"]} is not implemented in src/ssz/ssz.zig yet.

test "vectors.{stem}" {{
    return error.VectorNotImplemented;
}}
"""


def main():
    cases = load_fixtures()
    os.makedirs(OUT_DIR, exist_ok=True)
    supported = unsupported = 0
    for stem, path, test_id, case in cases:
        type_name = case.get("typeName", "")
        zig_type, value_expr, hex_n = zig_value_literal(type_name, case.get("value"))
        if zig_type is None:
            content = render_stub(stem, test_id, case)
            unsupported += 1
        else:
            content = render_supported(stem, test_id, case, zig_type, value_expr, hex_n)
            supported += 1
        with open(os.path.join(OUT_DIR, stem + ".zig"), "w") as f:
            f.write(content)
    with open(os.path.join(OUT_DIR, "tests.zig"), "w") as f:
        f.write("test {\n")
        for stem, _, _, _ in cases:
            f.write(f'    _ = @import("{stem}.zig");\n')
        f.write("}\n")
    print(f"wrote {supported + unsupported} vector tests "
          f"({supported} implemented, {unsupported} stubs) to {OUT_DIR}/")


if __name__ == "__main__":
    main()
