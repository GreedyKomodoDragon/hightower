// tests/fillers/ssz/test_compatible_unions.py::test_compatible_union_decode_failure_undeclared_selector[ssz_test]
// typeName: SampleShape
// value: {"selector": 1, "data": {"side": 4660, "color": 66}}
// serialized: 0x03341242
// root:
// TODO: SampleShape is not implemented in src/ssz/ssz.zig yet.

test "vectors.test_compatible_union_decode_failure_undeclared_selector" {
    return error.VectorNotImplemented;
}
