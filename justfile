# Hightower tasks (requires: just, zig 0.16.0, curl, tar)
TAG := "v0.1.0"
VECTORS_DIR := "testdata/ssz-test-vectors"

# list all recipes
default:
    @just --list

# show zig version
version:
    zig version

# build the binary (zig-out/bin/hightower)
build:
    zig build

# run the app (pass args: just run -- foo bar)
run *ARGS:
    zig build run -- {{ARGS}}

# run all wired-in tests (rlp + ssz + lib + exe)
test:
    zig build test

# run tests with the Zig test fuzzer
fuzz:
    zig build test -- --fuzz

# run official SSZ test vectors (expects failures for unimplemented types)
test-vectors:
    zig build test-vectors --summary all

# run one vector test by name substring, e.g. just test-vector bitlist_at_limit
test-vector NAME:
    #!/usr/bin/env bash
    out=$(zig build test-vectors 2>&1 || true)
    echo "$out" | grep -E "{{NAME}}" | head -n 10
    if echo "$out" | grep -qE "error: '[^']*{{NAME}}[^']*' failed"; then \
        echo "RESULT: vectors.{{NAME}} FAILED"; \
    else \
        echo "RESULT: vectors.{{NAME}} PASSED (no failure reported)"; \
    fi

# regenerate src/ssz/vectors/*.zig from downloaded fixtures
gen-vectors:
    python3 scripts/gen_ssz_vectors.py
    zig fmt src/ssz/vectors/ >/dev/null

# format source
fmt:
    zig fmt build.zig build.zig.zon src

# check formatting (CI)
fmt-check:
    zig fmt --check build.zig build.zig.zon src

# remove build artifacts
clean:
    rm -rf zig-out .zig-cache

# CI parity: fmt-check + build + test
ci: fmt-check build test

# download + verify + extract official SSZ test vectors into {{VECTORS_DIR}}
ssz-vectors:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p "{{VECTORS_DIR}}"
    cd "{{VECTORS_DIR}}"
    curl -sSLO "https://github.com/ethereum/ssz-specs/releases/download/{{TAG}}/ssz-test-vectors-{{TAG}}.tar.gz"
    curl -sSLO "https://github.com/ethereum/ssz-specs/releases/download/{{TAG}}/ssz-test-vectors-{{TAG}}.tar.gz.sha256"
    if command -v sha256sum >/dev/null 2>&1; then \
        sha256sum --check "ssz-test-vectors-{{TAG}}.tar.gz.sha256"; \
    else \
        shasum -a 256 --check "ssz-test-vectors-{{TAG}}.tar.gz.sha256"; \
    fi
    tar -xzf "ssz-test-vectors-{{TAG}}.tar.gz"
    echo "extracted to {{VECTORS_DIR}}/"

# remove downloaded SSZ test vectors + archives
clean-vectors:
    rm -rf "{{VECTORS_DIR}}"
