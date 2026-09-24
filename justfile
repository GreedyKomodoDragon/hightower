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
