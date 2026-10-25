# Execution RPC compatibility test

From the repository root, build and start the local fixture server:

```sh
zig build build-rpc-test-server
./zig-out/bin/hightower-rpc-test 18545
```

In another terminal, run the pinned independent client test:

```sh
cd tests/execution-rpc
npm ci --ignore-scripts
npm test
```

The server binds only `127.0.0.1`. It starts with one validated block containing a transaction, receipt, and log; subsequent raw transactions enter the in-memory pool without being mined.
