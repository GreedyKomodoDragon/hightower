# Local runtime

The executable currently serves the bundled fork-choice anchor through the
read-only Beacon API and Prometheus metrics endpoint. It does not import peer
blocks or attestations yet.

Create `hightower.json`:

```json
{
  "listen_address": "127.0.0.1:5052"
}
```

Start the service with:

```sh
zig build run -- --config hightower.json
```

The Beacon API is available under `/eth/v1`, and metrics are exposed at
`http://127.0.0.1:5052/metrics`. Stop the process with Ctrl-C.
