# FULU-106 sync aggregate lookup

`zig build bench -Doptimize=ReleaseFast` now includes `sync_aggregate.1m_validators`. It extends the pinned valid sync aggregate state to one million validators, then processes the aggregate three times. The added validators have distinct pubkeys and active balances. This measures the complete sync aggregate path, including the active balance scan and reward updates.

On the same machine, the baseline code took 41,628.500 µs/op and the committee-key index took 9,747.667 µs/op. These are short local runs, not a fixed performance threshold.

The lookup is rebuilt for each call from the current committee and registry, so deposits and registry changes cannot leave a stale index. Duplicate validator pubkeys still resolve to their first registry position.
