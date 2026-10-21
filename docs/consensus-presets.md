# FULU-035 consensus presets

Select the consensus constants and Fulu state dimensions at build time:

```sh
zig build                         # defaults to the minimal preset
zig build -Dpreset=minimal
zig build -Dpreset=mainnet
```

The selected preset is shared by the public `fulu.BeaconState` schema and consensus processing. Minimal remains the default because the checked-in consensus fixtures use its dimensions. The mainnet profile uses mainnet slot, epoch, history-vector, committee, fork-version, withdrawal, and blob-schedule values. A mainnet build verifies that those types and rules compile together; it does not claim that the existing minimal fixture suite validates mainnet transitions.

Do not mix a state decoded for one preset with code built for another. SSZ vector lengths and list limits are part of the schema selected by the build.
