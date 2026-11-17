# Mainnet Fulu attestation vectors

These files are from `ethereum/consensus-specs` v1.6.1, commit `5fa6edcca8ab4cf548653e6680b17b9d3e04d225`, in the [mainnet test bundle](https://github.com/ethereum/consensus-specs/releases/download/v1.6.1/mainnet.tar.gz). The bundle SHA-256 is `8401c58700c461154db2050c2a982af7aca259bd016c2184ec39c454edf6f1c5`.

Upstream paths start with `tests/mainnet/fulu/operations/attestation/pyspec_tests/` and continue with each local case name. The files remain separate from minimal preset vectors because the SSZ state dimensions differ.

The test also checks a one-slot-later inclusion by advancing both the pinned pre-state and reference post-state to slot 33 and keeping the pinned proposer at that slot. This stays within the same epoch; the source, target, committee, and proposer reward are unchanged. The comparison therefore uses the upstream post-state with only those two controlled state fields changed.

| Case | `pre.ssz_snappy` SHA-256 | `attestation.ssz_snappy` SHA-256 | `post.ssz_snappy` SHA-256 |
| --- | --- | --- | --- |
| `correct_attestation_included_at_one_epoch_delay` | `db1f198211216d332f9807e1f06b94ed2b9c694adc17fdf9436abb7f60cea6a2` | `e428abe3c2be3e2d879e64fb89521ec78ea7b0df5afe4ddc52ced9965eab60dc` | `023a0183ab2f1b059093a34778f4c590f537ac5fdfc43228d22107b9a9ca9138` |
