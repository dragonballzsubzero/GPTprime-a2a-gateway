# SAC-SCIENCE-EVIDENCE-1 — provenance-only research gate

The v0.34 scientific evidence module validates metadata completeness before any claim can enter an independent review queue. It **never** returns `scientifically_validated: true`: neither metadata nor cryptographic transport proves biology.

Call `inspectEvidence(record)` from `src/evidence.mjs`. It returns `state`, `problems`, `warnings`, and `scientifically_validated`.

## Required common fields
`version`, `domain`, `claim_id`, `claim`, `raw_data_sha256`, `raw_size_bytes`, `protocol_id`, `acquired_utc`, `instrument_id`, `calibration_sha256`, `custodian_id`, `controls[]`, `synthetic: false`, and an `analysis` object with `preregistered`, `n`, `primary_endpoint`, `effect_estimate`, `confidence_interval` and `p_value`.

## Mitochondrial domain
Stages must independently contain assay IDs, raw-file digests, and control IDs: `translation`, `mitochondrial_import`, `membrane_insertion`, `complex_assembly`, `functional_readout`. Require flags documenting nuclear-codon recoding and experimentally tested protein import topology. These flags are *metadata assertions*, not independent validation.

## Endovascular BCI domain
Requires electrode geometry ID, artifact controls, binary `heldout_sessions` and `heldout_participants` indicators, decoding and baseline accuracies. This is a conservative research gate to prevent training leakage being presented as generalization; small first-in-human feasibility studies may be important even if they cannot pass this gate.

## Invariants
1. Missing raw data digest or calibration metadata blocks promotion.
2. A synthetic-data record cannot be promoted as experimental evidence.
3. Invalid statistics are rejected, rather than clipped to plausible values.
4. Regardless of completeness, the output is never `validated` without separate independent raw-data verification and scientific review.
5. No signatures, TEE attestations, or consensus confirmations are fabricated by this module.

This release uses synthetic test fixtures to verify validator logic; no new biological samples, electrophysiological recordings, interventions, or experiments were acquired.