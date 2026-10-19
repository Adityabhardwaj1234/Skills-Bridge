# Assurance Closure & Digest-Bound Evidence (`docs/assurance-evidence.md`)

## 1. Deterministic Assurance Closure Graph

Adapted under Apache-2.0 from SKIL (`internal/assurance/closure.go`) in `src/skillbridge/verification/tier2_skil.py`, an `AssuranceClosure` represents the complete graph of every artifact and dependency required to trust a skill bundle:

- **Nodes (`ClosureNode`)**:
  - `root:<skill_id>` (`kind="root"`, `digest=bundle_digest`)
  - `file:<relative_path>` (`kind="artifact"` or `"nested_artifact"`, `digest=file_sha256`)
  - `dep:<ecosystem>:<package>` (`kind="dependency"`, `digest=version_spec_sha256`)
- **Edges (`ClosureEdge`)**:
  - `contains` (`root` -> `file`)
  - `depends-on` (`root` -> `dep`)

## 2. Canonical Identity Invariants

Verified by `TestVerificationTiers.test_tier2_skil_assurance_closure_determinism_and_capability_mismatch`:
1. **Traversal-Order Independence**: Nodes and edges are sorted and deduplicated canonically before SHA-256 hashing; reversing node or edge insertion order produces the exact same `closure_digest`.
2. **Child Mutation Sensitivity**: Modifying the digest of any required file or dependency node changes `closure_digest`.
3. **Aggregate Metadata Stability**: Derived summary counters (`required_nodes`, `unresolved_nodes`, `blocking_findings`, `max_depth`) are computed after canonical identity hashing and do not destabilize `closure_digest`.

## 3. Reviewed-vs-Current Verification (`verify_closure_against_reviewed`)

Before invoking a previously reviewed skill or executing a bundled script, `verify_closure_against_reviewed(current_closure, expected_closure_digest)` verifies both:
1. `current_closure.closure_digest == expected_closure_digest`
2. `current_closure.state == AssuranceState.SAFE`
Any drift immediately halts execution and requires fresh multi-tier verification.
