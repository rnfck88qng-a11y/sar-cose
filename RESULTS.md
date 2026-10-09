# Results (raw output)

Run: 2026-10-09T20:59:27Z · Apple M5 Pro · Darwin 27.0.0 · Python 3.14.5 · cbor2 5.9.0 · cryptography 50.0.2 · pycose 1.1.0 · hypothesis 6.168.5

sar_cose.py sha256: `6f99116cc81f520157548176f855bf32a8129c875aa5c395ae3ca1a3c6bec459`

## ./run_tests.sh
```
test_01_authorized_execution_allowed (test_sar_conformance.SarTests.test_01_authorized_execution_allowed) ... ok
test_02_missing_authorization_denied (test_sar_conformance.SarTests.test_02_missing_authorization_denied) ... ok
test_03_invalid_signature_denied (test_sar_conformance.SarTests.test_03_invalid_signature_denied) ... ok
test_04_rejected_proposal_denied (test_sar_conformance.SarTests.test_04_rejected_proposal_denied) ... ok
test_05_modified_payload_after_approval_denied (test_sar_conformance.SarTests.test_05_modified_payload_after_approval_denied) ... ok
test_06_replayed_authorization_denied (test_sar_conformance.SarTests.test_06_replayed_authorization_denied) ... ok
test_07a_expired_proposal_denied_even_if_ratification_valid (test_sar_conformance.SarTests.test_07a_expired_proposal_denied_even_if_ratification_valid) ... ok
test_07b_expired_ratification_denied_even_if_proposal_valid (test_sar_conformance.SarTests.test_07b_expired_ratification_denied_even_if_proposal_valid) ... ok
test_08_invalid_policy_configuration_denied (test_sar_conformance.SarTests.test_08_invalid_policy_configuration_denied) ... ok
test_09_offline_verification_needs_only_artifacts (test_sar_conformance.SarTests.test_09_offline_verification_needs_only_artifacts) ... ok
test_10_history_is_tamper_evident (test_sar_conformance.SarTests.test_10_history_is_tamper_evident) ... ok
test_11_quorum_requires_distinct_approvals (test_sar_conformance.SarTests.test_11_quorum_requires_distinct_approvals) ... ok
test_c07c_future_dated_ratification_denied (test_sar_gaps.SarGapTests.test_c07c_future_dated_ratification_denied) ... ok
test_c07c_ratification_before_proposal_denied (test_sar_gaps.SarGapTests.test_c07c_ratification_before_proposal_denied) ... ok
test_c07d_expired_ratification_reviewed_after_proposal_denied (test_sar_gaps.SarGapTests.test_c07d_expired_ratification_reviewed_after_proposal_denied) ... ok
test_c09b_offline_rejects_record_below_quorum (test_sar_gaps.SarGapTests.test_c09b_offline_rejects_record_below_quorum) ... ok
test_c09b_offline_rejects_record_with_only_rejection (test_sar_gaps.SarGapTests.test_c09b_offline_rejects_record_with_only_rejection) ... ok
test_c09b_offline_rejects_record_without_ratification (test_sar_gaps.SarGapTests.test_c09b_offline_rejects_record_without_ratification) ... ok
test_c10b_tail_truncation_detected (test_sar_gaps.SarGapTests.test_c10b_tail_truncation_detected) ... ok
test_c11b_duplicate_overseer_does_not_meet_quorum (test_sar_gaps.SarGapTests.test_c11b_duplicate_overseer_does_not_meet_quorum) ... ok
test_c12_policy_id_mismatch_denied (test_sar_gaps.SarGapTests.test_c12_policy_id_mismatch_denied) ... ok
test_c12_policy_id_mismatch_denied_offline (test_sar_gaps.SarGapTests.test_c12_policy_id_mismatch_denied_offline) ... ok
test_c13_ratification_cannot_be_moved_to_another_proposal (test_sar_gaps.SarGapTests.test_c13_ratification_cannot_be_moved_to_another_proposal) ... ok
test_content_type_confusion_rejected (test_sar_cose_specific.CoseStructureTests.test_content_type_confusion_rejected) ... ok
test_deprecated_polymorphic_alg_rejected (test_sar_cose_specific.CoseStructureTests.test_deprecated_polymorphic_alg_rejected) ... ok
test_kid_must_match_signer_identity (test_sar_cose_specific.CoseStructureTests.test_kid_must_match_signer_identity) ... ok
test_non_deterministic_payloads_rejected (test_sar_cose_specific.CoseStructureTests.test_non_deterministic_payloads_rejected) ... ok
test_non_deterministic_protected_header_rejected (test_sar_cose_specific.CoseStructureTests.test_non_deterministic_protected_header_rejected) ... ok
test_payload_digest_is_sha256_of_deterministic_cbor (test_sar_cose_specific.CoseStructureTests.test_payload_digest_is_sha256_of_deterministic_cbor) ... ok
test_protected_header_tampering_rejected (test_sar_cose_specific.CoseStructureTests.test_protected_header_tampering_rejected) ... ok
test_roundtrip_through_bytes_is_accepted_by_gate (test_sar_cose_specific.CoseStructureTests.test_roundtrip_through_bytes_is_accepted_by_gate) ... ok
test_statements_are_tagged_cose_sign1_with_ed25519_alg_minus19 (test_sar_cose_specific.CoseStructureTests.test_statements_are_tagged_cose_sign1_with_ed25519_alg_minus19) ... ok
test_unprotected_header_parameters_rejected (test_sar_cose_specific.CoseStructureTests.test_unprotected_header_parameters_rejected) ... ok
test_independent_verifier_cbor2_plus_cryptography (test_sar_cose_specific.CrossImplementationTests.test_independent_verifier_cbor2_plus_cryptography) ... ok
test_pycose_verifies_sar_cose_output (test_sar_cose_specific.CrossImplementationTests.test_pycose_verifies_sar_cose_output) ... ok
test_sar_cose_verifies_pycose_output (test_sar_cose_specific.CrossImplementationTests.test_sar_cose_verifies_pycose_output) ... ok
test_appendix_a_vectors (test_sar_cose_specific.DeterministicCBORVectors.test_appendix_a_vectors) ... ok
test_core_deterministic_key_order (test_sar_cose_specific.DeterministicCBORVectors.test_core_deterministic_key_order) ... ok
test_floats_rejected (test_sar_cose_specific.DeterministicCBORVectors.test_floats_rejected) ... ok
test_every_single_bit_flip_in_signed_statements_is_rejected (test_sar_properties.BitFlipTests.test_every_single_bit_flip_in_signed_statements_is_rejected) ... ok
test_clock_skew_boundary (test_sar_properties.BoundaryTests.test_clock_skew_boundary) ... ok
test_proposal_expiry_boundary (test_sar_properties.BoundaryTests.test_proposal_expiry_boundary) ... ok
test_ratification_expiry_boundary (test_sar_properties.BoundaryTests.test_ratification_expiry_boundary) ... ok
test_review_not_before_proposal_boundary (test_sar_properties.BoundaryTests.test_review_not_before_proposal_boundary) ... ok
test_any_change_to_payload_after_approval_is_denied (test_sar_properties.CborPropertyTests.test_any_change_to_payload_after_approval_is_denied) ... ok
test_gate_never_raises_and_never_allows_junk_statements (test_sar_properties.CborPropertyTests.test_gate_never_raises_and_never_allows_junk_statements) ... ok
test_map_insertion_order_does_not_matter (test_sar_properties.CborPropertyTests.test_map_insertion_order_does_not_matter) ... ok
test_parser_fails_safely_on_garbage (test_sar_properties.CborPropertyTests.test_parser_fails_safely_on_garbage) ... ok
test_roundtrip_and_canonical_form (test_sar_properties.CborPropertyTests.test_roundtrip_and_canonical_form) ... ok
test_unicode_normalisation_is_not_applied (test_sar_properties.CborPropertyTests.test_unicode_normalisation_is_not_applied) ... ok
test_gate_matches_spec_model_hypothesis (test_sar_properties.DifferentialTests.test_gate_matches_spec_model_hypothesis) ... ok
test_gate_matches_spec_model_on_3000_random_scenarios (test_sar_properties.DifferentialTests.test_gate_matches_spec_model_on_3000_random_scenarios) ... ok
test_gate_matches_spec_model_single_fault_injection (test_sar_properties.DifferentialTests.test_gate_matches_spec_model_single_fault_injection) ... ok
test_concurrent_presentations_allow_exactly_once (test_sar_properties.StoreConcurrencyTests.test_concurrent_presentations_allow_exactly_once) ... ok
test_replay_protection_survives_restart (test_sar_properties.StoreConcurrencyTests.test_replay_protection_survives_restart) ... ok

----------------------------------------------------------------------
Ran 55 tests in 5.249s

OK

    differential: 182 allowed, 2818 denied, 0 disagreements with the model 
    single-fault: none=557/557 allowed, agent=0/76 allowed, duplicate_overseer=40/94 allowed, expired=0/77 allowed, future_proposal=0/106 allowed, no_rats=0/101 allowed, payload=0/103 allowed, policy=0/91 allowed, psig=0/84 allowed, rat_before_proposal=0/102 allowed, rat_expired=0/77 allowed, rat_future=0/79 allowed, rat_rejected=0/80 allowed, rat_sig=0/85 allowed, rat_unauthorized=0/111 allowed, rat_unbound=0/88 allowed, rat_unknown_verdict=0/89 allowed ```

## ./run_mutants.sh
```
PASS baseline
PASS mutant skip_digest killed (5 failing tests)
PASS mutant skip_replay killed (7 failing tests)
PASS mutant skip_expiry killed (4 failing tests)
PASS mutant skip_rat_expiry killed (3 failing tests)
PASS mutant skip_sig killed (5 failing tests)
PASS mutant allow_rejected killed (8 failing tests)
PASS mutant chain_noop killed (2 failing tests)
PASS mutant dedup_overseer killed (3 failing tests)
PASS mutant skip_policy_bind killed (3 failing tests)
PASS mutant skip_future_check killed (7 failing tests)
PASS mutant offline_skip_quorum killed (2 failing tests)
PASS mutant skip_head_check killed (1 failing tests)
PASS mutant skip_alg_check killed (2 failing tests)
PASS mutant skip_ctype_check killed (1 failing tests)
PASS mutant skip_kid_check killed (1 failing tests)
PASS mutant accept_nondeterministic killed (5 failing tests)
PASS mutant skip_binding killed (3 failing tests)
PASS mutant offline_skip_binding killed (1 failing tests)
PASS mutant deferred_tx killed (1 failing tests)
mutants killed: 19/19
exit=0
```

## Concurrency stability (20 runs on fixed code, 10 runs on deferred_tx mutant)
```
fixed code: 20/20 passed
deferred_tx mutant: killed 10/10
```

## ./run_stub_against_gaps.sh (illustrative harness stub; failures expected)
```
test_c07c_future_dated_ratification_denied (test_sar_gaps.SarGapTests.test_c07c_future_dated_ratification_denied) ... FAIL
test_c07c_ratification_before_proposal_denied (test_sar_gaps.SarGapTests.test_c07c_ratification_before_proposal_denied) ... FAIL
test_c07d_expired_ratification_reviewed_after_proposal_denied (test_sar_gaps.SarGapTests.test_c07d_expired_ratification_reviewed_after_proposal_denied) ... ok
test_c09b_offline_rejects_record_below_quorum (test_sar_gaps.SarGapTests.test_c09b_offline_rejects_record_below_quorum) ... FAIL
test_c09b_offline_rejects_record_with_only_rejection (test_sar_gaps.SarGapTests.test_c09b_offline_rejects_record_with_only_rejection) ... FAIL
test_c09b_offline_rejects_record_without_ratification (test_sar_gaps.SarGapTests.test_c09b_offline_rejects_record_without_ratification) ... FAIL
test_c10b_tail_truncation_detected (test_sar_gaps.SarGapTests.test_c10b_tail_truncation_detected) ... FAIL
test_c11b_duplicate_overseer_does_not_meet_quorum (test_sar_gaps.SarGapTests.test_c11b_duplicate_overseer_does_not_meet_quorum) ... FAIL
test_c12_policy_id_mismatch_denied (test_sar_gaps.SarGapTests.test_c12_policy_id_mismatch_denied) ... FAIL
test_c12_policy_id_mismatch_denied_offline (test_sar_gaps.SarGapTests.test_c12_policy_id_mismatch_denied_offline) ... FAIL
test_c13_ratification_cannot_be_moved_to_another_proposal (test_sar_gaps.SarGapTests.test_c13_ratification_cannot_be_moved_to_another_proposal) ... ok
Ran 11 tests in 0.007s
FAILED (failures=9)
```

## bench.py 2000 (indicative only)
```
sar_cose micro-benchmark, N=2000, arm64 Darwin 27.0.0, Python 3.14.5
operation                                 median us     p99 us
make_proposal (sign)                           39.7       95.3
ratify (sign)                                  39.9      119.6
verify_record_offline                         142.0      360.5
Gate.authorize, in-memory store               195.2      531.6
Gate.authorize, file-backed store            1252.7    17418.6
Store.verify_chain (N records)               1759.8     1785.8
```
