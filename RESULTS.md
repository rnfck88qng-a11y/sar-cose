# Results (raw output)

Run: 2026-10-10T06:31:57Z · Apple M5 Pro · Darwin 27.0.0 · Python 3.14.5 · cbor2 5.9.0 · cryptography 50.0.2 · pycose 1.1.0 · hypothesis 6.168.5

sar_cose.py sha256: `bb857babb530ee6a7dcd8b4745d1eda2f620fe928629144fdb12657c061bd5a5` · independent/sar_indep.py sha256: `1d31fd4f72c04e495acf2cece3af9e6be56bebe668adbf24590fd79f93e0e5bf`

## ./run_tests.sh
```
== sar_cose: original harness, gap, COSE, property, hardening and cross-implementation suites
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
test_review_before_proposal_expiry_boundary (test_sar_properties.BoundaryTests.test_review_before_proposal_expiry_boundary) ... ok
test_review_not_before_proposal_boundary (test_sar_properties.BoundaryTests.test_review_not_before_proposal_boundary) ... ok
test_any_change_to_payload_after_approval_is_denied (test_sar_properties.CborPropertyTests.test_any_change_to_payload_after_approval_is_denied) ... ok
test_gate_never_raises_and_never_allows_junk_statements (test_sar_properties.CborPropertyTests.test_gate_never_raises_and_never_allows_junk_statements) ... ok
test_map_insertion_order_does_not_matter (test_sar_properties.CborPropertyTests.test_map_insertion_order_does_not_matter) ... ok
test_parser_fails_safely_on_garbage (test_sar_properties.CborPropertyTests.test_parser_fails_safely_on_garbage) ... ok
test_roundtrip_and_canonical_form (test_sar_properties.CborPropertyTests.test_roundtrip_and_canonical_form) ... ok
test_unicode_normalisation_is_not_applied (test_sar_properties.CborPropertyTests.test_unicode_normalisation_is_not_applied) ... ok
test_gate_matches_spec_model_hypothesis (test_sar_properties.DifferentialTests.test_gate_matches_spec_model_hypothesis) ... ok
test_gate_matches_spec_model_randomized (test_sar_properties.DifferentialTests.test_gate_matches_spec_model_randomized) ... ok
test_gate_matches_spec_model_single_fault_injection (test_sar_properties.DifferentialTests.test_gate_matches_spec_model_single_fault_injection) ... ok
test_concurrent_presentations_allow_exactly_once (test_sar_properties.StoreConcurrencyTests.test_concurrent_presentations_allow_exactly_once) ... ok
test_concurrent_processes_allow_exactly_once (test_sar_properties.StoreConcurrencyTests.test_concurrent_processes_allow_exactly_once)
Separate OS processes (not threads), each with its own gate, on one database file. ... ~/Documents/Obsidian Vault/02-Projects/AlterA-uWorld/SARWP/sar-cose/test_sar_properties.py:414: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/9m/0sngg4857_dgsmdq2dr2ykn80000gn/T/tmpklu0qhrw/job0.json' mode='w' encoding='utf-8'>
  json.dump({"p": S.to_cose(prop).hex(), "r": [S.to_cose(x).hex() for x in rats], "db": path,
ResourceWarning: Enable tracemalloc to get the object allocation traceback
~/Documents/Obsidian Vault/02-Projects/AlterA-uWorld/SARWP/sar-cose/test_sar_properties.py:414: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/9m/0sngg4857_dgsmdq2dr2ykn80000gn/T/tmpklu0qhrw/job1.json' mode='w' encoding='utf-8'>
  json.dump({"p": S.to_cose(prop).hex(), "r": [S.to_cose(x).hex() for x in rats], "db": path,
ResourceWarning: Enable tracemalloc to get the object allocation traceback
~/Documents/Obsidian Vault/02-Projects/AlterA-uWorld/SARWP/sar-cose/test_sar_properties.py:414: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/9m/0sngg4857_dgsmdq2dr2ykn80000gn/T/tmpklu0qhrw/job2.json' mode='w' encoding='utf-8'>
  json.dump({"p": S.to_cose(prop).hex(), "r": [S.to_cose(x).hex() for x in rats], "db": path,
ResourceWarning: Enable tracemalloc to get the object allocation traceback
~/Documents/Obsidian Vault/02-Projects/AlterA-uWorld/SARWP/sar-cose/test_sar_properties.py:414: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/9m/0sngg4857_dgsmdq2dr2ykn80000gn/T/tmpklu0qhrw/job3.json' mode='w' encoding='utf-8'>
  json.dump({"p": S.to_cose(prop).hex(), "r": [S.to_cose(x).hex() for x in rats], "db": path,
ResourceWarning: Enable tracemalloc to get the object allocation traceback
~/Documents/Obsidian Vault/02-Projects/AlterA-uWorld/SARWP/sar-cose/test_sar_properties.py:414: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/9m/0sngg4857_dgsmdq2dr2ykn80000gn/T/tmpklu0qhrw/job4.json' mode='w' encoding='utf-8'>
  json.dump({"p": S.to_cose(prop).hex(), "r": [S.to_cose(x).hex() for x in rats], "db": path,
ResourceWarning: Enable tracemalloc to get the object allocation traceback
ok
test_replay_protection_survives_restart (test_sar_properties.StoreConcurrencyTests.test_replay_protection_survives_restart) ... ok
test_cose_array_must_have_four_elements (test_sar_hardening.EncodingEdges.test_cose_array_must_have_four_elements) ... ok
test_cose_fields_must_be_byte_strings (test_sar_hardening.EncodingEdges.test_cose_fields_must_be_byte_strings) ... ok
test_cose_payload_must_be_a_map (test_sar_hardening.EncodingEdges.test_cose_payload_must_be_a_map) ... ok
test_cose_wrong_tag_or_untagged_rejected (test_sar_hardening.EncodingEdges.test_cose_wrong_tag_or_untagged_rejected) ... ok
test_integers_outside_cbor_major_types_rejected (test_sar_hardening.EncodingEdges.test_integers_outside_cbor_major_types_rejected) ... ok
test_protected_header_with_extra_parameter_rejected (test_sar_hardening.EncodingEdges.test_protected_header_with_extra_parameter_rejected) ... ok
test_unencodable_runtime_payload_is_denied_not_raised (test_sar_hardening.EncodingEdges.test_unencodable_runtime_payload_is_denied_not_raised) ... ok
test_forged_or_mismatched_checkpoint_rejected (test_sar_hardening.ExternalCheckpoint.test_forged_or_mismatched_checkpoint_rejected) ... ok
test_rewrite_detected_against_retained_checkpoint (test_sar_hardening.ExternalCheckpoint.test_rewrite_detected_against_retained_checkpoint) ... ok
test_truncation_detected_after_reopen_with_retained_checkpoint (test_sar_hardening.ExternalCheckpoint.test_truncation_detected_after_reopen_with_retained_checkpoint) ... ok
test_agent_key_substitution_denied (test_sar_hardening.GateEdges.test_agent_key_substitution_denied) ... ok
test_denials_are_recorded_in_the_log (test_sar_hardening.GateEdges.test_denials_are_recorded_in_the_log) ... ok
test_expired_approval_denies_even_if_quorum_met_otherwise (test_sar_hardening.GateEdges.test_expired_approval_denies_even_if_quorum_met_otherwise) ... ok
test_ratification_after_proposal_expiry_denied (test_sar_hardening.GateEdges.test_ratification_after_proposal_expiry_denied) ... ok
test_ratification_bound_to_other_policy_denied_even_if_proposal_matches (test_sar_hardening.GateEdges.test_ratification_bound_to_other_policy_denied_even_if_proposal_matches) ... ok
test_ratification_window_is_half_open (test_sar_hardening.GateEdges.test_ratification_window_is_half_open) ... ok
test_unauthorized_agent_denied (test_sar_hardening.GateEdges.test_unauthorized_agent_denied) ... ok
test_binding_requires_both_digest_and_proposal_id (test_sar_hardening.MutationSweepGaps.test_binding_requires_both_digest_and_proposal_id) ... ok
test_epoch_zero_timestamp_is_valid (test_sar_hardening.MutationSweepGaps.test_epoch_zero_timestamp_is_valid) ... ok
test_identifier_and_nonce_length_limits_are_inclusive (test_sar_hardening.MutationSweepGaps.test_identifier_and_nonce_length_limits_are_inclusive) ... ok
test_missing_inputs_are_denied_for_the_right_reason (test_sar_hardening.MutationSweepGaps.test_missing_inputs_are_denied_for_the_right_reason) ... ok
test_non_integer_clock_is_rejected_as_such (test_sar_hardening.MutationSweepGaps.test_non_integer_clock_is_rejected_as_such) ... ok
test_offline_at_is_inclusive_at_start (test_sar_hardening.MutationSweepGaps.test_offline_at_is_inclusive_at_start) ... ok
test_offline_rejects_bad_proposal_signature (test_sar_hardening.MutationSweepGaps.test_offline_rejects_bad_proposal_signature) ... ok
test_offline_rejects_ratified_proposal_with_bad_agent_signature (test_sar_hardening.MutationSweepGaps.test_offline_rejects_ratified_proposal_with_bad_agent_signature) ... ok
test_proposal_policy_checked_even_if_ratification_names_the_gate_policy (test_sar_hardening.MutationSweepGaps.test_proposal_policy_checked_even_if_ratification_names_the_gate_policy) ... ok
test_quorum_zero_with_valid_overseers_is_invalid (test_sar_hardening.MutationSweepGaps.test_quorum_zero_with_valid_overseers_is_invalid) ... ok
test_single_character_identities_are_valid (test_sar_hardening.MutationSweepGaps.test_single_character_identities_are_valid) ... ok
test_touching_but_disjoint_validity_intervals_denied (test_sar_hardening.MutationSweepGaps.test_touching_but_disjoint_validity_intervals_denied) ... ok
test_bad_ratification_signature (test_sar_hardening.OfflineEdges.test_bad_ratification_signature) ... ok
test_malformed_inputs (test_sar_hardening.OfflineEdges.test_malformed_inputs) ... ok
test_ratification_policy_mismatch (test_sar_hardening.OfflineEdges.test_ratification_policy_mismatch) ... ok
test_review_outside_validity_window (test_sar_hardening.OfflineEdges.test_review_outside_validity_window) ... ok
test_unauthorized_overseer (test_sar_hardening.OfflineEdges.test_unauthorized_overseer) ... ok
test_valid_record_verifies_without_store_or_clock (test_sar_hardening.OfflineEdges.test_valid_record_verifies_without_store_or_clock) ... ok
test_malformed_policies_deny (test_sar_hardening.PolicyValidation.test_malformed_policies_deny) ... ok
test_quorum_equal_to_overseer_count_is_valid (test_sar_hardening.PolicyValidation.test_quorum_equal_to_overseer_count_is_valid) ... ok
test_invalid_clock_values_deny (test_sar_hardening.SemanticsRules.test_invalid_clock_values_deny) ... ok
test_s10_denial_consumes_nothing (test_sar_hardening.SemanticsRules.test_s10_denial_consumes_nothing) ... ok
test_s10_nonce_reuse_by_a_new_proposal_denied (test_sar_hardening.SemanticsRules.test_s10_nonce_reuse_by_a_new_proposal_denied) ... ok
test_s10_transaction_id_reuse_denied (test_sar_hardening.SemanticsRules.test_s10_transaction_id_reuse_denied) ... ok
test_s11_offline_rejects_duplicate_overseer (test_sar_hardening.SemanticsRules.test_s11_offline_rejects_duplicate_overseer) ... ok
test_s11_offline_requires_common_validity_interval (test_sar_hardening.SemanticsRules.test_s11_offline_requires_common_validity_interval) ... ok
test_s12_unloggable_decision_never_allows (test_sar_hardening.SemanticsRules.test_s12_unloggable_decision_never_allows) ... ok
test_s13_no_common_validity_interval_denied_at_gate (test_sar_hardening.SemanticsRules.test_s13_no_common_validity_interval_denied_at_gate) ... ok
test_s6_rejection_vetoes_met_quorum (test_sar_hardening.SemanticsRules.test_s6_rejection_vetoes_met_quorum) ... ok
test_s8_agent_cannot_also_be_overseer (test_sar_hardening.SemanticsRules.test_s8_agent_cannot_also_be_overseer) ... ok
test_s8_one_key_under_two_overseer_ids_invalidates_policy (test_sar_hardening.SemanticsRules.test_s8_one_key_under_two_overseer_ids_invalidates_policy) ... ok
test_s8_policy_shape (test_sar_hardening.SemanticsRules.test_s8_policy_shape) ... ok
test_s8_self_ratification_by_agent_key_denied (test_sar_hardening.SemanticsRules.test_s8_self_ratification_by_agent_key_denied) ... ok
test_s9_attacker_chosen_proposal_id_denied (test_sar_hardening.SemanticsRules.test_s9_attacker_chosen_proposal_id_denied) ... ok
test_s9_empty_validity_interval_denied (test_sar_hardening.SemanticsRules.test_s9_empty_validity_interval_denied) ... ok
test_s9_extra_or_wrong_typed_body_fields_denied_even_if_validly_signed (test_sar_hardening.SemanticsRules.test_s9_extra_or_wrong_typed_body_fields_denied_even_if_validly_signed) ... ok
test_s9_ratification_shape (test_sar_hardening.SemanticsRules.test_s9_ratification_shape) ... ok
test_s9_signature_encoding_is_canonical (test_sar_hardening.SemanticsRules.test_s9_signature_encoding_is_canonical) ... ok
test_artifacts_are_byte_identical (test_sar_cross.CrossImplementation.test_artifacts_are_byte_identical) ... ok
test_randomized_scenarios_agree (test_sar_cross.CrossImplementation.test_randomized_scenarios_agree) ... ok
test_single_fault_scenarios_agree (test_sar_cross.CrossImplementation.test_single_fault_scenarios_agree) ... ok

----------------------------------------------------------------------
Ran 115 tests in 20.230s

OK

    differential seed=20261009: 144 allowed (replay-relevant), 2856 denied, 0 disagreements with the model 
    single-fault seed=4242: none=557/557 allowed, agent=0/76 allowed, duplicate_overseer=0/94 allowed, expired=0/77 allowed, future_proposal=0/106 allowed, no_rats=0/101 allowed, payload=0/103 allowed, policy=0/91 allowed, psig=0/84 allowed, rat_before_proposal=0/102 allowed, rat_expired=0/77 allowed, rat_future=0/79 allowed, rat_rejected=0/80 allowed, rat_sig=0/85 allowed, rat_unauthorized=0/111 allowed, rat_unbound=0/88 allowed, rat_unknown_verdict=0/89 allowed 
    cross random/seed7: 3000 decision pairs, 156 allowed, 0 disagreements 
    cross fault/seed8: 3000 decision pairs, 828 allowed, 0 disagreements == independent (blind) implementation: original harness
............
----------------------------------------------------------------------
Ran 12 tests in 0.006s

OK
== independent (blind) implementation: its own tests
......................................................................................
----------------------------------------------------------------------
Ran 86 tests in 1.063s

OK
exit=0
```

## ./run_mutants.sh
```
PASS baseline
PASS mutant skip_digest killed (10 failing tests)
PASS mutant skip_replay killed (12 failing tests)
PASS mutant skip_expiry killed (2 failing tests)
PASS mutant skip_rat_expiry killed (5 failing tests)
PASS mutant skip_sig killed (10 failing tests)
PASS mutant allow_rejected killed (3 failing tests)
PASS mutant chain_noop killed (5 failing tests)
PASS mutant dedup_overseer killed (5 failing tests)
PASS mutant skip_policy_bind killed (7 failing tests)
PASS mutant skip_future_check killed (7 failing tests)
PASS mutant offline_skip_quorum killed (7 failing tests)
PASS mutant skip_head_check killed (4 failing tests)
PASS mutant skip_alg_check killed (2 failing tests)
PASS mutant skip_ctype_check killed (1 failing tests)
PASS mutant skip_kid_check killed (1 failing tests)
PASS mutant accept_nondeterministic killed (5 failing tests)
PASS mutant skip_binding killed (6 failing tests)
PASS mutant offline_skip_binding killed (4 failing tests)
PASS mutant deferred_tx killed (2 failing tests)
PASS mutant skip_policy_shape killed (2 failing tests)
PASS mutant skip_role_separation killed (4 failing tests)
PASS mutant skip_shape_check killed (10 failing tests)
PASS mutant skip_proposal_id_check killed (1 failing tests)
PASS mutant inclusive_expiry killed (1 failing tests)
PASS mutant replay_proposal_id_only killed (2 failing tests)
PASS mutant skip_common_window killed (4 failing tests)
mutants killed: 26/26
exit=0
```

## Concurrency stability
```
threads, fixed code: 20/20 passed
processes, fixed code: 5/5 passed
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
Ran 11 tests in 0.005s
FAILED (failures=9)
```

## bench.py 2000 (indicative only)
```
sar_cose micro-benchmark, N=2000, arm64 Darwin 27.0.0, Python 3.14.5
operation                                 median us     p99 us
make_proposal (sign)                           31.1       54.5
ratify (sign)                                  31.6       46.4
verify_record_offline                         112.3      154.7
Gate.authorize, in-memory store               158.7      241.1
Gate.authorize, file-backed store             440.3      704.0
Store.verify_chain (N records)               1223.7     1438.2
```

## Deep run: `SAR_DEEP=1 SAR_SEEDS=101,202,303,404,505` (started 2026-10-09T22:59:32Z)
```
differential seed=20261009: 1608 allowed (replay-relevant), 28392 denied, 0 disagreements with the model 
differential seed=101: 1512 allowed (replay-relevant), 28488 denied, 0 disagreements with the model 
differential seed=202: 1554 allowed (replay-relevant), 28446 denied, 0 disagreements with the model 
differential seed=303: 1607 allowed (replay-relevant), 28393 denied, 0 disagreements with the model 
differential seed=404: 1523 allowed (replay-relevant), 28477 denied, 0 disagreements with the model 
differential seed=505: 1604 allowed (replay-relevant), 28396 denied, 0 disagreements with the model 
single-fault seed=4242: none=5392/5392 allowed, agent=0/908 allowed, duplicate_overseer=0/981 allowed, expired=0/927 allowed, future_proposal=0/895 allowed, no_rats=0/907 allowed, payload=0/898 allowed, policy=0/873 allowed, psig=0/923 allowed, rat_before_proposal=0/948 allowed, rat_expired=0/856 allowed, rat_future=0/870 allowed, rat_rejected=0/865 allowed, rat_sig=0/925 allowed, rat_unauthorized=0/937 allowed, rat_unbound=0/958 allowed, rat_unknown_verdict=0/937 allowed 
single-fault seed=101: none=5536/5536 allowed, agent=0/891 allowed, duplicate_overseer=0/933 allowed, expired=0/966 allowed, future_proposal=0/888 allowed, no_rats=0/889 allowed, payload=0/902 allowed, policy=0/931 allowed, psig=0/890 allowed, rat_before_proposal=0/904 allowed, rat_expired=0/916 allowed, rat_future=0/909 allowed, rat_rejected=0/891 allowed, rat_sig=0/868 allowed, rat_unauthorized=0/891 allowed, rat_unbound=0/916 allowed, rat_unknown_verdict=0/879 allowed 
single-fault seed=202: none=5344/5344 allowed, agent=0/925 allowed, duplicate_overseer=0/886 allowed, expired=0/873 allowed, future_proposal=0/882 allowed, no_rats=0/927 allowed, payload=0/892 allowed, policy=0/885 allowed, psig=0/926 allowed, rat_before_proposal=0/897 allowed, rat_expired=0/951 allowed, rat_future=0/935 allowed, rat_rejected=0/911 allowed, rat_sig=0/937 allowed, rat_unauthorized=0/897 allowed, rat_unbound=0/963 allowed, rat_unknown_verdict=0/969 allowed 
single-fault seed=303: none=5396/5396 allowed, agent=0/947 allowed, duplicate_overseer=0/911 allowed, expired=0/964 allowed, future_proposal=0/924 allowed, no_rats=0/919 allowed, payload=0/923 allowed, policy=0/925 allowed, psig=0/955 allowed, rat_before_proposal=0/935 allowed, rat_expired=0/941 allowed, rat_future=0/888 allowed, rat_rejected=0/835 allowed, rat_sig=0/875 allowed, rat_unauthorized=0/893 allowed, rat_unbound=0/876 allowed, rat_unknown_verdict=0/893 allowed 
single-fault seed=404: none=5404/5404 allowed, agent=0/870 allowed, duplicate_overseer=0/925 allowed, expired=0/921 allowed, future_proposal=0/900 allowed, no_rats=0/913 allowed, payload=0/901 allowed, policy=0/895 allowed, psig=0/954 allowed, rat_before_proposal=0/924 allowed, rat_expired=0/921 allowed, rat_future=0/941 allowed, rat_rejected=0/929 allowed, rat_sig=0/928 allowed, rat_unauthorized=0/900 allowed, rat_unbound=0/902 allowed, rat_unknown_verdict=0/872 allowed 
single-fault seed=505: none=5411/5411 allowed, agent=0/882 allowed, duplicate_overseer=0/878 allowed, expired=0/928 allowed, future_proposal=0/996 allowed, no_rats=0/907 allowed, payload=0/884 allowed, policy=0/849 allowed, psig=0/949 allowed, rat_before_proposal=0/916 allowed, rat_expired=0/926 allowed, rat_future=0/904 allowed, rat_rejected=0/930 allowed, rat_sig=0/913 allowed, rat_unauthorized=0/897 allowed, rat_unbound=0/874 allowed, rat_unknown_verdict=0/956 allowed 
cross random/seed7: 30000 decision pairs, 1516 allowed, 0 disagreements 
cross random/seed101: 30000 decision pairs, 1528 allowed, 0 disagreements 
cross random/seed202: 30000 decision pairs, 1484 allowed, 0 disagreements 
cross random/seed303: 30000 decision pairs, 1658 allowed, 0 disagreements 
cross random/seed404: 30000 decision pairs, 1572 allowed, 0 disagreements 
cross random/seed505: 30000 decision pairs, 1664 allowed, 0 disagreements 
cross fault/seed8: 30000 decision pairs, 8044 allowed, 0 disagreements 
cross fault/seed101: 30000 decision pairs, 8378 allowed, 0 disagreements 
cross fault/seed202: 30000 decision pairs, 8086 allowed, 0 disagreements 
cross fault/seed303: 30000 decision pairs, 8084 allowed, 0 disagreements 
cross fault/seed404: 30000 decision pairs, 8108 allowed, 0 disagreements 
cross fault/seed505: 30000 decision pairs, 8210 allowed, 0 disagreements real 560.13
Ran 115 tests in 559.958s
OK
```

## tools/mutation_sweep.py (12 jobs)
```
mutants: 444  killed: 431  survived: 13  score: 97.1%
  SURVIVED  line   58  [del] delete statement in _head
  SURVIVED  line   94  [del] delete statement in dcbor
  SURVIVED  line  151  [del] delete statement in from_cose
  SURVIVED  line  151  [bool] And swap in from_cose
  SURVIVED  line  222  [cmp] Lt->LtE (op 1) in _uint
  SURVIVED  line  250  [cmp] Lt->LtE (op 0) in proposal_shape_ok
  SURVIVED  line  291  [ret] return False->True in policy_valid
  SURVIVED  line  291  [const] False->True in policy_valid
  SURVIVED  line  295  [const] True->False in _canon_json
  SURVIVED  line  462  [del] delete statement in _authorize
  SURVIVED  line  460  [cmp] Eq->NotEq (op 0) in _authorize
  SURVIVED  line  484  [cmp] GtE->Gt (op 0) in _authorize
  SURVIVED  line  549  [cmp] Lt->LtE (op 1) in verify_record_offline

```
All 13 survivors are argued equivalent in `tools/EQUIVALENT_MUTANTS.md`.

## Concurrency, extended (2026-10-09)
```
threads (16 gates x 5 rounds): 50/50 runs passed
processes (8 gates x 5 rounds): 10/10 runs passed
deferred_tx mutant killed by thread test: 10/10
```
