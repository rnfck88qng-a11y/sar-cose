# Results (raw output)

Run: 2026-10-10T09:38:27Z · Apple M5 Pro · Darwin 27.0.0 · Python 3.14.5 · cbor2 5.9.0 · cryptography 50.0.2 · pycose 1.1.0 · hypothesis 6.168.5

sar_cose.py sha256: `197befcf49ea24f87af5a7edb9e258500532cca84de2699297f6c471dc37a2a4` · independent/sar_indep.py sha256: `2f937aa01500b17fd8000399e010af0f488238674dbb2d546ab89fe6fe9a9453`

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
test_gate_allows_at_t_iff_offline_verification_at_t (test_sar_properties.DifferentialTests.test_gate_allows_at_t_iff_offline_verification_at_t)
SEMANTICS.md S13 as an equivalence over all interval bounds of each scenario. ... ok
test_gate_matches_spec_model_hypothesis (test_sar_properties.DifferentialTests.test_gate_matches_spec_model_hypothesis) ... ok
test_gate_matches_spec_model_randomized (test_sar_properties.DifferentialTests.test_gate_matches_spec_model_randomized) ... ok
test_gate_matches_spec_model_single_fault_injection (test_sar_properties.DifferentialTests.test_gate_matches_spec_model_single_fault_injection) ... ok
test_concurrent_presentations_allow_exactly_once (test_sar_properties.StoreConcurrencyTests.test_concurrent_presentations_allow_exactly_once) ... ok
test_concurrent_processes_allow_exactly_once (test_sar_properties.StoreConcurrencyTests.test_concurrent_processes_allow_exactly_once)
Separate OS processes (not threads), each with its own gate, on one database file. ... ~/Documents/Obsidian Vault/02-Projects/AlterA-uWorld/SARWP/sar-cose/test_sar_properties.py:465: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/9m/0sngg4857_dgsmdq2dr2ykn80000gn/T/tmplocqzucr/job0.json' mode='w' encoding='utf-8'>
  json.dump({"p": S.to_cose(prop).hex(), "r": [S.to_cose(x).hex() for x in rats], "db": path,
ResourceWarning: Enable tracemalloc to get the object allocation traceback
~/Documents/Obsidian Vault/02-Projects/AlterA-uWorld/SARWP/sar-cose/test_sar_properties.py:465: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/9m/0sngg4857_dgsmdq2dr2ykn80000gn/T/tmplocqzucr/job1.json' mode='w' encoding='utf-8'>
  json.dump({"p": S.to_cose(prop).hex(), "r": [S.to_cose(x).hex() for x in rats], "db": path,
ResourceWarning: Enable tracemalloc to get the object allocation traceback
~/Documents/Obsidian Vault/02-Projects/AlterA-uWorld/SARWP/sar-cose/test_sar_properties.py:465: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/9m/0sngg4857_dgsmdq2dr2ykn80000gn/T/tmplocqzucr/job2.json' mode='w' encoding='utf-8'>
  json.dump({"p": S.to_cose(prop).hex(), "r": [S.to_cose(x).hex() for x in rats], "db": path,
ResourceWarning: Enable tracemalloc to get the object allocation traceback
~/Documents/Obsidian Vault/02-Projects/AlterA-uWorld/SARWP/sar-cose/test_sar_properties.py:465: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/9m/0sngg4857_dgsmdq2dr2ykn80000gn/T/tmplocqzucr/job3.json' mode='w' encoding='utf-8'>
  json.dump({"p": S.to_cose(prop).hex(), "r": [S.to_cose(x).hex() for x in rats], "db": path,
ResourceWarning: Enable tracemalloc to get the object allocation traceback
~/Documents/Obsidian Vault/02-Projects/AlterA-uWorld/SARWP/sar-cose/test_sar_properties.py:465: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/9m/0sngg4857_dgsmdq2dr2ykn80000gn/T/tmplocqzucr/job4.json' mode='w' encoding='utf-8'>
  json.dump({"p": S.to_cose(prop).hex(), "r": [S.to_cose(x).hex() for x in rats], "db": path,
ResourceWarning: Enable tracemalloc to get the object allocation traceback
ok
test_replay_protection_survives_restart (test_sar_properties.StoreConcurrencyTests.test_replay_protection_survives_restart) ... ok
test_denial_record_names_the_proposal (test_sar_hardening.AuditSurvivors.test_denial_record_names_the_proposal) ... ok
test_non_text_transaction_id_is_consumed (test_sar_hardening.AuditSurvivors.test_non_text_transaction_id_is_consumed) ... ok
test_nonce_comparison_is_exact (test_sar_hardening.AuditSurvivors.test_nonce_comparison_is_exact) ... ok
test_payload_digest_is_compared_in_full (test_sar_hardening.AuditSurvivors.test_payload_digest_is_compared_in_full) ... ok
test_policy_binding_is_exact (test_sar_hardening.AuditSurvivors.test_policy_binding_is_exact) ... ok
test_replay_is_denied_at_any_later_instant (test_sar_hardening.AuditSurvivors.test_replay_is_denied_at_any_later_instant) ... ok
test_transaction_ids_are_compared_as_cbor_values (test_sar_hardening.AuditSurvivors.test_transaction_ids_are_compared_as_cbor_values) ... ok
test_cose_array_must_have_four_elements (test_sar_hardening.EncodingEdges.test_cose_array_must_have_four_elements) ... ok
test_cose_fields_must_be_byte_strings (test_sar_hardening.EncodingEdges.test_cose_fields_must_be_byte_strings) ... ok
test_cose_payload_must_be_a_map (test_sar_hardening.EncodingEdges.test_cose_payload_must_be_a_map) ... ok
test_cose_wrong_tag_or_untagged_rejected (test_sar_hardening.EncodingEdges.test_cose_wrong_tag_or_untagged_rejected) ... ok
test_integers_outside_cbor_major_types_rejected (test_sar_hardening.EncodingEdges.test_integers_outside_cbor_major_types_rejected) ... ok
test_protected_header_with_extra_parameter_rejected (test_sar_hardening.EncodingEdges.test_protected_header_with_extra_parameter_rejected) ... ok
test_unencodable_runtime_payload_is_denied_not_raised (test_sar_hardening.EncodingEdges.test_unencodable_runtime_payload_is_denied_not_raised) ... ok
test_allow_returns_the_exact_immutable_bytes (test_sar_hardening.ExactBytes.test_allow_returns_the_exact_immutable_bytes) ... ok
test_denial_without_log_still_denies (test_sar_hardening.ExactBytes.test_denial_without_log_still_denies) ... ok
test_modified_or_non_canonical_bytes_are_denied (test_sar_hardening.ExactBytes.test_modified_or_non_canonical_bytes_are_denied) ... ok
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
test_agent_removed_after_ratification_is_denied (test_sar_hardening.Revocation.test_agent_removed_after_ratification_is_denied) ... ok
test_overseer_key_rotated_after_ratification_is_denied (test_sar_hardening.Revocation.test_overseer_key_rotated_after_ratification_is_denied) ... ok
test_overseer_removed_after_ratification_is_denied (test_sar_hardening.Revocation.test_overseer_removed_after_ratification_is_denied) ... ok
test_anchor_detects_a_modified_record_and_accepts_a_consistent_static_checkpoint (test_sar_hardening.RollbackAndCrash.test_anchor_detects_a_modified_record_and_accepts_a_consistent_static_checkpoint) ... ok
test_anchor_detects_deleted_consumed_keys_and_static_checkpoints (test_sar_hardening.RollbackAndCrash.test_anchor_detects_deleted_consumed_keys_and_static_checkpoints) ... ok
test_anchor_refuses_a_rolled_back_or_truncated_database (test_sar_hardening.RollbackAndCrash.test_anchor_refuses_a_rolled_back_or_truncated_database) ... ok
test_crash_at_every_statement_allows_at_most_once (test_sar_hardening.RollbackAndCrash.test_crash_at_every_statement_allows_at_most_once)
Inject a failure at each database statement of an authorization, then retry twice after ... ok
test_failure_after_allow_never_reenables_the_authorization (test_sar_hardening.RollbackAndCrash.test_failure_after_allow_never_reenables_the_authorization) ... ok
test_missing_anchor_for_a_non_empty_log_refuses (test_sar_hardening.RollbackAndCrash.test_missing_anchor_for_a_non_empty_log_refuses) ... ok
test_rollback_without_anchor_reenables_a_consumed_authorization (test_sar_hardening.RollbackAndCrash.test_rollback_without_anchor_reenables_a_consumed_authorization) ... ok
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
test_gate_offline_equivalence_in_both_implementations (test_sar_cross.CrossImplementation.test_gate_offline_equivalence_in_both_implementations)
SEMANTICS.md S13 for each implementation: gate allows at t iff offline(at=t). ... ok
test_randomized_scenarios_agree (test_sar_cross.CrossImplementation.test_randomized_scenarios_agree) ... ok
test_single_fault_scenarios_agree (test_sar_cross.CrossImplementation.test_single_fault_scenarios_agree) ... ok

----------------------------------------------------------------------
Ran 137 tests in 32.155s

OK

    gate/offline equivalence seed=13: 1000 scenarios, 12653 instants (1709 allowed), 0 disagreements 
    differential seed=20261009: 144 allowed (replay-relevant), 2856 denied, 0 disagreements with the model 
    single-fault seed=4242: none=557/557 allowed, agent=0/76 allowed, duplicate_overseer=0/94 allowed, expired=0/77 allowed, future_proposal=0/106 allowed, no_rats=0/101 allowed, payload=0/103 allowed, policy=0/91 allowed, psig=0/84 allowed, rat_before_proposal=0/102 allowed, rat_expired=0/77 allowed, rat_future=0/79 allowed, rat_rejected=0/80 allowed, rat_sig=0/85 allowed, rat_unauthorized=0/111 allowed, rat_unbound=0/88 allowed, rat_unknown_verdict=0/89 allowed 
    gate/offline equivalence, both implementations, seed=9: 600 scenarios, 7569 instants each, 0 disagreements 
    cross random/seed7: 3000 decision pairs, 156 allowed, 0 disagreements 
    cross fault/seed8: 3000 decision pairs, 828 allowed, 0 disagreements == second implementation (independent/, as amended): original harness
............
----------------------------------------------------------------------
Ran 12 tests in 0.008s

OK
== second implementation (independent/, as amended): its own tests
......................................................................................
----------------------------------------------------------------------
Ran 86 tests in 1.232s

OK
== reconstructed blind version (independent/original_blind/): original harness and its own tests
............
----------------------------------------------------------------------
Ran 12 tests in 0.007s

OK
......................................................................................
----------------------------------------------------------------------
Ran 86 tests in 1.286s

OK
exit=0
```

## ./run_mutants.sh
```
PASS baseline
PASS mutant skip_digest killed (12 failing tests)
PASS mutant skip_replay killed (27 failing tests)
PASS mutant skip_expiry killed (4 failing tests)
PASS mutant skip_rat_expiry killed (7 failing tests)
PASS mutant skip_sig killed (13 failing tests)
PASS mutant allow_rejected killed (3 failing tests)
PASS mutant chain_noop killed (7 failing tests)
PASS mutant dedup_overseer killed (7 failing tests)
PASS mutant skip_policy_bind killed (10 failing tests)
PASS mutant skip_future_check killed (9 failing tests)
PASS mutant offline_skip_quorum killed (9 failing tests)
PASS mutant skip_head_check killed (6 failing tests)
PASS mutant skip_alg_check killed (2 failing tests)
PASS mutant skip_ctype_check killed (1 failing tests)
PASS mutant skip_kid_check killed (1 failing tests)
PASS mutant accept_nondeterministic killed (7 failing tests)
PASS mutant skip_binding killed (8 failing tests)
PASS mutant offline_skip_binding killed (6 failing tests)
PASS mutant deferred_tx killed (2 failing tests)
PASS mutant skip_policy_shape killed (2 failing tests)
PASS mutant skip_role_separation killed (4 failing tests)
PASS mutant skip_shape_check killed (10 failing tests)
PASS mutant skip_proposal_id_check killed (1 failing tests)
PASS mutant inclusive_expiry killed (3 failing tests)
PASS mutant replay_proposal_id_only killed (6 failing tests)
PASS mutant skip_common_window killed (5 failing tests)
PASS mutant nonce_casefold killed (1 failing tests)
PASS mutant digest_prefix_only killed (1 failing tests)
PASS mutant replay_key_with_time killed (2 failing tests)
PASS mutant policy_bind_casefold killed (1 failing tests)
PASS mutant split_consume_tx killed (7 failing tests)
PASS mutant txn_key_str_only killed (3 failing tests)
PASS mutant deny_record_without_pid killed (1 failing tests)
PASS mutant offline_at_unskewed killed (5 failing tests)
PASS mutant payload_bytes_lenient killed (2 failing tests)
PASS mutant skip_anchor_check killed (5 failing tests)
PASS mutant skip_anchor_save killed (2 failing tests)
mutants killed: 37/37
exit=0
```

## Concurrency stability
```
threads, fixed code: 50/50 passed
processes, fixed code: 10/10 passed
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

## tools/audit_mutants.py (20 semantic mutants from the external audit of v1.2)
```
N01_future_skew_3600                           KILLED    FAIL: test_gate_offline_equivalence_in_both_implementations (test_sar_cross.CrossIm
N02_nonce_casefold                             KILLED    FAIL: test_nonce_comparison_is_exact (test_sar_hardening.AuditSurvivors.test_nonce_
N03_agent_overseer_same_identity_allowed       KILLED    FAIL: test_s8_agent_cannot_also_be_overseer (test_sar_hardening.SemanticsRules.test
N04_quorum_off_by_one                          KILLED    FAIL: test_11_quorum_requires_distinct_approvals (test_sar_conformance.SarTests.tes
N05_checkpoint_signature_not_verified          KILLED    FAIL: test_forged_or_mismatched_checkpoint_rejected (test_sar_hardening.ExternalChe
N06_digest_alg_sha3                            KILLED    FAIL: test_payload_digest_is_sha256_of_deterministic_cbor (test_sar_cose_specific.C
N07_digest_compare_truncated_8B                KILLED    FAIL: test_payload_digest_is_compared_in_full (test_sar_hardening.AuditSurvivors.te
N08_policy_unknown_keys_accepted               KILLED    FAIL: test_s8_policy_shape (test_sar_hardening.SemanticsRules.test_s8_policy_shape)
N09_replay_key_includes_time                   KILLED    FAIL: test_replay_is_denied_at_any_later_instant (test_sar_hardening.AuditSurvivors
N10_expired_ratification_ignored_not_denied    KILLED    FAIL: test_gate_allows_at_t_iff_offline_verification_at_t (test_sar_properties.Diff
N11_offline_skips_agent_signature              KILLED    FAIL: test_offline_rejects_ratified_proposal_with_bad_agent_signature (test_sar_har
N12_policy_binding_casefold                    KILLED    FAIL: test_policy_binding_is_exact (test_sar_hardening.AuditSurvivors.test_policy_b
N13_gate_accepts_alg_-8                        KILLED    FAIL: test_deprecated_polymorphic_alg_rejected (test_sar_cose_specific.CoseStructur
N14_review_before_issue_within_skew            KILLED    FAIL: test_review_not_before_proposal_boundary (test_sar_properties.BoundaryTests.t
N15_consume_in_separate_tx_after_record        KILLED    FAIL: test_crash_at_every_statement_allows_at_most_once (test_sar_hardening.Rollbac
N16_txn_only_if_str                            KILLED    FAIL: test_non_text_transaction_id_is_consumed (test_sar_hardening.AuditSurvivors.t
N17_proposal_id_16_hex                         KILLED    FAIL: test_artifacts_are_byte_identical (test_sar_cross.CrossImplementation.test_ar
N18_expiry_grace_equal_to_skew                 KILLED    FAIL: test_proposal_expiry_boundary (test_sar_properties.BoundaryTests.test_proposa
N19_unknown_verdict_treated_as_approved        KILLED    FAIL: test_gate_allows_at_t_iff_offline_verification_at_t (test_sar_properties.Diff
N20_deny_reason_logged_without_proposal_id     KILLED    FAIL: test_denial_record_names_the_proposal (test_sar_hardening.AuditSurvivors.test
audit mutants killed: 20/20; not killed: []
```

## tools/reproduce_blind_diff.sh (sar_cose at e2e39dd vs reconstructed blind version, 6,000 decisions)
```
reference: sar_cose.py at e2e39dd (sha256 6f99116cc81f520157548176f855bf32a8129c875aa5c395ae3ca1a3c6bec459)
blind:     independent/original_blind/sar_indep.py (sha256 8aa92673513aff7587b48da91cdf56617822a0107fac0a01b90ba7fc11841445)
scenarios per generator: 1500; decisions compared: 6000; byte-level wire mismatches between makers: 0
disagreements: 128
     36  ('fault', 'duplicate_overseer', 'gate', 'A=True/ok', 'B=False/DENY: duplicate ratification from one overseer')
     26  ('random', None, 'gate', 'A=True/ok', 'B=False/DENY: duplicate ratification from one overseer')
     20  ('random', None, 'gate', 'A=True/ok', 'B=False/DENY: ratification is future-dated')
     16  ('random', None, 'offline', 'A=False/ratification_time_invalid', 'B=False/DENY: duplicate ratification from one overseer')
     10  ('random', None, 'gate', 'A=True/ok', 'B=False/DENY: ratification issued after proposal expiry')
      6  ('random', None, 'offline', 'A=False/ratification_time_invalid', 'B=False/DENY: no instant at which proposal and all ratifications were valid')
      6  ('random', None, 'gate', 'A=True/ok', 'B=False/DENY: proposal is future-dated')
      6  ('random', None, 'gate', 'A=True/ok', 'B=False/DENY: no instant at which proposal and all ratifications were valid')
      2  ('random', None, 'offline', 'A=False/payload_mismatch', 'B=False/DENY: duplicate ratification from one overseer')
```

## bench.py 2000 (indicative only)
```
sar_cose micro-benchmark, N=2000, arm64 Darwin 27.0.0, Python 3.14.5
operation                                 median us     p99 us
make_proposal (sign)                           29.8       43.7
ratify (sign)                                  30.1       37.8
verify_record_offline                         108.4      131.8
baseline: unsigned flag, in memory              0.1        0.1
Gate.authorize, in-memory store               149.4      191.9
Gate.authorize_bytes, in-memory store         153.9      185.8
baseline: unsigned flag, file-backed          197.9     1779.3
Gate.authorize, file-backed store             437.9     2339.2
Store.verify_chain (N records)               1247.0     1260.7
```

## Deep run: `SAR_DEEP=1 SAR_SEEDS=101,202,303,404,505 python -m unittest -v test_sar_properties test_sar_cross test_sar_hardening test_sar_gaps test_sar_cose_specific test_sar_conformance`
```
2026-10-10T08:54:54Z
10:54  up 25 days, 14:21, 3 users, load averages: 31.39 39.28 39.62
Ran 137 tests in 1422.634s
OK
    gate/offline equivalence seed=13: 10000 scenarios, 125034 instants (16435 allowed), 0 disagreements 
    gate/offline equivalence seed=101: 10000 scenarios, 124671 instants (16298 allowed), 0 disagreements 
    gate/offline equivalence seed=202: 10000 scenarios, 124150 instants (15734 allowed), 0 disagreements 
    gate/offline equivalence seed=303: 10000 scenarios, 124869 instants (16579 allowed), 0 disagreements 
    gate/offline equivalence seed=404: 10000 scenarios, 124110 instants (16456 allowed), 0 disagreements 
    gate/offline equivalence seed=505: 10000 scenarios, 124824 instants (16274 allowed), 0 disagreements 
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
    gate/offline equivalence, both implementations, seed=9: 6000 scenarios, 74845 instants each, 0 disagreements 
    gate/offline equivalence, both implementations, seed=101: 6000 scenarios, 74558 instants each, 0 disagreements 
    gate/offline equivalence, both implementations, seed=202: 6000 scenarios, 74578 instants each, 0 disagreements 
    gate/offline equivalence, both implementations, seed=303: 6000 scenarios, 74653 instants each, 0 disagreements 
    gate/offline equivalence, both implementations, seed=404: 6000 scenarios, 74561 instants each, 0 disagreements 
    gate/offline equivalence, both implementations, seed=505: 6000 scenarios, 74942 instants each, 0 disagreements 
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
    cross fault/seed505: 30000 decision pairs, 8210 allowed, 0 disagreements
1397.87s user 27.43s system 100% cpu 23:43.08 total
```

## Automated mutation sweep: `tools/mutation_sweep.py --jobs 12` (final run, round 2)
```
mutants: 491  killed: 476  survived: 15  score: 96.9%
  SURVIVED  line   66  [del] delete statement in _head
  SURVIVED  line  102  [del] delete statement in dcbor
  SURVIVED  line  159  [del] delete statement in from_cose
  SURVIVED  line  159  [bool] And swap in from_cose
  SURVIVED  line  230  [cmp] Lt->LtE (op 1) in _uint
  SURVIVED  line  285  [cmp] Lt->LtE (op 0) in proposal_shape_ok
  SURVIVED  line  326  [ret] return False->True in policy_valid
  SURVIVED  line  326  [const] False->True in policy_valid
  SURVIVED  line  330  [const] True->False in _canon_json
  SURVIVED  line  368  [del] delete statement in save
  SURVIVED  line  507  [del] delete statement in consume_and_record
  SURVIVED  line  625  [del] delete statement in _authorize
  SURVIVED  line  623  [cmp] Eq->NotEq (op 0) in _authorize
  SURVIVED  line  647  [cmp] GtE->Gt (op 0) in _authorize
  SURVIVED  line  726  [cmp] Lt->LtE (op 1) in verify_record_offline
time: 14777.09s user 3792.25s system 1193% cpu 25:56.09 total
```

The first sweep of round 2 (before two tests were added for the anchor; see `tools/EQUIVALENT_MUTANTS.md`):
```
mutants: 491  killed: 474  survived: 17  score: 96.5%
```

## Benchmark: 5 runs of `bench.py 2000`, alternating with the v1.1 code (commit e2e39dd, its own bench.py), with load averages
```
### run 1 current  load averages: 4.76 5.42 8.15
sar_cose micro-benchmark, N=2000, arm64 Darwin 27.0.0, Python 3.14.5
operation                                 median us     p99 us
make_proposal (sign)                           31.2       62.5
ratify (sign)                                  30.6       69.2
verify_record_offline                         114.9      235.2
baseline: unsigned flag, in memory              0.1        0.2
Gate.authorize, in-memory store               155.3      288.4
Gate.authorize_bytes, in-memory store         161.3      305.7
baseline: unsigned flag, file-backed          208.2     6160.3
Gate.authorize, file-backed store             462.9    10624.7
Store.verify_chain (N records)               1375.8     1679.9
### run 1 e2e39dd  load averages: 4.78 5.42 8.13
sar_cose micro-benchmark, N=2000, arm64 Darwin 27.0.0, Python 3.14.5
operation                                 median us     p99 us
make_proposal (sign)                           31.4       48.1
ratify (sign)                                  31.9       85.5
verify_record_offline                         102.9      211.2
Gate.authorize, in-memory store               141.7      274.5
Gate.authorize, file-backed store             423.9     1255.4
Store.verify_chain (N records)               1223.9     1230.8
### run 2 current  load averages: 4.78 5.42 8.13
sar_cose micro-benchmark, N=2000, arm64 Darwin 27.0.0, Python 3.14.5
operation                                 median us     p99 us
make_proposal (sign)                           31.6      116.2
ratify (sign)                                  31.3       60.2
verify_record_offline                         111.9      201.5
baseline: unsigned flag, in memory              0.1        0.2
Gate.authorize, in-memory store               162.7      323.5
Gate.authorize_bytes, in-memory store         159.1      314.8
baseline: unsigned flag, file-backed          207.2     1453.7
Gate.authorize, file-backed store             470.7      809.5
Store.verify_chain (N records)               1343.8     1468.9
### run 2 e2e39dd  load averages: 4.71 5.39 8.11
sar_cose micro-benchmark, N=2000, arm64 Darwin 27.0.0, Python 3.14.5
operation                                 median us     p99 us
make_proposal (sign)                           31.3       66.4
ratify (sign)                                  32.0       63.6
verify_record_offline                         103.5      188.6
Gate.authorize, in-memory store               141.6      295.1
Gate.authorize, file-backed store             421.6     2767.5
Store.verify_chain (N records)               1207.0     1274.3
### run 3 current  load averages: 4.71 5.39 8.11
sar_cose micro-benchmark, N=2000, arm64 Darwin 27.0.0, Python 3.14.5
operation                                 median us     p99 us
make_proposal (sign)                           31.5       95.9
ratify (sign)                                  31.8       56.8
verify_record_offline                         115.1      232.5
baseline: unsigned flag, in memory              0.1        0.2
Gate.authorize, in-memory store               163.0      321.2
Gate.authorize_bytes, in-memory store         164.1      431.6
baseline: unsigned flag, file-backed          206.4     2665.5
Gate.authorize, file-backed store             476.8     4184.4
Store.verify_chain (N records)               1265.3     1284.7
### run 3 e2e39dd  load averages: 4.74 5.39 8.09
sar_cose micro-benchmark, N=2000, arm64 Darwin 27.0.0, Python 3.14.5
operation                                 median us     p99 us
make_proposal (sign)                           31.3       43.0
ratify (sign)                                  31.8      113.9
verify_record_offline                         104.3      194.4
Gate.authorize, in-memory store               143.8      320.6
Gate.authorize, file-backed store             420.5     1877.7
Store.verify_chain (N records)               1628.5     1670.9
### run 4 current  load averages: 4.76 5.38 8.07
sar_cose micro-benchmark, N=2000, arm64 Darwin 27.0.0, Python 3.14.5
operation                                 median us     p99 us
make_proposal (sign)                           31.6       64.4
ratify (sign)                                  32.4       86.9
verify_record_offline                         116.4      225.3
baseline: unsigned flag, in memory              0.1        0.2
Gate.authorize, in-memory store               162.5      314.5
Gate.authorize_bytes, in-memory store         161.8      381.8
baseline: unsigned flag, file-backed          202.6      638.0
Gate.authorize, file-backed store             481.0     3309.7
Store.verify_chain (N records)               1294.8     1304.7
### run 4 e2e39dd  load averages: 4.76 5.38 8.07
sar_cose micro-benchmark, N=2000, arm64 Darwin 27.0.0, Python 3.14.5
operation                                 median us     p99 us
make_proposal (sign)                           31.4       58.5
ratify (sign)                                  31.5       66.9
verify_record_offline                         104.5      183.5
Gate.authorize, in-memory store               144.5      279.2
Gate.authorize, file-backed store             429.8      901.9
Store.verify_chain (N records)               1238.9     1275.0
### run 5 current  load averages: 4.78 5.37 8.05
sar_cose micro-benchmark, N=2000, arm64 Darwin 27.0.0, Python 3.14.5
operation                                 median us     p99 us
make_proposal (sign)                           32.9       55.0
ratify (sign)                                  33.2       58.4
verify_record_offline                         115.6      218.3
baseline: unsigned flag, in memory              0.1        0.2
Gate.authorize, in-memory store               157.7      314.1
Gate.authorize_bytes, in-memory store         164.8      300.4
baseline: unsigned flag, file-backed          206.2      408.5
Gate.authorize, file-backed store             487.3     2767.6
Store.verify_chain (N records)               1320.8     1391.1
### run 5 e2e39dd  load averages: 4.78 5.37 8.05
sar_cose micro-benchmark, N=2000, arm64 Darwin 27.0.0, Python 3.14.5
operation                                 median us     p99 us
make_proposal (sign)                           32.2       67.5
ratify (sign)                                  32.9       61.4
verify_record_offline                         107.8      188.2
Gate.authorize, in-memory store               145.7      270.9
Gate.authorize, file-backed store             421.4      845.3
Store.verify_chain (N records)               1557.5     1777.2
```
