# 안경선배 공모전 준비도

- package_ready: `False`
- submission_ready (compatibility alias): `False`
- external_field_evidence_ready: `False`
- status: `package_verification_blocked`

## Checks

| check | passed |
|---|---|
| `submission_documented` | `True` |
| `submission_claims_current` | `False` |
| `three_minute_demo_video_valid` | `False` |
| `submission_video_attestation_valid` | `False` |
| `submission_report_bound_and_verified` | `False` |
| `submission_artifact_manifest_valid` | `False` |
| `submission_rights_documented` | `False` |
| `fresh_wheel_stdio_current_source_passed` | `False` |
| `submission_release_archives_match_current_source` | `False` |
| `current_source_public_replay_passed` | `False` |
| `current_language_validation_pack_complete` | `True` |
| `brand_consistent` | `True` |
| `demo_contract_passed` | `False` |
| `license_policy_passed` | `True` |
| `sbom_present` | `True` |
| `declared_sbom_component_count_matches_live_artifacts` | `False` |
| `evidence_integrity_passed` | `False` |
| `historical_client_evidence_contract_valid` | `False` |
| `current_self_attested_client_process_evidence_at_least_3` | `False` |
| `historical_public_effectiveness_evidence_contract_valid` | `False` |
| `release_workflow_static_contract_valid` | `True` |
| `community_files_present` | `True` |
| `owned_partner_field_apps_at_least_12` | `False` |
| `historical_client_recordings_at_least_3` | `False` |
| `historical_public_app_effectiveness_qualified` | `False` |

## Remaining Blockers

- `submission_claims_current`
- `three_minute_demo_video_valid`
- `submission_video_attestation_valid`
- `submission_report_bound_and_verified`
- `submission_artifact_manifest_valid`
- `submission_rights_documented`
- `fresh_wheel_stdio_current_source_passed`
- `submission_release_archives_match_current_source`
- `current_source_public_replay_passed`
- `demo_contract_passed`
- `declared_sbom_component_count_matches_live_artifacts`
- `evidence_integrity_passed`
- `historical_client_evidence_contract_valid`
- `current_self_attested_client_process_evidence_at_least_3`
- `historical_public_effectiveness_evidence_contract_valid`
- `owned_partner_field_apps_at_least_12`
- `historical_client_recordings_at_least_3`
- `historical_public_app_effectiveness_qualified`

## Claim Boundary

Package readiness proves that the current analyzer package was replayed deterministically on the pinned public-app corpus, that a freshly installed wheel completed the real stdio workflow, and that the bound report, media, manifest, and rights records verify. The release-workflow check validates committed static policy only; it does not assert that a hosted release run succeeded. The three client UI recordings and AI-reviewed public-app labels are historical process evidence. Public source-oracle probes and the preregistered Juliet first result support bounded detector claims only; the post-tuning replay is regression evidence. None substitutes for independent human adjudication on owned/partner field apps or grants release authority. Field evidence remains pending at 0 contract-verified apps.
