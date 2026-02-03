# stopbeinglazy.md

**Date/Time:** February 03, 2026 07:15 AM EST

## Current File Being Attacked
- meow_decoder/encode.py

## Batch
- Batch 1

## Tests Added (16)
1. `test_encode_file_duress_same_password_rejected` — reject duress=password; covers duress validation branch.
2. `test_encode_file_duress_requires_forward_secrecy` — duress + no FS rejected; covers error path.
3. `test_encode_file_duress_requires_pubkey_or_pq` — duress ambiguity guard; covers multi-line ValueError.
4. `test_encode_file_forward_secrecy_with_pubkey` — forward secrecy + pubkey + verbose; covers manifest/QR/GIF pipeline.
5. `test_encode_file_hardware_precomputed_key_passed` — precomputed key/salt passed into encrypt; covers hardware branch.
6. `test_encode_file_yubikey_kwargs_passed` — yubikey args propagated; covers yubikey path in encode_file.
7. `test_encode_file_manifest_hmac_uses_encryption_key` — HMAC uses encryption key; covers HMAC call path.
8. `test_encode_file_secure_zero_fails_gracefully` — secure_zero failure swallowed; covers exception path.
9. `test_main_about_exits_zero` — `--about` branch; covers early exit.
10. `test_main_hardware_status_exits_zero` — `--hardware-status` branch; covers provider detection/summary path.
11. `test_main_safety_checklist_import_error_exits_zero` — ImportError path; covers safety checklist fallback.
12. `test_main_noninteractive_requires_password` — non-TTY without `--password` fails closed.
13. `test_main_keyfile_validation_error` — verify_keyfile ValueError path; exit 1.
14. `test_main_yubikey_keyfile_conflict` — `--yubikey` + keyfile conflict; exit 1.
15. `test_main_duress_prompt_mismatch` — duress prompt mismatch; exit 1.
16. `test_main_hardware_derivation_failure_no_fallback` — hardware derivation failure with no fallback; exit 1.
17. `test_main_nine_lives_failure_exits` — Nine Lives retry fails; exit 1.

## Coverage Delta Estimate
- encode.py: +55–75 statements / several branches → from ~55% to ~73–80% (estimate)
- Overall repo: +2–4% (estimate)

## Overall Repo % Estimate After This Batch
- ~91–93% (estimate)

## Next Planned File
- encode.py (Batch 2) until ~95%, then qr_code.py.

## Blockers / Notes
- None. Heavy dependencies bypassed via stubs/mocks.
- Some hardware branches marked `pragma: no cover` may not move coverage.
