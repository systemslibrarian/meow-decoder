stopbeinglazy.md

Current date/time: February 03, 2026 10:45 AM EST
Current file: encode.py
Batch: Batch 4 (batch6 test file)

Tests added (18):
1. test_meow2_manifest_verbose_print — Line 118: MEOW2 manifest verbose print
2. test_safety_checklist_import_error — Lines 657-658: safety_checklist ImportError fallback
3. test_high_security_import_error — Lines 675-676: high_security ImportError fallback
4. test_password_prompt_stdin_interactive — Lines 802-807: getpass password prompt (TTY)
5. test_password_mismatch_exits — Lines 802-807: password confirm mismatch exits
6. test_yubikey_pin_prompted_when_none — Lines 840-846: yubikey_pin getpass prompt
7. test_duress_prompt_confirm_mismatch — Lines 888-889: duress confirm mismatch exits
8. test_duress_prompt_same_as_password — Lines 891-892: duress==password error
9. test_duress_prompt_success — Lines 885-902: duress prompt success path
10. test_duress_cli_same_as_password — Lines 891-892: CLI duress==password error
11. test_wipe_source_fallback_simple — Lines 1038-1044: wipe_source fallback (no high_security)
12. test_wipe_source_fallback_success — Lines 1038-1044: wipe_source fallback path
13. test_wipe_source_import_error — Lines 1038-1044: wipe_source ImportError handling
14. test_keyfile_too_small — Keyfile validation <32 bytes
15. test_keyfile_too_large — Keyfile validation >1MB
16. test_receiver_pubkey_wrong_size — Receiver pubkey validation !=32 bytes
17. test_receiver_pubkey_not_found — Receiver pubkey file not found
18. test_input_not_file — Input path is directory, not file

Coverage delta estimate: +20-30 statements, +8-12 branches → encode.py 94% → ~97-98%.
Overall repo % estimate after this batch: 96% → ~97-98%.
Next planned file (after encode.py hits ~98–100%): qr_code.py.
Blockers/notes: Terminal ENOPRO errors preventing validation. Need to retry pytest.

---
PREVIOUS BATCHES:

Batch 3 (17 tests in batch5):
1. test_encode_file_verbose_meow2_manifest_print — MEOW2 verbose branch in encode_file.
2. test_encode_file_verbose_meow4_manifest_print — MEOW4 verbose branch in encode_file.
3. test_encode_file_verbose_forward_secrecy_pubkey_print — MEOW3 FS verbose branch.
4. test_main_safety_checklist_import_error_exits_zero — safety checklist ImportError path.
5. test_main_high_security_import_error_warning — high-security ImportError warning path.
6. test_main_cat_judge_runs — cat_utils summon path.
7. test_main_keyfile_loads_verbose — keyfile load success with verbose.
8. test_main_keyfile_not_found_exit — keyfile FileNotFoundError exit path.
9. test_main_duress_prompt_empty_skips — duress prompt empty path.
10. test_main_hsm_pin_prompted — HSM pin prompt branch.
11. test_main_tpm_derive_sets_method — TPM derive branch.
12. test_main_hardware_auto_none_key_fallback — hardware auto returns None key path.
13. test_main_hardware_auto_success_verbose_prints — hardware auto success verbose print.
14. test_main_encode_file_exception_verbose_traceback — encode_file exception verbose path.
15. test_encode_file_secure_zero_exception_swallowed — secure_zero exception in encode_file.
16. test_encode_file_uses_verbose_password_only_message — MEOW3 password-only verbose path.
17. test_main_duress_password_cli_requires_forward_secrecy — duress CLI + no-fs error.
