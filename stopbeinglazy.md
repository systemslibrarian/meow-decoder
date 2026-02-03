stopbeinglazy.md

Current date/time: February 03, 2026 08:25 AM EST
Current file: encode.py
Batch: Batch 3

Tests added (17):
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

Coverage delta estimate: +45–65 statements, +12–18 branches → encode.py ~80–88% → ~92–97%.
Overall repo % estimate after this batch: ~92–94% → ~95–97%.
Next planned file (after encode.py hits ~98–100%): qr_code.py.
Blockers/notes: remaining encode.py misses likely in deadman switch + logo_eyes args; fix if still present.
