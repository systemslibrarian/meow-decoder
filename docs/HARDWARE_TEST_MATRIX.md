# Hardware Security Path — Test Matrix

**Status:** living document. Reflects what's covered today; rows
marked "Real-hardware validation" need to be filled in as physical
devices are exercised.

**Tracking:** gemini #2 from `gemini_suggetions.md` — "stabilize TPM
and hardware-backed flows; ensure hardware-backed security paths
are trustworthy across targets."

## What this document is

This page is the honest answer to the question:

> *"You say HSM/YubiKey/TPM are 'Complete' in the roadmap. What does
> that actually mean? What's tested, what's mocked, what's never
> been touched on real hardware?"*

The short version:

- The **integration code** is implemented end-to-end across
  `crypto_core/src/{hsm,tpm,yubikey_piv}.rs`,
  `meow_decoder/hardware_integration.py`, and the `meow-encode` /
  `meow-decode-gif` CLIs.
- **Unit and integration tests** in CI cover the integration code
  via in-memory mock providers. They prove the wiring works,
  not that any specific real device works.
- **Real-hardware validation** is, by necessity, out-of-band — CI
  runners don't have HSMs, YubiKeys, or TPM 2.0 chips attached.
  Coverage is recorded below as devices are exercised.

## Layer-by-layer coverage

### HSM (PKCS#11)

| Path | Covered by | Status |
|---|---|---|
| `crypto_core/src/hsm.rs` Rust unit tests | `cargo test` in CI | ✅ Green |
| Python `HardwareSecurityProvider.hsm_*` API surface | `tests/test_hardware_integration.py` (mocked import path) | ✅ Green |
| CLI flags `--hsm-slot`, `--hsm-pin` parse and route correctly | Argparse unit tests, mock provider end-to-end | ✅ Green |
| **SoftHSM2** (software PKCS#11 token) | Real-hardware validation | ⚪ Not yet recorded |
| **YubiHSM 2** | Real-hardware validation | ⚪ Not yet recorded |
| **Nitrokey HSM** | Real-hardware validation | ⚪ Not yet recorded |
| Any other PKCS#11-compatible device | Real-hardware validation | ⚪ Not yet recorded |

**Honest claim:** the integration is wired correctly against the
PKCS#11 spec and a mock backend. Until a real HSM exercises the
flow end-to-end (encode + decode roundtrip with the master key
held in HSM and never crossing the host), the "real device"
column above is unverified.

**SoftHSM2** is the recommended first validation target — it's
free, runs on the dev machine, and exercises the full PKCS#11
surface without needing physical hardware.

### YubiKey PIV / FIDO2

| Path | Covered by | Status |
|---|---|---|
| `crypto_core/src/yubikey_piv.rs` Rust unit tests | `cargo test` in CI | ✅ Green |
| Marvin Attack guard (RSA decrypt rejected) | `crypto_core/src/yubikey_piv.rs` `YubiKey::decrypt()` returns `NotSupported` for RSA1024/2048 (Finding 7.1, fixed) | ✅ Code path enforced |
| Python `HardwareSecurityProvider.derive_key_yubikey_piv` | `tests/test_hardware_integration.py` | ✅ Green |
| CLI flags `--yubikey`, `--yubikey-slot`, `--yubikey-pin` | Argparse + mock provider | ✅ Green |
| **YubiKey 5 series** PIV slot 9a/9c/9d/9e | Real-hardware validation | ⚪ Not yet recorded |
| **YubiKey 5 series** FIDO2 hmac-secret | Real-hardware validation | ⚪ Not yet recorded |
| **YubiKey 4 series** | Real-hardware validation | ⚪ Not yet recorded |
| Touch-required policy enforcement | Real-hardware validation | ⚪ Not yet recorded |

**Honest claim:** ECDH paths are implemented and the RSA decrypt
path is intentionally disabled to avoid the Marvin Attack class.
Touch policy and PIN-cache behavior on real silicon need a YK5
in hand to verify.

### TPM 2.0

| Path | Covered by | Status |
|---|---|---|
| `crypto_core/src/tpm.rs` Rust unit tests | `cargo test --features tpm` in CI | ✅ Green |
| `tss-esapi 7.6.0` API migration (16 distinct breakages fixed) | `crypto_core/src/tpm.rs` rewrite (Finding 12.6, fixed) | ✅ Compiles cleanly |
| `Auth::try_from(...)` no-panic guard | `TpmError::InvalidAuth` arm (Finding 6.6, fixed) | ✅ Defensive |
| `TctiNameConf::from_str(...)` no-panic guard | propagates via `TpmError::CommunicationFailed` (Finding 6.2, fixed) | ✅ Defensive |
| `PcrSlot` bitflag mapping | `crypto_core/src/tpm.rs:421-428` `map_err` (Finding 6.3, fixed) | ✅ Defensive |
| Python `HardwareSecurityProvider.tpm_seal` / `tpm_unseal` | `tests/test_hardware_integration.py` | ✅ Green |
| CLI flags `--tpm-seal`, `--tpm-unseal`, `--tpm-derive` | Argparse + mock | ✅ Green |
| **swtpm** (software TPM 2.0 simulator) | Real-hardware validation | ⚪ Not yet recorded |
| **fTPM** (firmware TPM, e.g. Intel PTT, AMD fTPM) | Real-hardware validation | ⚪ Not yet recorded |
| **dTPM** (discrete TPM 2.0 chip) | Real-hardware validation | ⚪ Not yet recorded |
| PCR-bound seal across reboot | Real-hardware validation | ⚪ Not yet recorded |
| **Cryptographer-review item:** `Context::create()` `SensitiveData`
   slot — flagged in commit `e43577e` as a possibly-broken-since-
   original judgment call during the tss-esapi 7.6 migration | Open | 🔶 Needs review |

**Honest claim:** the code compiles, tests pass under the mock,
and several panic-on-bad-input paths were hardened. End-to-end
with a real TPM 2.0 chip sealing keys to boot-state PCRs is the
high-value gap. **swtpm** is the recommended first validation
target; it runs on Linux without physical hardware.

## CI coverage today

| Workflow | Hardware | What it actually exercises |
|---|---|---|
| `Rust Tests & Coverage` | None | Mock providers in `crypto_core/src/{hsm,tpm,yubikey_piv}.rs` |
| `Rust Crypto Backend` | None | PyO3 bindings to the same mock providers |
| `CI - Tests + Coverage` | None | `tests/test_hardware_integration.py` against mocks |
| `Security CI` | None | bandit + dependency audit; no live hardware |

There is no current CI job that exercises a real HSM, YubiKey, or
TPM. Real-hardware validation is gated on a maintainer with the
device in hand.

## How to fill in this matrix

If you have a device and want to record a validation run:

1. Run the existing CLI roundtrip against the device. For example,
   for SoftHSM2:

   ```sh
   # Initialize a SoftHSM2 token first; see SoftHSM2 docs.
   meow-encode --hsm-slot 0 --hsm-pin <pin> -i some-file.pdf -o test.gif
   meow-decode-gif --hsm-slot 0 --hsm-pin <pin> -i test.gif -o decrypted.pdf
   diff some-file.pdf decrypted.pdf  # must be empty
   ```

2. Edit this file and update the relevant row from ⚪ to ✅ with a
   short note: what device, what OS, what software stack, what
   commit / version was tested.

3. If the run failed, change the row to ❌ and open an issue
   (or note in `FOLLOWUP.md`) with the failure mode.

## Cat Mode optical channel (real display + phone camera)

Automated screenshot/degradation coverage is documented in `docs/CAT_MODE.md`.
It does not substitute for a physical display, lens, autofocus system, rolling
shutter, or ambient reflections. No row below had been run as of 2026-07-17.

### Fixed procedure

1. Record the tested commit, phone model, OS, Meow Capture version, display
  model, native resolution, refresh rate, and display scaling.
2. Disable adaptive screen brightness, night mode, HDR enhancement, and phone
  auto-rotate. Clean both the display and camera lens.
3. Measure ambient illuminance at the phone position with a lux meter. Record
  the measured value; do not substitute a room-light setting name.
4. In the web demo, select Cat Mode and transmit the ASCII text
  `CAT-HW-0123456789abcdef` repeated 24 times with password
  `cat-hardware-test-2026`. Use the default 500 ms frame interval.
5. Enter fullscreen, place the phone camera lens at the specified straight-line
  distance from the display, and set the specified horizontal viewing angle.
6. In Meow Capture, select **Cat Mode · Experimental**. Start during the
  countdown and do not move the phone during a trial.
7. Record frames seen, QRs decoded, unique droplets, duplicate rate, completion
  time, loops required, and every three-second diagnostic shown.
8. Export the capture and verify that the reconstructed encrypted payload
  decrypts to the exact 552-byte test text. A wrong password must not report
  success.
9. Repeat each row three times. Run Standard animated QR under the same
  conditions as a control; any Standard regression fails the row.

### Pass criteria

A row passes only when all three Cat trials:

- auto-complete within three full transmit loops;
- reconstruct and decrypt to the exact test text;
- emit no false completion and no incorrect plaintext;
- keep the entire QR and quiet zone in frame; and
- leave Standard animated QR passing three of three control trials.

Record partial outcomes numerically. Do not replace a failed trial with an
adjective such as "mostly reliable."

### Required matrix

| Case | Distance | Horizontal angle | Ambient light | Display brightness | Phone / display | Cat passes | Median QR read rate | Median completion | Standard control | Status |
|---|---:|---:|---:|---:|---|---:|---:|---:|---:|---|
| Baseline | 45 cm | 0° | 300 ± 50 lux | 100% | — | —/3 | — | — | —/3 | ⚪ Not run |
| Near | 30 cm | 0° | 300 ± 50 lux | 100% | — | —/3 | — | — | —/3 | ⚪ Not run |
| Far | 60 cm | 0° | 300 ± 50 lux | 100% | — | —/3 | — | — | —/3 | ⚪ Not run |
| Slight angle | 45 cm | 15° | 300 ± 50 lux | 100% | — | —/3 | — | — | —/3 | ⚪ Not run |
| Oblique | 45 cm | 30° | 300 ± 50 lux | 100% | — | —/3 | — | — | —/3 | ⚪ Not run |
| Dim room | 45 cm | 0° | 100 ± 25 lux | 100% | — | —/3 | — | — | —/3 | ⚪ Not run |
| Bright room | 45 cm | 0° | 700 ± 75 lux | 100% | — | —/3 | — | — | —/3 | ⚪ Not run |
| Reduced display | 45 cm | 0° | 300 ± 50 lux | 50% | — | —/3 | — | — | —/3 | ⚪ Not run |

For a failed row, attach the mobile debug bundle and note whether the dominant
failure was no QR geometry, too-small/too-large QR bounds, luminance threshold,
motion, duplicate saturation, or fountain incompleteness.

## Related documents

- `docs/THREAT_MODEL.md` — what the hardware integration is meant to
  protect against (host-key extraction, OS compromise, etc.).
- `docs/SECURITY_INVARIANTS.md` — invariants the hardware paths must
  preserve (key-never-leaves-boundary, etc.).
- `crypto_core/src/{hsm,tpm,yubikey_piv}.rs` — implementation.
- `meow_decoder/hardware_integration.py` — Python API surface.
- `FOLLOWUP.md` — closed audit findings on hardware paths
  (Findings 6.2, 6.3, 6.6, 7.1, 12.6).
- `docs/CAT_MODE.md` — Cat optical design, automated measurements, and limits.
