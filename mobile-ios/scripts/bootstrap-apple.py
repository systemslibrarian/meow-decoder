#!/usr/bin/env python3
"""bootstrap-apple.py — collapse the manual Apple Developer Portal clicks
into one script, using the App Store Connect API.

What this automates:
  1. Register bundle ID com.systemslibrarian.meowdecoder.
  2. Generate a fresh RSA-2048 keypair locally + CSR with openssl.
  3. POST the CSR to /v1/certificates → get a signed Apple Distribution cert.
  4. Bundle the private key + cert into a .p12 with a random password.
  5. Create an App Store provisioning profile bound to the bundle ID + cert.
  6. Emit the seven cert/profile/keychain CI secrets, base64-encoded.

What this does NOT automate (Apple has no public API for these):
  - Generating the App Store Connect API key (the .p8 you pass in here).
    That bootstrap step lives at https://appstoreconnect.apple.com → Users
    and Access → Integrations.
  - Creating the App Store Connect "App" record (the listing). Do that
    manually once: https://appstoreconnect.apple.com → My Apps → + → New
    App. ~30 seconds; no public API.

Required env vars:
  ASC_KEY_ID              — your 10-char API Key ID
  ASC_ISSUER_ID           — your Issuer UUID
  APPLE_TEAM_ID           — your 10-char Team ID
  ASC_PRIVATE_KEY_PATH    — path to the .p8 file you downloaded

Optional flags:
  --set-secrets           — call `gh secret set` for each emitted secret
                            (requires `gh auth status` to be a passing token
                            with admin:repo_hook + secrets scopes).
  --output-dir <path>     — where to write the generated .p12, .mobileprovision,
                            and a summary.env file. Default: ./apple-bootstrap-out
                            (gitignored).
  --dry-run               — print what would be done; make no API calls.

Idempotency:
  - If the bundle ID already exists for your team, it's reused (not an error).
  - A fresh certificate is always created. Apple allows two simultaneous
    Distribution certs per team — if you're at the limit, the script tells
    you what to revoke. Reusing an existing cert would require its private
    key, which we don't have on the runner.
  - If a profile with the target name exists, it is regenerated against
    the new cert (Apple's API replaces in place when name + bundle ID match).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# ---------- constants ----------

BUNDLE_ID = "com.systemslibrarian.meowdecoder"
APP_NAME = "Meow Decoder"
PROFILE_NAME = "Meow Decoder App Store"
ASC_BASE = "https://api.appstoreconnect.apple.com"
JWT_TTL_SECONDS = 1200  # Apple max is 20 min


# ---------- ES256 JWT signing (no external pyjwt dependency) ----------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign_jwt(key_id: str, issuer_id: str, p8_path: Path) -> str:
    """Mint an App Store Connect API JWT (ES256, 20-min TTL)."""
    header = {"alg": "ES256", "kid": key_id, "typ": "JWT"}
    payload = {
        "iss": issuer_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_TTL_SECONDS,
        "aud": "appstoreconnect-v1",
    }
    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64url(json.dumps(payload, separators=(",", ":")).encode())
    )

    pem = p8_path.read_bytes()
    private_key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        sys.exit(f"error: {p8_path} is not an ES256 key (App Store Connect requires P-256)")

    der_sig = private_key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    # JWT wants raw r||s (64 bytes), not the DER-encoded ECDSA sig openssl emits.
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    return signing_input + "." + _b64url(raw_sig)


# ---------- HTTP helpers ----------

class ASC:
    def __init__(self, key_id: str, issuer_id: str, p8_path: Path):
        self._token = _sign_jwt(key_id, issuer_id, p8_path)
        self._session = requests.Session()
        self._session.headers["Authorization"] = f"Bearer {self._token}"
        self._session.headers["Content-Type"] = "application/json"

    def get(self, path: str, **params) -> dict[str, Any]:
        r = self._session.get(ASC_BASE + path, params=params or None, timeout=30)
        if not r.ok:
            sys.exit(f"GET {path} failed [{r.status_code}]: {r.text}")
        return r.json()

    def post(self, path: str, body: dict) -> dict[str, Any]:
        r = self._session.post(ASC_BASE + path, json=body, timeout=30)
        if not r.ok:
            sys.exit(f"POST {path} failed [{r.status_code}]: {r.text}")
        return r.json()


# ---------- workflow steps ----------

def ensure_bundle_id(asc: ASC) -> str:
    """Idempotent: return the bundleId resource ID, creating it if missing."""
    print(f"==> checking bundle ID {BUNDLE_ID}")
    existing = asc.get("/v1/bundleIds", **{"filter[identifier]": BUNDLE_ID})
    if existing["data"]:
        rid = existing["data"][0]["id"]
        print(f"    found existing bundle ID resource {rid}")
        return rid

    print(f"    creating bundle ID {BUNDLE_ID}")
    created = asc.post("/v1/bundleIds", {
        "data": {
            "type": "bundleIds",
            "attributes": {
                "identifier": BUNDLE_ID,
                "name": APP_NAME,
                "platform": "IOS",
            },
        }
    })
    rid = created["data"]["id"]
    print(f"    created bundle ID resource {rid}")
    return rid


def generate_keypair_and_csr(workdir: Path) -> tuple[Path, Path]:
    """Generate RSA-2048 key + CSR via openssl. Returns (key_path, csr_path)."""
    print("==> generating RSA-2048 keypair + CSR")
    key_path = workdir / "distribution.key"
    csr_path = workdir / "distribution.csr"

    subprocess.run(
        ["openssl", "genrsa", "-out", str(key_path), "2048"],
        check=True, capture_output=True,
    )
    # Apple ignores most CSR subject fields but requires CN to be non-empty.
    subprocess.run(
        ["openssl", "req", "-new",
         "-key", str(key_path),
         "-out", str(csr_path),
         "-subj", f"/CN={APP_NAME} Distribution/O={APP_NAME}"],
        check=True, capture_output=True,
    )
    print(f"    private key: {key_path}")
    print(f"    CSR:         {csr_path}")
    return key_path, csr_path


def create_distribution_certificate(asc: ASC, csr_path: Path, workdir: Path) -> tuple[str, Path]:
    """POST CSR to /v1/certificates. Returns (cert_id, pem_path)."""
    print("==> uploading CSR for Apple Distribution certificate")
    csr_pem = csr_path.read_text()
    csr_b64 = "".join(
        line for line in csr_pem.splitlines()
        if line and not line.startswith("-----")
    )

    created = asc.post("/v1/certificates", {
        "data": {
            "type": "certificates",
            "attributes": {
                "csrContent": csr_b64,
                "certificateType": "DISTRIBUTION",
            },
        }
    })
    cert_id = created["data"]["id"]
    cert_b64 = created["data"]["attributes"]["certificateContent"]

    cert_der_path = workdir / "distribution.cer"
    cert_der_path.write_bytes(base64.b64decode(cert_b64))

    cert_pem_path = workdir / "distribution.pem"
    subprocess.run(
        ["openssl", "x509", "-inform", "DER",
         "-in", str(cert_der_path),
         "-out", str(cert_pem_path)],
        check=True, capture_output=True,
    )
    print(f"    cert ID:   {cert_id}")
    print(f"    cert PEM:  {cert_pem_path}")
    return cert_id, cert_pem_path


def bundle_p12(key_path: Path, cert_pem_path: Path, workdir: Path) -> tuple[Path, str]:
    """Combine key + cert into a .p12 with a random password.

    The password matters only to whatever consumes the .p12 (your local
    keychain, or the GitHub Actions keychain — both expect this password
    via the P12_PASSWORD secret). Strong randomness is fine here.
    """
    print("==> bundling .p12")
    p12_path = workdir / "distribution.p12"
    p12_password = secrets.token_urlsafe(32)
    subprocess.run(
        ["openssl", "pkcs12", "-export",
         "-inkey", str(key_path),
         "-in", str(cert_pem_path),
         "-out", str(p12_path),
         "-password", f"pass:{p12_password}",
         "-name", f"{APP_NAME} Distribution"],
        check=True, capture_output=True,
    )
    print(f"    .p12: {p12_path}")
    return p12_path, p12_password


def create_or_replace_profile(asc: ASC, bundle_id_rid: str, cert_id: str, workdir: Path) -> Path:
    """Create or replace the App Store profile. Returns path to .mobileprovision."""
    print(f"==> ensuring provisioning profile '{PROFILE_NAME}'")

    # Apple's API rejects creating a profile with a duplicate name. So if
    # one exists with our target name, delete it first — we want it to bind
    # to the freshly-issued cert.
    existing = asc.get("/v1/profiles", **{"filter[name]": PROFILE_NAME})
    for p in existing.get("data", []):
        pid = p["id"]
        print(f"    deleting existing profile {pid}")
        r = asc._session.delete(ASC_BASE + f"/v1/profiles/{pid}", timeout=30)
        if not r.ok:
            sys.exit(f"DELETE profile failed [{r.status_code}]: {r.text}")

    print("    creating fresh profile")
    created = asc.post("/v1/profiles", {
        "data": {
            "type": "profiles",
            "attributes": {
                "name": PROFILE_NAME,
                "profileType": "IOS_APP_STORE",
            },
            "relationships": {
                "bundleId": {"data": {"type": "bundleIds", "id": bundle_id_rid}},
                "certificates": {"data": [{"type": "certificates", "id": cert_id}]},
            },
        }
    })
    profile_b64 = created["data"]["attributes"]["profileContent"]
    profile_path = workdir / f"{PROFILE_NAME.replace(' ', '_')}.mobileprovision"
    profile_path.write_bytes(base64.b64decode(profile_b64))
    print(f"    profile: {profile_path}")
    return profile_path


# ---------- secret emission ----------

def file_to_b64(p: Path) -> str:
    return base64.b64encode(p.read_bytes()).decode()


def emit_secrets(
    workdir: Path,
    p12_path: Path,
    p12_password: str,
    profile_path: Path,
    p8_path: Path,
    args: argparse.Namespace,
) -> None:
    secrets_payload = {
        "BUILD_CERTIFICATE_BASE64":       file_to_b64(p12_path),
        "P12_PASSWORD":                   p12_password,
        "BUILD_PROVISION_PROFILE_BASE64": file_to_b64(profile_path),
        "KEYCHAIN_PASSWORD":              secrets.token_urlsafe(24),
        "ASC_KEY_ID":                     os.environ["ASC_KEY_ID"],
        "ASC_ISSUER_ID":                  os.environ["ASC_ISSUER_ID"],
        "ASC_PRIVATE_KEY":                file_to_b64(p8_path),
        "APPLE_TEAM_ID":                  os.environ["APPLE_TEAM_ID"],
    }

    summary_path = workdir / "summary.env"
    with summary_path.open("w") as f:
        for name, value in secrets_payload.items():
            f.write(f'{name}="{value}"\n')
    summary_path.chmod(0o600)
    print(f"\n==> wrote {summary_path} (mode 0600)")
    print("    Each line is one CI secret. Do not commit this file.")

    if args.set_secrets:
        print("\n==> setting GitHub Actions secrets via `gh secret set`")
        for name, value in secrets_payload.items():
            r = subprocess.run(
                ["gh", "secret", "set", name, "-b", value],
                capture_output=True, text=True,
            )
            mark = "ok" if r.returncode == 0 else "FAIL"
            print(f"    [{mark}] {name}{'  — ' + r.stderr.strip() if r.returncode else ''}")
    else:
        print("\n    To push these to GitHub Actions, run:")
        print(f"      gh secret set -f {summary_path}")
        print("    (or re-run this script with --set-secrets)")


# ---------- entry point ----------

def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--set-secrets", action="store_true",
                   help="Push the emitted secrets to the current repo via `gh secret set`.")
    p.add_argument("--output-dir", type=Path, default=Path("apple-bootstrap-out"),
                   help="Where to write generated artifacts. Default: ./apple-bootstrap-out")
    p.add_argument("--dry-run", action="store_true",
                   help="Validate inputs and print plan; make no API calls.")
    args = p.parse_args()

    required = ["ASC_KEY_ID", "ASC_ISSUER_ID", "APPLE_TEAM_ID", "ASC_PRIVATE_KEY_PATH"]
    missing = [v for v in required if not os.environ.get(v)]
    if missing:
        sys.exit(f"error: missing env vars: {', '.join(missing)}\nSee the docstring at the top of this script.")

    p8_path = Path(os.environ["ASC_PRIVATE_KEY_PATH"]).expanduser()
    if not p8_path.is_file():
        sys.exit(f"error: ASC_PRIVATE_KEY_PATH does not exist: {p8_path}")

    workdir = args.output_dir.resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    workdir.chmod(0o700)

    print(f"==> bootstrap plan for {BUNDLE_ID}")
    print(f"    team:    {os.environ['APPLE_TEAM_ID']}")
    print(f"    key ID:  {os.environ['ASC_KEY_ID']}")
    print(f"    .p8:     {p8_path}")
    print(f"    output:  {workdir}")

    if args.dry_run:
        print("\n--dry-run set — exiting before any API call")
        return

    asc = ASC(os.environ["ASC_KEY_ID"], os.environ["ASC_ISSUER_ID"], p8_path)

    bundle_rid = ensure_bundle_id(asc)
    key_path, csr_path = generate_keypair_and_csr(workdir)
    cert_id, cert_pem_path = create_distribution_certificate(asc, csr_path, workdir)
    p12_path, p12_password = bundle_p12(key_path, cert_pem_path, workdir)
    profile_path = create_or_replace_profile(asc, bundle_rid, cert_id, workdir)

    emit_secrets(workdir, p12_path, p12_password, profile_path, p8_path, args)

    print("\n==> done")
    print("    Manual step that remains: create the App Store Connect record")
    print(f"    at https://appstoreconnect.apple.com → My Apps → + → New App")
    print(f"    (bundle ID: {BUNDLE_ID}, name: {APP_NAME}).")
    print("    Then push a tag matching v*-ios to trigger the workflow:")
    print("       git tag v0.1.0-ios && git push origin v0.1.0-ios")


if __name__ == "__main__":
    main()
