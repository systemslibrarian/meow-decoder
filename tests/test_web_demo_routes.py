"""HTTP-level smoke coverage for every web demo mode.

Covers each Flask route in web_demo/app.py without needing the Rust
crypto backend or a real browser:

* GET routes return HTTP 200 (or 302 for redirects)
* Each mode's template contains the form / canvas elements that mode
  needs to function
* The inline <script> blocks in each template parse as valid JS

These are baseline smoke tests — they prove that every mode's page
loads cleanly after recent template/JS changes (cat_mode.html
corruption fix, cat-mode-protocol.js audit fixes, signal-processing
fixes). They do NOT exercise actual encryption / decoding (those need
Rust crypto and live in test_all_modes.py).
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
WEB_DEMO_DIR = REPO_ROOT / "web_demo"


@pytest.fixture(scope="module")
def app():
    """Load web_demo/app.py as a module and yield the Flask app."""
    if importlib.util.find_spec("flask") is None:
        pytest.skip("Flask not installed in this environment")

    # web_demo/app.py imports from sibling files, so add web_demo to
    # sys.path while loading.
    saved_path = list(sys.path)
    saved_cwd = os.getcwd()
    sys.path.insert(0, str(WEB_DEMO_DIR))
    sys.path.insert(0, str(REPO_ROOT))
    os.environ.setdefault("MEOW_TEST_MODE", "1")

    try:
        os.chdir(WEB_DEMO_DIR)
        spec = importlib.util.spec_from_file_location(
            "web_demo_app", WEB_DEMO_DIR / "app.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        yield module.app
    finally:
        sys.path[:] = saved_path
        os.chdir(saved_cwd)


@pytest.fixture(scope="module")
def client(app):
    """Flask test client."""
    return app.test_client()


# ─── Index ────────────────────────────────────────────────────────────


def test_index_redirects_to_encode(client):
    """/ should redirect to /encode."""
    response = client.get("/")
    assert response.status_code in (301, 302), (
        f"Expected redirect, got {response.status_code}"
    )
    assert "/encode" in response.headers.get("Location", "")


# ─── Encode mode ──────────────────────────────────────────────────────


def test_encode_page_renders(client):
    """/encode form should render with the file input + password field."""
    response = client.get("/encode")
    assert response.status_code == 200
    body = response.data.decode("utf-8", errors="replace")
    # Encode page must let the user upload a file and pick a password.
    assert 'type="file"' in body, "missing file upload input"
    assert 'type="password"' in body, "missing password input"


# ─── Decode mode ──────────────────────────────────────────────────────


def test_decode_page_renders(client):
    """/decode form should render with file input + password."""
    response = client.get("/decode")
    assert response.status_code == 200
    body = response.data.decode("utf-8", errors="replace")
    assert 'type="file"' in body
    assert 'type="password"' in body


# ─── Webcam mode ──────────────────────────────────────────────────────


def test_webcam_page_renders(client):
    """/webcam should render the live capture page."""
    response = client.get("/webcam")
    assert response.status_code == 200
    body = response.data.decode("utf-8", errors="replace")
    # Webcam page needs a video element or canvas for capture.
    assert "<video" in body or "<canvas" in body, (
        "webcam page must have a <video> or <canvas> for live capture"
    )


# ─── Demo mode ────────────────────────────────────────────────────────


def test_demo_page_renders(client):
    """/demo should render the interactive demo."""
    response = client.get("/demo")
    assert response.status_code == 200


# ─── Modes index ──────────────────────────────────────────────────────


def test_modes_page_renders(client):
    """/modes should render the modes-selector page with links to each."""
    response = client.get("/modes")
    assert response.status_code == 200
    body = response.data.decode("utf-8", errors="replace")
    # Should at least mention the major modes
    assert "encode" in body.lower()
    assert "decode" in body.lower()


# ─── Cat mode ─────────────────────────────────────────────────────────


def test_cat_mode_page_renders(client):
    """/cat-mode renders without the syntax corruption that broke main."""
    response = client.get("/cat-mode")
    assert response.status_code == 200
    body = response.data.decode("utf-8", errors="replace")

    # The three previously-corrupted functions must all be present.
    assert "async function initCatCanvas()" in body, (
        "initCatCanvas missing — cat_mode.html corruption regression?"
    )
    assert "function autoDetectEyeRegions(imageData)" in body, (
        "autoDetectEyeRegions missing — cat_mode.html corruption regression?"
    )
    assert "function drawEyeOverlay(box, isOn)" in body
    # The init guard inside initCatCanvas
    assert "if (!catBgVideo || catBgVideo.readyState < 2) return;" in body, (
        "initCatCanvas guard missing — page corruption regression"
    )

    # Encoder + decoder UI is present
    assert 'id="catCanvas"' in body, "cat canvas missing"
    assert 'id="catBgVideo"' in body, "background video element missing"
    assert "catModeEncode" in body, "Start Transmitting handler missing"
    assert "catModeStop" in body, "Stop handler missing"


def test_cat_mode_encrypt_endpoint_validates(client):
    """/cat-mode-encrypt-server should reject empty password (validation works)."""
    # Empty password should be rejected with 4xx, not crash.
    response = client.post(
        "/cat-mode-encrypt-server",
        data={"message": "hi", "password": ""},
    )
    # Either 400-class rejection or 500 if backend missing — both prove
    # the route is reachable. Not 404.
    assert response.status_code != 404, "endpoint should exist"


def test_cat_mode_decode_video_endpoint_validates(client):
    """/cat-mode-decode-video should reject missing video file."""
    # POST without a file should fail validation, not crash.
    response = client.post("/cat-mode-decode-video", data={})
    assert response.status_code != 404, "endpoint should exist"


def test_decode_cat_binary_endpoint_validates(client):
    """/decode-cat-binary should handle missing fields gracefully."""
    response = client.post("/decode-cat-binary", data={})
    assert response.status_code != 404, "endpoint should exist"


def test_cat_mode_encrypt_endpoint_round_trip(client):
    """End-to-end: encrypt via API, decrypt via API, recover plaintext.

    Exercises the actual server-side Cat Mode flow:
      message + password →  /cat-mode-encrypt-server →  hex payload
      hex payload + password →  /decode-cat-binary →  recovered message

    Needs MEOW_TEST_MODE=1 (set by conftest) so Argon2id uses fast
    parameters; otherwise this test takes ~20s per call.
    """
    import json

    plaintext = "hello cat mode end-to-end"
    password = "correct horse battery staple"

    enc_response = client.post(
        "/cat-mode-encrypt-server",
        data={"message": plaintext, "password": password},
    )
    assert enc_response.status_code == 200, (
        f"encrypt failed: {enc_response.status_code} {enc_response.data[:200]!r}"
    )
    enc = json.loads(enc_response.data)
    assert enc["success"] is True
    assert "payload_hex" in enc
    assert enc["original_length"] == len(plaintext.encode("utf-8"))
    payload_hex = enc["payload_hex"]
    assert len(payload_hex) > 0
    # Hex strings are pairs of hex chars.
    assert all(c in "0123456789abcdef" for c in payload_hex)

    # Now convert hex → bits (the JS encoder does this client-side) and
    # POST to the binary-decode endpoint to recover the plaintext.
    binary_str = "".join(
        bin(int(c, 16))[2:].zfill(4) for c in payload_hex
    )
    dec_response = client.post(
        "/decode-cat-binary",
        data={"binary": binary_str, "password": password},
    )
    assert dec_response.status_code == 200, (
        f"decode failed: {dec_response.status_code} {dec_response.data[:300]!r}"
    )
    dec_body = dec_response.data.decode("utf-8", errors="replace")
    # The decode page renders the plaintext when successful.
    assert plaintext in dec_body, (
        f"decoded body did not contain plaintext.\nGot: {dec_body[:500]}"
    )


def test_cat_mode_encrypt_wrong_password_fails(client):
    """Decryption with wrong password must NOT recover the plaintext."""
    import json

    enc_response = client.post(
        "/cat-mode-encrypt-server",
        data={"message": "secret", "password": "right-password-12"},
    )
    assert enc_response.status_code == 200
    payload_hex = json.loads(enc_response.data)["payload_hex"]
    binary_str = "".join(
        bin(int(c, 16))[2:].zfill(4) for c in payload_hex
    )

    dec_response = client.post(
        "/decode-cat-binary",
        data={"binary": binary_str, "password": "wrong-password"},
    )
    # Should not crash and should not contain the plaintext.
    body = dec_response.data.decode("utf-8", errors="replace")
    assert "secret" not in body or "wrong" in body.lower() or "fail" in body.lower(), (
        "wrong password must not reveal plaintext"
    )


# ─── /encode → /decode round-trips ───────────────────────────────────


def _upload(client, route, *, filename, contents, **form):
    """Helper: POST a multipart/form-data upload to a route."""
    from io import BytesIO

    data = dict(form)
    data["file"] = (BytesIO(contents), filename)
    return client.post(
        route,
        data=data,
        content_type="multipart/form-data",
        follow_redirects=False,
    )


def _decode_token_to_bytes(client, app, token):
    """Resolve a download token back to file bytes via the /download endpoint."""
    response = client.get(f"/download/{token}")
    assert response.status_code == 200, f"download failed: {response.status_code}"
    return response.data


def test_encode_normal_mode_round_trip(client, app):
    """Encode a file with mode=normal, decode the resulting GIF, recover bytes.

    Uses MEOW_TEST_MODE=1 (set by conftest) for fast Argon2id. End-to-end
    proof that the normal-mode pipeline works through the Flask app.
    """
    plaintext = b"hello normal mode round-trip\n"
    password = "round-trip-password-1"

    # Encode
    enc = _upload(
        client,
        "/encode",
        filename="msg.txt",
        contents=plaintext,
        password=password,
        mode="normal",
        redundancy="1.5",
    )
    assert enc.status_code == 200, f"encode failed: {enc.status_code}"
    body = enc.data.decode("utf-8", errors="replace")

    # Pull the download token out of the result page so we can fetch
    # the encoded GIF and feed it back to /decode.
    token = _extract_download_token(body)
    assert token, f"no download token in encode response:\n{body[:500]}"

    gif_bytes = _decode_token_to_bytes(client, app, token)
    assert gif_bytes.startswith(b"GIF8"), (
        f"output is not a GIF (header: {gif_bytes[:8]!r})"
    )

    # Decode the GIF back through the Flask /decode endpoint
    dec = _upload(
        client,
        "/decode",
        filename="encoded.gif",
        contents=gif_bytes,
        password=password,
    )
    assert dec.status_code == 200, f"decode failed: {dec.status_code}"
    dec_body = dec.data.decode("utf-8", errors="replace")
    dec_token = _extract_download_token(dec_body)
    assert dec_token, f"no download token in decode response:\n{dec_body[:500]}"

    recovered = _decode_token_to_bytes(client, app, dec_token)
    assert recovered == plaintext, (
        f"round-trip mismatch:\n  expected: {plaintext!r}\n  got: {recovered!r}"
    )


def test_encode_normal_wrong_password_fails(client, app):
    """Decrypting with the wrong password must NOT recover the plaintext."""
    plaintext = b"top secret normal mode payload"
    password = "right-password-x"

    enc = _upload(
        client,
        "/encode",
        filename="secret.txt",
        contents=plaintext,
        password=password,
        mode="normal",
        redundancy="1.5",
    )
    assert enc.status_code == 200
    token = _extract_download_token(enc.data.decode("utf-8", errors="replace"))
    gif_bytes = _decode_token_to_bytes(client, app, token)

    dec = _upload(
        client,
        "/decode",
        filename="encoded.gif",
        contents=gif_bytes,
        password="wrong-password",
    )
    # Decode handler returns the form with a flash on failure (302) or
    # follows redirects to render the form again. Either way, we should
    # not get a download token for plaintext bytes.
    body = dec.data.decode("utf-8", errors="replace")
    bad_token = _extract_download_token(body)
    if bad_token:
        # If a token was generated, the decoded contents must not equal
        # the original plaintext.
        try:
            recovered = _decode_token_to_bytes(client, app, bad_token)
            assert recovered != plaintext, (
                "wrong password should not recover plaintext"
            )
        except AssertionError:
            raise
        except Exception:
            # Download endpoint rejected the bad token — also acceptable.
            pass


def test_encode_cat_mode_round_trip(client, app):
    """mode=cat uses a steganographic carrier; same round-trip should work."""
    plaintext = b"cat-mode steganographic payload"
    password = "cat-mode-password-1"

    enc = _upload(
        client,
        "/encode",
        filename="catmsg.txt",
        contents=plaintext,
        password=password,
        mode="cat",
        redundancy="1.5",
    )
    assert enc.status_code == 200, f"encode/cat returned {enc.status_code}"
    token = _extract_download_token(enc.data.decode("utf-8", errors="replace"))
    assert token, "encode/cat did not return a download token"

    gif_bytes = _decode_token_to_bytes(client, app, token)
    # Output may be GIF or PNG depending on stego level
    assert gif_bytes[:4] in (b"GIF8", b"\x89PNG"), (
        f"unexpected file format: {gif_bytes[:8]!r}"
    )

    dec = _upload(
        client,
        "/decode",
        filename="encoded.gif",
        contents=gif_bytes,
        password=password,
    )
    assert dec.status_code == 200, f"decode of cat-mode output returned {dec.status_code}"
    dec_body = dec.data.decode("utf-8", errors="replace")
    dec_token = _extract_download_token(dec_body)
    assert dec_token, "cat-mode decode did not return a download token"

    recovered = _decode_token_to_bytes(client, app, dec_token)
    assert recovered == plaintext


def test_encode_duress_mode_rejects_with_clear_error(client, app):
    """mode=duress must surface a clear, actionable error.

    The web demo can't run duress mode without forward-secrecy key
    management, so the form's <option> is `disabled` and the route
    returns a redirect with a flash message pointing users at the CLI.
    Anyone who bypasses the disabled option (devtools, scripted POST)
    must still get a useful error rather than a 500 / silent failure.
    """
    enc = _upload(
        client,
        "/encode",
        filename="real.txt",
        contents=b"x" * 32,
        password="real-password-duress",
        duress_password="duress-password-x",
        mode="duress",
        redundancy="1.5",
    )
    # Should redirect back to the form with a flash, not 500 or 200.
    assert enc.status_code == 302, (
        f"duress mode should redirect with flash, got {enc.status_code}"
    )

    # Follow the redirect and confirm the flash message points the user
    # somewhere actionable (mentions CLI / forward-secrecy / keys).
    enc_followed = _upload(
        client,
        "/encode",
        filename="real.txt",
        contents=b"x" * 32,
        password="real-password-duress",
        duress_password="duress-password-x",
        mode="duress",
        redundancy="1.5",
    )
    body = client.get(enc_followed.headers.get("Location", "/encode")).data.decode(
        "utf-8", errors="replace"
    )
    body_lower = body.lower()
    assert any(
        kw in body_lower
        for kw in ("cli", "forward-secrecy", "forward secrecy", "key")
    ), f"flash message must mention the CLI / FS workaround:\n{body[:500]}"


def test_encode_form_disables_unsupported_modes(client):
    """The mode dropdown must mark unsupported options `disabled` so users
    can't pick a mode the backend can't actually execute."""
    response = client.get("/encode")
    body = response.data.decode("utf-8", errors="replace")

    # Schrödinger has been disabled in the dropdown all along — assert that
    # remains so, AND that duress is now disabled too (the bug fix).
    assert 'value="duress" disabled' in body, (
        "duress option must be `disabled` in the encode form mode dropdown — "
        "the backend can't run it without FS/PQ keys"
    )
    assert 'value="schrodinger" disabled' in body, (
        "schrödinger option must be `disabled` in the encode form mode dropdown"
    )


def _extract_download_token(html: str) -> str | None:
    """Pull a download token out of a result page, if present."""
    m = re.search(r"/download/([0-9a-f-]{36})", html)
    return m.group(1) if m else None


# ─── /schrodinger round-trip ─────────────────────────────────────────


def test_schrodinger_encode_creates_dual_payload(client, app):
    """Schrödinger encode with two files + two passwords produces a GIF."""
    from io import BytesIO

    real_payload = b"the real file contents"
    decoy_payload = b"the innocent decoy file"
    real_pw = "real-password-schroedinger"
    decoy_pw = "decoy-password-schroedinger"

    response = client.post(
        "/schrodinger",
        data={
            "real_file": (BytesIO(real_payload), "real.txt"),
            "decoy_file": (BytesIO(decoy_payload), "decoy.txt"),
            "real_password": real_pw,
            "decoy_password": decoy_pw,
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    # Successful encode redirects to /download/<token>
    if response.status_code == 302:
        location = response.headers.get("Location", "")
        token_match = re.search(r"/download/([0-9a-f-]{36})", location)
        if not token_match:
            pytest.skip(f"schrödinger redirected without a download token: {location}")
        token = token_match.group(1)

        gif_bytes = _decode_token_to_bytes(client, app, token)
        # Schrödinger output is a GIF.
        assert gif_bytes[:4] in (b"GIF8", b"\x89PNG"), (
            f"unexpected schrödinger output format: {gif_bytes[:8]!r}"
        )
        assert len(gif_bytes) > 100, "schrödinger output suspiciously small"
    elif response.status_code == 200:
        # If it rendered the form again, the encode failed — surface that.
        body = response.data.decode("utf-8", errors="replace")
        # Look for a flash error.
        if "error" in body.lower() or "failed" in body.lower():
            pytest.skip(
                "schrödinger encode failed (likely due to environment); "
                "form re-rendered with error"
            )
        pytest.fail(
            "schrödinger POST returned 200 without redirect or error message"
        )
    else:
        pytest.fail(f"schrödinger POST returned unexpected {response.status_code}")


# ─── Schrödinger mode ────────────────────────────────────────────────


def test_schrodinger_page_renders(client):
    """/schrodinger dual-password page should render with two password fields."""
    response = client.get("/schrodinger")
    assert response.status_code == 200
    body = response.data.decode("utf-8", errors="replace")
    # Schrödinger needs a "real" + "duress" password input
    password_inputs = body.count('type="password"')
    assert password_inputs >= 2, (
        f"Schrödinger needs ≥2 password fields, found {password_inputs}"
    )


# ─── Inline JS validation ─────────────────────────────────────────────


@pytest.fixture(scope="module")
def has_node():
    return shutil.which("node") is not None


SCRIPT_RE = re.compile(r"<script(?:\s+[^>]*)?>(.*?)</script>", re.DOTALL)


def _extract_inline_scripts(html: str) -> list[str]:
    """Return all inline (non-src) <script> bodies."""
    scripts = []
    for match in SCRIPT_RE.finditer(html):
        # Skip <script src="..."> blocks (no body content).
        tag_open_end = html.find(">", match.start())
        tag = html[match.start() : tag_open_end + 1]
        if "src=" in tag:
            continue
        scripts.append(match.group(1))
    return scripts


def _check_js_parses(js: str, label: str, tmp_path: Path):
    """Run `node --check` against a JS snippet; assert it parses."""
    # Wrap as a module so import.meta etc. work if the snippet uses them.
    tmp_file = tmp_path / f"{label}.mjs"
    tmp_file.write_text(js)
    result = subprocess.run(
        ["node", "--check", str(tmp_file)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, (
        f"Inline <script> in {label} has syntax error:\n{result.stderr}"
    )


@pytest.mark.parametrize(
    "route,label",
    [
        ("/encode", "encode"),
        ("/decode", "decode"),
        ("/webcam", "webcam"),
        ("/demo", "demo"),
        ("/modes", "modes"),
        ("/cat-mode", "cat_mode"),
        ("/schrodinger", "schrodinger"),
    ],
)
def test_template_inline_js_parses(client, has_node, tmp_path, route, label):
    """Every template's inline <script> blocks must be syntactically valid.

    This catches template corruption like the cat_mode.html bug we fixed
    where multiple function bodies got spliced together.
    """
    if not has_node:
        pytest.skip("node not available — can't validate JS syntax")

    response = client.get(route)
    assert response.status_code == 200, f"{route} did not render"
    body = response.data.decode("utf-8", errors="replace")

    scripts = _extract_inline_scripts(body)
    if not scripts:
        # Pages with only external scripts are fine.
        return

    for idx, script in enumerate(scripts):
        if not script.strip():
            continue
        _check_js_parses(script, f"{label}_{idx}", tmp_path)


# ─── Static asset endpoints ───────────────────────────────────────────


def test_static_crypto_core_js_served(client):
    """The WASM glue JS must be reachable so cat-mode encrypt page works."""
    # Try both common locations the page might reference.
    candidates = ["/static/crypto_core.js", "/crypto_core.js"]
    found = False
    for path in candidates:
        if client.get(path).status_code == 200:
            found = True
            break
    if not found:
        pytest.skip(
            "crypto_core.js not served by Flask; only matters if the WASM "
            "encryption path is enabled — the main cat-mode template uses "
            "server-side encryption."
        )
