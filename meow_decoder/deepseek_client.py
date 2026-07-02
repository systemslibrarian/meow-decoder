"""
DeepSeek API Client (standalone, zero-dependency)

A small client for DeepSeek's OpenAI-compatible Chat Completions API.
Reads the API key from a local key file (default: ``china.key``, falling back
to ``china.key.txt``) or the ``DEEPSEEK_API_KEY`` environment variable.

Uses only the Python standard library (urllib) so it adds no new dependencies
to the project.

Example:
    from meow_decoder.deepseek_client import DeepSeekClient

    client = DeepSeekClient()
    print(client.chat("Summarize what fountain codes are in one sentence."))

CLI:
    python -m meow_decoder.deepseek_client "your prompt here"
"""

from __future__ import annotations

import glob
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# OpenAI-compatible endpoint. See https://api-docs.deepseek.com/
DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-v4-pro"
DEFAULT_TIMEOUT = 60  # seconds

# Candidate key-file names, searched in order. ``china.key`` is preferred
# because the repo's .gitignore already excludes ``*.key`` from commits.
KEY_FILE_CANDIDATES = ("china.key", "china.key.txt")


class DeepSeekError(RuntimeError):
    """Raised for configuration or API errors."""


def _repo_root() -> Path:
    # meow_decoder/deepseek_client.py -> repo root is two levels up.
    return Path(__file__).resolve().parent.parent


def load_api_key(key_path: Optional[str] = None) -> str:
    """Resolve the DeepSeek API key.

    Resolution order:
      1. Explicit ``key_path`` argument, if given.
      2. ``DEEPSEEK_API_KEY`` environment variable.
      3. A key file (``china.key`` then ``china.key.txt``) located in the
         current working directory or the repository root.

    The file contents are stripped of surrounding whitespace/newlines.
    """
    if key_path:
        p = Path(key_path)
        if not p.is_file():
            raise DeepSeekError(f"Key file not found: {p}")
        return _read_key(p)

    env_key = os.environ.get("DEEPSEEK_API_KEY")
    if env_key and env_key.strip():
        return env_key.strip()

    search_dirs = [Path.cwd(), _repo_root()]
    for directory in search_dirs:
        for name in KEY_FILE_CANDIDATES:
            candidate = directory / name
            if candidate.is_file():
                return _read_key(candidate)

    raise DeepSeekError(
        "No API key found. Set DEEPSEEK_API_KEY, pass key_path, or create a "
        f"'china.key' file in {search_dirs[0]} or {search_dirs[1]}."
    )


def _read_key(path: Path) -> str:
    key = path.read_text(encoding="utf-8").strip()
    if not key:
        raise DeepSeekError(f"Key file is empty: {path}")
    return key


@dataclass
class DeepSeekClient:
    """Minimal client for the DeepSeek Chat Completions API."""

    api_key: Optional[str] = None
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    timeout: int = DEFAULT_TIMEOUT
    key_path: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.api_key:
            self.api_key = load_api_key(self.key_path)
        self.base_url = self.base_url.rstrip("/")

    def chat(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        thinking: bool = False,
        reasoning_effort: Optional[str] = None,
    ) -> str:
        """Send a single-turn prompt and return the assistant's reply text.

        Set ``thinking=True`` to enable V4 Pro's thinking mode; pair it with
        ``reasoning_effort`` ("low" | "medium" | "high") to tune depth.
        """
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        data = self.complete(
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
            thinking=thinking,
            reasoning_effort=reasoning_effort,
        )
        return data["choices"][0]["message"]["content"]

    def complete(
        self,
        messages: list,
        *,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        thinking: bool = False,
        reasoning_effort: Optional[str] = None,
    ) -> dict:
        """Call /chat/completions with raw messages; return the parsed JSON."""
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "stream": False,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if thinking:
            payload["thinking"] = {"type": "enabled"}
        if reasoning_effort is not None:
            payload["reasoning_effort"] = reasoning_effort

        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise DeepSeekError(f"DeepSeek API returned HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise DeepSeekError(f"Could not reach DeepSeek API: {exc.reason}") from exc


REVIEW_SYSTEM_PROMPT = (
    "You are a meticulous security code reviewer for a cryptography-heavy "
    "Python project. Report only concrete, real bugs and security issues. For "
    "each finding give: the relevant code, severity (low/medium/high/critical), "
    "why it is a bug, and a suggested fix. If you find nothing, say so plainly."
)

_USAGE = (
    "Usage:\n"
    "  python -m meow_decoder.deepseek_client <prompt>\n"
    "  python -m meow_decoder.deepseek_client review [-o FILE] <file> [<file> ...]\n\n"
    "Reads the API key from DEEPSEEK_API_KEY or a 'china.key' file.\n"
    f"Model: {DEFAULT_MODEL} (override with DEEPSEEK_MODEL).\n"
    "Thinking mode: set DEEPSEEK_THINKING=1 and optionally "
    "DEEPSEEK_REASONING_EFFORT=low|medium|high.\n\n"
    "review options:\n"
    "  -o, --output FILE   write findings as Markdown to FILE instead of stdout.\n"
    "Glob patterns (e.g. meow_decoder/*.py) are expanded by the script, so they\n"
    "work even in shells (like PowerShell) that don't expand them for you."
)


def _expand_paths(patterns: list) -> list:
    """Expand any glob patterns; pass through literal paths unchanged.

    PowerShell doesn't glob-expand arguments to native programs, so we do it
    here to keep ``meow_decoder/*.py`` working everywhere. Order is preserved
    and duplicates are dropped.
    """
    out: list = []
    seen: set = set()
    for pattern in patterns:
        matches = glob.glob(pattern) if glob.has_magic(pattern) else [pattern]
        # A pattern that matches nothing falls back to itself so the caller
        # still gets a clear "not a file" error rather than silent omission.
        for match in matches or [pattern]:
            if match not in seen:
                seen.add(match)
                out.append(match)
    return out


def _review_files(
    client: "DeepSeekClient",
    paths: list,
    *,
    thinking: bool,
    effort: Optional[str],
    output: Optional[str] = None,
) -> int:
    """Send each file to DeepSeek for a bug/security review.

    Findings are printed to stdout, or, when ``output`` is given, collected into
    a single Markdown document and written to that path.
    """
    rc = 0
    sections: list = []
    for raw in _expand_paths(paths):
        path = Path(raw)
        if not path.is_file():
            print(f"error: not a file: {path}", file=sys.stderr)
            rc = 1
            continue
        code = path.read_text(encoding="utf-8", errors="replace")
        lang = "python" if path.suffix == ".py" else ""
        prompt = (
            f"Review this file ({path}) for bugs and security issues.\n\n" f"```{lang}\n{code}\n```"
        )
        if output:
            print(f"reviewing {path} ...", file=sys.stderr)
        else:
            print(f"\n===== {path} =====")
        try:
            findings = client.chat(
                prompt,
                system=REVIEW_SYSTEM_PROMPT,
                thinking=thinking,
                reasoning_effort=effort,
            )
        except DeepSeekError as exc:
            print(f"error reviewing {path}: {exc}", file=sys.stderr)
            rc = 1
            if output:
                sections.append(f"## `{path}`\n\n_Review failed: {exc}_")
            continue
        if output:
            sections.append(f"## `{path}`\n\n{findings.strip()}")
        else:
            print(findings)

    if output:
        document = (
            f"# DeepSeek code review\n\n"
            f"Model: `{client.model}`\n\n" + "\n\n---\n\n".join(sections) + "\n"
        )
        Path(output).write_text(document, encoding="utf-8")
        print(f"wrote {output} ({len(sections)} file(s) reviewed)", file=sys.stderr)
    return rc


def main(argv: Optional[list] = None) -> int:
    """CLI entry point.

    Forms:
      python -m meow_decoder.deepseek_client <prompt>
      python -m meow_decoder.deepseek_client review <file> [<file> ...]
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(_USAGE, file=sys.stderr)
        return 0 if argv and argv[0] in ("-h", "--help") else 2

    thinking = os.environ.get("DEEPSEEK_THINKING", "").lower() in ("1", "true", "yes")
    effort = os.environ.get("DEEPSEEK_REASONING_EFFORT") or None

    try:
        client = DeepSeekClient(model=os.environ.get("DEEPSEEK_MODEL", DEFAULT_MODEL))
    except DeepSeekError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if argv[0] == "review":
        rest = argv[1:]
        output: Optional[str] = None
        files: list = []
        i = 0
        while i < len(rest):
            arg = rest[i]
            if arg in ("-o", "--output"):
                if i + 1 >= len(rest):
                    print(f"error: {arg} needs a file path", file=sys.stderr)
                    return 2
                output = rest[i + 1]
                i += 2
                continue
            if arg.startswith("--output="):
                output = arg[len("--output=") :]
                i += 1
                continue
            files.append(arg)
            i += 1
        if not files:
            print("error: 'review' needs at least one file path", file=sys.stderr)
            return 2
        # 'review' reasons hard by default; thinking is on unless explicitly off.
        review_thinking = os.environ.get("DEEPSEEK_THINKING", "1").lower() in ("1", "true", "yes")
        return _review_files(
            client,
            files,
            thinking=review_thinking,
            effort=effort or "high",
            output=output,
        )

    prompt = " ".join(argv)
    try:
        print(client.chat(prompt, thinking=thinking, reasoning_effort=effort))
    except DeepSeekError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
