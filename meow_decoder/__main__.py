"""Meow Decoder module entrypoint.

Supports:
  python -m meow_decoder                -> meow-encode behavior
  python -m meow_decoder encode ...     -> meow-encode behavior
  python -m meow_decoder decode ...     -> meow-decode-gif behavior
  python -m meow_decoder schrodinger ...-> meow-schrodinger-encode behavior
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    if os.environ.get("MEOW_STRICT_ISOLATION") == "1":
        from .env_safety import require_safe_environment

        require_safe_environment(strict=True)

    argv = sys.argv[1:]

    if argv and argv[0] in {"decode", "meow-decode-gif"}:
        from .decode_gif import main as decode_main

        sys.argv = [sys.argv[0]] + argv[1:]
        return int(decode_main() or 0)

    if argv and argv[0] in {"schrodinger", "meow-schrodinger-encode"}:
        from .schrodinger_encode import main as schrodinger_main

        sys.argv = [sys.argv[0]] + argv[1:]
        return int(schrodinger_main() or 0)

    if argv and argv[0] in {"encode", "meow-encode"}:
        argv = argv[1:]

    from .encode import main as encode_main

    sys.argv = [sys.argv[0]] + argv
    return int(encode_main() or 0)


if __name__ == "__main__":
    raise SystemExit(main())
