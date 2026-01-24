#!/usr/bin/env python3
"""Docker end-to-end demo.

Creates a small text file, encodes it to an animated QR GIF, then decodes it back.
Outputs are written to /data (mounted volume) so you can inspect them on the host.
"""

from pathlib import Path
import os
import sys

from meow_decoder.encode import encode_file
from meow_decoder.decode_gif import decode_gif

DATA_DIR = Path(os.environ.get("MEOW_DATA_DIR", "/data")).resolve()
PASSWORD = os.environ.get("MEOW_PASSWORD", "meow-meow")
MESSAGE = os.environ.get("MEOW_MESSAGE", "Meow Decoder says hello 🐾\n")

def main() -> int:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    input_path = DATA_DIR / "secret.txt"
    gif_path = DATA_DIR / "secret.gif"
    out_path = DATA_DIR / "recovered.txt"

    input_path.write_text(MESSAGE, encoding="utf-8")

    print("🐱 Docker demo starting")
    print(f"  Input:  {input_path}")
    print(f"  Output GIF: {gif_path}")
    print(f"  Recovered:  {out_path}")
    print()

    stats_enc = encode_file(
        input_path=input_path,
        output_path=gif_path,
        password=PASSWORD,
        forward_secrecy=True,
        use_pq=False,
        verbose=True,
    )

    print("\n✅ Encode complete")
    if isinstance(stats_enc, dict):
        print(f"  Frames: {stats_enc.get('frames', 'n/a')}")
        print(f"  Droplets: {stats_enc.get('droplets', 'n/a')}")
    print()

    stats_dec = decode_gif(
        input_path=gif_path,
        output_path=out_path,
        password=PASSWORD,
        verbose=True,
    )

    print("\n✅ Decode complete")
    if out_path.exists():
        recovered = out_path.read_text(encoding="utf-8", errors="replace")
        ok = recovered == MESSAGE
        print(f"  Match: {ok}")
        if not ok:
            print("----- recovered -----")
            print(recovered)
            print("---------------------")
    else:
        print("❌ No recovered output was produced.")
        return 2

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
