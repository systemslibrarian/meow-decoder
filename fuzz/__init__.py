"""
Fuzzing targets for Meow Decoder.

Uses Atheris (Google's coverage-guided Python fuzzer) and AFL++.

To run locally:
    pip install atheris
    python fuzz/fuzz_manifest.py fuzz/corpus/manifest

To run AFL++:
    pip install python-afl
    py-afl-fuzz -i fuzz/afl-corpus -o fuzz/afl-output -- python fuzz/afl_fuzz_manifest.py
"""
