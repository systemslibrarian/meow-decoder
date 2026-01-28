name: Security CI

on:
  push:
    branches: ["main"]
  pull_request:
    branches: ["main"]
  schedule:
    - cron: "15 6 * * 1" # Mondays 06:15 UTC (strict audits)

permissions:
  contents: read

jobs:
  security:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install system dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y libzbar0 libgl1 libglib2.0-0

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install -r requirements-dev.txt
          pip install -e .

      # -----------------------
      # Required security tests
      # -----------------------
      - name: Security-focused tests (required)
        run: |
          pytest tests/test_security.py tests/test_adversarial.py \
            -o "addopts=" \
            --cov=meow_decoder.crypto \
            --cov=meow_decoder.fountain \
            --cov=meow_decoder.frame_mac \
            --cov-config=.coveragerc-security \
            --cov-report=term \
            --cov-fail-under=70 \
            -v
        env:
          MEOW_TEST_MODE: "1"

      # -----------------------
      # Bandit (report + fail on real issues if you want)
      # -----------------------
      - name: Bandit scan (report)
        run: |
          pip install "bandit[toml]"
          bandit -r meow_decoder/ -f json -o bandit-report.json || true
          # Fail only on HIGH severity + HIGH confidence
          bandit -r meow_decoder/ -lll -iii
          
      - name: Upload Bandit report
        uses: actions/upload-artifact@v4
        with:
          name: bandit-report
          path: bandit-report.json

      # -----------------------
      # pip-audit (warn on PR, strict on schedule)
      # -----------------------
      - name: pip-audit (requirements files)
        run: |
          pip install pip-audit
          set +e
          pip-audit -r requirements.txt -r requirements-dev.txt --desc on > pip-audit.txt 2>&1
          status=$?
          set -e

          echo "pip-audit exit code: $status"
          if [[ "${{ github.event_name }}" == "schedule" ]]; then
            # Strict on scheduled runs
            if [[ $status -ne 0 ]]; then
              cat pip-audit.txt
              exit 1
            fi
          else
            # Warn-only on PR/push
            if [[ $status -ne 0 ]]; then
              echo "::warning::pip-audit found vulnerabilities. See pip-audit.txt artifact."
            fi
          fi

      - name: Upload pip-audit report
        uses: actions/upload-artifact@v4
        with:
          name: pip-audit-report
          path: pip-audit.txt

      # -----------------------
      # Rust audit (only if rust_crypto exists; warn on PR, strict on schedule)
      # -----------------------
      - name: Check for rust backend
        id: has_rust
        run: |
          if [[ -d "rust_crypto" ]]; then
            echo "present=true" >> $GITHUB_OUTPUT
          else
            echo "present=false" >> $GITHUB_OUTPUT
          fi

      - name: Set up Rust
        if: steps.has_rust.outputs.present == 'true'
        uses: dtolnay/rust-toolchain@stable

      - name: cargo-audit
        if: steps.has_rust.outputs.present == 'true'
        run: |
          cargo install cargo-audit
          set +e
          (cd rust_crypto && cargo audit) > cargo-audit.txt 2>&1
          status=$?
          set -e

          if [[ "${{ github.event_name }}" == "schedule" ]]; then
            if [[ $status -ne 0 ]]; then
              cat cargo-audit.txt
              exit 1
            fi
          else
            if [[ $status -ne 0 ]]; then
              echo "::warning::cargo-audit reported issues. See cargo-audit.txt artifact."
            fi
          fi

      - name: Upload cargo-audit report
        if: steps.has_rust.outputs.present == 'true'
        uses: actions/upload-artifact@v4
        with:
          name: cargo-audit-report
          path: cargo-audit.txt