
#!/usr/bin/env bash
# Winflux — run ALL the tests at once and print a summary.
#
#   ./audit_winflux.sh              # full run
#   ./audit_winflux.sh --quick      # compile + pytest only
#   ./audit_winflux.sh --no-smoke   # skip the smoke test
#   ./audit_winflux.sh --no-demos   # skip the demo scripts
#   ./audit_winflux.sh --out DIR    # output directory
#
# Each step writes its own log under the output directory plus a summary.txt.
# Exit code: 0 if every step passed (skips do not count as failures), 1 if any step failed.

set -u

QUICK=0
SMOKE=1
DEMOS=1
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${TEST_OUT:-test-report-$STAMP}"

while (($#)); do
  case "$1" in
    --quick) QUICK=1; SMOKE=0; DEMOS=0 ;;
    --no-smoke) SMOKE=0 ;;
    --no-demos) DEMOS=0 ;;
    --out)
      shift
      OUT="${1:?--out needs a directory}"
      ;;
    -h|--help)
      sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "unknown option: $1 (try --help)" >&2
      exit 2
      ;;
  esac
  shift
done

# Root is the directory containing this script.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT" || exit 1

export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"

PY=""
if command -v python >/dev/null 2>&1; then
  PY="python"
elif command -v python3 >/dev/null 2>&1; then
  PY="python3"
fi

if [[ -z "$PY" ]]; then
  echo "ERROR: neither python nor python3 is available" >&2
  exit 1
fi

PASSED=0
FAILED=0
SKIPPED=0
FAILED_LABELS=()

run_check() {
  local label="$1"
  shift
  local logfile="$OUT/${label//[^a-zA-Z0-9_-]/_}.log"
  local t0=$SECONDS

  printf '\n===== %s =====\n' "$label" | tee -a "$SUMMARY"

  if "$@" >"$logfile" 2>&1; then
    printf 'PASS (%ss): %s\n' "$((SECONDS - t0))" "$label" | tee -a "$SUMMARY"
    PASSED=$((PASSED + 1))
  else
    local rc=$?
    printf 'FAIL (exit %s, %ss): %s — see %s\n' \
      "$rc" "$((SECONDS - t0))" "$label" "$logfile" | tee -a "$SUMMARY"
    tail -n 15 "$logfile" | sed 's/^/    | /' | tee -a "$SUMMARY"
    FAILED=$((FAILED + 1))
    FAILED_LABELS+=("$label")
  fi
}

skip() {
  printf 'SKIP: %s\n' "$1" | tee -a "$SUMMARY"
  SKIPPED=$((SKIPPED + 1))
}

echo "Winflux test run: $OUT" | tee -a "$SUMMARY"
echo "Date: $(date -Is)" | tee -a "$SUMMARY"
echo "Root: $ROOT" | tee -a "$SUMMARY"
echo "Python: $($PY --version 2>&1)" | tee -a "$SUMMARY"

VERSION="$($PY -c 'import winflux; print(getattr(winflux, "__version__", "unknown"))' 2>/dev/null || echo unknown)"
echo "Winflux version: $VERSION" | tee -a "$SUMMARY"

# 0. prerequisites
if ! "$PY" -c 'import pytest, cryptography' >/dev/null 2>&1; then
  echo "ERROR: pytest and cryptography are required (pip install -r requirements.txt)" | tee -a "$SUMMARY" >&2
  exit 1
fi

# 1. static checks
run_check compile "$PY" -m compileall -q winflux tests scripts
run_check imports "$PY" -c 'import winflux.node.main, winflux.cli, winflux.tools.netgen, winflux.tools.localnet'

# 2. unit, integration and adversarial tests
run_check pytest "$PY" -m pytest -q -ra

PYTEST_LINE="$(tail -n 3 "$OUT/pytest.log" | grep -E 'passed|failed|error' | tail -n 1 || true)"
if [[ -n "$PYTEST_LINE" ]]; then
  echo "    pytest: $PYTEST_LINE" | tee -a "$SUMMARY"
fi

# 3. demo scripts
if ((DEMOS)); then
  for demo in demo_local demo_offline_vault demo_chained_notes demo_note_claim; do
    run_check "$demo" "$PY" "scripts/$demo.py"
  done
else
  skip "demo scripts (--quick/--no-demos)"
fi

# 4. smoke test on real processes
if ((SMOKE)); then
  run_check smoke_test "$PY" scripts/smoke_test.py
  sleep 1

  LEFT="$(pgrep -fa 'python.* -m winflux\.node\.main' 2>/dev/null || true)"
  if [[ -n "$LEFT" ]]; then
    printf 'WARNING: node process(es) still running after the smoke test:\n%s\n' "$LEFT" | tee -a "$SUMMARY"
  fi
else
  skip "smoke test (--quick/--no-smoke)"
fi

# 5. Android wallet core tests
if ((QUICK)); then
  skip "android-wallet tests (--quick)"
elif [[ -x android-wallet/gradlew && ( -n "${ANDROID_HOME:-}" || -n "${ANDROID_SDK_ROOT:-}" ) ]]; then
  run_check android_unit_tests bash -c 'cd android-wallet && ./gradlew --no-daemon :app:testDebugUnitTest'
else
  skip "android-wallet tests (need android-wallet/gradlew and ANDROID_HOME; see android-wallet/README.md)"
fi

# Summary
{
  echo
  echo "================ SUMMARY ================"
  echo "passed: $PASSED   failed: $FAILED   skipped: $SKIPPED"
  if ((FAILED)); then
    echo "FAILED steps: ${FAILED_LABELS[*]}"
  fi
  echo "logs: $OUT"
} | tee -a "$SUMMARY"

if ((FAILED)); then
  exit 1
fi

echo "ALL TESTS PASSED" | tee -a "$SUMMARY"

