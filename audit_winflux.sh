#!/usr/bin/env bash
# Winflux audit helper — non-destructive, best-effort checks.
set -u
ROOT="$(pwd)"
IS_GIT=0
if git rev-parse --show-toplevel >/dev/null 2>&1; then ROOT="$(git rev-parse --show-toplevel)"; IS_GIT=1; fi
cd "$ROOT" || exit 1
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${AUDIT_OUT:-audit-report-$STAMP}"
mkdir -p "$OUT"
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"
run_check() {
  local label="$1"; shift
  local logfile="$OUT/${label//[^a-zA-Z0-9_-]/_}.log"
  printf '\n===== %s =====\n' "$label" | tee -a "$SUMMARY"
  if "$@" >"$logfile" 2>&1; then printf 'PASS: %s\n' "$label" | tee -a "$SUMMARY"
  else local rc=$?; printf 'FAIL/NOTICE (exit %s): %s — see %s\n' "$rc" "$label" "$logfile" | tee -a "$SUMMARY"; fi
}
echo "Winflux audit report: $OUT" | tee -a "$SUMMARY"
echo "Date: $(date -Is)" | tee -a "$SUMMARY"
echo "Root: $ROOT" | tee -a "$SUMMARY"
if (( IS_GIT )); then
  run_check git_status git status --short --branch
  run_check git_diff git diff --check
  run_check git_recent git log -n 30 --oneline --decorate
  run_check git_remotes git remote -v
  git ls-files >"$OUT/tracked_files.txt" 2>&1 || true
else
  echo "NOTICE: no Git repository detected at $ROOT; Git checks skipped." | tee -a "$SUMMARY"
  echo "No Git repository detected." >"$OUT/tracked_files.txt"
fi
PY=""
if command -v python >/dev/null 2>&1; then PY="python"; elif command -v python3 >/dev/null 2>&1; then PY="python3"; fi
if [[ -n "$PY" ]]; then
  run_check python_version "$PY" --version
  run_check python_compile "$PY" -m compileall -q winflux tests
  run_check pip_check "$PY" -m pip check
  if "$PY" -m pip show pytest >/dev/null 2>&1; then run_check pytest "$PY" -m pytest -ra; else echo "SKIP: pytest not installed in selected Python environment" | tee -a "$SUMMARY"; fi
  if "$PY" -m pip show pip_audit >/dev/null 2>&1; then run_check pip_audit "$PY" -m pip_audit
  elif command -v pip-audit >/dev/null 2>&1; then run_check pip_audit pip-audit
  else echo "SKIP: pip-audit unavailable" | tee -a "$SUMMARY"; fi
else echo "SKIP: neither python nor python3 available" | tee -a "$SUMMARY"; fi
if command -v bandit >/dev/null 2>&1; then run_check bandit bandit -r winflux -ll; else echo "SKIP: bandit unavailable" | tee -a "$SUMMARY"; fi
if command -v semgrep >/dev/null 2>&1; then run_check semgrep semgrep scan --config auto winflux; else echo "SKIP: semgrep unavailable" | tee -a "$SUMMARY"; fi
if command -v gitleaks >/dev/null 2>&1; then run_check gitleaks gitleaks detect --source . --no-git --redact; else echo "SKIP: gitleaks unavailable" | tee -a "$SUMMARY"; fi
if command -v trivy >/dev/null 2>&1; then run_check trivy_fs trivy fs --scanners vuln,misconfig,secret --skip-dirs .venv --skip-dirs venv .; else echo "SKIP: trivy unavailable" | tee -a "$SUMMARY"; fi
if command -v ruff >/dev/null 2>&1; then run_check ruff ruff check winflux tests; else echo "SKIP: ruff unavailable" | tee -a "$SUMMARY"; fi
if command -v mypy >/dev/null 2>&1; then run_check mypy mypy winflux; else echo "SKIP: mypy unavailable" | tee -a "$SUMMARY"; fi
if command -v shellcheck >/dev/null 2>&1; then
  mapfile -t shfiles < <(find scripts -type f -name '*.sh' -print 2>/dev/null)
  if ((${#shfiles[@]})); then run_check shellcheck shellcheck "${shfiles[@]}"; else echo "SKIP: no scripts/*.sh files" | tee -a "$SUMMARY"; fi
else echo "SKIP: shellcheck unavailable" | tee -a "$SUMMARY"; fi
grep -RInE --exclude-dir=.git --exclude-dir=.venv --exclude-dir=venv --exclude-dir=__pycache__ --exclude='*.log' '(TODO|FIXME|XXX|eval\(|exec\(|pickle\.loads|shell=True|password\s*=|secret\s*=|private_key)' winflux scripts tests >"$OUT/pattern_review.txt" 2>&1 || true
echo "Pattern search saved: $OUT/pattern_review.txt" | tee -a "$SUMMARY"
find . -maxdepth 3 -type f \( -name 'requirements*.txt' -o -name 'pyproject.toml' -o -name 'setup.cfg' -o -name 'Pipfile*' \) -not -path './.git/*' -not -path './.venv/*' >"$OUT/dependency_files.txt" 2>/dev/null || true
echo
echo "Audit run finished. Summary: $SUMMARY"
echo "Logs: $OUT"
echo "Note: automated checks are not an independent security audit."

