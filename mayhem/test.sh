#!/usr/bin/env bash
#
# opennavsurf-bag/mayhem/test.sh — RUN BAG's OWN Catch2 unit-test binary (built by mayhem/build.sh
# with normal flags) over a subset of the suite and emit a CTRF summary. exit 0 iff no test failed.
#
# PATCH-grade oracle: BAG's tests are real golden / round-trip assertions over the file format —
# they create BAGs, open real sample .bag files, and assert metadata (dims, resolution, reference
# systems), layer contents, tracking-list entries, value tables, etc. against known values. These
# exercise the exact open()/read path the fuzzers drive, so a no-op / exit(0) patch (or any change
# that breaks the BAG read/decode round-trip) cannot pass. This script only RUNS the pre-built
# binary; it never compiles.
#
# We run the same subset OSS-Fuzz's run_tests.sh runs: a handful of cases are excluded upstream
# (GDAL-dependent VR reads and two layer-read cases that fail in the OSS-Fuzz environment).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "${SRC:-/mayhem}"

TESTBUILD="${SRC:-/mayhem}/mayhem-tests"
# CMake places the test binary under tests/ in the build tree.
TESTBIN="$(find "$TESTBUILD" -name bag_tests -type f -perm -u+x 2>/dev/null | head -1)"
SAMPLES="${SRC:-/mayhem}/examples/sample-data"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-${SRC:-/mayhem}/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ -z "$TESTBIN" ] || [ ! -x "$TESTBIN" ]; then
  echo "missing bag_tests binary under $TESTBUILD — run mayhem/build.sh first" >&2
  emit_ctrf "catch2-bag_tests" 0 1 0; exit 2
fi

echo "=== running $TESTBIN ==="
# Same path/exclusions as OSS-Fuzz run_tests.sh: BAG_SAMPLES_PATH points the tests at the sample
# data; the '~<name>' args deselect cases that need GDAL or fail in this minimal environment.
out="$(BAG_SAMPLES_PATH="$SAMPLES" "$TESTBIN" \
        '~test VR BAG reading GDAL' \
        '~test simple layer read' \
        '~test interleaved legacy layer read' \
        '~test VR BAG reading NBS' \
        2>&1)"; rc=$?
echo "$out"

# Catch2 v3 final line:  "All tests passed (N assertions in M test cases)"  on success,
# or  "test cases: X | Y passed | Z failed"  +  "assertions: ..."  on failure.
PASSED=0; FAILED=0
if printf '%s\n' "$out" | grep -q "All tests passed"; then
  PASSED=$(printf '%s\n' "$out" | sed -n 's/.*in \([0-9][0-9]*\) test case.*/\1/p' | tail -1)
  : "${PASSED:=1}"
else
  # "test cases: 27 | 25 passed | 2 failed"  (fields vary; parse the passed/failed tokens)
  PASSED=$(printf '%s\n' "$out" | sed -n 's/.*| \([0-9][0-9]*\) passed.*/\1/p' | tail -1)
  FAILED=$(printf '%s\n' "$out" | sed -n 's/.*| \([0-9][0-9]*\) failed.*/\1/p' | tail -1)
  : "${PASSED:=0}" "${FAILED:=0}"
  # If we could not parse a summary at all, fall back to the exit code.
  if [ "$(( PASSED + FAILED ))" -eq 0 ]; then
    if [ "$rc" -eq 0 ]; then PASSED=1; else FAILED=1; fi
  fi
fi

emit_ctrf "catch2-bag_tests" "$PASSED" "$FAILED" 0
