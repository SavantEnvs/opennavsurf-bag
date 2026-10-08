#!/usr/bin/env bash
#
# opennavsurf-bag/mayhem/build.sh — build OpenNavigationSurface/BAG's two OSS-Fuzz harnesses as
# sanitized libFuzzer targets (+ standalone reproducers), AND BAG's own Catch2 unit-test binary
# for mayhem/test.sh.
#
# Fuzzed surface = the BAG (Bathymetric Attributed Grid) file reader. A BAG is an HDF5 container
# whose metadata is an embedded XML document. Both harnesses write the input bytes to a temp file
# and call BAG::Dataset::open(path, BAG_OPEN_READONLY), which drives the full HDF5 superblock /
# object-header / b-tree / heap decode AND the libxml2 parse of the BAG metadata on attacker bytes:
#   bag_read_fuzzer     — open() then close() (the parse + metadata-validate path).
#   bag_extended_fuzzer — open() then walk the descriptor / layers / tracking list (deeper getters).
#
# We compile BAG's OWN library (baglib) with $SANITIZER_FLAGS + coverage so the fuzzed BAG parser
# is instrumented. The heavy, well-fuzzed-elsewhere deps (HDF5 + libxml2) come from apt as system
# libraries to keep the build light — only the BAG code under test is sanitized/instrumented.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

# ── Build-time patch: stop Dataset::open() SEGV-ing on every non-openable input ────────────────────
# See mayhem/patches/0001-dataset-open-null-guard.patch for the full rationale. Applied here (not in
# the repo) so all tracked changes stay additive. Idempotent: skip if it does not apply cleanly
# (e.g. upstream already merged the equivalent guard after a sync).
PATCH="$SRC/mayhem/patches/0001-dataset-open-null-guard.patch"
if [ -f "$PATCH" ]; then
  if git -C "$SRC" apply --check "$PATCH" 2>/dev/null; then
    git -C "$SRC" apply "$PATCH" && echo "applied $(basename "$PATCH")"
  else
    echo "skipping $(basename "$PATCH") (already applied or no longer applies)"
  fi
fi

# Build-time patch: catch ALL exceptions from readDataset() in Dataset::open()
# so that BAG files that throw BAG::ErrorLoadingMetadata or H5::AttributeIException
# return nullptr instead of propagating through LLVMFuzzerTestOneInput to std::terminate().
# Without this patch, seeds such as nominal_only.bag and metadata_layer_example.bag
# cause std::terminate() on the first corpus pass, exiting the fuzzer with 0 edges.
PATCH2="$SRC/mayhem/patches/0002-dataset-open-catch-all-exceptions.patch"
if [ -f "$PATCH2" ]; then
  if git -C "$SRC" apply --check "$PATCH2" 2>/dev/null; then
    git -C "$SRC" apply "$PATCH2" && echo "applied $(basename "$PATCH2")"
  else
    echo "skipping $(basename "$PATCH2") (already applied or no longer applies)"
  fi
fi

# Build-time patch: add LLVMFuzzerInitialize to disable HDF5 file locking and clean up
# temp files in both harnesses. HDF5 uses POSIX fcntl locks by default; in Mayhem's
# overlay-filesystem container the lock calls either fail (ENOLCK) or are silently
# dropped, causing every H5Fopen() to return an error even on valid BAG seeds. With
# all opens failing, coverage stays at the ~94-edge harness-bootstrap baseline and
# Mayhem reports the run as broken / 0 edges. Setting HDF5_USE_FILE_LOCKING=FALSE via
# LLVMFuzzerInitialize (called before any corpus input, before HDF5's lazy H5open())
# ensures locking is disabled regardless of Mayhem's injected ASAN_OPTIONS env.
PATCH3="$SRC/mayhem/patches/0003-harness-hdf5-locking-cleanup.patch"
if [ -f "$PATCH3" ]; then
  if git -C "$SRC" apply --check "$PATCH3" 2>/dev/null; then
    git -C "$SRC" apply "$PATCH3" && echo "applied $(basename "$PATCH3")"
  else
    echo "skipping $(basename "$PATCH3") (already applied or no longer applies)"
  fi
fi

# Debian's HDF5 uses the "serial" layout (headers + libs under .../hdf5/serial/).
H5INC=/usr/include/hdf5/serial
H5LIBDIR=/usr/lib/x86_64-linux-gnu/hdf5/serial

# -fsanitize=fuzzer-no-link gives baglib coverage instrumentation without pulling in the libFuzzer
# main (the harness / standalone driver supplies main); halting ASan+UBSan stay on for the lib.
FUZZ_COV="-fsanitize=fuzzer-no-link"

# Benign-UB relax (alignment only): BAG decodes packed HDF5 georef-metadata records via
# reinterpret_cast at computed field offsets (api/bag_valuetable.cpp convertMemoryToRecord) — a
# harmless misaligned load on x86 that trips -fsanitize=alignment on EVERY valid BAG with a
# georef-metadata layer (the upstream bag_georefmetadata_layer.bag sample reproduces it). It would
# flood the campaign with non-bugs, so we disable ONLY the alignment check. ASan and every OTHER
# UBSan check (null, signed-overflow, shift, bounds, object-size, enum, return, ...) STAY HALTING.
#
# NB: we deliberately do NOT relax -fsanitize=null. On master, BAG::Dataset::open() has a real
# pre-existing crash: readDataset() catches the H5File-open exception but only LOGS it and falls
# through to `make_unique<Metadata>(*this)` with a null m_pH5file, so Metadata::Metadata(Dataset&)
# -> getH5file() (`return *m_pH5file;`) -> h5file.openDataSet() dereferences null and SEGVs. This
# fires on the empty seed (and any non-BAG input) the harness starts from, so the fuzzers crash on
# input #0. It is a genuine BAG defect (upstream's `fuzzer` branch is actively trying to fix exactly
# this — "Attempt to catch FileIException in BAG::Dataset::open()"), surfaced here as the very first
# finding, NOT a harness/build problem on our side. We keep null halting so Mayhem reports it as the
# real crash it is rather than masking it into a rawer SEGV.
NOUB="-fno-sanitize=alignment"

# ── 1) Build baglib (static) WITH sanitizers + coverage ───────────────────────────────────────────
# HDF5_PREFER_PARALLEL=OFF so CMake's FindHDF5 picks the serial libs (not an MPI variant). We build
# the static lib in place and link against it directly — no `install` step (the image runs as the
# non-root mayhem user, so a /opt install prefix is not writable; the build tree is under $SRC).
BUILD="$SRC/mayhem-build"
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -B "$BUILD" -S "$SRC" \
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS $FUZZ_COV $NOUB" \
  -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS $FUZZ_COV $NOUB" \
  -DBAG_BUILD_SHARED_LIBS:BOOL=OFF \
  -DBAG_BUILD_TESTS:BOOL=OFF -DBAG_CODE_COVERAGE:BOOL=OFF \
  -DBAG_BUILD_PYTHON:BOOL=OFF -DBAG_BUILD_EXAMPLES:BOOL=OFF \
  -DHDF5_PREFER_PARALLEL:BOOL=OFF
cmake --build "$BUILD" --config Release --target baglib -j"$MAYHEM_JOBS"

LIBBAG="$(find "$BUILD" -name libbaglib.a -type f 2>/dev/null | head -1)"
[ -n "$LIBBAG" ] && [ -f "$LIBBAG" ] || { echo "ERROR: libbaglib.a not produced"; exit 1; }

# Link line shared by every harness. baglib (sanitized) + system HDF5/libxml2/zlib.
# The BAG headers come straight from the source tree ($SRC/api); bag_version.h is generated into
# the build tree, so add that include dir too.
BAGVER_INC="$(dirname "$(find "$BUILD" -name bag_version.h -type f 2>/dev/null | head -1)")"
LINK_LIBS=( "$LIBBAG" -L"$H5LIBDIR" -lhdf5_cpp -lhdf5 -lxml2 -lz )

# The standalone driver ($STANDALONE_FUZZ_MAIN) is C and declares LLVMFuzzerTestOneInput with C
# linkage. Compile it as a C object FIRST — letting clang++ pull the .c in mangles the reference
# (it would treat the .c as C++) and the link fails. Match the lib's sanitizer set (incl. the
# benign-UB relax) so it does not re-flag the same harmless cases.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $NOUB -c -x c "$STANDALONE_FUZZ_MAIN" -o "$SRC/mayhem-build/standalone_main.o"

# ── 2) Build each OSS-Fuzz harness twice: libFuzzer (-> /mayhem/<name>) + standalone reproducer ────
INCS=( -I"$SRC/api" -I"$H5INC" )
[ -n "$BAGVER_INC" ] && INCS+=( -I"$BAGVER_INC" )

# LeakSanitizer off at BUILD time (SPEC 6.2 item 15): mayhem/lsan_off.cc defines the
# __lsan_is_turned_off() hook. Compile it once with $SANITIZER_FLAGS and link it into every
# libFuzzer and standalone binary. All other ASan/UBSan checks stay on and halting.
LSAN_OFF_OBJ="$SRC/mayhem-build/lsan_off.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $NOUB -c "$SRC/mayhem/lsan_off.cc" -o "$LSAN_OFF_OBJ"

# Harness-side input guard (mayhem/bag_input_guard.cc). BAG reads /BAG_root/metadata as one
# fixed-length string, and HDF5's C++ layer does `new char[size]` with a size taken from the file
# header; a mutated header asks for petabytes and ASan aborts with allocation-size-too-big before
# the bad_alloc that BAG already handles can be thrown. HDF5's C metadata cache does the same with a
# local-heap ("HEAP") size from the file. The guard owns LLVMFuzzerTestOneInput, skips inputs that
# declare a heap block larger than the input or a metadata string > 64 MiB (both invalid; a normal
# build rejects them), and calls the upstream entry point, which is
# renamed at compile time with -DLLVMFuzzerTestOneInput=BagUpstreamTestOneInput (no source edit).
GUARD_OBJ="$SRC/mayhem-build/bag_input_guard.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $NOUB $FUZZ_COV -I"$H5INC" -c "$SRC/mayhem/bag_input_guard.cc" -o "$GUARD_OBJ"
RENAME_ENTRY=( -DLLVMFuzzerTestOneInput=BagUpstreamTestOneInput )

for harness in bag_read_fuzzer bag_extended_fuzzer; do
  # libFuzzer target -> /mayhem/<name>
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $NOUB "${INCS[@]}" "${RENAME_ENTRY[@]}" \
      "$SRC/fuzzers/$harness.cpp" "$GUARD_OBJ" "$LSAN_OFF_OBJ" $LIB_FUZZING_ENGINE "${LINK_LIBS[@]}" \
      -o "/mayhem/$harness"

  # standalone reproducer (no libFuzzer runtime; runs each input file once) -> /mayhem/<name>-standalone
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $NOUB "${INCS[@]}" "${RENAME_ENTRY[@]}" \
      "$SRC/fuzzers/$harness.cpp" "$GUARD_OBJ" "$LSAN_OFF_OBJ" "$SRC/mayhem-build/standalone_main.o" "${LINK_LIBS[@]}" \
      -o "/mayhem/$harness-standalone"

  echo "built $harness (+ standalone)"
done

# ── 3) Build BAG's OWN Catch2 unit-test binary with NORMAL flags (clean, separate tree) so test.sh
#       only RUNS it. Tests don't run under ASan (HDF5/libxml2 global leaks), so keep this tree
#       un-sanitized — an honest functional oracle, not the fuzzed build. ───────────────────────────
TESTBUILD="$SRC/mayhem-tests"
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -B "$TESTBUILD" -S "$SRC" \
    -DBAG_BUILD_SHARED_LIBS:BOOL=OFF \
    -DBAG_BUILD_TESTS:BOOL=ON -DBAG_CODE_COVERAGE:BOOL=OFF \
    -DBAG_BUILD_PYTHON:BOOL=OFF -DBAG_BUILD_EXAMPLES:BOOL=OFF \
    -DHDF5_PREFER_PARALLEL:BOOL=OFF
# Build the bag_tests target only (no install — image runs non-root; test.sh runs it from the tree).
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  cmake --build "$TESTBUILD" --config Release --target bag_tests -j"$MAYHEM_JOBS"
echo "built BAG Catch2 test binary in mayhem-tests/"

echo "build.sh complete:"
ls -la /mayhem/bag_read_fuzzer /mayhem/bag_extended_fuzzer \
       /mayhem/bag_read_fuzzer-standalone /mayhem/bag_extended_fuzzer-standalone 2>&1 || true
