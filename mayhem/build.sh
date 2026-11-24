#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Everything the build writes goes under build/ (upstream's .gitignore covers it) or upstream's own
# gitignored outputs (libphpcpp.so.*, libphpcpp.a.*), so `git clean -ffdX` resets the tree.
PHP_INCLUDES="$(php-config --includes)"
OUT="$SRC/build/mayhem"
mkdir -p "$OUT/bin" "$OUT/oracle/lib" "$OUT/oracle/ext" "$OUT/inc/phpcpp"
# phpcpp.h includes <phpcpp/...>: expose the headers under the installed names
cp -f "$SRC"/include/*.h "$OUT/inc/phpcpp/"
cp -f "$SRC/phpcpp.h" "$OUT/inc/"

# upstream's Makefile always writes objects to build/{common,zend}; start each pass from none so the
# oracle and the fuzz build never share objects (and a re-run is a clean, idempotent rebuild)
reset_objs() { rm -rf "$SRC/build/common" "$SRC/build/zend" "$SRC"/libphpcpp.so.* "$SRC"/libphpcpp.a.*; }

# 1) ORACLE: upstream's library with its NORMAL flags (`make`), its tests/ extensions, and an
#    embed-SAPI php runner (mayhem/harnesses/phpcpp_php.cpp) that mayhem/test.sh drives.
reset_objs
make -j"$MAYHEM_JOBS" CXX="$CXX" COMPILER_FLAGS="-Wall -c -std=c++11 -g -fvisibility=hidden -DBUILDING_PHPCPP -Wno-write-strings -MD -fpic $PHP_INCLUDES $COVERAGE_FLAGS" LINKER_FLAGS="-shared -g $COVERAGE_FLAGS" phpcpp
LIB_SO="$(ls "$SRC"/libphpcpp.so.*.*.*)"
SONAME="$(readelf -d "$LIB_SO" | sed -n 's/.*soname: \[\(.*\)\]/\1/p')"
cp -f "$LIB_SO" "$OUT/oracle/lib/$SONAME"
ln -sf "$SONAME" "$OUT/oracle/lib/libphpcpp.so"
for t in compare-nonobject traverse-optional-callbacks traverse-release; do
  src="$(ls "$SRC/tests/$t"/*.cpp)"
  "$CXX" -Wall -O2 -std=c++11 -fpic -shared $COVERAGE_FLAGS -I"$SRC" -I"$OUT/inc" $PHP_INCLUDES \
    -o "$OUT/oracle/ext/$t.so" "$src" -L"$OUT/oracle/lib" -lphpcpp -Wl,-rpath,"$OUT/oracle/lib"
done
"$CXX" -O1 -g -std=c++17 $COVERAGE_FLAGS $PHP_INCLUDES "$SRC/mayhem/harnesses/phpcpp_php.cpp" -lphp -ldl \
  -o "$OUT/oracle/phpcpp_php"

# 2) FUZZ: the same library rebuilt with the sanitizers + DWARF-3 (static archive), then each
#    harness linked twice: libFuzzer binary and run-once standalone reproducer. The library and the
#    harness objects also get SanitizerCoverage (-fsanitize=fuzzer-no-link) so libFuzzer sees edges
#    in libphpcpp (libphp itself is an uninstrumented distro library).
#    UBSan's `alignment` check is relaxed (only it): ClassImpl::find (zend/classimpl.cpp) stores the
#    ClassImpl pointer at doc_comment+1 by design and reads it back unaligned on every class use, so
#    the check would stop every input that touches a PHP-CPP class. ASan and all other UBSan checks halt.
COV_FLAGS="-fsanitize=fuzzer-no-link -fno-sanitize=alignment"
reset_objs
make -j"$MAYHEM_JOBS" CXX="$CXX" COMPILER_FLAGS="-Wall -c -std=c++11 -O1 $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS -fvisibility=hidden -DBUILDING_PHPCPP -Wno-write-strings -MD -fpic $PHP_INCLUDES" \
  "libphpcpp.a.$(sed -n 's/^VERSION[[:space:]]*=[[:space:]]*//p' "$SRC/Makefile")"
LIB_A="$(ls "$SRC"/libphpcpp.a.*.*.*)"
cp -f "$LIB_A" "$OUT/libphpcpp-fuzz.a"

"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OUT/lsan_off.o"
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"
for h in fuzz_value fuzz_script fuzz_unserialize fuzz_api; do
  "$CXX" -std=c++17 -O1 $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS -I"$OUT/inc" $PHP_INCLUDES \
    -c "$SRC/mayhem/harnesses/$h.cpp" -o "$OUT/$h.o"
  "$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/$h.o" "$OUT/lsan_off.o" \
    "$OUT/libphpcpp-fuzz.a" -lphp -o "$OUT/bin/$h"
  "$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/standalone_main.o" "$OUT/$h.o" "$OUT/lsan_off.o" \
    "$OUT/libphpcpp-fuzz.a" $COV_FLAGS -lphp -o "$OUT/bin/$h-standalone"
done
reset_objs
echo "built: $(ls "$OUT/bin")"
