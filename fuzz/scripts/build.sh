#!/usr/bin/env bash
#
# Build Squid fuzzing harnesses using libFuzzer + ASan + UBSan.
#
# Usage:
#   ./scripts/build.sh configure   # configure Squid for fuzzing
#   ./scripts/build.sh make        # build Squid libraries + stubs
#   ./scripts/build.sh harnesses   # compile fuzzing harnesses
#   ./scripts/build.sh all         # do all of the above
#
# The script auto-detects the platform:
#   macOS:  uses Homebrew LLVM (/opt/homebrew/opt/llvm/bin/clang++)
#   Linux:  uses system clang++
#
# OSS-Fuzz compatibility:
#   If $LIB_FUZZING_ENGINE is set, uses it instead of -fsanitize=fuzzer.
#   If $CC/$CXX/$CFLAGS/$CXXFLAGS are set, uses them as-is.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FUZZ_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SQUID_SRC="$(cd "$FUZZ_DIR/.." && pwd)"
HARNESS_DIR="$FUZZ_DIR/harnesses"
BUILD_DIR="$FUZZ_DIR/build"

# --- Platform detection ---

detect_compiler() {
    if [[ -n "${CXX:-}" && -n "${CC:-}" ]]; then
        echo "Using provided CC=$CC CXX=$CXX"
    elif [[ "$(uname)" == "Darwin" ]]; then
        LLVM_PREFIX="${LLVM_PREFIX:-/opt/homebrew/opt/llvm}"
        if [[ ! -x "$LLVM_PREFIX/bin/clang++" ]]; then
            echo "ERROR: Homebrew LLVM not found at $LLVM_PREFIX" >&2
            echo "Install it: brew install llvm" >&2
            echo "Or set LLVM_PREFIX to your LLVM installation." >&2
            exit 1
        fi
        CXX="$LLVM_PREFIX/bin/clang++"
        CC="$LLVM_PREFIX/bin/clang"
    else
        CXX="${CXX:-clang++}"
        CC="${CC:-clang}"
    fi

    if [[ "$(uname)" == "Darwin" ]]; then
        OPENSSL_PREFIX="${OPENSSL_PREFIX:-$(brew --prefix openssl@3 2>/dev/null || echo /opt/homebrew/opt/openssl@3)}"
        SYSLIBS="-L$OPENSSL_PREFIX/lib -lssl -lcrypto -lpthread"
        NPROC="sysctl -n hw.ncpu"
        GROUP_START=""
        GROUP_END=""
    else
        SYSLIBS="-lssl -lcrypto -lpthread -ldl"
        NPROC="nproc"
        GROUP_START="-Wl,--start-group"
        GROUP_END="-Wl,--end-group"
    fi

    echo "Compiler: $CXX"
    "$CXX" --version 2>&1 | head -1
}

# Sanitizer and fuzzer flags (only used when OSS-Fuzz env vars not set)
SANITIZER_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all"
FUZZER_COMPILE="-fsanitize=fuzzer-no-link"
OPT_FLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only"

# If CXXFLAGS/CFLAGS already set (OSS-Fuzz), use them; otherwise build our own
if [[ -z "${CXXFLAGS:-}" ]]; then
    CXXFLAGS="$OPT_FLAGS $SANITIZER_FLAGS $FUZZER_COMPILE"
fi
if [[ -z "${CFLAGS:-}" ]]; then
    CFLAGS="$OPT_FLAGS $SANITIZER_FLAGS $FUZZER_COMPILE"
fi

# Fuzzer link: prefer $LIB_FUZZING_ENGINE if set (OSS-Fuzz), else -fsanitize=fuzzer
if [[ -n "${LIB_FUZZING_ENGINE:-}" ]]; then
    FUZZER_LINK_LIB="$LIB_FUZZING_ENGINE"
    FUZZER_LINK_FLAGS=""
else
    FUZZER_LINK_LIB=""
    FUZZER_LINK_FLAGS="-fsanitize=fuzzer"
fi

# --- configure ---

do_configure() {
    detect_compiler
    echo "=== Configuring Squid for fuzzing ==="
    cd "$SQUID_SRC"

    if [[ ! -f configure ]]; then
        echo "Running bootstrap.sh..."
        ./bootstrap.sh
    fi

    ./configure \
        CXX="$CXX" \
        CC="$CC" \
        CXXFLAGS="$CXXFLAGS" \
        CFLAGS="$CFLAGS" \
        LDFLAGS="$SANITIZER_FLAGS" \
        --disable-shared \
        --without-nettle \
        --without-gnutls \
        --disable-auth \
        --disable-snmp \
        --disable-eui \
        --disable-htcp \
        --disable-wccp \
        --disable-wccpv2 \
        --disable-esi \
        --disable-icap-client \
        --disable-ecap

    echo "=== Squid configured ==="
}

# --- make ---

do_make() {
    detect_compiler
    echo "=== Building Squid libraries ==="
    cd "$SQUID_SRC"

    JOBS="$($NPROC)"

    make -j"$JOBS" || true

    echo "=== Compiling test stubs ==="
    cd "$SQUID_SRC/src"
    STUB_FLAGS="-std=c++17 -DHAVE_CONFIG_H -DSTUB_THROWS \
        -DDEFAULT_CONFIG_FILE=\"/usr/local/squid/etc/squid.conf\" \
        -DDEFAULT_SQUID_DATA_DIR=\"/usr/local/squid/share\" \
        -DDEFAULT_SQUID_CONFIG_DIR=\"/usr/local/squid/etc\" \
        -I.. -I../include -I../lib -I. -I../include \
        $CXXFLAGS"
    for stub in \
        tests/stub_HelperChildConfig.cc tests/stub_MemObject.cc \
        tests/stub_cache_cf.cc tests/stub_cache_manager.cc \
        tests/stub_cbdata.cc tests/stub_comm.cc tests/stub_debug.cc \
        tests/stub_event.cc tests/stub_libanyp.cc tests/stub_libmem.cc \
        tests/stub_libsecurity.cc tests/stub_stmem.cc tests/stub_store.cc \
        tests/stub_store_stats.cc tests/stub_tools.cc tests/stub_libtime.cc \
        tests/stub_fatal.cc \
        globals.cc MemBuf.cc String.cc mime_header.cc wordlist.cc; do
        out=$(echo "$stub" | sed 's|\.cc$|.o|')
        if [[ -f "$out" ]]; then continue; fi
        echo "  $stub -> $out"
        "$CXX" $STUB_FLAGS \
            -c "$stub" -o "$out" || echo "    FAILED: $stub"
    done

    if [[ ! -f test_tools.o ]]; then
        echo "  test-suite/test_tools.cc -> test_tools.o"
        "$CXX" $STUB_FLAGS \
            -c ../test-suite/test_tools.cc -o test_tools.o
    fi

    echo "=== Build complete ==="
}

# --- harnesses ---

do_harnesses() {
    detect_compiler
    echo "=== Building fuzzing harnesses ==="
    mkdir -p "$BUILD_DIR"

    S="$SQUID_SRC/src"

    INC="-I$SQUID_SRC/include -I$S -I$SQUID_SRC/lib -I$SQUID_SRC -I$HARNESS_DIR"

    STUBS="\
        $S/globals.o \
        $S/test_tools.o \
        $S/tests/stub_HelperChildConfig.o \
        $S/tests/stub_MemObject.o \
        $S/tests/stub_cache_cf.o \
        $S/tests/stub_cache_manager.o \
        $S/tests/stub_cbdata.o \
        $S/tests/stub_comm.o \
        $S/tests/stub_debug.o \
        $S/tests/stub_event.o \
        $S/tests/stub_libmem.o \
        $S/tests/stub_libsecurity.o \
        $S/tests/stub_stmem.o \
        $S/tests/stub_store.o \
        $S/tests/stub_store_stats.o \
        $S/tests/stub_tools.o \
        $S/tests/stub_libtime.o \
        $S/tests/stub_fatal.o \
        $S/SquidConfig.o \
        $S/MemBuf.o \
        $S/String.o \
        $S/mime_header.o \
        $S/wordlist.o"

    LIBS="$GROUP_START \
        $S/http/.libs/libhttp.a \
        $S/parser/.libs/libparser.a \
        $S/anyp/.libs/libanyp.a \
        $S/base/.libs/libbase.a \
        $S/ip/.libs/libip.a \
        $S/sbuf/.libs/libsbuf.a \
        $SQUID_SRC/lib/.libs/libmiscutil.a \
        $SQUID_SRC/lib/.libs/libmiscencoding.a \
        $SQUID_SRC/compat/.libs/libcompatsquid.a \
        $GROUP_END"

    LINK_CXXFLAGS="-std=c++17 -DHAVE_CONFIG_H -DSTUB_THROWS $OPT_FLAGS $SANITIZER_FLAGS $FUZZER_LINK_FLAGS"

    # --- HTTP/1 request parser ---
    echo "  Building fuzz_http1_request_parser..."
    "$CXX" $LINK_CXXFLAGS $INC \
        "$HARNESS_DIR/fuzz_http1_request_parser.cc" \
        $STUBS $S/tests/stub_libanyp.o \
        $LIBS $SYSLIBS $FUZZER_LINK_LIB \
        -o "$BUILD_DIR/fuzz_http1_request_parser"

    # --- HTTP/1 response parser ---
    echo "  Building fuzz_http1_response_parser..."
    "$CXX" $LINK_CXXFLAGS $INC \
        "$HARNESS_DIR/fuzz_http1_response_parser.cc" \
        $STUBS $S/tests/stub_libanyp.o \
        $LIBS $SYSLIBS $FUZZER_LINK_LIB \
        -o "$BUILD_DIR/fuzz_http1_response_parser"

    # --- URI parser (needs real libanyp, not the stub) ---
    echo "  Compiling URI typeinfo stubs..."
    "$CXX" $OPT_FLAGS $SANITIZER_FLAGS $FUZZER_COMPILE -std=c++17 \
        -c "$HARNESS_DIR/uri_typeinfo_stubs.cc" \
        -o "$BUILD_DIR/uri_typeinfo_stubs.o"

    echo "  Building fuzz_uri_parser..."
    "$CXX" $LINK_CXXFLAGS $INC \
        "$HARNESS_DIR/fuzz_uri_parser.cc" \
        $STUBS \
        "$BUILD_DIR/uri_typeinfo_stubs.o" \
        $LIBS $SYSLIBS $FUZZER_LINK_LIB \
        -o "$BUILD_DIR/fuzz_uri_parser"

    echo ""
    echo "=== Built harnesses ==="
    ls -la "$BUILD_DIR"/fuzz_* 2>/dev/null || echo "No harnesses built."
    echo ""
    echo "Run:"
    echo "  $BUILD_DIR/fuzz_http1_request_parser $FUZZ_DIR/seeds/http1_requests/"
}

do_all() {
    do_configure
    do_make
    do_harnesses
}

case "${1:-all}" in
    configure)  do_configure ;;
    make)       do_make ;;
    harnesses)  do_harnesses ;;
    all)        do_all ;;
    *)
        echo "Usage: $0 {configure|make|harnesses|all}" >&2
        exit 1
        ;;
esac
