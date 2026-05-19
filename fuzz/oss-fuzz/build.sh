#!/bin/bash -eu
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
#
# OSS-Fuzz build script for Squid proxy.
# Builds parser fuzzing harnesses against Squid's static convenience libraries.
#
# Environment (provided by OSS-Fuzz):
#   $CC, $CXX         -- compiler
#   $CFLAGS, $CXXFLAGS -- compiler flags (sanitizers, coverage, etc.)
#   $LIB_FUZZING_ENGINE -- fuzzing engine library (libFuzzer, AFL, etc.)
#   $SRC               -- source checkout directory
#   $OUT               -- output directory for harness binaries + corpora
#   $WORK              -- scratch directory

cd $SRC/squid

./bootstrap.sh

./configure \
    CXX="$CXX" \
    CC="$CC" \
    CXXFLAGS="$CXXFLAGS" \
    CFLAGS="$CFLAGS" \
    LDFLAGS="$CXXFLAGS" \
    --disable-shared \
    --without-gnutls \
    --without-nettle \
    --disable-auth \
    --disable-snmp \
    --disable-eui \
    --disable-htcp \
    --disable-wccp \
    --disable-wccpv2 \
    --disable-esi \
    --disable-icap-client \
    --disable-ecap

# Build convenience libraries (final link will fail -- no main())
make -j$(nproc) || true

# Compile test stubs needed for linking harnesses
STUB_CXXFLAGS="-std=c++17 -DHAVE_CONFIG_H -DSTUB_THROWS \
    -DDEFAULT_CONFIG_FILE=\"/dev/null\" \
    -DDEFAULT_SQUID_DATA_DIR=\"/dev/null\" \
    -DDEFAULT_SQUID_CONFIG_DIR=\"/dev/null\" \
    $CXXFLAGS"
STUB_INC="-I. -I./include -I./lib -I./src"

cd src
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
    if [ -f "$out" ]; then continue; fi
    $CXX $STUB_CXXFLAGS $STUB_INC -c "$stub" -o "$out" || echo "WARN: $stub failed"
done

# test_tools.cc is in test-suite/, not src/
if [ ! -f test_tools.o ]; then
    $CXX $STUB_CXXFLAGS $STUB_INC -c ../test-suite/test_tools.cc -o test_tools.o
fi
cd ..

S="$SRC/squid/src"
FUZZ="$SRC/squid/fuzz"

INC="-I$SRC/squid/include -I$S -I$SRC/squid/lib -I$SRC/squid -I$FUZZ/harnesses"

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

LIBS="-Wl,--start-group \
    $S/http/.libs/libhttp.a \
    $S/parser/.libs/libparser.a \
    $S/anyp/.libs/libanyp.a \
    $S/base/.libs/libbase.a \
    $S/ip/.libs/libip.a \
    $S/sbuf/.libs/libsbuf.a \
    $SRC/squid/lib/.libs/libmiscutil.a \
    $SRC/squid/lib/.libs/libmiscencoding.a \
    $SRC/squid/compat/.libs/libcompatsquid.a \
    -Wl,--end-group"

SYSLIBS="-lssl -lcrypto -lpthread -ldl"

HARNESS_CXXFLAGS="-std=c++17 -DHAVE_CONFIG_H -DSTUB_THROWS $CXXFLAGS"

# --- fuzz_http1_request_parser ---
$CXX $HARNESS_CXXFLAGS $INC \
    $FUZZ/harnesses/fuzz_http1_request_parser.cc \
    $STUBS $S/tests/stub_libanyp.o \
    $LIBS $SYSLIBS \
    $LIB_FUZZING_ENGINE \
    -o $OUT/fuzz_http1_request_parser

# --- fuzz_http1_response_parser ---
$CXX $HARNESS_CXXFLAGS $INC \
    $FUZZ/harnesses/fuzz_http1_response_parser.cc \
    $STUBS $S/tests/stub_libanyp.o \
    $LIBS $SYSLIBS \
    $LIB_FUZZING_ENGINE \
    -o $OUT/fuzz_http1_response_parser

# --- fuzz_uri_parser (uses real libanyp, not stub) ---
$CXX $HARNESS_CXXFLAGS \
    -c $FUZZ/harnesses/uri_typeinfo_stubs.cc \
    -o $WORK/uri_typeinfo_stubs.o

$CXX $HARNESS_CXXFLAGS $INC \
    $FUZZ/harnesses/fuzz_uri_parser.cc \
    $STUBS \
    $WORK/uri_typeinfo_stubs.o \
    $LIBS $SYSLIBS \
    $LIB_FUZZING_ENGINE \
    -o $OUT/fuzz_uri_parser

# --- Seed corpora ---
cd $FUZZ/seeds
for dir in http1_requests http1_responses uris; do
    harness=""
    case "$dir" in
        http1_requests)  harness="fuzz_http1_request_parser" ;;
        http1_responses) harness="fuzz_http1_response_parser" ;;
        uris)            harness="fuzz_uri_parser" ;;
    esac
    if [ -d "$dir" ] && [ -n "$harness" ]; then
        zip -j $OUT/${harness}_seed_corpus.zip $dir/*
    fi
done

# --- Dictionaries ---
cp $FUZZ/dictionaries/http.dict $OUT/fuzz_http1_request_parser.dict
cp $FUZZ/dictionaries/http.dict $OUT/fuzz_http1_response_parser.dict
cp $FUZZ/dictionaries/uri.dict $OUT/fuzz_uri_parser.dict
