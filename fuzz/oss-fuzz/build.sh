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
    tests/stub_CachePeer.cc tests/stub_ETag.cc \
    tests/stub_HttpRequest.cc tests/stub_StatHist.cc \
    tests/stub_access_log.cc tests/stub_client_side.cc \
    tests/stub_errorpage.cc tests/stub_fd.cc tests/stub_fde.cc \
    tests/stub_libauth.cc tests/stub_libcomm.cc \
    tests/stub_liberror.cc tests/stub_libformat.cc \
    tests/stub_libmgr.cc tests/stub_libsslsquid.cc \
    tests/stub_neighbors.cc tests/stub_Instance.cc \
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

# --- fuzz_http_header_parser (mirrors testHttpReply deps) ---
HDR_STUBS="\
    $S/tests/stub_CachePeer.o \
    $S/tests/stub_ETag.o \
    $S/tests/stub_HttpRequest.o \
    $S/tests/stub_StatHist.o \
    $S/tests/stub_access_log.o \
    $S/tests/stub_client_side.o \
    $S/tests/stub_errorpage.o \
    $S/tests/stub_fd.o \
    $S/tests/stub_fde.o \
    $S/tests/stub_libauth.o \
    $S/tests/stub_libcomm.o \
    $S/tests/stub_liberror.o \
    $S/tests/stub_libformat.o \
    $S/tests/stub_libmgr.o \
    $S/tests/stub_libsslsquid.o \
    $S/tests/stub_neighbors.o \
    $S/tests/stub_Instance.o"

HEADER_OBJS="\
    $S/HttpHeader.o \
    $S/HttpHeaderTools.o \
    $S/HttpHdrCc.o \
    $S/HttpHdrContRange.o \
    $S/HttpHdrRange.o \
    $S/HttpHdrSc.o \
    $S/HttpHdrScTarget.o \
    $S/HttpBody.o \
    $S/HttpControlMsg.o \
    $S/HttpReply.o \
    $S/ConfigParser.o \
    $S/MasterXaction.o \
    $S/Notes.o \
    $S/StatCounters.o \
    $S/CommCalls.o \
    $S/StrList.o \
    $S/Parsing.o \
    $S/cbdata.o \
    $S/hier_code.o"

HEADER_LIBS="-Wl,--start-group \
    $S/http/.libs/libhttp.a \
    $S/parser/.libs/libparser.a \
    $S/acl/.libs/libacls.a \
    $S/acl/.libs/libapi.a \
    $S/acl/.libs/libstate.a \
    $S/anyp/.libs/libanyp.a \
    $S/ip/.libs/libip.a \
    $S/base/.libs/libbase.a \
    $S/ipc/.libs/libipc.a \
    $S/sbuf/.libs/libsbuf.a \
    $SRC/squid/lib/.libs/libmisccontainers.a \
    $SRC/squid/lib/.libs/libmiscutil.a \
    $SRC/squid/lib/.libs/libmiscencoding.a \
    $SRC/squid/compat/.libs/libcompatsquid.a \
    -Wl,--end-group"

# Exclude stub_cbdata since we use real cbdata.o
HDR_BASE_STUBS=$(echo "$STUBS" | sed 's|[^ ]*/stub_cbdata\.o||')

$CXX $HARNESS_CXXFLAGS $INC \
    $FUZZ/harnesses/fuzz_http_header_parser.cc \
    $HDR_BASE_STUBS $HDR_STUBS \
    $HEADER_OBJS \
    $HEADER_LIBS $SYSLIBS \
    $LIB_FUZZING_ENGINE \
    -o $OUT/fuzz_http_header_parser

# --- fuzz_content_length ---
$CXX $HARNESS_CXXFLAGS $INC \
    -c $FUZZ/harnesses/cl_helpers.cc \
    -o $WORK/cl_helpers.o

$CXX $HARNESS_CXXFLAGS $INC \
    $FUZZ/harnesses/fuzz_content_length.cc \
    $STUBS $S/tests/stub_libanyp.o \
    $WORK/cl_helpers.o \
    $LIBS $SYSLIBS \
    $LIB_FUZZING_ENGINE \
    -o $OUT/fuzz_content_length

# --- fuzz_tls_handshake (uses real libsecurity, not stub) ---
TLS_STUBS=$(echo "$STUBS" | sed 's|[^ ]*/stub_libsecurity\.o||')

$CXX $HARNESS_CXXFLAGS $INC \
    $FUZZ/harnesses/fuzz_tls_handshake.cc \
    $TLS_STUBS $S/tests/stub_libanyp.o \
    -Wl,--start-group \
    $S/security/.libs/libsecurity.a \
    $S/http/.libs/libhttp.a \
    $S/parser/.libs/libparser.a \
    $S/anyp/.libs/libanyp.a \
    $S/base/.libs/libbase.a \
    $S/ip/.libs/libip.a \
    $S/sbuf/.libs/libsbuf.a \
    $SRC/squid/lib/.libs/libmiscutil.a \
    $SRC/squid/lib/.libs/libmiscencoding.a \
    $SRC/squid/compat/.libs/libcompatsquid.a \
    -Wl,--end-group \
    $SYSLIBS \
    $LIB_FUZZING_ENGINE \
    -o $OUT/fuzz_tls_handshake

# --- Seed corpora ---
cd $FUZZ/seeds
for dir in http1_requests http1_responses uris http_headers content_lengths tls_handshakes; do
    harness=""
    case "$dir" in
        http1_requests)  harness="fuzz_http1_request_parser" ;;
        http1_responses) harness="fuzz_http1_response_parser" ;;
        uris)            harness="fuzz_uri_parser" ;;
        http_headers)    harness="fuzz_http_header_parser" ;;
        content_lengths) harness="fuzz_content_length" ;;
        tls_handshakes)  harness="fuzz_tls_handshake" ;;
    esac
    if [ -d "$dir" ] && [ -n "$harness" ]; then
        zip -j $OUT/${harness}_seed_corpus.zip $dir/*
    fi
done

# --- Dictionaries ---
cp $FUZZ/dictionaries/http.dict $OUT/fuzz_http1_request_parser.dict
cp $FUZZ/dictionaries/http.dict $OUT/fuzz_http1_response_parser.dict
cp $FUZZ/dictionaries/uri.dict $OUT/fuzz_uri_parser.dict
cp $FUZZ/dictionaries/http.dict $OUT/fuzz_http_header_parser.dict
cp $FUZZ/dictionaries/http.dict $OUT/fuzz_content_length.dict
cp $FUZZ/dictionaries/tls.dict $OUT/fuzz_tls_handshake.dict
