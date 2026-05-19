FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    clang-14 llvm-14 lld-14 \
    build-essential automake autoconf libtool pkg-config \
    libssl-dev zip \
    && update-alternatives --install /usr/bin/clang clang /usr/bin/clang-14 100 \
    && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-14 100 \
    && rm -rf /var/lib/apt/lists/*

ENV CC=clang
ENV CXX=clang++

WORKDIR /squid
COPY . /squid/

RUN ./bootstrap.sh

ENV FUZZ_CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -fsanitize=address,undefined,fuzzer-no-link -fno-sanitize-recover=all"

RUN ./configure \
    CXX="clang++" \
    CC="clang" \
    CXXFLAGS="$FUZZ_CFLAGS" \
    CFLAGS="$FUZZ_CFLAGS" \
    LDFLAGS="-fsanitize=address,undefined" \
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

RUN make -j$(nproc) || true

# Compile test stubs (only built during `make check`, not regular `make`)
RUN cd src && \
    STUB_FLAGS="-std=c++17 -DHAVE_CONFIG_H -DSTUB_THROWS \
        -DDEFAULT_CONFIG_FILE=\"/usr/local/squid/etc/squid.conf\" \
        -DDEFAULT_SQUID_DATA_DIR=\"/usr/local/squid/share\" \
        -DDEFAULT_SQUID_CONFIG_DIR=\"/usr/local/squid/etc\" \
        -I.. -I../include -I../lib -I. -I../include \
        $FUZZ_CFLAGS" && \
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
        globals.cc MemBuf.cc String.cc mime_header.cc wordlist.cc; do \
        out=$(echo "$stub" | sed 's|\.cc$|.o|'); \
        clang++ $STUB_FLAGS \
            -c "$stub" -o "$out" || echo "  FAILED: $stub"; \
    done && \
    clang++ $STUB_FLAGS \
        -c ../test-suite/test_tools.cc -o test_tools.o

RUN ls src/http/.libs/libhttp.a \
       src/parser/.libs/libparser.a \
       src/base/.libs/libbase.a \
       src/sbuf/.libs/libsbuf.a \
       src/SquidConfig.o \
       src/tests/stub_debug.o \
       src/tests/stub_fatal.o \
       src/globals.o \
       src/test_tools.o

RUN mkdir -p /fuzz/build && \
    cp -r /squid/fuzz/harnesses /fuzz/harnesses && \
    cp -r /squid/fuzz/seeds /fuzz/seeds && \
    cp -r /squid/fuzz/dictionaries /fuzz/dictionaries

WORKDIR /fuzz

ENV FUZZ_LINK="-O1 -fno-omit-frame-pointer -gline-tables-only -fsanitize=address,undefined,fuzzer -fno-sanitize-recover=all -std=c++17 -DSTUB_THROWS"
ENV FUZZ_INC="-I/squid/include -I/squid/src -I/squid/lib -I/squid -I/fuzz/harnesses"

ENV COMMON_STUBS="\
    /squid/src/globals.o \
    /squid/src/test_tools.o \
    /squid/src/tests/stub_HelperChildConfig.o \
    /squid/src/tests/stub_MemObject.o \
    /squid/src/tests/stub_cache_cf.o \
    /squid/src/tests/stub_cache_manager.o \
    /squid/src/tests/stub_cbdata.o \
    /squid/src/tests/stub_comm.o \
    /squid/src/tests/stub_debug.o \
    /squid/src/tests/stub_event.o \
    /squid/src/tests/stub_libmem.o \
    /squid/src/tests/stub_libsecurity.o \
    /squid/src/tests/stub_stmem.o \
    /squid/src/tests/stub_store.o \
    /squid/src/tests/stub_store_stats.o \
    /squid/src/tests/stub_tools.o \
    /squid/src/tests/stub_libtime.o \
    /squid/src/tests/stub_fatal.o \
    /squid/src/SquidConfig.o \
    /squid/src/MemBuf.o \
    /squid/src/String.o \
    /squid/src/mime_header.o \
    /squid/src/wordlist.o"

ENV COMMON_LIBS="\
    -Wl,--start-group \
    /squid/src/http/.libs/libhttp.a \
    /squid/src/parser/.libs/libparser.a \
    /squid/src/anyp/.libs/libanyp.a \
    /squid/src/base/.libs/libbase.a \
    /squid/src/ip/.libs/libip.a \
    /squid/src/sbuf/.libs/libsbuf.a \
    /squid/lib/.libs/libmiscutil.a \
    /squid/lib/.libs/libmiscencoding.a \
    /squid/compat/.libs/libcompatsquid.a \
    -Wl,--end-group"

ENV COMMON_SYSLIBS="-lssl -lcrypto -lpthread -ldl"

# HTTP/1 parser fuzzers (use stub_libanyp)
RUN echo "=== Building fuzz_http1_request_parser ===" && \
    clang++ $FUZZ_LINK $FUZZ_INC \
        harnesses/fuzz_http1_request_parser.cc \
        $COMMON_STUBS /squid/src/tests/stub_libanyp.o \
        $COMMON_LIBS $COMMON_SYSLIBS \
        -o build/fuzz_http1_request_parser && \
    echo "  OK" && \
    echo "=== Building fuzz_http1_response_parser ===" && \
    clang++ $FUZZ_LINK $FUZZ_INC \
        harnesses/fuzz_http1_response_parser.cc \
        $COMMON_STUBS /squid/src/tests/stub_libanyp.o \
        $COMMON_LIBS $COMMON_SYSLIBS \
        -o build/fuzz_http1_response_parser && \
    echo "  OK"

# URI parser fuzzer (real libanyp + typeinfo stubs)
RUN echo "=== Building fuzz_uri_parser ===" && \
    clang++ $FUZZ_LINK \
        -c harnesses/uri_typeinfo_stubs.cc -o build/uri_typeinfo_stubs.o && \
    clang++ $FUZZ_LINK $FUZZ_INC \
        harnesses/fuzz_uri_parser.cc \
        $COMMON_STUBS \
        build/uri_typeinfo_stubs.o \
        $COMMON_LIBS $COMMON_SYSLIBS \
        -o build/fuzz_uri_parser && \
    echo "  OK"

# HTTP header parser (mirrors testHttpReply deps from Makefile.am)
RUN echo "=== Building fuzz_http_header_parser ===" && \
    HDR_BASE_STUBS=$(echo "$COMMON_STUBS" | sed 's|[^ ]*/stub_cbdata\.o||') && \
    clang++ $FUZZ_LINK $FUZZ_INC \
        harnesses/fuzz_http_header_parser.cc \
        $HDR_BASE_STUBS \
        /squid/src/tests/stub_CachePeer.o \
        /squid/src/tests/stub_ETag.o \
        /squid/src/tests/stub_HttpRequest.o \
        /squid/src/tests/stub_StatHist.o \
        /squid/src/tests/stub_access_log.o \
        /squid/src/tests/stub_client_side.o \
        /squid/src/tests/stub_errorpage.o \
        /squid/src/tests/stub_fd.o \
        /squid/src/tests/stub_fde.o \
        /squid/src/tests/stub_libauth.o \
        /squid/src/tests/stub_libcomm.o \
        /squid/src/tests/stub_liberror.o \
        /squid/src/tests/stub_libformat.o \
        /squid/src/tests/stub_libmgr.o \
        /squid/src/tests/stub_libsslsquid.o \
        /squid/src/tests/stub_neighbors.o \
        /squid/src/tests/stub_Instance.o \
        /squid/src/HttpHeader.o \
        /squid/src/HttpHeaderTools.o \
        /squid/src/HttpHdrCc.o \
        /squid/src/HttpHdrContRange.o \
        /squid/src/HttpHdrRange.o \
        /squid/src/HttpHdrSc.o \
        /squid/src/HttpHdrScTarget.o \
        /squid/src/HttpBody.o \
        /squid/src/HttpControlMsg.o \
        /squid/src/HttpReply.o \
        /squid/src/ConfigParser.o \
        /squid/src/MasterXaction.o \
        /squid/src/Notes.o \
        /squid/src/StatCounters.o \
        /squid/src/CommCalls.o \
        /squid/src/StrList.o \
        /squid/src/Parsing.o \
        /squid/src/cbdata.o \
        /squid/src/hier_code.o \
        -Wl,--start-group \
        /squid/src/http/.libs/libhttp.a \
        /squid/src/parser/.libs/libparser.a \
        /squid/src/acl/.libs/libacls.a \
        /squid/src/acl/.libs/libapi.a \
        /squid/src/acl/.libs/libstate.a \
        /squid/src/anyp/.libs/libanyp.a \
        /squid/src/ip/.libs/libip.a \
        /squid/src/base/.libs/libbase.a \
        /squid/src/ipc/.libs/libipc.a \
        /squid/src/sbuf/.libs/libsbuf.a \
        /squid/lib/.libs/libmisccontainers.a \
        /squid/lib/.libs/libmiscutil.a \
        /squid/lib/.libs/libmiscencoding.a \
        /squid/compat/.libs/libcompatsquid.a \
        -Wl,--end-group \
        $COMMON_SYSLIBS \
        -o build/fuzz_http_header_parser && \
    echo "  OK"

# Content-Length interpreter
RUN echo "=== Building fuzz_content_length ===" && \
    clang++ $FUZZ_LINK $FUZZ_INC \
        -c harnesses/cl_helpers.cc -o build/cl_helpers.o && \
    clang++ $FUZZ_LINK $FUZZ_INC \
        harnesses/fuzz_content_length.cc \
        $COMMON_STUBS /squid/src/tests/stub_libanyp.o \
        build/cl_helpers.o \
        $COMMON_LIBS $COMMON_SYSLIBS \
        -o build/fuzz_content_length && \
    echo "  OK"

# TLS handshake parser (uses real libsecurity, not stub)
RUN echo "=== Building fuzz_tls_handshake ===" && \
    TLS_STUBS=$(echo "$COMMON_STUBS" | sed 's|[^ ]*/stub_libsecurity\.o||') && \
    clang++ $FUZZ_LINK $FUZZ_INC \
        harnesses/fuzz_tls_handshake.cc \
        $TLS_STUBS /squid/src/tests/stub_libanyp.o \
        -Wl,--start-group \
        /squid/src/security/.libs/libsecurity.a \
        /squid/src/http/.libs/libhttp.a \
        /squid/src/parser/.libs/libparser.a \
        /squid/src/anyp/.libs/libanyp.a \
        /squid/src/base/.libs/libbase.a \
        /squid/src/ip/.libs/libip.a \
        /squid/src/sbuf/.libs/libsbuf.a \
        /squid/lib/.libs/libmiscutil.a \
        /squid/lib/.libs/libmiscencoding.a \
        /squid/compat/.libs/libcompatsquid.a \
        -Wl,--end-group \
        $COMMON_SYSLIBS \
        -o build/fuzz_tls_handshake && \
    echo "  OK"

# Cache-Control parser
RUN echo "=== Building fuzz_cache_control ===" && \
    clang++ $FUZZ_LINK $FUZZ_INC \
        -c harnesses/cc_helpers.cc -o build/cc_helpers.o && \
    clang++ $FUZZ_LINK $FUZZ_INC \
        harnesses/fuzz_cache_control.cc \
        $COMMON_STUBS /squid/src/tests/stub_libanyp.o \
        /squid/src/HttpHdrCc.o \
        build/cc_helpers.o \
        $COMMON_LIBS $COMMON_SYSLIBS \
        -o build/fuzz_cache_control && \
    echo "  OK"

# DNS message parser
RUN echo "=== Building fuzz_dns_message ===" && \
    clang++ $FUZZ_LINK $FUZZ_INC \
        harnesses/fuzz_dns_message.cc \
        $COMMON_STUBS /squid/src/tests/stub_libanyp.o \
        /squid/src/dns/rfc1035.o /squid/src/dns/rfc2671.o \
        $COMMON_LIBS $COMMON_SYSLIBS \
        -o build/fuzz_dns_message && \
    echo "  OK"

# FTP address parsing
RUN echo "=== Building fuzz_ftp_parsing ===" && \
    clang++ $FUZZ_LINK $FUZZ_INC \
        harnesses/fuzz_ftp_parsing.cc \
        $COMMON_STUBS /squid/src/tests/stub_libanyp.o \
        /squid/src/ftp/Parsing.o \
        $COMMON_LIBS $COMMON_SYSLIBS \
        -o build/fuzz_ftp_parsing && \
    echo "  OK"

RUN echo "=== Built harnesses ===" && ls -la build/fuzz_* 2>/dev/null || echo "(none built)"
