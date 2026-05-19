/*
 * libFuzzer harness for Security::HandshakeParser
 *
 * Parses TLS/SSL ClientHello and ServerHello messages. This is the code
 * that extracts SNI, TLS version, ciphers, and session info from the
 * initial TLS handshake -- used for ssl_bump peek/splice decisions.
 *
 * A malicious origin server or client could send crafted TLS records to
 * exploit parser bugs, potentially bypassing SSL bump policy or crashing
 * the proxy.
 *
 * The parser handles:
 *   - TLS 1.0-1.3 record format
 *   - SSLv2 ClientHello (legacy compatibility)
 *   - Extensions: SNI, supported_versions, ALPN, etc.
 */

#include "squid.h"
#include "security/Handshake.h"
#include "sbuf/SBuf.h"
#include "SquidConfig.h"

#include "fuzz_init.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzInitParser();

    if (size == 0 || size > 64 * 1024)
        return 0;

    SBuf input(reinterpret_cast<const char *>(data), size);

    // Parse as ClientHello (the primary attack surface for egress proxies)
    {
        Security::HandshakeParser parser(Security::HandshakeParser::fromClient);
        try {
            parser.parseHello(input);
        } catch (...) {
        }
    }

    // Parse as ServerHello (attacker-controlled in egress scenario)
    {
        Security::HandshakeParser parser(Security::HandshakeParser::fromServer);
        try {
            parser.parseHello(input);
        } catch (...) {
        }
    }

    return 0;
}
