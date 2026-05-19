/*
 * libFuzzer harness for HttpHeader::parse()
 *
 * HTTP header parsing bugs have been the source of multiple CVEs:
 *   SQUID-2024:2 (header parser DoS)
 *   MegaManSec: multiple header parsing crashes and UAFs
 *
 * HttpHeader::parse() processes raw header blocks into structured
 * header entries. It integrates with ContentLengthInterpreter for
 * smuggling-critical Content-Length validation.
 *
 * The two parse() overloads:
 *   parse(buf, len, interpreter) -- parses pre-extracted header block
 *   parse(buf, len, atEnd, hdr_sz, interpreter) -- finds header end first
 */

#include "squid.h"
#include "HttpHeader.h"
#include "http/ContentLengthInterpreter.h"
#include "sbuf/SBuf.h"
#include "SquidConfig.h"

#include "fuzz_init.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzInitParser();

    if (size == 0 || size > 64 * 1024)
        return 0;

    const char *buf = reinterpret_cast<const char *>(data);

    // Test the header-block parse (assumes header block already extracted)
    {
        HttpHeader hdr(hoRequest);
        Http::ContentLengthInterpreter interpreter;
        try {
            hdr.parse(buf, size, interpreter);
        } catch (...) {
        }
        hdr.clean();
    }

    // Test as a response header
    {
        HttpHeader hdr(hoReply);
        Http::ContentLengthInterpreter interpreter;
        try {
            hdr.parse(buf, size, interpreter);
        } catch (...) {
        }
        hdr.clean();
    }

    // Test the full-message parse that finds the header boundary
    {
        HttpHeader hdr(hoRequest);
        Http::ContentLengthInterpreter interpreter;
        size_t hdr_sz = 0;
        try {
            hdr.parse(buf, size, true, hdr_sz, interpreter);
        } catch (...) {
        }
        hdr.clean();
    }

    return 0;
}
