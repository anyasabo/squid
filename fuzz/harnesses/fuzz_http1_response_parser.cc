/*
 * libFuzzer harness for Http::One::ResponseParser
 *
 * Exercises the HTTP/1.x response parser that processes all origin server
 * replies. Origin responses are attacker-controlled in an egress proxy
 * scenario (malicious destination servers).
 *
 * CVEs in this area:
 *   SQUID-2024:1 (chunked decoding crash)
 *   Opera/CVE-2021-33620 (Content-Range crash)
 *   Opera/CVE-2021-28662 (Vary: Other assertion)
 *   MegaManSec: multiple response parsing crashes and UAFs
 */

#include "squid.h"
#include "http/one/ResponseParser.h"
#include "sbuf/SBuf.h"
#include "SquidConfig.h"

#include "fuzz_init.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzInitParser();

    if (size == 0 || size > 64 * 1024)
        return 0;

    SBuf input(reinterpret_cast<const char *>(data), size);

    {
        Http::One::ResponseParser strictParser;
        Config.onoff.relaxed_header_parser = 0;
        try {
            strictParser.parse(input);
        } catch (...) {
        }
    }

    {
        Http::One::ResponseParser relaxedParser;
        Config.onoff.relaxed_header_parser = 1;
        try {
            relaxedParser.parse(input);
        } catch (...) {
        }
    }

    return 0;
}
