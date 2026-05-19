/*
 * libFuzzer harness for Http::One::RequestParser
 *
 * Exercises the HTTP/1.x request parser that processes all inbound client
 * requests. This is the #1 CVE-producing parser in Squid -- see:
 *   SQUID-2024:2 (header parser DoS)
 *   SQUID-2024:1 (chunked decoding)
 *   SQUID-2023:1 (request smuggling in HTTP/1.1)
 *   SQUID-2020:1 (improper input validation)
 *
 * Prior art:
 *   - MegaManSec/Squid-Security-Audit (2021): AFL++ persistent mode,
 *     55 vulns found via patched Squid binary
 *   - PR #1531 (2023): oss-fuzz integration attempt, closed without merge
 *   - Opera Security (2021): custom fuzzer, 5 CVEs in response parsing
 *
 * Build: see ../scripts/build.sh or oss-fuzz/projects/squid/build.sh
 */

#include "squid.h"
#include "http/one/RequestParser.h"
#include "http/RequestMethod.h"
#include "MemBuf.h"
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
        Http::One::RequestParser strictParser;
        Config.onoff.relaxed_header_parser = 0;
        try {
            strictParser.parse(input);
        } catch (...) {
        }
    }

    {
        Http::One::RequestParser relaxedParser;
        Config.onoff.relaxed_header_parser = 1;
        try {
            relaxedParser.parse(input);
        } catch (...) {
        }
    }

    return 0;
}
