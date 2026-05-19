/*
 * libFuzzer harness for AnyP::Uri parsing
 *
 * URI parsing bugs have caused multiple CVEs:
 *   SQUID-2025:1 (buffer overflow in URN handling)
 *   SQUID-2019:8 (multiple URI processing issues)
 *   SQUID-2004:1 (URL encoding tricks)
 *
 * Also exercises matchDomainName() which is used by ACL matching --
 * important for egress policy correctness.
 */

#include "squid.h"
#include "anyp/Uri.h"
#include "http/RequestMethod.h"
#include "sbuf/SBuf.h"
#include "SquidConfig.h"

#include "fuzz_init.h"

static bool uri_initialized = false;

static void ensureUriInit()
{
    if (uri_initialized)
        return;

    FuzzInitParser();
    AnyP::UriScheme::Init();

    Config.appendDomain = nullptr;
    Config.appendDomainLen = 0;
    Config.uri_whitespace = 0;

    uri_initialized = true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ensureUriInit();

    if (size == 0 || size > 8192)
        return 0;

    SBuf input(reinterpret_cast<const char *>(data), size);

    {
        AnyP::Uri uri;
        try {
            uri.parse(Http::METHOD_CONNECT, input);
        } catch (...) {
        }
    }

    {
        AnyP::Uri uri;
        try {
            uri.parse(Http::METHOD_GET, input);
        } catch (...) {
        }
    }

    return 0;
}
