/*
 * libFuzzer harness for HttpHdrCc::parse()
 *
 * Cache-Control is a complex header with many directives that interact
 * with caching behavior. Bugs here can cause stale content delivery or
 * cache poisoning.
 *
 * Input: raw Cache-Control header value string (e.g., "max-age=0, no-cache")
 */

#include "squid.h"
#include "HttpHdrCc.h"
#include "SquidString.h"
#include "SquidConfig.h"

#include "fuzz_init.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzInitParser();

    if (size == 0 || size > 4096)
        return 0;

    String field;
    field.assign(reinterpret_cast<const char *>(data), size);

    HttpHdrCc cc;
    try {
        cc.parse(field);
    } catch (...) {
    }

    return 0;
}
