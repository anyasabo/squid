/*
 * libFuzzer harness for Http::ContentLengthInterpreter
 *
 * ContentLengthInterpreter handles the security-critical task of
 * determining the intended Content-Length from potentially ambiguous
 * header fields. Disagreements in Content-Length interpretation between
 * Squid and backend servers are the root cause of HTTP smuggling.
 *
 * Attack surface:
 *   - Multiple Content-Length values: "Content-Length: 1, 100"
 *   - Repeated Content-Length fields with different values
 *   - Whitespace/sign tricks: " 100", "+100", "100 "
 *   - Overflow values: "99999999999999999999"
 *   - Non-numeric prefixes/suffixes
 */

#include "squid.h"
#include "http/ContentLengthInterpreter.h"
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

    // Test as a fresh interpreter (first field seen)
    {
        Http::ContentLengthInterpreter interpreter;
        try {
            interpreter.checkField(field);
        } catch (...) {
        }
    }

    // Test with multiple fields: split input at first newline
    {
        Http::ContentLengthInterpreter interpreter;
        const char *buf = reinterpret_cast<const char *>(data);
        const char *split = static_cast<const char *>(memchr(buf, '\n', size));
        if (split && split > buf && split < buf + size - 1) {
            String first;
            first.assign(buf, split - buf);
            String second;
            second.assign(split + 1, size - (split - buf) - 1);
            try {
                interpreter.checkField(first);
                interpreter.checkField(second);
            } catch (...) {
            }
        }
    }

    return 0;
}
