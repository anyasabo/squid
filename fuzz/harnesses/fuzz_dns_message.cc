/*
 * libFuzzer harness for rfc1035MessageUnpack()
 *
 * DNS response parsing. This is the code that unpacks DNS reply
 * packets from upstream resolvers. A malicious or compromised DNS
 * server could send crafted responses to exploit parser bugs.
 *
 * rfc1035MessageUnpack is pure C with no Squid global state dependencies,
 * making it an ideal fuzzing target. Existing testRFC1035.cc has only 4
 * hand-crafted test cases.
 *
 * Attack surface includes:
 *   - Name compression pointer loops
 *   - Oversized/truncated records
 *   - Malformed header counts (qdcount, ancount, nscount, arcount)
 *   - CNAME chains
 */

#include "squid.h"
#include "dns/rfc1035.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 65536)
        return 0;

    rfc1035_message *message = nullptr;
    int result = rfc1035MessageUnpack(
        reinterpret_cast<const char *>(data),
        size,
        &message);

    if (message) {
        if (result > 0 && message->answer)
            rfc1035RRDestroy(&message->answer, result);
        rfc1035MessageDestroy(&message);
    }

    return 0;
}
