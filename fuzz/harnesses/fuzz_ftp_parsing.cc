/*
 * libFuzzer harness for FTP address parsing functions
 *
 * Ftp::ParseIpPort() parses "A1,A2,A3,A4,P1,P2" from PORT/PASV responses.
 * Ftp::ParseProtoIpPort() parses EPRT "<d><proto><d><addr><d><port><d>".
 *
 * These parse untrusted data from FTP servers and clients. Bugs can
 * lead to SSRF (connecting to attacker-controlled IPs/ports) or crashes.
 */

#include "squid.h"
#include "ftp/Parsing.h"
#include "ip/Address.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 4096)
        return 0;

    // Ensure null-termination for C string APIs
    char *buf = new char[size + 1];
    memcpy(buf, data, size);
    buf[size] = '\0';

    Ip::Address addr;

    // ParseIpPort: "A1,A2,A3,A4,P1,P2"
    try {
        Ftp::ParseIpPort(buf, nullptr, addr);
    } catch (...) {
    }

    // ParseIpPort with forced IP
    try {
        Ftp::ParseIpPort(buf, "127.0.0.1", addr);
    } catch (...) {
    }

    // ParseProtoIpPort: EPRT format
    try {
        Ftp::ParseProtoIpPort(buf, addr);
    } catch (...) {
    }

    delete[] buf;
    return 0;
}
