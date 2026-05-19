/*
 * Minimal implementations of functions needed by ContentLengthInterpreter,
 * extracted to avoid pulling in HttpHeaderTools.o and StrList.o which have
 * deep dependency chains into HttpHeader, HttpHdrContRange, etc.
 *
 * httpHeaderParseOffset: from src/HttpHeaderTools.cc (strtoll wrapper)
 * strListGetItem: from src/StrList.cc (comma-separated list iterator)
 */

#include "squid.h"
#include "SquidString.h"

#include <cerrno>
#include <climits>
#include <cstdlib>

bool
httpHeaderParseOffset(const char *start, int64_t *value, char **endPtr)
{
    char *end = nullptr;
    errno = 0;
    const int64_t res = strtoll(start, &end, 10);
    if (errno && !res)
        return false;
    if (errno == ERANGE && (res == LLONG_MIN || res == LLONG_MAX))
        return false;
    if (start == end)
        return false;
    *value = res;
    if (endPtr)
        *endPtr = end;
    return true;
}

int
strListGetItem(const String *str, char del, const char **item, int *ilen, const char **pos)
{
    size_t len;

    if (*pos) {
        if (!**pos)
            return 0;
    } else {
        *pos = str->rawBuf();
        if (!*pos)
            return 0;
    }

    while (**pos == ' ' || **pos == del)
        ++(*pos);

    *item = *pos;

    char delstr[2] = { del, '\0' };
    len = strcspn(*pos, delstr);
    *pos += len;

    while (len > 0 && (*item)[len - 1] == ' ')
        --len;

    *ilen = static_cast<int>(len);

    if (**pos) {
        ++(*pos);
        return 1;
    } else {
        return *ilen ? 1 : 0;
    }
}
