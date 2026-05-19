/*
 * Minimal implementations of functions needed by HttpHdrCc::parse(),
 * avoiding the deep dependency chain from HttpHeaderTools.o and HttpHeader.o.
 *
 * httpHeaderParseInt: from HttpHeaderTools.cc (atoi wrapper)
 * httpHeaderParseQuotedString: from HttpHeader.cc (quoted-string parser)
 * strListGetItem: from StrList.cc (comma-separated list iterator)
 */

#include "squid.h"
#include "HttpHeaderStat.h"
#include "SquidString.h"
#include "StatHist.h"

#include <cstdlib>
#include <cstring>

// HttpHdrCc.cc references this global for stats dumping
const HttpHeaderStat *dump_stat = nullptr;

// StatHist::count is called from HttpHdrCc stats tracking
void StatHist::count(double) {}

int
httpHeaderParseInt(const char *start, int *value)
{
    *value = atoi(start);
    if (!*value && *start != '0')
        return 0;
    return 1;
}

int
httpHeaderParseQuotedString(const char *start, const int len, String *val)
{
    val->clean();
    if (*start != '"')
        return 0;

    const char *pos = start + 1;

    while (*pos != '"' && len > (pos - start)) {
        if (*pos == '\r') {
            ++pos;
            if ((pos - start) > len || *pos != '\n') {
                val->clean();
                return 0;
            }
        }
        if (*pos == '\n') {
            ++pos;
            if ((pos - start) > len || (*pos != ' ' && *pos != '\t')) {
                val->clean();
                return 0;
            }
        }
        if (*pos == '\\') {
            ++pos;
            if ((pos - start) > len) {
                val->clean();
                return 0;
            }
        }
        val->append(pos, 1);
        ++pos;
    }

    if (*pos != '"')
        return 0;

    return 1;
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
