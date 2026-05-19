/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * A stub implementation of the Debug.h API.
 * For use by test binaries which do not need the full context debugging
 *
 * Note: it doesn't use the STUB API as the functions defined here must
 * not abort the unit test.
 */
#include "squid.h"
#include "debug/Stream.h"

#define STUB_API "debug/libdebug.la"
#include "tests/STUB.h"

char *Debug::debugOptions;
char *Debug::cache_log= nullptr;
int Debug::rotateNumber = 0;
int Debug::Levels[MAX_DEBUG_SECTIONS];
int Debug::override_X = 0;
bool Debug::log_syslog = false;
void Debug::ForceAlert() STUB

void ResyncDebugLog(FILE *) STUB

FILE *
DebugStream()
{
    return stderr;
}

void
_db_rotate_log(void)
{}

void
Debug::FormatStream(std::ostream &buf)
{
    const static std::ostringstream cleanStream;
    buf.flags(cleanStream.flags() | std::ios::fixed);
    buf.width(cleanStream.width());
    buf.precision(2);
    buf.fill(' ');
}

void
Debug::LogMessage(const Context &context)
{
    if (context.level > DBG_IMPORTANT)
        return;

    if (!stderr)
        return;

    fprintf(stderr, "%s| %s\n",
            "stub time", // debugLogTime(current_time),
            context.buf.str().c_str());
}

std::ostream &
Debug::Extra(std::ostream &os)
{
    FormatStream(os);
    os << "\n    ";
    return os;
}

bool Debug::StderrEnabled() STUB_RETVAL(false)
void Debug::PrepareToDie() STUB

void
Debug::parseOptions(char const *)
{}

Debug::Context *Debug::Current = nullptr;

Debug::Context::Context(const int aSection, const int aLevel):
    section(aSection),
    level(aLevel),
    sectionLevel(Levels[aSection]),
    upper(Current),
    forceAlert(false)
{
    FormatStream(buf);
}

std::ostringstream &
Debug::Start(const int section, const int level)
{
    // Use a static thread-local Context to avoid heap allocation on every
    // debugs() call. In fuzzing this eliminates ~30% throughput loss from
    // malloc/free churn; in regular unit tests the difference is negligible.
    static thread_local Context ctx(0, 0);
    ctx.section = section;
    ctx.level = level;
    ctx.sectionLevel = Levels[section];
    ctx.upper = Current;
    ctx.forceAlert = false;
    ctx.buf.str(std::string());
    ctx.buf.clear();
    FormatStream(ctx.buf);
    Current = &ctx;
    return Current->buf;
}

void
Debug::Finish()
{
    if (Current) {
        LogMessage(*Current);
        Current = nullptr;
    }
}

std::ostream&
ForceAlert(std::ostream& s)
{
    return s;
}

