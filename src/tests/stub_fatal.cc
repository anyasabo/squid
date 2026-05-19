/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * A stub implementation of fatal.cc that throws instead of calling exit().
 *
 * This allows unit tests and fuzz targets to exercise error paths without
 * terminating the process. Link this instead of the real fatal.o when
 * building test binaries that need to survive fatal() calls.
 *
 * Follows the same stub pattern as stub_debug.cc, stub_tools.cc, etc.
 */

#include "squid.h"
#include "fatal.h"

#include <stdexcept>

void
fatal(const char *message)
{
    throw std::runtime_error(message ? message : "fatal");
}

void
fatalf(const char *fmt, ...)
{
    static char buf[BUFSIZ];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    throw std::runtime_error(buf);
}

void
fatal_dump(const char *message)
{
    throw std::runtime_error(message ? message : "fatal_dump");
}
