/*
 * Shared initialization for libFuzzer harnesses.
 *
 * Call FuzzInitParser() or FuzzInitUri() once in LLVMFuzzerTestOneInput
 * (via ensureInit pattern) to set up the minimal Squid global state
 * needed for parser fuzzing.
 */

#ifndef SQUID_FUZZ_INIT_H
#define SQUID_FUZZ_INIT_H

#include "SquidConfig.h"

static bool fuzz_initialized = false;

static void FuzzInitParser()
{
    if (fuzz_initialized)
        return;

    Mem::Init();

    Config.onoff.relaxed_header_parser = 0;
    Config.maxRequestHeaderSize = 64 * 1024;
    Config.maxReplyHeaderSize = 64 * 1024;

    fuzz_initialized = true;
}

#endif /* SQUID_FUZZ_INIT_H */
