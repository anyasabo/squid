# Squid Parser Fuzzing Harnesses

libFuzzer-based fuzz targets for security-critical Squid parsers, with
AddressSanitizer and UndefinedBehaviorSanitizer enabled.

Designed for [OSS-Fuzz](https://github.com/google/oss-fuzz) compatibility:
harnesses use the standard `LLVMFuzzerTestOneInput` entry point and can link
against `$LIB_FUZZING_ENGINE` (libFuzzer, AFL++, Honggfuzz, or Centipede).

## Targets

| Harness | Parser | CVE history |
|---------|--------|-------------|
| `fuzz_http1_request_parser` | `Http::One::RequestParser::parse()` | SQUID-2024:2, 2023:1, 2020:1 |
| `fuzz_http1_response_parser` | `Http::One::ResponseParser::parse()` | SQUID-2024:1, CVE-2021-33620/28662 |
| `fuzz_uri_parser` | `AnyP::Uri::parse()` | SQUID-2025:1, 2019:8 |

## Setup

### macOS ARM64 (Apple Silicon)

Apple's system clang does not ship the libFuzzer runtime. Install LLVM via
Homebrew:

```bash
brew install llvm automake libtool
```

This installs clang with libFuzzer at `/opt/homebrew/opt/llvm/`. The build
script detects and uses it automatically.

Build and run:

```bash
cd fuzz
make build    # bootstrap + configure + compile Squid + link harnesses (~5 min)
make run      # run HTTP/1 request parser fuzzer
```

### Ubuntu 22.04

```bash
sudo apt-get install -y clang-14 llvm-14 lld-14 \
    build-essential automake autoconf libtool pkg-config libssl-dev

sudo update-alternatives --install /usr/bin/clang   clang   /usr/bin/clang-14   100
sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-14 100
```

Build and run:

```bash
cd fuzz
make build
make run
```

### Docker (any platform)

If you don't want to install toolchains locally, Docker works everywhere:

```bash
cd fuzz
make docker-build   # builds Ubuntu 22.04 image with Squid + harnesses (~10 min)
make docker-run     # run HTTP/1 request parser fuzzer
```

## Usage

```bash
# Run a specific fuzzer (with dictionary)
make run TARGET=fuzz_http1_response_parser SEEDS=http1_responses
make run TARGET=fuzz_uri_parser SEEDS=uris

# Run all three fuzzers for 5 minutes each
make run-all

# Docker equivalents
make docker-run TARGET=fuzz_uri_parser SEEDS=uris
make docker-run-all

# Interactive Docker shell for debugging crashes
make docker-shell
```

Crash inputs are saved to `fuzz/crashes/`. To reproduce a crash:

```bash
./build/fuzz_http1_request_parser crashes/crash-<hash>
```

### Using dictionaries

Dictionaries improve fuzzing efficiency by seeding the mutator with protocol
tokens. Pass them to libFuzzer with `-dict=`:

```bash
./build/fuzz_http1_request_parser \
    seeds/http1_requests/ corpus/ \
    -dict=dictionaries/http.dict \
    -artifact_prefix=crashes/
```

## Build Steps (what `make build` does)

The build script (`scripts/build.sh`) runs three stages:

1. **`configure`** -- bootstraps Squid's autotools and configures with
   sanitizer instrumentation. Libraries get sanitizer flags; the fuzzer
   `main()` is added only at harness link time.

2. **`make`** -- builds Squid's convenience libraries (`.a` files) and compiles
   stub objects from `src/tests/` that isolate parsers from the rest of Squid.
   Stubs are compiled with `-DSTUB_THROWS` so they throw exceptions instead of
   calling `exit()` when hit.

3. **`harnesses`** -- compiles each fuzz target and links it against the
   instrumented libraries, stubs, and the fuzzing engine (libFuzzer by default,
   or `$LIB_FUZZING_ENGINE` if set).

You can run these individually:

```bash
./scripts/build.sh configure   # just configure
./scripts/build.sh make        # just build libs (after configure)
./scripts/build.sh harnesses   # just link harnesses (after make)
```

## Testability Improvements

This fork includes changes to Squid's test infrastructure that improve both
unit test robustness and fuzzing throughput:

| Change | File | Effect |
|--------|------|--------|
| `stub_fatal.cc` | `src/tests/stub_fatal.cc` | `fatal()` throws `std::runtime_error` instead of `exit()` |
| `STUB_THROWS` mode | `src/tests/STUB.h` | When `-DSTUB_THROWS` is defined, `stub_fatal()` throws instead of `exit()` |
| `Debug::Start()` optimization | `src/tests/stub_debug.cc` | Uses `thread_local` Context instead of heap allocation (~30% fuzzing throughput gain) |
| Shared init | `fuzz/harnesses/fuzz_init.h` | Canonical `FuzzInitParser()` / `FuzzInitUri()` reduces harness boilerplate |

These changes are upstream-friendly: they follow existing Squid patterns
(`stub_*.cc`, `Assure()` throw-instead-of-abort), don't add `#ifdef`
conditionals to production code, and are concentrated in `src/tests/`.

## OSS-Fuzz Integration

The `oss-fuzz/` directory contains the three files needed to submit Squid to
[Google OSS-Fuzz](https://github.com/google/oss-fuzz):

- `oss-fuzz/project.yaml` -- project metadata
- `oss-fuzz/Dockerfile` -- build environment (based on `gcr.io/oss-fuzz-base/base-builder`)
- `oss-fuzz/build.sh` -- build script using `$CC`, `$CXX`, `$CFLAGS`,
  `$CXXFLAGS`, `$LIB_FUZZING_ENGINE`, `$OUT`

To test locally with the OSS-Fuzz infrastructure:

```bash
git clone https://github.com/google/oss-fuzz.git
cp -r fuzz/oss-fuzz/* oss-fuzz/projects/squid/
cd oss-fuzz
python3 infra/helper.py build_image squid
python3 infra/helper.py build_fuzzers --sanitizer address squid
python3 infra/helper.py check_build squid
python3 infra/helper.py run_fuzzer squid fuzz_http1_request_parser
```

## Architecture

Each harness links against Squid's static libraries the same way unit tests do.
Different harnesses use different stub sets:

- **HTTP parsers** use `stub_libanyp.o` (stubs out URI parsing they don't need)
- **URI parser** links the real `libanyp.a` and uses `uri_typeinfo_stubs.cc`
  to provide RTTI symbols for classes referenced but never instantiated

On Linux, `-Wl,--start-group`/`--end-group` handles circular dependencies
between static libraries. On macOS, `ld64` rescans archives by default.

## Extending

To add a new fuzz target:

1. Create `harnesses/fuzz_<name>.cc` with `LLVMFuzzerTestOneInput()`
2. Add seed inputs to `seeds/<name>/`
3. Add the link command to `scripts/build.sh`, `Dockerfile`, and `oss-fuzz/build.sh`
4. Add a dictionary entry to `dictionaries/`
5. If the target needs types not in the common stubs, add typeinfo stubs

Good candidates for new targets:
- `HttpHeader::parse()` -- header field parsing
- `HttpHdrCc::parse()` -- Cache-Control header
- `ContentLengthInterpreter::checkField()` -- Content-Length framing (smuggling-critical)
- `security/Handshake.cc` -- TLS ClientHello parsing
- `rfc1035MessageUnpack()` -- DNS response parsing

## Prior Art

- **[MegaManSec (2021)](https://joshua.hu/squid-security-audit-35-0days-45-exploits)**:
  AFL++ persistent mode, found 55 vulnerabilities. Required deep source patches.
- **[PR #1531 (2023)](https://github.com/squid-cache/squid/pull/1531)**:
  oss-fuzz integration attempt. Closed due to architectural disagreements.
- **[Opera Security (2021)](https://blogs.opera.com/security/2021/10/fuzzing-http-proxies-squid-part-2/)**:
  Custom fuzzer, found 5 CVEs in response header handling.
