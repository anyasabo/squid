/*
 * Typeinfo/vtable stubs for the URI parser fuzzer.
 *
 * libanyp.a and the common stubs reference RTTI for several classes whose
 * full implementations pull in the entire Squid binary. We satisfy the linker
 * by providing a key virtual function (destructor) for each class, which
 * forces the compiler to emit typeinfo and vtable entries.
 *
 * We include the real Squid headers to get the correct class layout, then
 * define just the destructor. To avoid pulling in implementation dependencies,
 * we only define the destructor body (no other methods).
 *
 * We also stub a few functions called from code paths in Uri.cc that
 * the fuzzer doesn't exercise.
 */

// NOTE: this file is compiled WITHOUT Squid include paths (-I flags) to avoid
// redefinition conflicts between these minimal stubs and the real headers.

#include <cstdint>
#include <cstddef>

// --- HttpRequest: referenced by libanyp, stub_MemObject, stub_libsecurity ---
// Including HttpRequest.h pulls in many headers. To avoid that, we define
// just enough of the class hierarchy to emit the correct typeinfo.
// The trick: we compile with the *same* includes as Squid, so the mangled
// names will match.

// We need to define destructors for the key classes. Rather than including
// their complex headers (which pull in everything), we use a targeted approach:
// define the minimal virtual class with the same fully-qualified name and
// namespace, and provide a destructor.
//
// For each class, we use a separate namespace scope to avoid ODR issues
// within this TU. The compiler only cares that the mangled destructor name
// matches what the linker needs.

// -- Approach: include real headers one at a time, provide destructor stubs --
// Some headers have deep include chains that conflict. For those, we use
// the extern "C++" / asm trick on platforms that support it, or weak
// attribute on macOS.

// For StoreIOState, HttpReply, HttpRequest: these have complex header chains.
// Instead of including headers, we just provide the typeinfo as weak C++ symbols.

// On macOS (Mach-O), weak_import is the equivalent of ELF weak.
// For typeinfo, the simplest cross-platform approach is to provide dummy
// key functions via weak symbols that won't conflict with real implementations.

// --- Minimal class stubs that emit correct typeinfo ---
// We redeclare just enough of each class hierarchy to get the right mangling.
// IMPORTANT: these must NOT be included alongside the real headers.

#ifdef __APPLE__
#define WEAK_SYM __attribute__((weak))
#else
#define WEAK_SYM __attribute__((weak))
#endif

// Http::Message -> base for HttpRequest, HttpReply
namespace Http {
class Message {
public:
    virtual ~Message();
};
WEAK_SYM Message::~Message() {}
}

class HttpRequest : public Http::Message {
public:
    ~HttpRequest() override;
    char *canonicalCleanUrl() const;
};
WEAK_SYM HttpRequest::~HttpRequest() {}
WEAK_SYM char *HttpRequest::canonicalCleanUrl() const { return nullptr; }

class HttpReply : public Http::Message {
public:
    ~HttpReply() override;
};
WEAK_SYM HttpReply::~HttpReply() {}

class StoreIOState {
public:
    virtual ~StoreIOState();
};
WEAK_SYM StoreIOState::~StoreIOState() {}

namespace Comm {
class Connection {
public:
    virtual ~Connection();
};
WEAK_SYM Connection::~Connection() {}
}

class AccessLogEntry {
public:
    virtual ~AccessLogEntry();
};
WEAK_SYM AccessLogEntry::~AccessLogEntry() {}

namespace Store {
class Disk {
public:
    virtual ~Disk();
};
WEAK_SYM Disk::~Disk() {}
}

// --- Stub functions for unreachable code paths in Uri.cc ---

// HttpHeader::getInt64(Http::HdrType) - called from urlCheckRequest()
namespace Http { enum class HdrType : int; }
class HttpHeader {
public:
    int64_t getInt64(Http::HdrType) const;
};
WEAK_SYM int64_t HttpHeader::getInt64(Http::HdrType) const { return 0; }
