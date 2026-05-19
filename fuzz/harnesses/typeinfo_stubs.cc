/*
 * Typeinfo stubs for fuzzing harness linkage.
 *
 * Several Squid stubs (stub_MemObject, stub_libsecurity, etc.) reference
 * virtual classes via RefCount<T> pointers, which emits typeinfo. The real
 * class definitions live deep in Squid's object tree and pulling them in
 * creates a dependency avalanche. These minimal stubs provide just enough
 * typeinfo to satisfy the linker.
 */
#include "squid.h"

namespace Store {
class Disk { public: virtual ~Disk(); };
Disk::~Disk() {}
}

class StoreIOState { public: virtual ~StoreIOState(); };
StoreIOState::~StoreIOState() {}

class AccessLogEntry { public: virtual ~AccessLogEntry(); };
AccessLogEntry::~AccessLogEntry() {}

class BodyPipe { public: virtual ~BodyPipe(); };
BodyPipe::~BodyPipe() {}

class Server { public: virtual ~Server(); };
Server::~Server() {}

class HttpReply { public: virtual ~HttpReply(); };
HttpReply::~HttpReply() {}

class HttpRequest { public: virtual ~HttpRequest(); };
HttpRequest::~HttpRequest() {}

namespace Comm {
class Connection { public: virtual ~Connection(); };
Connection::~Connection() {}
}
