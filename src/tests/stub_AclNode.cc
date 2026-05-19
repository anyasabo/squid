/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Node.h"
#include "acl/Options.h"

#define STUB_API "acl/Node.cc"
#include "tests/STUB.h"

void *Acl::Node::operator new(size_t sz) { return ::operator new(sz); }
void Acl::Node::operator delete(void *p) { ::operator delete(p); }

Acl::Node::Node() {}
Acl::Node::~Node() { safe_free(cfgline); }

void Acl::Node::ParseNamedAcl(ConfigParser &, NamedAcls *&) STUB
void Acl::Node::Initialize() STUB
Acl::Node *Acl::Node::FindByName(const SBuf &) STUB_RETVAL(nullptr)

void Acl::Node::context(const SBuf &, const char *) STUB
bool Acl::Node::matches(ACLChecklist *) const STUB_RETVAL(false)
void Acl::Node::parseFlags() STUB

bool Acl::Node::isProxyAuth() const STUB_RETVAL(false)
bool Acl::Node::valid() const STUB_RETVAL(true)
int Acl::Node::cacheMatchAcl(dlink_list *, ACLChecklist *) STUB_RETVAL(0)
int Acl::Node::matchForCache(ACLChecklist *) STUB_RETVAL(0)
void Acl::Node::dumpWhole(const char *, std::ostream &) STUB
bool Acl::Node::requiresAle() const STUB_RETVAL(false)
bool Acl::Node::requiresRequest() const STUB_RETVAL(false)
bool Acl::Node::requiresReply() const STUB_RETVAL(false)

const Acl::Options &Acl::NoOptions() {
    static const Acl::Options empty;
    return empty;
}
