/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/DomainData.h"
#include "acl/SplayInserter.h"
#include "anyp/Uri.h"
#include "compat/cppunit.h"
#include "ip/Address.h"
#include "SquidConfig.h"
#include "unitTestMain.h"

#include <cstring>
#include <string>

class SquidConfig Config;
class SquidConfig2 Config2;

// Reproduces the ACLServerNameData::match() comparison logic from
// src/acl/ServerName.cc (aclHostDomainCompare).
// In the real code, the splay find passes (searchKey=host, treeData=domain)
// to this comparator, then calls matchDomainName(host, domain, mdnHonorWildcards).
static int
serverNameCompare(char *const &a, char *const &b)
{
    const char *h = static_cast<const char *>(a);
    const char *d = static_cast<const char *>(b);
    return matchDomainName(h, d, mdnHonorWildcards);
}

static bool
serverNameMatch(Splay<char *> &domains, const char *host)
{
    if (host == nullptr)
        return false;
    char *h = const_cast<char *>(host);
    char const *const *result = domains.find(h, serverNameCompare);
    return (result != nullptr);
}

// Also test the base ACLDomainData comparison (without wildcards) for contrast
static int
domainCompare(char *const &a, char *const &b)
{
    return matchDomainName(a, b);
}

static bool
domainMatch(Splay<char *> &domains, const char *host)
{
    if (host == nullptr)
        return false;
    char *h = const_cast<char *>(host);
    char const *const *result = domains.find(h, domainCompare);
    return (result != nullptr);
}

static std::string
formatIpForServerName(const Ip::Address &ip)
{
    char hostStr[MAX_IPSTRLEN];
    (void)ip.toStr(hostStr, sizeof(hostStr));
    return std::string(hostStr);
}

class TestAclServerName : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestAclServerName);
    CPPUNIT_TEST(testSubdomainMatchDot);
    CPPUNIT_TEST(testExactDomainMatch);
    CPPUNIT_TEST(testCaseInsensitive);
    CPPUNIT_TEST(testNullInput);
    CPPUNIT_TEST(testNoneFallback);
    CPPUNIT_TEST(testIPv6Unbracketed);
    CPPUNIT_TEST(testIPv6ConfiguredBracketed);
    CPPUNIT_TEST(testMultipleDomains);
    CPPUNIT_TEST(testWildcardBug);
    CPPUNIT_TEST(testSubdomainVsDstdomain);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() override;
    void tearDown() override;

protected:
    void testSubdomainMatchDot();
    void testExactDomainMatch();
    void testCaseInsensitive();
    void testNullInput();
    void testNoneFallback();
    void testIPv6Unbracketed();
    void testIPv6ConfiguredBracketed();
    void testMultipleDomains();
    void testWildcardBug();
    void testSubdomainVsDstdomain();

private:
    void insertDomain(Splay<char *> &tree, const char *domain);
};

CPPUNIT_TEST_SUITE_REGISTRATION(TestAclServerName);

void TestAclServerName::setUp() {}
void TestAclServerName::tearDown() {}

void
TestAclServerName::insertDomain(Splay<char *> &tree, const char *domain)
{
    Acl::SplayInserter<char *>::Merge(tree, xstrdup(domain));
}

void
TestAclServerName::testSubdomainMatchDot()
{
    // .example.com syntax matches the domain and all subdomains
    Splay<char *> domains;
    insertDomain(domains, ".example.com");

    CPPUNIT_ASSERT(serverNameMatch(domains, "example.com"));
    CPPUNIT_ASSERT(serverNameMatch(domains, "sub.example.com"));
    CPPUNIT_ASSERT(serverNameMatch(domains, "deep.sub.example.com"));
    CPPUNIT_ASSERT(!serverNameMatch(domains, "notexample.com"));
    CPPUNIT_ASSERT(!serverNameMatch(domains, "other.org"));
}

void
TestAclServerName::testExactDomainMatch()
{
    Splay<char *> domains;
    insertDomain(domains, "exact.example.com");

    CPPUNIT_ASSERT(serverNameMatch(domains, "exact.example.com"));
    CPPUNIT_ASSERT(!serverNameMatch(domains, "other.example.com"));
    // Exact match does NOT include subdomains (no leading dot)
    CPPUNIT_ASSERT(!serverNameMatch(domains, "sub.exact.example.com"));
}

void
TestAclServerName::testCaseInsensitive()
{
    Splay<char *> domains;
    insertDomain(domains, ".Example.COM");

    CPPUNIT_ASSERT(serverNameMatch(domains, "sub.example.com"));
    CPPUNIT_ASSERT(serverNameMatch(domains, "SUB.EXAMPLE.COM"));
    CPPUNIT_ASSERT(serverNameMatch(domains, "Sub.Example.Com"));
}

void
TestAclServerName::testNullInput()
{
    Splay<char *> domains;
    insertDomain(domains, ".example.com");

    CPPUNIT_ASSERT(!serverNameMatch(domains, nullptr));
}

void
TestAclServerName::testNoneFallback()
{
    // ServerNameCheck::match() passes "none" when no SNI is available.
    // This should NOT match normal domain patterns.
    {
        Splay<char *> domains;
        insertDomain(domains, ".example.com");
        CPPUNIT_ASSERT(!serverNameMatch(domains, "none"));
    }
    // But if "none" is explicitly configured, it should match
    {
        Splay<char *> domains;
        insertDomain(domains, "none");
        CPPUNIT_ASSERT(serverNameMatch(domains, "none"));
    }
}

void
TestAclServerName::testIPv6Unbracketed()
{
    // ServerNameMatcher::matchIp() uses Ip::Address::toStr() which produces
    // unbracketed inet_ntop format (e.g., "::1" not "[::1]")
    Ip::Address addr;
    addr = "::1";

    std::string formatted = formatIpForServerName(addr);
    CPPUNIT_ASSERT(formatted.find('[') == std::string::npos);
    CPPUNIT_ASSERT(formatted.find(']') == std::string::npos);

    // Unbracketed config matches unbracketed IP
    Splay<char *> domains;
    insertDomain(domains, "::1");
    CPPUNIT_ASSERT(serverNameMatch(domains, formatted.c_str()));
}

void
TestAclServerName::testIPv6ConfiguredBracketed()
{
    // If admin configures [::1] (URL-style brackets), it will NOT match
    // the unbracketed inet_ntop format from toStr().
    // This documents the known format mismatch (ServerName.cc:82 TODO).
    Ip::Address addr;
    addr = "::1";

    std::string formatted = formatIpForServerName(addr);

    Splay<char *> domains;
    insertDomain(domains, "[::1]");
    // KNOWN BUG: bracketed config does NOT match unbracketed IP string
    CPPUNIT_ASSERT(!serverNameMatch(domains, formatted.c_str()));
}

void
TestAclServerName::testMultipleDomains()
{
    Splay<char *> domains;
    insertDomain(domains, ".allowed.com");
    insertDomain(domains, ".internal.corp");
    insertDomain(domains, "exact.special.org");

    CPPUNIT_ASSERT(serverNameMatch(domains, "app.allowed.com"));
    CPPUNIT_ASSERT(serverNameMatch(domains, "db.internal.corp"));
    CPPUNIT_ASSERT(serverNameMatch(domains, "exact.special.org"));
    CPPUNIT_ASSERT(!serverNameMatch(domains, "evil.external.com"));
    CPPUNIT_ASSERT(!serverNameMatch(domains, "special.org"));
}

void
TestAclServerName::testWildcardBug()
{
    // BUG FINDING: *.example.com wildcards do NOT work in ACLServerNameData.
    //
    // aclHostDomainCompare() passes arguments to matchDomainName() as:
    //   matchDomainName(host, domain_pattern, mdnHonorWildcards)
    //
    // But matchDomainName() checks h[hl] (first arg) for '*' (line 981 of
    // Uri.cc), meaning it expects the PATTERN as the first argument:
    //   matchDomainName(pattern, host, mdnHonorWildcards)
    //
    // Since the arguments are inverted, the wildcard in the tree data
    // (domain_pattern) is never checked. The test below documents this.

    Splay<char *> domains;
    insertDomain(domains, "*.example.com");

    // These SHOULD match but DON'T due to the argument inversion bug
    CPPUNIT_ASSERT(!serverNameMatch(domains, "sub.example.com"));
    CPPUNIT_ASSERT(!serverNameMatch(domains, "deep.sub.example.com"));

    // The correct way to configure subdomain matching is with a leading dot
    Splay<char *> domains2;
    insertDomain(domains2, ".example.com");
    CPPUNIT_ASSERT(serverNameMatch(domains2, "sub.example.com"));
}

void
TestAclServerName::testSubdomainVsDstdomain()
{
    // Verify that ssl::server_name and dstdomain (ACLDomainData) both handle
    // .example.com subdomain matching identically
    Splay<char *> snDomains;
    insertDomain(snDomains, ".example.com");

    Splay<char *> dstDomains;
    insertDomain(dstDomains, ".example.com");

    // Both should match subdomains
    CPPUNIT_ASSERT(serverNameMatch(snDomains, "sub.example.com"));
    CPPUNIT_ASSERT(domainMatch(dstDomains, "sub.example.com"));

    // Both should match the domain itself
    CPPUNIT_ASSERT(serverNameMatch(snDomains, "example.com"));
    CPPUNIT_ASSERT(domainMatch(dstDomains, "example.com"));

    // Neither should match unrelated domains
    CPPUNIT_ASSERT(!serverNameMatch(snDomains, "other.org"));
    CPPUNIT_ASSERT(!domainMatch(dstDomains, "other.org"));
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}
