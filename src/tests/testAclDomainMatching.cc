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
#include "SquidConfig.h"
#include "unitTestMain.h"

// Uri.cc references Config for appendDomain etc.
class SquidConfig Config;
class SquidConfig2 Config2;

#include <cstring>
#include <string>

/**
 * Test suite for ACL domain matching (ACLDomainData, ACLServerNameData).
 *
 * The ACL domain matching code is used by dstdomain, srcdomain,
 * and ssl::server_name ACLs. It's the primary mechanism for
 * policy enforcement on egress proxies (e.g., "allow traffic to
 * *.example.com but deny everything else").
 *
 * Known concerns:
 *   - ServerName uses mdnHonorWildcards for matching, DomainData does not
 *   - IPv6 addresses formatted as strings for SNI matching (see comment at
 *     ServerName.cc:87)
 *   - "none" fallback when connection has no SNI
 */

class TestAclDomainMatching : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestAclDomainMatching);
    CPPUNIT_TEST(testMatchDomainNameExact);
    CPPUNIT_TEST(testMatchDomainNameSubdomain);
    CPPUNIT_TEST(testMatchDomainNameCaseInsensitive);
    CPPUNIT_TEST(testMatchDomainNameWildcard);
    CPPUNIT_TEST(testMatchDomainNameRejectSubsub);
    CPPUNIT_TEST(testMatchDomainNameEmpty);
    CPPUNIT_TEST(testDomainDataDirectMatch);
    CPPUNIT_TEST(testDomainDataSubdomainMatch);
    CPPUNIT_TEST(testDomainDataNoMatch);
    CPPUNIT_TEST_SUITE_END();

public:
protected:
    void testMatchDomainNameExact();
    void testMatchDomainNameSubdomain();
    void testMatchDomainNameCaseInsensitive();
    void testMatchDomainNameWildcard();
    void testMatchDomainNameRejectSubsub();
    void testMatchDomainNameEmpty();
    void testDomainDataDirectMatch();
    void testDomainDataSubdomainMatch();
    void testDomainDataNoMatch();

private:
    /// Insert a domain into a DomainData splay tree
    void insertDomain(ACLDomainData &data, const char *domain);
};

CPPUNIT_TEST_SUITE_REGISTRATION(TestAclDomainMatching);

void
TestAclDomainMatching::insertDomain(ACLDomainData &data, const char *domain)
{
    Acl::SplayInserter<char*>::Merge(data.domains, xstrdup(domain));
}

// --- matchDomainName() tests ---
// These complement the assert-based tests in anyp/Uri.cc with proper
// CppUnit assertions and additional edge cases.

void
TestAclDomainMatching::testMatchDomainNameExact()
{
    CPPUNIT_ASSERT_EQUAL(0, matchDomainName("foo.com", "foo.com"));
    CPPUNIT_ASSERT_EQUAL(0, matchDomainName(".foo.com", "foo.com"));
    CPPUNIT_ASSERT_EQUAL(0, matchDomainName("foo.com", ".foo.com"));
    CPPUNIT_ASSERT_EQUAL(0, matchDomainName(".foo.com", ".foo.com"));
}

void
TestAclDomainMatching::testMatchDomainNameSubdomain()
{
    CPPUNIT_ASSERT_EQUAL(0, matchDomainName("x.foo.com", ".foo.com"));
    CPPUNIT_ASSERT_EQUAL(0, matchDomainName("y.x.foo.com", ".foo.com"));
    // host is NOT a subdomain of a bare domain
    CPPUNIT_ASSERT(0 != matchDomainName("x.foo.com", "foo.com"));
}

void
TestAclDomainMatching::testMatchDomainNameCaseInsensitive()
{
    CPPUNIT_ASSERT_EQUAL(0, matchDomainName("FOO.com", "foo.COM"));
    CPPUNIT_ASSERT_EQUAL(0, matchDomainName("Example.Com", ".example.com"));
}

void
TestAclDomainMatching::testMatchDomainNameWildcard()
{
    CPPUNIT_ASSERT_EQUAL(0, matchDomainName("*.foo.com", "x.foo.com", mdnHonorWildcards));
    CPPUNIT_ASSERT_EQUAL(0, matchDomainName("*.foo.com", ".x.foo.com", mdnHonorWildcards));
    CPPUNIT_ASSERT_EQUAL(0, matchDomainName("*.foo.com", ".foo.com", mdnHonorWildcards));
    // Wildcard should NOT match the bare domain
    CPPUNIT_ASSERT(0 != matchDomainName("*.foo.com", "foo.com", mdnHonorWildcards));
    // Without the flag, wildcards are not honored
    CPPUNIT_ASSERT(0 != matchDomainName("*.foo.com", "x.foo.com"));
}

void
TestAclDomainMatching::testMatchDomainNameRejectSubsub()
{
    CPPUNIT_ASSERT_EQUAL(0, matchDomainName(".foo.com", ".foo.com", mdnRejectSubsubDomains));
    CPPUNIT_ASSERT_EQUAL(0, matchDomainName("x.foo.com", ".foo.com", mdnRejectSubsubDomains));
    // Sub-subdomain should be rejected
    CPPUNIT_ASSERT(0 != matchDomainName("y.x.foo.com", ".foo.com", mdnRejectSubsubDomains));
    CPPUNIT_ASSERT(0 != matchDomainName(".x.foo.com", ".foo.com", mdnRejectSubsubDomains));
}

void
TestAclDomainMatching::testMatchDomainNameEmpty()
{
    CPPUNIT_ASSERT(0 != matchDomainName("foo.com", ""));
    CPPUNIT_ASSERT(0 != matchDomainName("foo.com", "", mdnHonorWildcards));
    CPPUNIT_ASSERT(0 != matchDomainName("foo.com", "", mdnRejectSubsubDomains));
}

// --- ACLDomainData::match() tests ---

void
TestAclDomainMatching::testDomainDataDirectMatch()
{
    ACLDomainData data;
    insertDomain(data, "example.com");
    insertDomain(data, "other.org");

    CPPUNIT_ASSERT(data.match("example.com"));
    CPPUNIT_ASSERT(data.match("other.org"));
    CPPUNIT_ASSERT(!data.match("nothere.net"));
}

void
TestAclDomainMatching::testDomainDataSubdomainMatch()
{
    ACLDomainData data;
    insertDomain(data, ".example.com");

    CPPUNIT_ASSERT(data.match("sub.example.com"));
    CPPUNIT_ASSERT(data.match("deep.sub.example.com"));
    CPPUNIT_ASSERT(data.match("example.com"));
    CPPUNIT_ASSERT(!data.match("notexample.com"));
    CPPUNIT_ASSERT(!data.match("xample.com"));
}

void
TestAclDomainMatching::testDomainDataNoMatch()
{
    ACLDomainData data;
    insertDomain(data, "example.com");

    CPPUNIT_ASSERT(!data.match(nullptr));
    CPPUNIT_ASSERT(!data.match(""));
    CPPUNIT_ASSERT(!data.match("example.org"));
    CPPUNIT_ASSERT(!data.match("sub.example.com"));
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}
