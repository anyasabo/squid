/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Ip.h"
#include "compat/cppunit.h"
#include "ip/Address.h"
#include "ip/tools.h"
#include "unitTestMain.h"

#include <cstring>
#include <string>

/**
 * Test suite for ACL IP matching (acl_ip_data and ACLIP).
 *
 * The ACL IP subsystem is the foundation of Squid's network-level access
 * control. Bugs here have direct security implications for egress proxies:
 * a matching failure can allow traffic that should be denied.
 *
 * src/acl/ has ~87 source files and zero dedicated unit tests.
 * This is a start.
 */

/// Test subclass to expose the protected match(Ip::Address) method
class TestableACLIP : public ACLIP
{
public:
    const char *typeString() const override { return "test-ip"; }
    int match(ACLChecklist *) override { return 0; }
    using ACLIP::match; // expose protected match(const Ip::Address &)
    using ACLIP::data;  // expose protected data splay tree
};

class TestAclIp : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestAclIp);
    CPPUNIT_TEST(testFactoryParseIPv4Single);
    CPPUNIT_TEST(testFactoryParseIPv4Cidr);
    CPPUNIT_TEST(testFactoryParseIPv4Range);
    CPPUNIT_TEST(testFactoryParseIPv6Single);
    CPPUNIT_TEST(testFactoryParseIPv6Cidr);
    CPPUNIT_TEST(testMatchIPv4InCidr);
    CPPUNIT_TEST(testMatchIPv4OutOfCidr);
    CPPUNIT_TEST(testMatchIPv4Range);
    CPPUNIT_TEST(testMatchIPv6InCidr);
    CPPUNIT_TEST(testIPv4MappedIPv6);
    CPPUNIT_TEST(testNetmaskEdgeCases);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() override;
    void tearDown() override;

protected:
    void testFactoryParseIPv4Single();
    void testFactoryParseIPv4Cidr();
    void testFactoryParseIPv4Range();
    void testFactoryParseIPv6Single();
    void testFactoryParseIPv6Cidr();
    void testMatchIPv4InCidr();
    void testMatchIPv4OutOfCidr();
    void testMatchIPv4Range();
    void testMatchIPv6InCidr();
    void testIPv4MappedIPv6();
    void testNetmaskEdgeCases();

private:
    /// Helper: parse an ACL IP spec and insert into a splay tree
    void addAclSpec(TestableACLIP &acl, const char *spec);
};

CPPUNIT_TEST_SUITE_REGISTRATION(TestAclIp);

void
TestAclIp::setUp()
{
    Ip::ProbeTransport();
}

void
TestAclIp::tearDown()
{
}

void
TestAclIp::addAclSpec(TestableACLIP &acl, const char *spec)
{
    if (!acl.data)
        acl.data = new TestableACLIP::IPSplay();

    acl_ip_data *q = acl_ip_data::FactoryParse(spec);
    CPPUNIT_ASSERT_MESSAGE(
        std::string("FactoryParse failed for: ") + spec,
        q != nullptr);

    while (q != nullptr) {
        acl_ip_data *next = q->next;
        q->next = nullptr;
        acl.data->insert(q, [](acl_ip_data * const &a, acl_ip_data * const &b) {
            return a->addr1.matchIPAddr(b->addr1);
        });
        q = next;
    }
}

// --- FactoryParse tests ---

void
TestAclIp::testFactoryParseIPv4Single()
{
    acl_ip_data *result = acl_ip_data::FactoryParse("192.168.1.1");
    CPPUNIT_ASSERT(result != nullptr);

    Ip::Address expected;
    expected = "192.168.1.1";
    CPPUNIT_ASSERT(result->addr1 == expected);
    CPPUNIT_ASSERT(result->next == nullptr);
    delete result;
}

void
TestAclIp::testFactoryParseIPv4Cidr()
{
    acl_ip_data *result = acl_ip_data::FactoryParse("10.0.0.0/8");
    CPPUNIT_ASSERT(result != nullptr);

    Ip::Address expected;
    expected = "10.0.0.0";
    CPPUNIT_ASSERT(result->addr1 == expected);
    delete result;
}

void
TestAclIp::testFactoryParseIPv4Range()
{
    acl_ip_data *result = acl_ip_data::FactoryParse("10.0.0.1-10.0.0.255");
    CPPUNIT_ASSERT(result != nullptr);

    Ip::Address lo, hi;
    lo = "10.0.0.1";
    hi = "10.0.0.255";
    CPPUNIT_ASSERT(result->addr1 == lo);
    CPPUNIT_ASSERT(result->addr2 == hi);
    delete result;
}

void
TestAclIp::testFactoryParseIPv6Single()
{
    acl_ip_data *result = acl_ip_data::FactoryParse("::1");
    CPPUNIT_ASSERT(result != nullptr);

    Ip::Address expected;
    expected = "::1";
    CPPUNIT_ASSERT(result->addr1 == expected);
    delete result;
}

void
TestAclIp::testFactoryParseIPv6Cidr()
{
    acl_ip_data *result = acl_ip_data::FactoryParse("2001:db8::/32");
    CPPUNIT_ASSERT(result != nullptr);

    Ip::Address expected;
    expected = "2001:db8::";
    CPPUNIT_ASSERT(result->addr1 == expected);
    delete result;
}

// --- match() tests (via TestableACLIP) ---

void
TestAclIp::testMatchIPv4InCidr()
{
    TestableACLIP acl;
    addAclSpec(acl, "10.0.0.0/8");

    Ip::Address inside;
    inside = "10.1.2.3";
    CPPUNIT_ASSERT_EQUAL(1, acl.match(inside));

    Ip::Address boundary;
    boundary = "10.0.0.0";
    CPPUNIT_ASSERT_EQUAL(1, acl.match(boundary));

    Ip::Address high;
    high = "10.255.255.255";
    CPPUNIT_ASSERT_EQUAL(1, acl.match(high));
}

void
TestAclIp::testMatchIPv4OutOfCidr()
{
    TestableACLIP acl;
    addAclSpec(acl, "10.0.0.0/8");

    Ip::Address outside;
    outside = "11.0.0.1";
    CPPUNIT_ASSERT_EQUAL(0, acl.match(outside));

    Ip::Address way_outside;
    way_outside = "192.168.1.1";
    CPPUNIT_ASSERT_EQUAL(0, acl.match(way_outside));
}

void
TestAclIp::testMatchIPv4Range()
{
    TestableACLIP acl;
    addAclSpec(acl, "10.0.0.1-10.0.0.100");

    Ip::Address inside;
    inside = "10.0.0.50";
    CPPUNIT_ASSERT_EQUAL(1, acl.match(inside));

    Ip::Address at_start;
    at_start = "10.0.0.1";
    CPPUNIT_ASSERT_EQUAL(1, acl.match(at_start));

    Ip::Address at_end;
    at_end = "10.0.0.100";
    CPPUNIT_ASSERT_EQUAL(1, acl.match(at_end));

    Ip::Address below;
    below = "10.0.0.0";
    CPPUNIT_ASSERT_EQUAL(0, acl.match(below));

    Ip::Address above;
    above = "10.0.0.101";
    CPPUNIT_ASSERT_EQUAL(0, acl.match(above));
}

void
TestAclIp::testMatchIPv6InCidr()
{
    TestableACLIP acl;
    addAclSpec(acl, "2001:db8::/32");

    Ip::Address inside;
    inside = "2001:db8::1";
    CPPUNIT_ASSERT_EQUAL(1, acl.match(inside));

    Ip::Address outside;
    outside = "2001:db9::1";
    CPPUNIT_ASSERT_EQUAL(0, acl.match(outside));
}

void
TestAclIp::testIPv4MappedIPv6()
{
    // IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) should match IPv4 ACLs
    TestableACLIP acl;
    addAclSpec(acl, "10.0.0.0/8");

    Ip::Address mapped;
    mapped = "::ffff:10.1.2.3";
    // Squid normalizes IPv4-mapped IPv6 to IPv4 internally
    CPPUNIT_ASSERT_EQUAL(1, acl.match(mapped));
}

void
TestAclIp::testNetmaskEdgeCases()
{
    // /32 should match only the exact IP
    {
        TestableACLIP acl;
        addAclSpec(acl, "10.0.0.1/32");

        Ip::Address exact;
        exact = "10.0.0.1";
        CPPUNIT_ASSERT_EQUAL(1, acl.match(exact));

        Ip::Address neighbor;
        neighbor = "10.0.0.2";
        CPPUNIT_ASSERT_EQUAL(0, acl.match(neighbor));
    }

    // /24 boundary
    {
        TestableACLIP acl;
        addAclSpec(acl, "172.16.0.0/24");

        Ip::Address inside;
        inside = "172.16.0.200";
        CPPUNIT_ASSERT_EQUAL(1, acl.match(inside));

        Ip::Address outside;
        outside = "172.16.1.0";
        CPPUNIT_ASSERT_EQUAL(0, acl.match(outside));
    }
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}
