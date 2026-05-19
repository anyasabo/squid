/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Ip.h"
#include "acl/SplayInserter.h"
#include "compat/cppunit.h"
#include "ip/Address.h"
#include "SquidConfig.h"
#include "unitTestMain.h"

class SquidConfig Config;
class SquidConfig2 Config2;

/*
 * Reproduces ACLIP::match(const Ip::Address &) by constructing
 * acl_ip_data entries and searching via the same splay comparator
 * used in production (aclIpAddrNetworkCompare, declared in Ip.cc).
 *
 * We cannot call aclIpAddrNetworkCompare directly since it is static,
 * so we replicate its logic here. This is the same approach used by
 * testAclServerName.cc for domain matching.
 */
static int
ipNetworkCompare(acl_ip_data *const &needle, acl_ip_data *const &entry)
{
    Ip::Address A = needle->addr1;
    A.applyMask(entry->mask);

    if (entry->addr2.isAnyAddr()) {
        return A.matchIPAddr(entry->addr1);
    } else {
        if ((A >= entry->addr1) && (A <= entry->addr2))
            return 0;
        else
            return A.matchIPAddr(entry->addr1);
    }
}

static bool
ipMatch(Splay<acl_ip_data *> &tree, const Ip::Address &clientip)
{
    static acl_ip_data clientEntry;
    clientEntry.addr1 = clientip;
    clientEntry.addr2.setEmpty();
    clientEntry.mask.setEmpty();

    const acl_ip_data *const *result = tree.find(&clientEntry, ipNetworkCompare);
    return (result != nullptr);
}

static void
insertSingleIp(Splay<acl_ip_data *> &tree, const char *ipStr)
{
    auto *entry = new acl_ip_data;
    entry->addr1 = ipStr;
    entry->addr2.setAnyAddr();
    entry->mask.setNoAddr();
    entry->next = nullptr;
    Acl::SplayInserter<acl_ip_data *>::Merge(tree, std::move(entry));
}

static void
insertCidr(Splay<acl_ip_data *> &tree, const char *ipStr, int prefixLen, int family)
{
    auto *entry = new acl_ip_data;
    entry->addr1 = ipStr;
    entry->addr2.setAnyAddr();
    entry->mask.setNoAddr();
    entry->mask.applyMask(prefixLen, family);
    entry->addr1.applyMask(entry->mask);
    entry->next = nullptr;
    Acl::SplayInserter<acl_ip_data *>::Merge(tree, std::move(entry));
}

static void
insertRange(Splay<acl_ip_data *> &tree, const char *lo, const char *hi)
{
    auto *entry = new acl_ip_data;
    entry->addr1 = lo;
    entry->addr2 = hi;
    entry->mask.setNoAddr();
    entry->next = nullptr;
    Acl::SplayInserter<acl_ip_data *>::Merge(tree, std::move(entry));
}

class TestAclIp : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestAclIp);
    CPPUNIT_TEST(testExactIpv4Match);
    CPPUNIT_TEST(testCidr24);
    CPPUNIT_TEST(testCidr32ExactMatch);
    CPPUNIT_TEST(testCidr16);
    CPPUNIT_TEST(testIpRange);
    CPPUNIT_TEST(testIpv6Exact);
    CPPUNIT_TEST(testIpv6Cidr);
    CPPUNIT_TEST(testIpv4MappedIpv6);
    CPPUNIT_TEST(testLoopback);
    CPPUNIT_TEST(testMultipleEntries);
    CPPUNIT_TEST(testNoMatch);
    CPPUNIT_TEST_SUITE_END();

public:
    void testExactIpv4Match();
    void testCidr24();
    void testCidr32ExactMatch();
    void testCidr16();
    void testIpRange();
    void testIpv6Exact();
    void testIpv6Cidr();
    void testIpv4MappedIpv6();
    void testLoopback();
    void testMultipleEntries();
    void testNoMatch();
};

CPPUNIT_TEST_SUITE_REGISTRATION(TestAclIp);

void
TestAclIp::testExactIpv4Match()
{
    Splay<acl_ip_data *> tree;
    insertSingleIp(tree, "10.0.0.1");

    Ip::Address client;
    client = "10.0.0.1";
    CPPUNIT_ASSERT(ipMatch(tree, client));

    client = "10.0.0.2";
    CPPUNIT_ASSERT(!ipMatch(tree, client));
}

void
TestAclIp::testCidr24()
{
    Splay<acl_ip_data *> tree;
    insertCidr(tree, "192.168.1.0", 24, AF_INET);

    Ip::Address client;
    client = "192.168.1.1";
    CPPUNIT_ASSERT(ipMatch(tree, client));

    client = "192.168.1.254";
    CPPUNIT_ASSERT(ipMatch(tree, client));

    client = "192.168.1.0";
    CPPUNIT_ASSERT(ipMatch(tree, client));

    client = "192.168.2.1";
    CPPUNIT_ASSERT(!ipMatch(tree, client));

    client = "10.0.0.1";
    CPPUNIT_ASSERT(!ipMatch(tree, client));
}

void
TestAclIp::testCidr32ExactMatch()
{
    Splay<acl_ip_data *> tree;
    insertCidr(tree, "10.20.30.40", 32, AF_INET);

    Ip::Address client;
    client = "10.20.30.40";
    CPPUNIT_ASSERT(ipMatch(tree, client));

    client = "10.20.30.41";
    CPPUNIT_ASSERT(!ipMatch(tree, client));
}

void
TestAclIp::testCidr16()
{
    Splay<acl_ip_data *> tree;
    insertCidr(tree, "172.16.0.0", 16, AF_INET);

    Ip::Address client;
    client = "172.16.0.1";
    CPPUNIT_ASSERT(ipMatch(tree, client));

    client = "172.16.255.255";
    CPPUNIT_ASSERT(ipMatch(tree, client));

    client = "172.17.0.1";
    CPPUNIT_ASSERT(!ipMatch(tree, client));
}

void
TestAclIp::testIpRange()
{
    Splay<acl_ip_data *> tree;
    insertRange(tree, "10.0.0.10", "10.0.0.20");

    Ip::Address client;
    client = "10.0.0.10";
    CPPUNIT_ASSERT(ipMatch(tree, client));

    client = "10.0.0.15";
    CPPUNIT_ASSERT(ipMatch(tree, client));

    client = "10.0.0.20";
    CPPUNIT_ASSERT(ipMatch(tree, client));

    client = "10.0.0.9";
    CPPUNIT_ASSERT(!ipMatch(tree, client));

    client = "10.0.0.21";
    CPPUNIT_ASSERT(!ipMatch(tree, client));
}

void
TestAclIp::testIpv6Exact()
{
    Splay<acl_ip_data *> tree;
    insertSingleIp(tree, "2001:db8::1");

    Ip::Address client;
    client = "2001:db8::1";
    CPPUNIT_ASSERT(ipMatch(tree, client));

    client = "2001:db8::2";
    CPPUNIT_ASSERT(!ipMatch(tree, client));
}

void
TestAclIp::testIpv6Cidr()
{
    Splay<acl_ip_data *> tree;
    insertCidr(tree, "2001:db8::", 48, AF_INET6);

    Ip::Address client;
    client = "2001:db8::1";
    CPPUNIT_ASSERT(ipMatch(tree, client));

    client = "2001:db8:0:ffff::1";
    CPPUNIT_ASSERT(ipMatch(tree, client));

    client = "2001:db8:1::1";
    CPPUNIT_ASSERT(!ipMatch(tree, client));
}

void
TestAclIp::testIpv4MappedIpv6()
{
    // Squid stores IPv4 addresses as IPv4-mapped IPv6 internally.
    // An ACL entry for 10.0.0.1 should match whether the client
    // presents as IPv4 or IPv4-mapped-IPv6.
    Splay<acl_ip_data *> tree;
    insertSingleIp(tree, "10.0.0.1");

    Ip::Address client;

    // Direct IPv4
    client = "10.0.0.1";
    CPPUNIT_ASSERT(ipMatch(tree, client));

    // IPv4-mapped IPv6 representation
    client = "::ffff:10.0.0.1";
    CPPUNIT_ASSERT(ipMatch(tree, client));
}

void
TestAclIp::testLoopback()
{
    Splay<acl_ip_data *> tree;
    insertSingleIp(tree, "127.0.0.1");

    Ip::Address client;
    client = "127.0.0.1";
    CPPUNIT_ASSERT(ipMatch(tree, client));

    // IPv6 loopback is a different address
    client = "::1";
    CPPUNIT_ASSERT(!ipMatch(tree, client));

    // Add IPv6 loopback too
    insertSingleIp(tree, "::1");
    CPPUNIT_ASSERT(ipMatch(tree, client));
}

void
TestAclIp::testMultipleEntries()
{
    Splay<acl_ip_data *> tree;
    insertCidr(tree, "10.0.0.0", 8, AF_INET);
    insertCidr(tree, "172.16.0.0", 12, AF_INET);
    insertSingleIp(tree, "8.8.8.8");

    Ip::Address client;
    client = "10.1.2.3";
    CPPUNIT_ASSERT(ipMatch(tree, client));

    client = "172.20.1.1";
    CPPUNIT_ASSERT(ipMatch(tree, client));

    client = "8.8.8.8";
    CPPUNIT_ASSERT(ipMatch(tree, client));

    client = "8.8.4.4";
    CPPUNIT_ASSERT(!ipMatch(tree, client));

    client = "192.168.1.1";
    CPPUNIT_ASSERT(!ipMatch(tree, client));
}

void
TestAclIp::testNoMatch()
{
    Splay<acl_ip_data *> tree;
    insertSingleIp(tree, "1.2.3.4");

    Ip::Address client;
    client = "5.6.7.8";
    CPPUNIT_ASSERT(!ipMatch(tree, client));

    // Completely different address family
    client = "fe80::1";
    CPPUNIT_ASSERT(!ipMatch(tree, client));
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}
