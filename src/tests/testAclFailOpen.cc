/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/Uri.h"
#include "compat/cppunit.h"
#include "ip/Address.h"
#include "SquidConfig.h"
#include "unitTestMain.h"

#include <cstring>
#include <string>

class SquidConfig Config;
class SquidConfig2 Config2;

/**
 * Tests for known ACL fail-open bugs and edge cases.
 *
 * These tests focus on the deterministic, synchronous aspects of the bugs
 * that can be tested without mocking the async checklist infrastructure.
 *
 * Known bugs documented here:
 *
 * 1. Url.cc null-byte truncation (testable):
 *    DecodeOrDupe() decodes %00 to NUL, then c_str() truncates at NUL.
 *    ACL matching sees only the prefix, enabling policy bypass.
 *
 * 2. DestinationIp.cc fail-open (documented only):
 *    When goAsync() fails and DNS lookup hasn't completed, match() returns 0.
 *    In deny-list configs ("deny dst X; allow all"), this silently allows.
 *
 * 3. SourceDomain.cc "none" fallback (documented only):
 *    When RDNS fails and goAsync() fails, match() evaluates against "none".
 *    In deny-list configs, the block ACL never matches → traffic allowed.
 */
class TestAclFailOpen : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestAclFailOpen);
    CPPUNIT_TEST(testUrlNullByteTruncation);
    CPPUNIT_TEST(testUrlNullByteInPath);
    CPPUNIT_TEST(testUrlDoubleEncodedNull);
    CPPUNIT_TEST(testUrlNormalDecode);
    CPPUNIT_TEST(testSourceDomainNoneLiteral);
    CPPUNIT_TEST(testSourceDomainNoneNotSubdomain);
    CPPUNIT_TEST(testDestinationIpFailOpenScenario);
    CPPUNIT_TEST_SUITE_END();

public:
protected:
    void testUrlNullByteTruncation();
    void testUrlNullByteInPath();
    void testUrlDoubleEncodedNull();
    void testUrlNormalDecode();
    void testSourceDomainNoneLiteral();
    void testSourceDomainNoneNotSubdomain();
    void testDestinationIpFailOpenScenario();
};

CPPUNIT_TEST_SUITE_REGISTRATION(TestAclFailOpen);

void
TestAclFailOpen::testUrlNullByteTruncation()
{
    // Url.cc:24 does: DecodeOrDupe(uri).c_str()
    // %00 decodes to NUL byte, c_str() truncates at it
    const SBuf encoded("http://evil.com/allowed%00/blocked");
    SBuf decoded = AnyP::Uri::DecodeOrDupe(encoded);

    // The SBuf contains the full decoded string including NUL
    CPPUNIT_ASSERT(decoded.length() > strlen("http://evil.com/allowed"));

    // But c_str() truncates at the NUL byte
    const char *cstr = decoded.c_str();
    CPPUNIT_ASSERT_EQUAL(std::string("http://evil.com/allowed"), std::string(cstr));

    // The ACL would only see "http://evil.com/allowed", missing "/blocked"
    CPPUNIT_ASSERT(strstr(cstr, "blocked") == nullptr);
}

void
TestAclFailOpen::testUrlNullByteInPath()
{
    const SBuf encoded("/safe%00/../etc/passwd");
    SBuf decoded = AnyP::Uri::DecodeOrDupe(encoded);

    const char *cstr = decoded.c_str();
    CPPUNIT_ASSERT_EQUAL(std::string("/safe"), std::string(cstr));
    CPPUNIT_ASSERT(strstr(cstr, "passwd") == nullptr);
}

void
TestAclFailOpen::testUrlDoubleEncodedNull()
{
    // %2500 should decode to "%00" (literal string), NOT to NUL
    const SBuf encoded("/%2500test");
    SBuf decoded = AnyP::Uri::DecodeOrDupe(encoded);

    const char *cstr = decoded.c_str();
    CPPUNIT_ASSERT(strstr(cstr, "test") != nullptr);
}

void
TestAclFailOpen::testUrlNormalDecode()
{
    const SBuf encoded("/%41%42%43");
    SBuf decoded = AnyP::Uri::DecodeOrDupe(encoded);

    CPPUNIT_ASSERT_EQUAL(SBuf("/ABC"), decoded);
}

void
TestAclFailOpen::testSourceDomainNoneLiteral()
{
    // SourceDomain.cc:58: data->match("none") when RDNS + async both fail.
    // This test documents that "none" is a special value in domain matching.
    // If an admin configures `acl x srcdomain none`, it will match on
    // RDNS failure -- which may be surprising.
    //
    // We test matchDomainName directly to verify "none" matching semantics.
    CPPUNIT_ASSERT_EQUAL(0, matchDomainName("none", "none"));
    CPPUNIT_ASSERT(0 != matchDomainName("none", ".example.com"));
    CPPUNIT_ASSERT(0 != matchDomainName("none", "example.com"));

    // ".none" as a configured domain would match "x.none" subdomains
    CPPUNIT_ASSERT_EQUAL(0, matchDomainName("x.none", ".none"));
}

void
TestAclFailOpen::testSourceDomainNoneNotSubdomain()
{
    // Verify that "none" does NOT match subdomain patterns.
    // SourceDomain.cc:58 falls through to data->match("none") on RDNS failure.
    // If admin configures "acl blocked srcdomain .evil.com", the "none" fallback
    // should not match -- and indeed it doesn't. But the *consequence* is that
    // traffic is allowed through a deny-list: the block ACL returns no-match,
    // so "http_access deny blocked" doesn't fire, and "http_access allow all" does.
    CPPUNIT_ASSERT(0 != matchDomainName("none", ".evil.com"));
    CPPUNIT_ASSERT(0 != matchDomainName("none", ".example.com"));
    CPPUNIT_ASSERT(0 != matchDomainName("none", "specific.host.com"));
}

void
TestAclFailOpen::testDestinationIpFailOpenScenario()
{
    // DestinationIp.cc:76-84 fail-open scenario:
    //
    // The code path is:
    //   1. ipcache_gethostbyname() returns nullptr (no cached entry)
    //   2. destinationIpLookedUp is false (first attempt)
    //   3. goAsync() fails (returns false -- e.g., async not supported in context)
    //   4. Falls through to return 0 (no-match)
    //
    // In a deny-list config:
    //   http_access deny dst 10.0.0.0/8
    //   http_access allow all
    //
    // When DNS lookup can't go async, the deny rule silently fails to match,
    // and traffic is allowed. The XXX comment at line 81 acknowledges this.
    //
    // We can't easily test the full async path without mocking ipcache and
    // ACLChecklist, but we CAN verify the semantics: return value 0 means
    // "no match" which in a deny-list equals "allow".
    //
    // The fix would be to return -1 (access denied / needs async) or to
    // use a fail-closed approach where unknown destinations are blocked.

    // Demonstrate that matchIPAddr returns non-zero for non-matching IPs
    // (this is the comparison that DestinationIp would do IF DNS succeeded)
    Ip::Address configured;
    configured = "10.1.2.3";

    Ip::Address client;
    client = "10.1.2.3";
    CPPUNIT_ASSERT_EQUAL(0, configured.matchIPAddr(client));

    client = "192.168.1.1";
    CPPUNIT_ASSERT(0 != configured.matchIPAddr(client));

    // But when DNS fails entirely, match() returns 0 without ever calling
    // matchIPAddr -- the comparison is silently skipped.
    // This is the fail-open: 0 == "no match" == "don't deny" == "allow"
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}
