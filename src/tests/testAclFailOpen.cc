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
    CPPUNIT_TEST_SUITE_END();

public:
protected:
    void testUrlNullByteTruncation();
    void testUrlNullByteInPath();
    void testUrlDoubleEncodedNull();
    void testUrlNormalDecode();
    void testSourceDomainNoneLiteral();
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

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}
