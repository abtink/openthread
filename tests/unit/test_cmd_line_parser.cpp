/*
 *  Copyright (c) 2020, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>

#include "test_platform.h"

#include <openthread/config.h>

#include "common/instance.hpp"
#include "utils/parse_cmdline.hpp"

#include "test_util.h"

using ot::Utils::CmdLineParser::ParseAsBool;
using ot::Utils::CmdLineParser::ParseAsHexString;
using ot::Utils::CmdLineParser::ParseAsInt8;
using ot::Utils::CmdLineParser::ParseAsInt16;
using ot::Utils::CmdLineParser::ParseAsInt32;
using ot::Utils::CmdLineParser::ParseAsIp6Address;
using ot::Utils::CmdLineParser::ParseAsIp6Prefix;
using ot::Utils::CmdLineParser::ParseAsUint16;
using ot::Utils::CmdLineParser::ParseAsUint32;
using ot::Utils::CmdLineParser::ParseAsUint64;
using ot::Utils::CmdLineParser::ParseAsUint8;

static const char kWhiteSpaces[] = "                                                                ";

enum : uint8_t
{
    kAligment = 40,
};

template <typename ValueType> struct TestCase
{
    const char *mString;
    otError     mError;
    ValueType   mValue;
};


template<typename ValueType, otError (&Parser)(const char *aString, ValueType &aValue)>
void VerifyParser(const TestCase<ValueType> *aTestCases, const char *aParserName, const char *aPrintFormat)
{
    const TestCase<ValueType> *testCase = aTestCases;
    ValueType value;
    otError   error;
    int       len;

    printf("----------------------------------------------------------------------------------\n");

    while (true)
    {
        len = printf("%s(\"%s\")", aParserName, testCase->mString);
        printf("%s -> ", &kWhiteSpaces[sizeof(kWhiteSpaces) - kAligment + len]);

        if (testCase->mError != OT_ERROR_NONE)
        {
            printf("error:%s", otThreadErrorToString(testCase->mError));
        }
        else
        {
            printf(aPrintFormat, testCase->mValue);
        }

        printf("\n");

        error = Parser(testCase->mString, value);

        VerifyOrQuit(error == testCase->mError, "Parser did not return the expected error");

        if (error == OT_ERROR_NONE)
        {
            VerifyOrQuit(value == testCase->mValue, "Parser failed");
        }

        if (testCase->mString[0] == '\0')
        {
            break;
        }

        testCase++;
    }
}

void TestParsingInts(void)
{
    // Empty string "" indicates the end of test-case list

    TestCase<bool> kBoolTestCases[] =
    {
        { "0", OT_ERROR_NONE, false },
        { "1", OT_ERROR_NONE, true  },
        { "0x0", OT_ERROR_NONE, false },
        { "0x1", OT_ERROR_NONE, true },
        { "10", OT_ERROR_NONE, true },
        { "a", OT_ERROR_INVALID_ARGS },
        { "-1", OT_ERROR_INVALID_ARGS },
        { "", OT_ERROR_INVALID_ARGS },
    };

    TestCase<uint8_t> kUint8TestCases[] = {
        {"0", OT_ERROR_NONE, 0 },
        {"1", OT_ERROR_NONE, 1 },
        {"74", OT_ERROR_NONE, 74 },
        {"255", OT_ERROR_NONE, 255 },
        {"0xa", OT_ERROR_NONE, 0xa },
        {"0x04", OT_ERROR_NONE, 4},
        {"0x7e", OT_ERROR_NONE, 0x7e},
        {"0xcd", OT_ERROR_NONE, 0xcd},
        {"0x0", OT_ERROR_NONE, 0},
        {"0xff", OT_ERROR_NONE, 0xff},
        {"0x0000ff", OT_ERROR_NONE, 0xff},
        {"0xB", OT_ERROR_NONE, 0xb},
        {"0X04", OT_ERROR_NONE, 4},
        {"0X7E", OT_ERROR_NONE, 0x7e},
        {"0XCD", OT_ERROR_NONE, 0xcd},
        {"0X0", OT_ERROR_NONE, 0},
        {"0XFF", OT_ERROR_NONE, 0xff},
        {"00", OT_ERROR_NONE, 0},
        {"-5", OT_ERROR_INVALID_ARGS},
        {"0y", OT_ERROR_INVALID_ARGS},
        {"0x7g", OT_ERROR_INVALID_ARGS},
        {"0xaaa", OT_ERROR_INVALID_ARGS},
        {"256", OT_ERROR_INVALID_ARGS},
        {"12e", OT_ERROR_INVALID_ARGS},
        {"", OT_ERROR_INVALID_ARGS }
    };

    TestCase<uint16_t> kUint16TestCases[] = {
        {"0", OT_ERROR_NONE, 0 },
        {"1245", OT_ERROR_NONE, 1245 },
        {"0xa", OT_ERROR_NONE, 0xa },
        {"0xab7d", OT_ERROR_NONE, 0xab7d},
        {"0X1AE", OT_ERROR_NONE, 0x1ae},
        {"0X7E", OT_ERROR_NONE, 0x7e},
        {"65535", OT_ERROR_NONE, 65535},
        {"0xffff", OT_ERROR_NONE, 0xffff},
        {"-1", OT_ERROR_INVALID_ARGS},
        {"0y", OT_ERROR_INVALID_ARGS},
        {"0xq", OT_ERROR_INVALID_ARGS},
        {"0x12345", OT_ERROR_INVALID_ARGS},
        {"65536", OT_ERROR_INVALID_ARGS},
        {"", OT_ERROR_INVALID_ARGS }
    };

    TestCase<uint32_t> kUint32TestCases[] = {
        {"0", OT_ERROR_NONE, 0 },
        {"1234567", OT_ERROR_NONE, 1234567 },
        {"0xc", OT_ERROR_NONE, 0xc },
        {"0x01234567", OT_ERROR_NONE, 0x1234567},
        {"0XABCDEF09", OT_ERROR_NONE, 0xabcdef09},
        {"0X54321", OT_ERROR_NONE, 0x54321},
        {"4294967295", OT_ERROR_NONE, 4294967295},
        {"0xffffffff", OT_ERROR_NONE, 0xffffffff},
        {"-1", OT_ERROR_INVALID_ARGS},
        {"0y", OT_ERROR_INVALID_ARGS},
        {"0x1234zz", OT_ERROR_INVALID_ARGS},
        {"0x123456789", OT_ERROR_INVALID_ARGS},
        {"4294967296", OT_ERROR_INVALID_ARGS},
        {"", OT_ERROR_INVALID_ARGS }
    };

    TestCase<uint64_t> kUint64TestCases[] = {
        {"0", OT_ERROR_NONE, 0 },
        {"123456789087654321", OT_ERROR_NONE, 123456789087654321},
        {"0xb", OT_ERROR_NONE, 0xb },
        {"0x1234567890acbdef", OT_ERROR_NONE, 0x1234567890acbdef},
        {"0XFEDCBA9876543210", OT_ERROR_NONE, 0xfedcba9876543210},
        {"0xffffffffffffffff", OT_ERROR_NONE, 0xffffffffffffffff},
        {"18446744073709551615", OT_ERROR_NONE, 18446744073709551615ull},
        {"-1", OT_ERROR_INVALID_ARGS},
        {"0x1234567890acbdef0", OT_ERROR_INVALID_ARGS},
        {"18446744073709551616", OT_ERROR_INVALID_ARGS},
        {"", OT_ERROR_INVALID_ARGS }
    };

    TestCase<int8_t> kInt8TestCases[] = {
        {"0", OT_ERROR_NONE, 0 },
        {"-1", OT_ERROR_NONE, -1 },
        {"+74", OT_ERROR_NONE, 74 },
        {"-0x12", OT_ERROR_NONE, -0x12},
        {"-0XB", OT_ERROR_NONE, -11},
        {"127", OT_ERROR_NONE, 127},
        {"-128", OT_ERROR_NONE, -128},
        {"128", OT_ERROR_INVALID_ARGS},
        {"-129", OT_ERROR_INVALID_ARGS},
        {"--1", OT_ERROR_INVALID_ARGS},
        {"+-2", OT_ERROR_INVALID_ARGS},
        {"++1", OT_ERROR_INVALID_ARGS},
        {"", OT_ERROR_INVALID_ARGS }
    };

    TestCase<int16_t> kInt16TestCases[] = {
        {"-1", OT_ERROR_NONE, -1 },
        {"+0x1234", OT_ERROR_NONE, 0x1234 },
        {"-0X6E8", OT_ERROR_NONE, -0x6E8 },
        {"32767", OT_ERROR_NONE, 32767},
        {"0X7FFF", OT_ERROR_NONE, 0x7fff},
        {"-32768", OT_ERROR_NONE, -32768},
        {"-0x8000", OT_ERROR_NONE, -0x8000},
        {"32768", OT_ERROR_INVALID_ARGS},
        {"0X8000", OT_ERROR_INVALID_ARGS},
        {"-32769", OT_ERROR_INVALID_ARGS},
        {"-0x8001", OT_ERROR_INVALID_ARGS},
        {"", OT_ERROR_INVALID_ARGS }
    };

    TestCase<int32_t> kInt32TestCases[] = {
        {"-256", OT_ERROR_NONE, -256 },
        {"+0x12345678", OT_ERROR_NONE, 0x12345678},
        {"-0X6677aB", OT_ERROR_NONE, -0X6677aB },
        {"2147483647", OT_ERROR_NONE, 2147483647},
        {"0x7fffFFFF", OT_ERROR_NONE, 0x7fffffff},
        {"-2147483648", OT_ERROR_NONE, -2147483648},
        {"2147483648", OT_ERROR_INVALID_ARGS},
        {"0X80000000", OT_ERROR_INVALID_ARGS},
        {"-2147483649", OT_ERROR_INVALID_ARGS},
        {"-0x80000001", OT_ERROR_INVALID_ARGS},
        {"", OT_ERROR_INVALID_ARGS }
    };

    VerifyParser<bool, ParseAsBool>(kBoolTestCases, "ParseAsBool", "%d");
    VerifyParser<uint8_t, ParseAsUint8>(kUint8TestCases, "ParseAsUint8", "0x%02x");
    VerifyParser<uint16_t, ParseAsUint16>(kUint16TestCases, "ParseAsUint16", "0x%04x");
    VerifyParser<uint32_t, ParseAsUint32>(kUint32TestCases, "ParseAsUint32", "0x%08x");
    VerifyParser<uint64_t, ParseAsUint64>(kUint64TestCases, "ParseAsUint64", "0x%016llx");

    VerifyParser<int8_t, ParseAsInt8>(kInt8TestCases, "ParseAsInt8", "%d");
    VerifyParser<int16_t, ParseAsInt16>(kInt16TestCases, "ParseAsInt16", "%d");
    VerifyParser<int32_t, ParseAsInt32>(kInt32TestCases, "ParseAsInt32", "%d");
}

int main(void)
{
    TestParsingInts();

    printf("All tests passed\n");
    return 0;
}
