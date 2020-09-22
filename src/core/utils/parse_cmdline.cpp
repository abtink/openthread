/*
 *  Copyright (c) 2018, The OpenThread Authors.
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

/**
 * @file
 *   This file implements the command line parser.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse_cmdline.hpp"

#include "common/code_utils.hpp"
#include "net/ip6_address.hpp"

namespace ot {
namespace Utils {

bool CmdLineParser::Args::IsEqual(const char *aString)
{
    bool matches = (mLength > 0) && (strcmp(mArgs[0], aString) == 0);

    if (matches)
    {
        Advance();
    }

    return matches;
}

void CmdLineParser::Args::Advance(void)
{
    if (mLength > 0)
    {
        mArgs++;
        mLength--;
    }
}

otError CmdLineParser::Args::ParseAsUint8(uint8_t &aUint8)
{
    otError       error;
    unsigned long value;

    SuccessOrExit(error = ParseAsUnsignedLong(value));

    VerifyOrExit(value <= UINT8_MAX, error = OT_ERROR_INVALID_ARGS);
    aUint8 = static_cast<uint8_t>(value);

exit:
    return error;
}

otError CmdLineParser::Args::ParseAsUint16(uint16_t &aUint16)
{
    otError       error;
    unsigned long value;

    SuccessOrExit(error = ParseAsUnsignedLong(value));

    VerifyOrExit(value <= UINT16_MAX, error = OT_ERROR_INVALID_ARGS);
    aUint16 = static_cast<uint16_t>(value);

exit:
    return error;
}

otError CmdLineParser::Args::ParseAsUint32(uint32_t &aUint32)
{
    otError       error;
    unsigned long value;

    SuccessOrExit(error = ParseAsUnsignedLong(value));

    VerifyOrExit(value <= UINT32_MAX, error = OT_ERROR_INVALID_ARGS);
    aUint32 = static_cast<uint32_t>(value);

exit:
    return error;
}

otError CmdLineParser::Args::ParseAsUnsignedLong(unsigned long &aUnsignedLong)
{
    otError error = OT_ERROR_NONE;
    char *  endptr;

    VerifyOrExit(mLength > 0, error = OT_ERROR_INVALID_ARGS);

    aUnsignedLong = strtoul(mArgs[0], &endptr, 0);
    VerifyOrExit(*endptr == '\0', error = OT_ERROR_INVALID_ARGS);

    Advance();

exit:
    return error;
}

otError CmdLineParser::Args::ParseAsInt8(int8_t &aInt8)
{
    otError error;
    long    value;

    SuccessOrExit(error = ParseAsLong(value));

    VerifyOrExit((INT8_MIN <= value) && (value <= INT8_MAX), error = OT_ERROR_INVALID_ARGS);
    aInt8 = static_cast<int8_t>(value);

exit:
    return error;
}

otError CmdLineParser::Args::ParseAsInt16(int16_t &aInt16)
{
    otError error;
    long    value;

    SuccessOrExit(error = ParseAsLong(value));

    VerifyOrExit((INT16_MIN <= value) && (value <= INT16_MAX), error = OT_ERROR_INVALID_ARGS);
    aInt16 = static_cast<int16_t>(value);

exit:
    return error;
}

otError CmdLineParser::Args::ParseAsInt32(int32_t &aInt32)
{
    otError error;
    long    value;

    SuccessOrExit(error = ParseAsLong(value));

    VerifyOrExit((INT32_MIN <= value) && (value <= INT32_MAX), error = OT_ERROR_INVALID_ARGS);
    aInt32 = static_cast<int32_t>(value);

exit:
    return error;
}

otError CmdLineParser::Args::ParseAsLong(long &aLong)
{
    otError error = OT_ERROR_NONE;
    char *  endptr;

    VerifyOrExit(mLength > 0, error = OT_ERROR_INVALID_ARGS);

    aLong = strtol(mArgs[0], &endptr, 0);
    VerifyOrExit(*endptr == '\0', error = OT_ERROR_INVALID_ARGS);

    Advance();

exit:
    return error;
}

otError CmdLineParser::Args::ParseAsBool(bool &aBool)
{
    otError  error = OT_ERROR_NONE;
    uint32_t value;

    if (ParseAsUint32(value) == OT_ERROR_NONE)
    {
        ExitNow(aBool = (value != 0));
    }

    error = OT_ERROR_INVALID_ARGS;

exit:
    return error;
}
#if OPENTHREAD_FTD || OPENTHREAD_MTD
otError CmdLineParser::Args::ParseAsIp6Address(otIp6Address &aAddress)
{
    otError error = OT_ERROR_INVALID_ARGS;

    VerifyOrExit(mLength > 0, OT_NOOP);
    SuccessOrExit(static_cast<Ip6::Address &>(aAddress).FromString(mArgs[0]));

    Advance();
    error = OT_ERROR_NONE;

exit:
    return error;
}

otError CmdLineParser::Args::ParseAsIp6Prefix(otIp6Prefix &aPrefix)
{
    otError error = OT_ERROR_INVALID_ARGS;
    char *  prefixLengthStr;

    VerifyOrExit(mLength > 0, OT_NOOP);

    prefixLengthStr = strchr(mArgs[0], '/');
    VerifyOrExit(prefixLengthStr != nullptr, OT_NOOP);
    *prefixLengthStr++ = '\0';

    SuccessOrExit(static_cast<Ip6::Address &>(aPrefix.mPrefix).FromString(mArgs[0]));

    mArgs[0] = prefixLengthStr;
    error    = ParseAsUint8(aPrefix.mLength);

exit:
    return error;
}
#endif // #if OPENTHREAD_FTD || OPENTHREAD_MTD

otError CmdLineParser::Args::ParseAsString(char *&aString)
{
    otError error = OT_ERROR_NONE;

    VerifyOrExit(mLength > 0, error = OT_ERROR_INVALID_ARGS);
    aString = mArgs[0];
    Advance();

exit:
    return error;
}

otError CmdLineParser::Args::ParseAsFixedSizeHexString(uint8_t *aBuffer, uint16_t aSize)
{
    otError  error;
    uint16_t readSize = aSize;

    SuccessOrExit(error = ParseAsHexString(aBuffer, readSize, kDisallowTruncate));
    VerifyOrExit(readSize == aSize, error = OT_ERROR_INVALID_ARGS);

exit:
    return error;
}

otError CmdLineParser::Args::ParseAsHexString(uint8_t *aBuffer, uint16_t &aSize, HexStringParseMode aMode)
{
    otError     error     = OT_ERROR_NONE;
    uint8_t     byte      = 0;
    uint16_t    readBytes = 0;
    size_t      hexLength;
    const char *hex;
    uint8_t     numChars;

    VerifyOrExit(mLength > 0, error = OT_ERROR_INVALID_ARGS);

    hex       = mArgs[0];
    hexLength = strlen(hex);

    if (aMode == kDisallowTruncate)
    {
        VerifyOrExit((hexLength + 1) / 2 <= aSize, error = OT_ERROR_INVALID_ARGS);
    }

    // Handle the case where number of chars in hex string is odd.
    numChars = hexLength & 1;

    while (*hex != '\0')
    {
        char c = *hex;

        if (('A' <= c) && (c <= 'F'))
        {
            byte |= 10 + (c - 'A');
        }
        else if (('a' <= c) && (c <= 'f'))
        {
            byte |= 10 + (c - 'a');
        }
        else if (('0' <= c) && (c <= '9'))
        {
            byte |= c - '0';
        }
        else
        {
            ExitNow(error = OT_ERROR_INVALID_ARGS);
        }

        hex++;
        numChars++;

        if (numChars >= 2)
        {
            numChars   = 0;
            *aBuffer++ = byte;
            byte       = 0;
            readBytes++;

            if (readBytes == aSize)
            {
                ExitNow();
            }
        }
        else
        {
            byte <<= 4;
        }
    }

    aSize = readBytes;
    Advance();

exit:
    return error;
}

static bool IsSeparator(char aChar)
{
    return (aChar == ' ') || (aChar == '\t') || (aChar == '\r') || (aChar == '\n');
}

static bool IsEscapable(char aChar)
{
    return IsSeparator(aChar) || (aChar == '\\');
}

otError CmdLineParser::Parse(char *aString, uint16_t aMaxArgsLength, Args &aArgs)
{
    otError  error  = OT_ERROR_NONE;
    uint16_t length = 0;
    char *   cmd;

    for (cmd = aString; *cmd; cmd++)
    {
        if ((*cmd == '\\') && IsEscapable(*(cmd + 1)))
        {
            // include the null terminator: strlen(cmd) = strlen(cmd + 1) + 1
            memmove(cmd, cmd + 1, strlen(cmd));
        }
        else if (IsSeparator(*cmd))
        {
            *cmd = '\0';
        }

        if ((*cmd != '\0') && ((length == 0) || (*(cmd - 1) == '\0')))
        {
            VerifyOrExit(length < aMaxArgsLength, error = OT_ERROR_INVALID_ARGS);
            aArgs.mArgs[length++] = cmd;
        }
    }

    aArgs.mLength = length;

exit:
    return error;
}

otError CmdLineParser::ParseCmd(char *aString, uint8_t &aArgsLength, char *aArgs[], uint8_t aArgsLengthMax)
{
    otError error = OT_ERROR_NONE;
    char *  cmd;

    aArgsLength = 0;

    for (cmd = aString; *cmd; cmd++)
    {
        if ((*cmd == '\\') && IsEscapable(*(cmd + 1)))
        {
            // include the null terminator: strlen(cmd) = strlen(cmd + 1) + 1
            memmove(cmd, cmd + 1, strlen(cmd));
        }
        else if (IsSeparator(*cmd))
        {
            *cmd = '\0';
        }

        if ((*cmd != '\0') && ((aArgsLength == 0) || (*(cmd - 1) == '\0')))
        {
            VerifyOrExit(aArgsLength < aArgsLengthMax, error = OT_ERROR_INVALID_ARGS);
            aArgs[aArgsLength++] = cmd;
        }
    }

exit:
    return error;
}

} // namespace Utils
} // namespace ot
