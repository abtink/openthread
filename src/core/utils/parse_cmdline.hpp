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
 *   This file includes definitions for command line parser.
 */

#ifndef PARSE_CMD_LINE_HPP_
#define PARSE_CMD_LINE_HPP_

#include <stdint.h>

#include <openthread/error.h>
#include <openthread/ip6.h>

namespace ot {
namespace Utils {
namespace CmdLineParser {

/**
 * @addtogroup utils-parse-cmd-line
 *
 * @brief
 *   This module includes definitions for command line parser.
 *
 * @{
 */

enum HexStringParseMode : uint8_t
{
    kDisallowTruncate,
    kAllowTruncate,
};

/**
 * This function parses a given command line string and breaks it into an argument list.
 *
 * Note: this method may change the input @p aCommandString, it will put a '\0' by the end of each argument,
 *       and @p aArgs will point to the arguments in the input @p aCommandString. Backslash ('\') can be used
 *       to escape separators (' ', '\t', '\r', '\n') and the backslash itself.
 *
 * @param[in]   aCommandString  A null-terminated input string.
 * @param[out]  aArgsLength     The argument counter of the command line.
 * @param[out]  aArgs           The argument vector of the command line.
 * @param[in]   aArgsLengthMax  The maximum argument counter.
 *
 */
otError ParseCmd(char *aCommandString, uint8_t &aArgsLength, char *aArgs[], uint8_t aArgsLengthMax);

otError ParseAsUint8(const char *aString, uint8_t &aUint8);
otError ParseAsUint16(const char *aString, uint16_t &aUint16);
otError ParseAsUint32(const char *aString, uint32_t &aUint32);
otError ParseAsUint64(const char *aString, uint64_t &aUint64);

otError ParseAsInt8(const char *aString, int8_t &aInt8);
otError ParseAsInt16(const char *aString, int16_t &aInt16);
otError ParseAsInt32(const char *aString, int32_t &aInt32);

otError ParseAsBool(const char *aString, bool &aBool);

#if OPENTHREAD_FTD || OPENTHREAD_MTD
inline otError ParseAsIp6Address(const char *aString, otIp6Address &aAddress)
{
    return otIp6AddressFromString(aString, &aAddress);
}

otError ParseAsIp6Prefix(const char *aString, otIp6Prefix &aPrefix);
#endif

otError ParseAsHexString(const char *aString, uint8_t *aBuffer, uint16_t aSize);
otError ParseAsHexString(const char *       aString,
                         uint16_t &         aSize,
                         uint8_t *          aBuffer,
                         HexStringParseMode aMode = kDisallowTruncate);

template <uint16_t kBufferSize> static otError ParseAsHexString(const char *aString, uint8_t (&aBuffer)[kBufferSize])
{
    return ParseAsHexString(aString, aBuffer, kBufferSize);
}

/**
 * @}
 */

} // namespace CmdLineParser
} // namespace Utils
} // namespace ot

#endif // PARSE_CMD_LINE_HPP_
