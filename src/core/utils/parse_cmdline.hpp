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

/**
 * @addtogroup utils-parse-cmd-line
 *
 * @brief
 *   This module includes definitions for command line parser.
 *
 * @{
 */

/**
 * This class implements the command line parser.
 *
 */
class CmdLineParser
{
public:
    class Args
    {
        friend class CmdLineParser;

    public:
        enum HexStringParseMode : uint8_t
        {
            kDisallowTruncate,
            kAllowTruncate,
        };

        bool     IsEmpty(void) const { return (mLength == 0); }
        uint16_t GetLength(void) const { return mLength; }
        char **  GetArgs(void) const { return mArgs; }

        char *GetCurArg(void) const { return mArgs[0]; }

        // const char *operator[](uint16_t index) const { return mArgs[index]; }

        bool IsEqual(const char *aString);
        void Advance(void);

        otError ParseAsUint8(uint8_t &aUint8);
        otError ParseAsUint16(uint16_t &aUint16);
        otError ParseAsUint32(uint32_t &aUint32);
        otError ParseAsUnsignedLong(unsigned long &aUnsignedLong);

        otError ParseAsInt8(int8_t &aInt8);
        otError ParseAsInt16(int16_t &aInt16);
        otError ParseAsInt32(int32_t &aInt32);
        otError ParseAsLong(long &aLong);

        otError ParseAsBool(bool &aBool);

#if OPENTHREAD_FTD || OPENTHREAD_MTD
        otError ParseAsIp6Address(otIp6Address &aAddress);
        otError ParseAsIp6Prefix(otIp6Prefix &aPrefix);
#endif

        otError ParseAsString(char *&aString);

        template <uint16_t kBufferSize> otError ParseAsFixedSizeHexString(uint8_t (&aBuffer)[kBufferSize])
        {
            return ParseAsFixedSizeHexString(aBuffer, kBufferSize);
        }

        otError ParseAsFixedSizeHexString(uint8_t *aBuffer, uint16_t aSize);

        otError ParseAsHexString(uint8_t *aBuffer, uint16_t &aSize, HexStringParseMode aMode = kDisallowTruncate);

    protected:
        Args(char **aArgs)
            : mArgs(aArgs)
            , mLength(0)
        {
        }

    private:
        char **  mArgs;
        uint16_t mLength;
    };

    template <uint16_t kMaxArgsLength> class ArgsArray : public Args
    {
        friend class CmdLineParser;

    public:
        ArgsArray(void)
            : Args(mArgsArray)
        {
        }

    private:
        char *mArgsArray[kMaxArgsLength];
    };

    template <uint16_t kMaxArgsLength> static otError Parse(char *aInput, ArgsArray<kMaxArgsLength> &aArgsArray)
    {
        aArgsArray.mArgs   = &aArgsArray.mArgsArray[0];
        aArgsArray.mLength = 0;

        return Parse(aInput, kMaxArgsLength, aArgsArray);
    }

    /**
     * This function parses the command line.
     *
     * Note: this method may change the input @p aString, it will put a '\0' by the end of each argument,
     *       and @p aArgs will point to the arguments in the input @p aString. Backslash ('\') can be used
     *       to escape separators (' ', '\t', '\r', '\n') and the backslash itself.
     *
     * @param[in]   aString         A null-terminated input string.
     * @param[out]  aArgsLength     The argument counter of the command line.
     * @param[out]  aArgs           The argument vector of the command line.
     * @param[in]   aArgsLengthMax  The maximum argument counter.
     *
     */
    static otError ParseCmd(char *aString, uint8_t &aArgsLength, char *aArgs[], uint8_t aArgsLengthMax);

private:
    static otError Parse(char *aString, uint16_t aMaxArgsLength, Args &aArgs);
};

/**
 * @}
 */

} // namespace Utils
} // namespace ot

#endif // PARSE_CMD_LINE_HPP_
