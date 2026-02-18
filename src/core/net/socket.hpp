/*
 *  Copyright (c) 2016, The OpenThread Authors.
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
 *   This file includes definitions for IPv6 sockets.
 */

#ifndef OT_CORE_NET_SOCKET_HPP_
#define OT_CORE_NET_SOCKET_HPP_

#include "openthread-core-config.h"

#include "common/clearable.hpp"
#include "common/equatable.hpp"
#include "net/ip6_address.hpp"
#include "net/ip6_types.hpp"

namespace ot {

class ThreadLinkInfo;

namespace Ip6 {

/**
 * @addtogroup core-ip6-ip6
 *
 * @{
 */

/**
 * Implements a socket address.
 */
class SockAddr : public otSockAddr, public Clearable<SockAddr>, public Unequatable<SockAddr>
{
public:
    static constexpr uint16_t kInfoStringSize = OT_IP6_SOCK_ADDR_STRING_SIZE; ///< Info string size (`ToString()`).

    /**
     * Defines the fixed-length `String` object returned from `ToString()`.
     */
    typedef String<kInfoStringSize> InfoString;

    /**
     * Initializes the socket address (all fields are set to zero).
     */
    SockAddr(void) { Clear(); }

    /**
     * Initializes the socket address with a given port number.
     *
     * @param[in] aPort   A port number.
     */
    explicit SockAddr(uint16_t aPort)
    {
        mPort = aPort;
        GetAddress().Clear();
    }

    /**
     * Initializes the socket address with a given address and port number.
     *
     * @param[in] aAddress  An IPv6 address.
     * @param[in] aPort     A port number.
     */
    SockAddr(const Address &aAddress, uint16_t aPort)
    {
        mAddress = aAddress;
        mPort    = aPort;
    }

    /**
     * Returns a reference to the IPv6 address.
     *
     * @returns A reference to the IPv6 address.
     */
    Address &GetAddress(void) { return AsCoreType(&mAddress); }

    /**
     * Returns a reference to the IPv6 address.
     *
     * @returns A reference to the IPv6 address.
     */
    const Address &GetAddress(void) const { return AsCoreType(&mAddress); }

    /**
     * Sets the IPv6 address.
     *
     * @param[in] aAddress The IPv6 address.
     */
    void SetAddress(const Address &aAddress) { mAddress = aAddress; }

    /**
     * Returns the socket address port number.
     *
     * @returns The port number
     */
    uint16_t GetPort(void) const { return mPort; }

    /**
     * Sets the socket address port number.
     *
     * @param[in] aPort  The port number.
     */
    void SetPort(uint16_t aPort) { mPort = aPort; }

    /**
     * Overloads operator `==` to evaluate whether or not two `SockAddr` instances are equal (same address
     * and port number).
     *
     * @param[in]  aOther  The other `SockAddr` instance to compare with.
     *
     * @retval TRUE   If the two `SockAddr` instances are equal.
     * @retval FALSE  If the two `SockAddr` instances not equal.
     */
    bool operator==(const SockAddr &aOther) const
    {
        return (GetPort() == aOther.GetPort()) && (GetAddress() == aOther.GetAddress());
    }

    /**
     * Converts the socket address to a string.
     *
     * The string is formatted as "[<ipv6 address>]:<port number>".
     *
     * @returns An `InfoString` containing the string representation of the `SockAddr`
     */
    InfoString ToString(void) const;

    /**
     * Converts a given IPv6 socket address to a human-readable string.
     *
     * The IPv6 socket address string is formatted as "[<ipv6 address>]:<port>".
     *
     * If the resulting string does not fit in @p aBuffer (within its @p aSize characters), the string will be
     * truncated but the outputted string is always null-terminated.
     *
     * @param[out] aBuffer   A pointer to a char array to output the string (MUST NOT be NULL).
     * @param[in]  aSize     The size of @p aBuffer (in bytes).
     */
    void ToString(char *aBuffer, uint16_t aSize) const;

private:
    void ToString(StringWriter &aWriter) const;
};

/**
 * @}
 */

} // namespace Ip6

DefineCoreType(otMessageInfo, Ip6::MessageInfo);
DefineCoreType(otSockAddr, Ip6::SockAddr);

} // namespace ot

#endif // OT_CORE_NET_SOCKET_HPP_
