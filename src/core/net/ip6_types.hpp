/*
 *  Copyright (c) 2016-2022, The OpenThread Authors.
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
 *   This file includes types and constants for IPv6 processing.
 */

#ifndef OT_CORE_NET_IP6_TYPES_HPP_
#define OT_CORE_NET_IP6_TYPES_HPP_

#include "openthread-core-config.h"

#include <stddef.h>
#include <stdint.h>

#include <openthread/ip6.h>

#include "common/message.hpp"

namespace ot {
namespace Ip6 {

/**
 * @addtogroup core-ip6-ip6
 *
 * @brief
 *   This module includes definitions for core IPv6 networking.
 *
 * @{
 */

// Internet Protocol Numbers
static constexpr uint8_t kProtoHopOpts  = OT_IP6_PROTO_HOP_OPTS; ///< IPv6 Hop-by-Hop Option
static constexpr uint8_t kProtoTcp      = OT_IP6_PROTO_TCP;      ///< Transmission Control Protocol
static constexpr uint8_t kProtoUdp      = OT_IP6_PROTO_UDP;      ///< User Datagram
static constexpr uint8_t kProtoIp6      = OT_IP6_PROTO_IP6;      ///< IPv6 encapsulation
static constexpr uint8_t kProtoRouting  = OT_IP6_PROTO_ROUTING;  ///< Routing Header for IPv6
static constexpr uint8_t kProtoFragment = OT_IP6_PROTO_FRAGMENT; ///< Fragment Header for IPv6
static constexpr uint8_t kProtoIcmp6    = OT_IP6_PROTO_ICMP6;    ///< ICMP for IPv6
static constexpr uint8_t kProtoNone     = OT_IP6_PROTO_NONE;     ///< No Next Header for IPv6
static constexpr uint8_t kProtoDstOpts  = OT_IP6_PROTO_DST_OPTS; ///< Destination Options for IPv6

/**
 * The max datagram length (in bytes) of an IPv6 message.
 */
static constexpr uint16_t kMaxDatagramLength = OPENTHREAD_CONFIG_IP6_MAX_DATAGRAM_LENGTH;

/**
 * The max datagram length (in bytes) of an unfragmented IPv6 message.
 */
static constexpr uint16_t kMaxAssembledDatagramLength = OPENTHREAD_CONFIG_IP6_MAX_ASSEMBLED_DATAGRAM;

/**
 * 6-bit Differentiated Services Code Point (DSCP) values.
 */
enum IpDscpCs : uint8_t
{
    kDscpCs0    = 0,    ///< Class selector codepoint 0
    kDscpCs1    = 8,    ///< Class selector codepoint 8
    kDscpCs2    = 16,   ///< Class selector codepoint 16
    kDscpCs3    = 24,   ///< Class selector codepoint 24
    kDscpCs4    = 32,   ///< Class selector codepoint 32
    kDscpCs5    = 40,   ///< Class selector codepoint 40
    kDscpCs6    = 48,   ///< Class selector codepoint 48
    kDscpCs7    = 56,   ///< Class selector codepoint 56
    kDscpCsMask = 0x38, ///< Class selector mask (0b111000)

    // DSCP values to use within Thread mesh (from local codepoint space 0bxxxx11 [RFC 2474 - section 6]).

    kDscpTmfNetPriority    = 0x07, ///< TMF network priority (0b000111).
    kDscpTmfNormalPriority = 0x0f, ///< TMF normal priority  (0b001111).
    kDscpTmfLowPriority    = 0x17, ///< TMF low priority     (0b010111).
};

/**
 * Represents the 2-bit Explicit Congestion Notification (ECN) values.
 */
enum Ecn : uint8_t
{
    kEcnNotCapable = OT_ECN_NOT_CAPABLE, ///< Non ECN-Capable Transport (ECT).
    kEcnCapable0   = OT_ECN_CAPABLE_0,   ///< ECN Capable Transport, ECT(0).
    kEcnCapable1   = OT_ECN_CAPABLE_1,   ///< ECN Capable Transport, ECT(1).
    kEcnMarked     = OT_ECN_MARKED,      ///< Congestion encountered.
};

/**
 * Implements message information for an IPv6 message.
 */
class MessageInfo : public otMessageInfo, public Clearable<MessageInfo>
{
public:
    /**
     * Initializes the object.
     */
    MessageInfo(void) { Clear(); }

    /**
     * Returns a reference to the local socket address.
     *
     * @returns A reference to the local socket address.
     */
    Address &GetSockAddr(void) { return AsCoreType(&mSockAddr); }

    /**
     * Returns a reference to the local socket address.
     *
     * @returns A reference to the local socket address.
     */
    const Address &GetSockAddr(void) const { return AsCoreType(&mSockAddr); }

    /**
     * Sets the local socket address.
     *
     * @param[in]  aAddress  The IPv6 address.
     */
    void SetSockAddr(const Address &aAddress) { mSockAddr = aAddress; }

    /**
     * Gets the local socket port.
     *
     * @returns The local socket port.
     */
    uint16_t GetSockPort(void) const { return mSockPort; }

    /**
     * Gets the local socket port.
     *
     * @param[in]  aPort  The port value.
     */
    void SetSockPort(uint16_t aPort) { mSockPort = aPort; }

    /**
     * Returns a reference to the peer socket address.
     *
     * @returns A reference to the peer socket address.
     */
    Address &GetPeerAddr(void) { return AsCoreType(&mPeerAddr); }

    /**
     * Returns a reference to the peer socket address.
     *
     * @returns A reference to the peer socket address.
     */
    const Address &GetPeerAddr(void) const { return AsCoreType(&mPeerAddr); }

    /**
     * Sets the peer's socket address.
     *
     * @param[in]  aAddress  The IPv6 address.
     */
    void SetPeerAddr(const Address &aAddress) { mPeerAddr = aAddress; }

    /**
     * Gets the peer socket port.
     *
     * @returns The peer socket port.
     */
    uint16_t GetPeerPort(void) const { return mPeerPort; }

    /**
     * Gets the peer socket port.
     *
     * @param[in]  aPort  The port value.
     */
    void SetPeerPort(uint16_t aPort) { mPeerPort = aPort; }

    /**
     * Gets the Hop Limit.
     *
     * @returns The Hop Limit.
     */
    uint8_t GetHopLimit(void) const { return mHopLimit; }

    /**
     * Sets the Hop Limit.
     *
     * @param[in]  aHopLimit  The Hop Limit.
     */
    void SetHopLimit(uint8_t aHopLimit) { mHopLimit = aHopLimit; }

    /**
     * Returns whether multicast may be looped back.
     *
     * @retval TRUE   If message may be looped back.
     * @retval FALSE  If message must not be looped back.
     */
    bool GetMulticastLoop(void) const { return mMulticastLoop; }

    /**
     * Sets whether multicast may be looped back.
     *
     * @param[in]  aMulticastLoop  Whether allow looping back multicast.
     */
    void SetMulticastLoop(bool aMulticastLoop) { mMulticastLoop = aMulticastLoop; }

    /**
     * Gets the ECN status.
     *
     * @returns The ECN status, as represented in the IP header.
     */
    Ecn GetEcn(void) const { return static_cast<Ecn>(mEcn); }

    /**
     * Sets the ECN status.
     *
     * @param[in]  aEcn  The ECN status, as represented in the IP header.
     */
    void SetEcn(Ecn aEcn) { mEcn = aEcn; }

    /**
     * Indicates whether peer is via the host interface.
     *
     * @retval TRUE if the peer is via the host interface.
     * @retval FALSE if the peer is via the Thread interface.
     */
    bool IsHostInterface(void) const { return mIsHostInterface; }

    /**
     * Indicates whether or not to apply hop limit 0.
     *
     * @retval TRUE  if applying hop limit 0 when `mHopLimit` field is 0.
     * @retval FALSE if applying default `OPENTHREAD_CONFIG_IP6_HOP_LIMIT_DEFAULT` when `mHopLimit` field is 0.
     */
    bool ShouldAllowZeroHopLimit(void) const { return mAllowZeroHopLimit; }

    /**
     * Sets whether the peer is via the host interface.
     *
     * @param[in]  aIsHost  TRUE if the peer is via the host interface, FALSE otherwise.
     */
    void SetIsHostInterface(bool aIsHost) { mIsHostInterface = aIsHost; }

    /**
     * Checks if the peer address and port match those of another `MessageInfo`.
     *
     * @param[in] aOther  The other `MessageInfo` to compare with.
     *
     * @retval TRUE   The peer address and port of the two `MessageInfo` objects match.
     * @retval FALSE  The peer address and port of the two `MessageInfo` objects do not match.
     */
    bool HasSamePeerAddrAndPort(const MessageInfo &aOther) const;
};

struct Msg
{
    Msg(void)
        : mMessage(nullptr)
    {
    }

    Msg(Message &aMessage)
        : mMessage(&aMessage)
    {
    }

    Msg(Message &aMessage, const MessageInfo &aMessageInfo)
        : mMessage(&aMessage)
    {
        mMessageInfo = aMessageInfo;
    }

    Msg(const Msg &aMsg)
        : mMessage(aMsg.mMessage)
        , mMessageInfo(aMsg.mMessageInfo)
    {
    }

    bool HasMessage(void) const { return mMessage != nullptr; }

    Message    *mMessage;
    MessageInfo mMessageInfo;
};

/**
 * @}
 */

} // namespace Ip6
} // namespace ot

#endif // OT_CORE_NET_IP6_TYPES_HPP_
