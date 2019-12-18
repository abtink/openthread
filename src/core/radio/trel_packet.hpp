/*
 *  Copyright (c) 2019, The OpenThread Authors.
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
 *   This file includes definitions for Thread Radio Encapsulation Link (TREL) Packet
 */

#ifndef TREL_PACKET_HPP_
#define TREL_PACKET_HPP_

#include "openthread-core-config.h"

#include "common/encoding.hpp"
#include "common/locator.hpp"
#include "mac/mac_types.hpp"

#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE

namespace ot {
namespace Trel {

/**
 * This class represents a TREL radio link packet encapsulation header.
 *
 */
OT_TOOL_PACKED_BEGIN
class Header
{
public:
    /**
     * This enumeration defines header types.
     *
     */
    enum Type
    {
        kTypeUnicast,   ///< Unicast header type.
        kTypeBroadcast, ///< Broadcast header type.
    };

    /**
     * This method initializes the header.
     *
     * @param[in] aType   The header type.
     */
    void Init(Type aType) { mVersionFlags = kVersion | ((aType == kTypeUnicast) ? kFlagIsUnicast : 0); }

    /**
     * This method checks whether the version field in header is valid or not
     *
     * @returns TRUE if the version field is valid, FALSE otherwise.
     *
     */
    bool IsVersionValid(void) const { return (mVersionFlags & kVersionMask) == kVersion; }

    /**
     * This method indicates whether the header is a broadcast type or not.
     *
     * @returns TRUE if the header is a broadcast, FALSE otherwise.
     *
     */
    bool IsBroadcast(void) const { return (mVersionFlags & kFlagIsUnicast) == 0; }

    /**
     * This method indicates whether the header is a unicast type or not.
     *
     * @returns TRUE if the header is a unicast, FALSE otherwise.
     *
     */
    bool IsUnicast(void) const { return !IsBroadcast(); }

    /**
     * This method gets the type of header (unicast or broadcast).
     *
     * @returns The header type.
     *
     */
    Type GetType(void) const { return IsBroadcast() ? kTypeBroadcast : kTypeUnicast; }

    /**
     * This method gets the header length based on its type.
     *
     * @returns the header length (number of bytes).
     *
     */
    uint16_t GetLength(void) const { return GetSize(GetType()); }

    /**
     * This method gets the channel field from the header.
     *
     * @returns The channel field.
     *
     */
    uint8_t GetChannel(void) const { return mChannel; }

    /**
     * This method sets the channel field in the header.
     *
     * @param[in] aChannel   A channel.
     *
     */
    void SetChannel(uint8_t aChannel) { mChannel = aChannel; }

    /**
     * This method gets the PAN Identifier field from the header.
     *
     * @returns The PAN Identifier field.
     *
     */
    Mac::PanId GetPanId(void) const { return Encoding::BigEndian::HostSwap16(mPanId); }

    /**
     * This method sets the PAN Identifier field in the header.
     *
     * @param[in] aPanId   A PAN Identifier.
     *
     */
    void SetPanId(Mac::PanId aPanId) { mPanId = Encoding::BigEndian::HostSwap16(aPanId); }

    /**
     * This method gets the source MAC address field from the header.
     *
     * @returns The source MAC address field.
     *
     */
    const Mac::ExtAddress &GetSource(void) const { return mSource; }

    /**
     * This method sets the source MAC address filed in the header.
     *
     * @param[in] aSource   A MAC extended address to set as source.
     *
     */
    void SetSource(const Mac::ExtAddress &aSource) { mSource = aSource; }

    /**
     * This method gets the destination MAC address field from the header.
     *
     * This method MUST be used with a unicast type header, otherwise its behavior is undefined.
     *
     * @returns The destination MAC address field.
     *
     */
    const Mac::ExtAddress &GetDestination(void) const { return mDestination; }

    /**
     * This method sets the destination MAC address field in the header.
     *
     * This method MUST be used with a unicast type header, otherwise its behavior is undefined.
     *
     * @param[in] aDest   A MAC extended address to set as destination.
     *
     */
    void SetDestination(const Mac::ExtAddress &aDest) { mDestination = aDest; }

    /**
     * This static method gets the size (number of bytes) in header of given type.
     *
     * @param[in] aType   The header type.
     *
     * @returns The fixed header size (number of bytes) for @p aType header.
     *
     */
    static uint16_t GetSize(Type aType);

private:
    enum
    {
        kVersion       = (0 << 5),
        kVersionMask   = (7 << 5),
        kFlagIsUnicast = (1 << 0),
    };

    // All header fields are big-endian.

    uint8_t         mVersionFlags;
    uint8_t         mChannel;
    uint16_t        mPanId;
    Mac::ExtAddress mSource;
    Mac::ExtAddress mDestination; // Only on `kTypeUnicast` header.
} OT_TOOL_PACKED_END;

/**
 * This class represent a TREL radio link packet.
 *
 */
class Packet
{
public:
    /**
     * This method initializes the `Packet` with a given buffer and length.
     *
     * @param[in] A pointer to a buffer containing the entire packet (header and payload).
     * @param[in] Length (number of bytes) of the packet (including header and payload).
     *
     */
    void Init(uint8_t *aBuffer, uint16_t aLength);

    /**
     * This method initializes the `Packet` with a specified header type and given a payload.
     *
     * The payload buffer @p aPayload should have space reserved before the start of payload for the packet header.
     * This method will initialize the header with the given type @p aType. Rest of header fields can be updated after
     * initializing the packet.
     *
     * @param[in] aType          The header type.
     * @param[in] aPayload       A pointer to a buffer containing the packet payload. Buffer should have space reserved
     *                           for header before the payload.
     * @param[in] aPayloadLength The length (number of bytes) in the payload only (not including the header).
     *
     */

    void Init(Header::Type aType, uint8_t *aPayload, uint16_t aPayloadLength);

    /**
     * This method gets a pointer to buffer containing the packet.
     *
     * @returns A pointer to buffer containing the packet.
     *
     */
    uint8_t *GetBuffer(void) { return mBuffer; }

    /**
     * This method gets a pointer to buffer containing the packet.
     *
     * @returns A pointer to buffer containing the packet.
     *
     */
    const uint8_t *GetBuffer(void) const { return mBuffer; }

    /**
     * This method gets the length of packet.
     *
     * @returns The length (number of bytes) of packet (header and payload).
     *
     */
    uint16_t GetLength(void) const { return mLength; }

    /**
     * This method validates the packet header.
     *
     * @retval OT_ERROR_NONE    Successfully parsed and validated the packet header.
     * @retval OT_ERROR_PARSE   Failed to parse the packet header
     *
     */
    otError ValidateHeader(void) const;

    /**
     * This method gets the packet header.
     *
     * @returns A reference to the packet header as `Header`.
     *
     */
    Header &GetHeader(void) { return *reinterpret_cast<Header *>(mBuffer); }

    /**
     * This method gets the packet header.
     *
     * @returns A reference to the packet header as `Header`.
     *
     */
    const Header &GetHeader(void) const { return *reinterpret_cast<const Header *>(mBuffer); }

    /**
     * This method gets a pointer to start of packet payload.
     *
     * @returns A pointer to start of packet payload (after header).
     *
     */
    uint8_t *GetPayload(void) { return mBuffer + GetHeader().GetLength(); }

    /**
     * This method gets a pointer to start of packet payload.
     *
     * @returns A pointer to start of packet payload (after header).
     *
     */
    const uint8_t *GetPayload(void) const { return mBuffer + GetHeader().GetLength(); }

    /**
     * This method gets the payload length.
     *
     * @returns The packet payload length (number of bytes).
     *
     */
    uint16_t GetPayloadLength(void) const { return mLength - GetHeader().GetLength(); }

private:
    uint8_t *mBuffer;
    uint16_t mLength;
};

} // namespace Trel
} // namespace ot

#endif // #if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE

#endif // TREL_PACKET_HPP_
