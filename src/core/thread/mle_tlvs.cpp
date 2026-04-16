/*
 *  Copyright (c) 2022, The OpenThread Authors.
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
 *   This file implements function for generating and processing MLE TLVs.
 */

#include "mle_tlvs.hpp"

#include "common/clearable.hpp"
#include "common/code_utils.hpp"
#include "common/numeric_limits.hpp"
#include "radio/radio.hpp"

namespace ot {
namespace Mle {

//---------------------------------------------------------------------------------------------------------------------
// RouteTlvData

uint8_t RouteTlvData::GetRouteCost(uint8_t aRouterId) const
{
    uint8_t cost = mRouteInfo[aRouterId].mRouteCost;

    if (cost == 0)
    {
        cost = kMaxRouteCost;
    }

    return cost;
}

void RouteTlvData::SetRouteInfoFor(uint16_t    aRouterId,
                                   LinkQuality aLinkQualityIn,
                                   LinkQuality aLinkQualityOut,
                                   uint8_t     aRouteCost)
{
    VerifyOrExit(aRouterId <= kMaxRouterId);

    mRouteInfo[aRouterId].mLinkQualityIn  = aLinkQualityIn;
    mRouteInfo[aRouterId].mLinkQualityOut = aLinkQualityOut;
    mRouteInfo[aRouterId].mRouteCost      = (aRouteCost >= kMaxRouteCost) ? 0 : aRouteCost;

exit:
    return;
}

Error RouteTlvData::ParseFrom(const Message &aMessage, const OffsetRange &aOffsetRange)
{
    Error       error;
    OffsetRange offsetRange = aOffsetRange;
#if OPENTHREAD_CONFIG_MLE_LONG_ROUTES_ENABLE
    bool isEven = true;
#endif

    Clear();

    SuccessOrExit(error = aMessage.Read(offsetRange, mRouterIdMask));
    offsetRange.AdvanceOffset(sizeof(RouterIdMask));

    VerifyOrExit(mRouterIdMask.IsValid(), error = kErrorParse);

    for (uint8_t routerId = 0; routerId <= kMaxRouterId; routerId++)
    {
        RouteInfo::EncodedValue encoded;

        if (!mRouterIdMask.IsAllocated(routerId))
        {
            continue;
        }

        // Read and decode the Route Data encoded entry for each
        // allocated Router ID. When `LONG_ROUTES` enabled, each entry
        // uses 12 bits and they are staggered across bytes. Even
        // entries use the upper 12 bits. Odd entries use the lower 12
        // bits.

        SuccessOrExit(error = aMessage.Read(offsetRange, encoded));

#if !OPENTHREAD_CONFIG_MLE_LONG_ROUTES_ENABLE
        offsetRange.AdvanceOffset(sizeof(encoded));
#else
        encoded = BigEndian::HostSwap(encoded);

        if (isEven)
        {
            encoded = (encoded >> RouteInfo::kEvenEntryBitShift);
            offsetRange.AdvanceOffset(sizeof(uint8_t));
        }
        else
        {
            encoded &= RouteInfo::kOddEntryMask;
            offsetRange.AdvanceOffset(sizeof(uint16_t));
        }

        isEven = !isEven;
#endif

        mRouteInfo[routerId].DecodeFrom(encoded);
    }

exit:
    return error;
}

Error RouteTlvData::AppendAsTlv(uint8_t aTlvType, Message &aMessage) const
{
    Error         error;
    Tlv::Bookmark tlvBookmark;

#if OPENTHREAD_CONFIG_MLE_LONG_ROUTES_ENABLE
    bool isEven = true;
#endif

    SuccessOrExit(error = Tlv::StartTlv(aMessage, aTlvType, tlvBookmark));

    SuccessOrExit(error = aMessage.Append(mRouterIdMask));

    for (uint8_t routerId = 0; routerId <= kMaxRouterId; routerId++)
    {
        if (!mRouterIdMask.IsAllocated(routerId))
        {
            continue;
        }

#if !OPENTHREAD_CONFIG_MLE_LONG_ROUTES_ENABLE
        SuccessOrExit(error = aMessage.Append<RouteInfo::EncodedValue>(mRouteInfo[routerId].Encode()));
#else
        {
            RouteInfo::EncodedValue encoded = mRouteInfo[routerId].Encode();

            if (isEven)
            {
                encoded <<= RouteInfo::kEvenEntryBitShift;

                encoded = BigEndian::HostSwap(encoded);
                SuccessOrExit(error = aMessage.Append(encoded));
            }
            else
            {
                uint16_t                offset;
                RouteInfo::EncodedValue prevValue;

                // When `LONG_ROUTES` is enabled, two 12-bit entries
                // (1.5 bytes each) are staggered across 3 bytes. The
                // even entry was appended as a 2-byte `uint16_t`. We
                // now append one more byte (making 3 bytes in total)
                // and then update the last 2 bytes to merge the
                // 12-bit odd entry with the previous 4 bits from the
                // even entry.

                SuccessOrExit(error = aMessage.Append<uint8_t>(0));

                offset = aMessage.GetLength() - sizeof(RouteInfo::EncodedValue);

                IgnoreError(aMessage.Read(offset, prevValue));
                prevValue = BigEndian::HostSwap(prevValue);

                encoded |= prevValue;

                encoded = BigEndian::HostSwap(encoded);
                aMessage.Write(offset, encoded);
            }

            isEven = !isEven;
        }
#endif // OPENTHREAD_CONFIG_MLE_LONG_ROUTES_ENABLE
    }

    error = Tlv::EndTlv(aMessage, tlvBookmark);

exit:
    return error;
}

void RouteTlvData::RouteInfo::DecodeFrom(EncodedValue aEncoded)
{
    mLinkQualityOut = static_cast<uint8_t>(ReadBits<EncodedValue, kLinkQualityOutMask>(aEncoded));
    mLinkQualityIn  = static_cast<uint8_t>(ReadBits<EncodedValue, kLinkQualityInMask>(aEncoded));
    mRouteCost      = static_cast<uint8_t>(ReadBits<EncodedValue, kRouteCostMask>(aEncoded));
}

RouteTlvData::RouteInfo::EncodedValue RouteTlvData::RouteInfo::Encode(void) const
{
    EncodedValue encoded = 0;

    WriteBits<EncodedValue, kLinkQualityOutMask>(encoded, mLinkQualityOut);
    WriteBits<EncodedValue, kLinkQualityInMask>(encoded, mLinkQualityIn);
    WriteBits<EncodedValue, kRouteCostMask>(encoded, mRouteCost);

    return encoded;
}

//---------------------------------------------------------------------------------------------------------------------
// RouteTlv

Error RouteTlv::FindIn(const Message &aMessage, RouteTlvData &aRouteTlvData)
{
    Error       error;
    OffsetRange offsetRange;

    SuccessOrExit(error = Tlv::FindTlvValueOffsetRange(aMessage, Tlv::kRoute, offsetRange));
    error = aRouteTlvData.ParseFrom(aMessage, offsetRange);

exit:
    return error;
}

//---------------------------------------------------------------------------------------------------------------------
// ConnectivityTlvValue

void ConnectivityTlvValue::InitFrom(const Connectivity &aConnectivity)
{
    mFlags = 0;

    WriteBits<uint8_t, kFlagsParentPriorityMask>(mFlags, Preference::To2BitUint(aConnectivity.GetParentPriority()));
    mLinkQuality3     = aConnectivity.GetNumLinkQuality3();
    mLinkQuality2     = aConnectivity.GetNumLinkQuality2();
    mLinkQuality1     = aConnectivity.GetNumLinkQuality1();
    mLeaderCost       = aConnectivity.GetLeaderCost();
    mIdSequence       = aConnectivity.GetIdSequence();
    mActiveRouters    = aConnectivity.GetActiveRouterCount();
    mSedBufferSize    = BigEndian::HostSwap16(aConnectivity.GetSedBufferSize());
    mSedDatagramCount = aConnectivity.GetSedDatagramCount();
}

void ConnectivityTlvValue::GetConnectivity(Connectivity &aConnectivity) const
{
    aConnectivity.Clear();

    aConnectivity.mParentPriority   = Preference::From2BitUint(ReadBits<uint8_t, kFlagsParentPriorityMask>(mFlags));
    aConnectivity.mLinkQuality3     = mLinkQuality3;
    aConnectivity.mLinkQuality2     = mLinkQuality2;
    aConnectivity.mLinkQuality1     = mLinkQuality1;
    aConnectivity.mLeaderCost       = mLeaderCost;
    aConnectivity.mIdSequence       = mIdSequence;
    aConnectivity.mActiveRouters    = mActiveRouters;
    aConnectivity.mSedBufferSize    = BigEndian::HostSwap16(mSedBufferSize);
    aConnectivity.mSedDatagramCount = mSedDatagramCount;
}

Error ConnectivityTlvValue::ParseFrom(const Message &aMessage, const OffsetRange &aOffsetRange)
{
    Error    error = kErrorNone;
    uint16_t size  = aOffsetRange.GetLength();

    // The `mSedBufferSize` and `mSedDatagramCount` fields are
    // optional and are included as a pair. If the received TLV size
    // indicates they are not present, we read the partial TLV value
    // and then set the fields to their default minimum values.
    // Otherwise, we read the full structure.

    if (size == kMinSize)
    {
        SuccessOrExit(error = aMessage.Read(aOffsetRange, this, size));

        mSedBufferSize    = BigEndian::HostSwap16(kMinSedBufferSize);
        mSedDatagramCount = kMinSedDatagramCount;
    }
    else
    {
        SuccessOrExit(error = aMessage.Read(aOffsetRange, *this));
    }

exit:
    return error;
}

//---------------------------------------------------------------------------------------------------------------------
// ChannelTlvValue

void ChannelTlvValue::SetChannelAndPage(uint16_t aChannel)
{
    uint8_t channelPage = OT_RADIO_CHANNEL_PAGE_0;

#if OPENTHREAD_CONFIG_RADIO_915MHZ_OQPSK_SUPPORT
    if ((OT_RADIO_915MHZ_OQPSK_CHANNEL_MIN <= aChannel) && (aChannel <= OT_RADIO_915MHZ_OQPSK_CHANNEL_MAX))
    {
        channelPage = OT_RADIO_CHANNEL_PAGE_2;
    }
#endif

#if OPENTHREAD_CONFIG_PLATFORM_RADIO_PROPRIETARY_SUPPORT
    if ((OPENTHREAD_CONFIG_PLATFORM_RADIO_PROPRIETARY_CHANNEL_MIN == aChannel) ||
        ((OPENTHREAD_CONFIG_PLATFORM_RADIO_PROPRIETARY_CHANNEL_MIN < aChannel) &&
         (aChannel <= OPENTHREAD_CONFIG_PLATFORM_RADIO_PROPRIETARY_CHANNEL_MAX)))
    {
        channelPage = OPENTHREAD_CONFIG_PLATFORM_RADIO_PROPRIETARY_CHANNEL_PAGE;
    }
#endif

    SetChannelPage(channelPage);
    SetChannel(aChannel);
}

bool ChannelTlvValue::IsValid(void) const
{
    bool     isValid = false;
    uint16_t channel;

    VerifyOrExit(Radio::SupportsChannelPage(mChannelPage));

    channel = GetChannel();
    VerifyOrExit((Radio::kChannelMin <= channel) && (channel <= Radio::kChannelMax));

    isValid = true;

exit:
    return isValid;
}

//---------------------------------------------------------------------------------------------------------------------
// LeaderDataTlvValue

LeaderDataTlvValue::LeaderDataTlvValue(const LeaderData &aLeaderData)
    : mPartitionId(BigEndian::HostSwap32(aLeaderData.GetPartitionId()))
    , mWeighting(aLeaderData.GetWeighting())
    , mDataVersion(aLeaderData.GetDataVersion(NetworkData::kFullSet))
    , mStableDataVersion(aLeaderData.GetDataVersion(NetworkData::kStableSubset))
    , mLeaderRouterId(aLeaderData.GetLeaderRouterId())
{
}

void LeaderDataTlvValue::Get(LeaderData &aLeaderData) const
{
    aLeaderData.SetPartitionId(BigEndian::HostSwap32(mPartitionId));
    aLeaderData.SetWeighting(mWeighting);
    aLeaderData.SetDataVersion(mDataVersion);
    aLeaderData.SetStableDataVersion(mStableDataVersion);
    aLeaderData.SetLeaderRouterId(mLeaderRouterId);
}

//---------------------------------------------------------------------------------------------------------------------
// CslClockAccuracyTlvValue

#if OPENTHREAD_CONFIG_MAC_CSL_RECEIVER_ENABLE || OPENTHREAD_CONFIG_MAC_CSL_TRANSMITTER_ENABLE

CslClockAccuracyTlvValue::CslClockAccuracyTlvValue(uint8_t aClockAccuracy, uint8_t aUncertainty)
    : mClockAccuracy(aClockAccuracy)
    , mUncertainty(aUncertainty)
{
}

void CslClockAccuracyTlvValue::Get(Mac::CslAccuracy &aAccuracy) const
{
    aAccuracy.SetClockAccuracy(mClockAccuracy);
    aAccuracy.SetUncertainty(mUncertainty);
}

#endif

} // namespace Mle
} // namespace ot
