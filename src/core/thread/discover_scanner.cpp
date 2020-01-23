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

/**
 * @file
 *   This file implements MLE Discover Scan process.
 */

#include "discover_scanner.hpp"

#include "common/code_utils.hpp"
#include "common/instance.hpp"
#include "common/locator-getters.hpp"
#include "common/logging.hpp"
#include "thread/mesh_forwarder.hpp"
#include "thread/mle.hpp"
#include "thread/mle_router.hpp"

namespace ot {
namespace Mle {

DiscoverScanner::DiscoverScanner(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mHandler(NULL)
    , mHandlerContext(NULL)
    , mRequestMessage(NULL)
    , mTimer(aInstance, DiscoverScanner::HandleTimer, this)
    , mFilterIndexes()
    , mScanChannels()
    , mEnableFiltering(false)
    , mShouldRestorePanId(false)
{
}

otError DiscoverScanner::Discover(const Mac::ChannelMask &aScanChannels,
                                  uint16_t                aPanId,
                                  bool                    aJoiner,
                                  bool                    aEnableFiltering,
                                  Handler                 aCallback,
                                  void *                  aContext)
{
    otError                      error   = OT_ERROR_NONE;
    Message *                    message = NULL;
    Ip6::Address                 destination;
    MeshCoP::DiscoveryRequestTlv discoveryRequest;

    VerifyOrExit(!IsInProgress(), error = OT_ERROR_BUSY);

    mEnableFiltering = aEnableFiltering;

    if (mEnableFiltering)
    {
        Mac::ExtAddress extAddress;

        Get<Radio>().GetIeeeEui64(extAddress);
        MeshCoP::ComputeJoinerId(extAddress, extAddress);

        MeshCoP::SteeringData::CalculateHashBitIndexes(extAddress, mFilterIndexes);
    }

    mHandler            = aCallback;
    mHandlerContext     = aContext;
    mShouldRestorePanId = false;
    mScanChannels       = Get<Mac::Mac>().GetSupportedChannelMask();

    if (!aScanChannels.IsEmpty())
    {
        mScanChannels.Intersect(aScanChannels);
    }

    VerifyOrExit((message = Get<Mle>().NewMleMessage()) != NULL, error = OT_ERROR_NO_BUFS);
    message->SetSubType(Message::kSubTypeMleDiscoverRequest);
    message->SetPanId(aPanId);
    SuccessOrExit(error = Get<Mle>().AppendHeader(*message, Header::kCommandDiscoveryRequest));

    // Append MLE Discovery TLV with a single sub-TLV (MeshCoP Discovery Request).
    discoveryRequest.Init();
    discoveryRequest.SetVersion(kThreadVersion);
    discoveryRequest.SetJoiner(aJoiner);

    SuccessOrExit(error = Tlv::AppendTlv(*message, Tlv::kDiscovery, &discoveryRequest, sizeof(discoveryRequest)));

    destination.SetToLinkLocalAllRoutersMulticast();

    SuccessOrExit(error = Get<Mle>().SendMessage(*message, destination));

    if ((aPanId == Mac::kPanIdBroadcast) && (Get<Mac::Mac>().GetPanId() == Mac::kPanIdBroadcast))
    {
        // In case a specific PAN ID of a Thread Network to be
        // discovered is not known, Discovery Request messages MUST
        // have the Destination PAN ID in the IEEE 802.15.4 MAC
        // header set to be the Broadcast PAN ID (0xffff) and the
        // Source PAN ID set to a randomly generated value.

        Get<Mac::Mac>().SetPanId(Mac::GenerateRandomPanId());
        mShouldRestorePanId = true;
    }

    mRequestMessage = message;
    message         = NULL;

    otLogInfoMle("Send Discovery Request (%s)", destination.ToString().AsCString());

exit:
    if (message != NULL)
    {
        message->Free();
    }

    return error;
}

otError DiscoverScanner::PrepareDiscoveryRequestFrame(const Message &aMessage, Mac::TxFrame &aFrame)
{
    otError error = OT_ERROR_NONE;
    uint8_t channel;

    // This callback may be called with a message corresponding to
    // a canceled previous scan. We first verify that `aMessage`
    // matches the current Discovery Scan.

    VerifyOrExit(&aMessage == mRequestMessage, error = OT_ERROR_ABORT);

    // We go to next scan channel in the `mScanChannels` mask, if
    // all channels are covered, we return `OT_ERROR_ABORT` to
    // abort the current frame tx. The end of scan is then signaled
    // from `HandleDiscoveryRequestFrameTxDone()`.

    VerifyOrExit(!mScanChannels.IsEmpty(), error = OT_ERROR_ABORT);

    channel = Mac::ChannelMask::kChannelIteratorFirst;
    IgnoreError(mScanChannels.GetNextChannel(channel));

    aFrame.SetChannel(channel);
    IgnoreError(Get<Mac::Mac>().SetTemporaryChannel(channel));

exit:
    return error;
}

void DiscoverScanner::HandleDiscoveryRequestFrameTxDone(Message &aMessage)
{
    uint8_t channel;

    VerifyOrExit(&aMessage == mRequestMessage, OT_NOOP);

    if (mScanChannels.IsEmpty())
    {
        SignalScanCompleted();
        ExitNow();

        // Note that `aMessage` will be dequeued and freed upon return
        // from callback by `MessageForwarder`
    }

    // Remove the channel from the `mScanChannels` mask.
    channel = Mac::ChannelMask::kChannelIteratorFirst;
    IgnoreError(mScanChannels.GetNextChannel(channel));
    mScanChannels.RemoveChannel(channel);

    // Mark the Discovery Request message for direct transmission
    // so that it will not be dequeued and freed and is ready for
    // tx on the next scan channel. Also pause transmissions on
    // `MeshForwarder` while listening for MLE Discovery Response
    // messages.

    aMessage.SetDirectTransmission();
    Get<MeshForwarder>().PuaseMessageTransmissions();
    mTimer.Start(kDefaultScanDuration);

exit:
    return;
}

void DiscoverScanner::SignalScanCompleted(void)
{
    VerifyOrExit(IsInProgress(), OT_NOOP);

    mTimer.Stop();
    Get<Mac::Mac>().ClearTemporaryChannel();
    Get<MeshForwarder>().ResumeMessageTransmissions();

    if (mShouldRestorePanId)
    {
        Get<Mac::Mac>().SetPanId(Mac::kPanIdBroadcast);
        mShouldRestorePanId = false;
    }

    mEnableFiltering = false;
    mRequestMessage  = NULL;

    if (mHandler)
    {
        mHandler(NULL, mHandlerContext);
    }

exit:
    return;
}

void DiscoverScanner::HandleTimer(Timer &aTimer)
{
    aTimer.GetOwner<DiscoverScanner>().HandleTimer();
}

void DiscoverScanner::HandleTimer(void)
{
    // When timer expires, we resume message transmissions on
    // `MeshForwarder` This will in turn prepare the MLE Discovery
    // Request message for the next channel.

    Get<MeshForwarder>().ResumeMessageTransmissions();
}

void DiscoverScanner::HandleDiscoveryResponse(const Message &aMessage, const Ip6::MessageInfo &aMessageInfo) const
{
    otError                       error    = OT_ERROR_NONE;
    const otThreadLinkInfo *      linkInfo = static_cast<const otThreadLinkInfo *>(aMessageInfo.GetLinkInfo());
    Tlv                           tlv;
    MeshCoP::Tlv                  meshcopTlv;
    MeshCoP::DiscoveryResponseTlv discoveryResponse;
    MeshCoP::NetworkNameTlv       networkName;
    ScanResult                    result;
    uint16_t                      offset;
    uint16_t                      end;
    bool                          didCheckSteeringData = false;

    otLogInfoMle("Receive Discovery Response (%s)", aMessageInfo.GetPeerAddr().ToString().AsCString());

    VerifyOrExit(IsInProgress(), error = OT_ERROR_DROP);

    // Find MLE Discovery TLV
    VerifyOrExit(Tlv::FindTlvOffset(aMessage, Tlv::kDiscovery, offset) == OT_ERROR_NONE, error = OT_ERROR_PARSE);
    aMessage.Read(offset, sizeof(tlv), &tlv);

    offset += sizeof(tlv);
    end = offset + tlv.GetLength();

    memset(&result, 0, sizeof(result));
    result.mPanId   = linkInfo->mPanId;
    result.mChannel = linkInfo->mChannel;
    result.mRssi    = linkInfo->mRss;
    result.mLqi     = linkInfo->mLqi;
    aMessageInfo.GetPeerAddr().ToExtAddress(*static_cast<Mac::ExtAddress *>(&result.mExtAddress));

    // Process MeshCoP TLVs
    while (offset < end)
    {
        aMessage.Read(offset, sizeof(meshcopTlv), &meshcopTlv);

        switch (meshcopTlv.GetType())
        {
        case MeshCoP::Tlv::kDiscoveryResponse:
            aMessage.Read(offset, sizeof(discoveryResponse), &discoveryResponse);
            VerifyOrExit(discoveryResponse.IsValid(), error = OT_ERROR_PARSE);
            result.mVersion  = discoveryResponse.GetVersion();
            result.mIsNative = discoveryResponse.IsNativeCommissioner();
            break;

        case MeshCoP::Tlv::kExtendedPanId:
            SuccessOrExit(error = Tlv::ReadTlv(aMessage, offset, &result.mExtendedPanId, sizeof(Mac::ExtendedPanId)));
            break;

        case MeshCoP::Tlv::kNetworkName:
            aMessage.Read(offset, sizeof(networkName), &networkName);
            IgnoreError(static_cast<Mac::NetworkName &>(result.mNetworkName).Set(networkName.GetNetworkName()));
            break;

        case MeshCoP::Tlv::kSteeringData:
            if (meshcopTlv.GetLength() > 0)
            {
                MeshCoP::SteeringData &steeringData = static_cast<MeshCoP::SteeringData &>(result.mSteeringData);
                uint8_t                dataLength   = MeshCoP::SteeringData::kMaxLength;

                if (meshcopTlv.GetLength() < dataLength)
                {
                    dataLength = meshcopTlv.GetLength();
                }

                steeringData.Init(dataLength);

                SuccessOrExit(error = Tlv::ReadTlv(aMessage, offset, steeringData.GetData(), dataLength));

                if (mEnableFiltering)
                {
                    VerifyOrExit(steeringData.Contains(mFilterIndexes), OT_NOOP);
                }

                didCheckSteeringData = true;
            }
            break;

        case MeshCoP::Tlv::kJoinerUdpPort:
            SuccessOrExit(error = Tlv::ReadUint16Tlv(aMessage, offset, result.mJoinerUdpPort));
            break;

        default:
            break;
        }

        offset += sizeof(meshcopTlv) + meshcopTlv.GetLength();
    }

    VerifyOrExit(!mEnableFiltering || didCheckSteeringData, OT_NOOP);

    if (mHandler)
    {
        mHandler(&result, mHandlerContext);
    }

exit:

    if (error != OT_ERROR_NONE)
    {
        otLogWarnMle("Failed to process Discovery Response: %s", otThreadErrorToString(error));
    }
}

} // namespace Mle
} // namespace ot
