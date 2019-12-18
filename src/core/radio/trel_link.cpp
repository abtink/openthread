/*
 *    Copyright (c) 2019, The OpenThread Authors.
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 *    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
 *    DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *    ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *   This file implements Thread Radio Encapsulation Link (TREL).
 */

#include "trel_link.hpp"

#include "common/code_utils.hpp"
#include "common/debug.hpp"
#include "common/instance.hpp"
#include "common/locator-getters.hpp"
#include "common/logging.hpp"

#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE

namespace ot {
namespace Trel {

Link::Link(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mState(kStateDisabled)
    , mRxChannel(0)
    , mPanId(Mac::kPanIdBroadcast)
    , mTxTasklet(aInstance, &HandleTxTasklet, this)
    , mAckTimer(aInstance, &HandleAckTimer, this)
    , mInterface(aInstance)
{
    memset(&mTxFrame, 0, sizeof(mTxFrame));
    memset(&mRxFrame, 0, sizeof(mRxFrame));
    memset(mAckFrameBuffer, 0, sizeof(mAckFrameBuffer));

    mTxFrame.mPsdu = &mTxPacketBuffer[kMaxHeaderSize];
    mTxFrame.SetLength(0);

#if OPENTHREAD_CONFIG_MULTI_RADIO
    mTxFrame.SetRadioType(Mac::kRadioTypeTrel);
    mRxFrame.SetRadioType(Mac::kRadioTypeTrel);
#endif

    // `mTxTasklet` is used for initializing the interface (in addition
    // to handling `Send()` requests). Invoking `Interface::Init()` from
    // a tasklet ensures that it happens after the constructors for
    // `Instance` and all its objects are done, allowing the interface
    // to safely use any of the core object methods (e.g., get the
    // randomly generated MAC address).

    mTxTasklet.Post();
}

void Link::Enable(void)
{
    if (mState == kStateDisabled)
    {
        SetState(kStateSleep);
    }
}

void Link::Disable(void)
{
    SetState(kStateDisabled);
}

void Link::Sleep(void)
{
    assert(mState != kStateDisabled);
    SetState(kStateSleep);
}

void Link::Receive(uint8_t aChannel)
{
    assert(mState != kStateDisabled);
    mRxChannel = aChannel;
    SetState(kStateReceive);
}

void Link::Send(void)
{
    assert(mState != kStateDisabled);

    SetState(kStateTransmit);
    mTxTasklet.Post();
}

void Link::HandleTxTasklet(Tasklet &aTasklet)
{
    aTasklet.GetOwner<Link>().HandleTxTasklet();
}

void Link::HandleTxTasklet(void)
{
    if (!mInterface.IsInitialized())
    {
        mInterface.Init();
    }

    BeginTransmit();
}

void Link::BeginTransmit(void)
{
    Mac::Address destAddr;
    Mac::PanId   destPanId;
    Header::Type type;

    VerifyOrExit(mState == kStateTransmit);

    // After sending a frame on a given channel we should
    // continue to rx on same channel
    mRxChannel = mTxFrame.GetChannel();

    VerifyOrExit(!mTxFrame.IsEmpty(), InvokeSendDone(OT_ERROR_ABORT));

    mTxFrame.GetDstAddr(destAddr);

    if (destAddr.IsNone() || destAddr.IsBroadcast())
    {
        type = Header::kTypeBroadcast;
    }
    else
    {
        type = Header::kTypeUnicast;

        if (destAddr.IsShort())
        {
            Neighbor *neighbor = Get<Mle::MleRouter>().FindNeighbor(destAddr, Neighbor::kInStateAnyExceptInvalid);

            if (neighbor == NULL)
            {
                // Send as a broadcast since we don't know the dest
                // ext address to include in the packet header.
                type = Header::kTypeBroadcast;
            }
            else
            {
                destAddr.SetExtended(neighbor->GetExtAddress());
            }
        }
    }

    if (mTxFrame.GetDstPanId(destPanId) != OT_ERROR_NONE)
    {
        destPanId = Mac::kPanIdBroadcast;
    }

    mTxPacket.Init(type, mTxFrame.GetPsdu(), mTxFrame.GetLength());

    mTxPacket.GetHeader().SetChannel(mTxFrame.GetChannel());
    mTxPacket.GetHeader().SetPanId(destPanId);
    mTxPacket.GetHeader().SetSource(Get<Mac::Mac>().GetExtAddress());

    if (type == Header::kTypeUnicast)
    {
        assert(destAddr.IsExtended());
        mTxPacket.GetHeader().SetDestination(destAddr.GetExtended());
    }

    VerifyOrExit(mInterface.Send(mTxPacket) == OT_ERROR_NONE, InvokeSendDone(OT_ERROR_ABORT));

    if (mTxFrame.GetAckRequest())
    {
        SetState(kStateWaitForAck);
        mAckTimer.Start(kAckTimeout);
    }
    else
    {
        InvokeSendDone(OT_ERROR_NONE);
    }

exit:
    return;
}

void Link::InvokeSendDone(otError aError, Mac::RxFrame *aAckFrame)
{
    SetState(kStateReceive);

    Get<Mac::Mac>().RecordFrameTransmitStatus(mTxFrame, aAckFrame, aError, /* aRetryCount */ 0, /* aWillRetx */ false);
    Get<Mac::Mac>().HandleTransmitDone(mTxFrame, aAckFrame, aError);
}

void Link::HandleAckTimer(Timer &aTimer)
{
    aTimer.GetOwner<Link>().HandleAckTimer();
}

void Link::HandleAckTimer(void)
{
    VerifyOrExit(mState == kStateWaitForAck);
    InvokeSendDone(OT_ERROR_NO_ACK);

exit:
    return;
}

void Link::ProcessReceivedPacket(Packet &aPacket)
{
    SuccessOrExit(aPacket.ValidateHeader());

    VerifyOrExit((mState == kStateReceive) || (mState == kStateTransmit) || (mState == kStateWaitForAck));

    VerifyOrExit(aPacket.GetHeader().GetChannel() == mRxChannel);

    if (mPanId != Mac::kPanIdBroadcast)
    {
        Mac::PanId rxPanId = aPacket.GetHeader().GetPanId();

        VerifyOrExit((rxPanId == mPanId) || (rxPanId == Mac::kPanIdBroadcast));
    }

    // Drop packets originating from same device.
    VerifyOrExit(aPacket.GetHeader().GetSource() != Get<Mac::Mac>().GetExtAddress());

    if (aPacket.GetHeader().IsUnicast())
    {
        VerifyOrExit(aPacket.GetHeader().GetDestination() == Get<Mac::Mac>().GetExtAddress());
    }

    mRxFrame.mPsdu    = aPacket.GetPayload();
    mRxFrame.mLength  = aPacket.GetPayloadLength();
    mRxFrame.mChannel = aPacket.GetHeader().GetChannel();
#if OPENTHREAD_CONFIG_MULTI_RADIO
    mRxFrame.mRadioType = Mac::kRadioTypeTrel;
#endif
    mRxFrame.mInfo.mRxInfo.mTimestamp             = 0;
    mRxFrame.mInfo.mRxInfo.mRssi                  = kRxRssi;
    mRxFrame.mInfo.mRxInfo.mLqi                   = OT_RADIO_LQI_NONE;
    mRxFrame.mInfo.mRxInfo.mAckedWithFramePending = false; // may be updated when/if ack is prepared.

    SuccessOrExit(mRxFrame.ValidatePsdu());

    if (mRxFrame.GetType() == Mac::Frame::kFcfFrameAck)
    {
        // Process the received ack frame.

        VerifyOrExit(aPacket.GetHeader().IsUnicast());

        VerifyOrExit(mState == kStateWaitForAck, otLogDebgMac("Trel: Received untimely ack frame"));

        if (mTxPacket.GetHeader().IsUnicast())
        {
            VerifyOrExit(aPacket.GetHeader().GetSource() == mTxPacket.GetHeader().GetDestination());
        }

        VerifyOrExit(mRxFrame.GetSequence() == mTxFrame.GetSequence());

        mAckTimer.Stop();
        InvokeSendDone(OT_ERROR_NONE, &mRxFrame);

        ExitNow();
    }

    if (mRxFrame.GetAckRequest())
    {
        Packet   ackPacket;
        uint16_t fcf = Mac::Frame::kFcfFrameAck;
        uint8_t *bytes;

        // Prepare the packet encapsulation header for ack frame

        ackPacket.Init(mAckFrameBuffer, sizeof(mAckFrameBuffer));

        ackPacket.GetHeader().Init(Header::kTypeUnicast);
        ackPacket.GetHeader().SetChannel(mRxFrame.mChannel);
        ackPacket.GetHeader().SetPanId(Get<Mac::Mac>().GetPanId());
        ackPacket.GetHeader().SetSource(Get<Mac::Mac>().GetExtAddress());
        ackPacket.GetHeader().SetDestination(aPacket.GetHeader().GetSource());

        bytes = ackPacket.GetPayload();

        if (ShouldAckRxFrameWithFramePending())
        {
            fcf |= Mac::Frame::kFcfFramePending;
            mRxFrame.mInfo.mRxInfo.mAckedWithFramePending = true;
        }

        Encoding::LittleEndian::WriteUint16(fcf, bytes);
        bytes += sizeof(fcf);
        *bytes = mRxFrame.GetSequence();

        assert(ackPacket.GetPayloadLength() == k154AckFrameSize);

        mInterface.Send(ackPacket);
    }

    Get<Mac::Mac>().HandleReceivedFrame(&mRxFrame, OT_ERROR_NONE);

exit:
    return;
}

bool Link::ShouldAckRxFrameWithFramePending(void) const
{
    bool         framePending = false;
    Mac::Address srcAddr;
    Child *      child;

    VerifyOrExit(mRxFrame.IsDataRequestCommand());

    mRxFrame.GetSrcAddr(srcAddr);
    child = Get<ChildTable>().FindChild(srcAddr, Child::kInStateValidOrRestoring);

    framePending = (child != NULL) && (child->GetIndirectMessageCount() > 0);

exit:
    return framePending;
}

void Link::SetState(State aState)
{
    if (mState != aState)
    {
        otLogDebgMac("Trel: State: %s -> %s", StateToString(mState), StateToString(aState));
        mState = aState;
    }
}

// LCOV_EXCL_START

const char *Link::StateToString(State aState)
{
    const char *str = "Unknown";

    switch (aState)
    {
    case kStateDisabled:
        str = "Disabled";
        break;

    case kStateSleep:
        str = "Sleep";
        break;

    case kStateReceive:
        str = "Receive";
        break;

    case kStateTransmit:
        str = "Transmit";
        break;

    case kStateWaitForAck:
        str = "WaitForAck";
        break;

    default:
        break;
    }

    return str;
}

// LCOV_EXCL_STOP

} // namespace Trel
} // namespace ot

#endif // #if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
