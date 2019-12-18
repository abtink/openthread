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
 *   This file includes definitions for Thread Radio Encapsulation Link (TREL).
 */

#ifndef TREL_LINK_HPP_
#define TREL_LINK_HPP_

#include "openthread-core-config.h"

#include "common/encoding.hpp"
#include "common/locator.hpp"
#include "common/tasklet.hpp"
#include "common/timer.hpp"
#include "mac/mac_frame.hpp"
#include "mac/mac_types.hpp"
#include "radio/trel_interface.hpp"
#include "radio/trel_packet.hpp"

#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE

namespace ot {

class Neighbor;

namespace Trel {

/**
 * @addtogroup core-trel
 *
 * @brief
 *   This module includes definitions for Thread Radio Encapsulation Link (TREL)
 *
 * @{
 *
 */

/**
 * This class represents a Thread Radio Encapsulation Link (TREL).
 *
 */
class Link : public InstanceLocator
{
    friend class ot::Instance;
    friend class Interface;

public:
    enum
    {
        kMtuSize = OT_RADIO_FRAME_MAX_SIZE, ///< MTU size for TREL frame.
        kFcsSize = 2,                       ///< FCS size for TREL frame.
    };

    /**
     * This constructor initializes the `Link` object.
     *
     * @param[in]  aInstance  A reference to the OpenThread instance.
     *
     */
    explicit Link(Instance &aInstance);

    /**
     * This method sets the PAN Identifier.
     *
     * @param[in] aPanId   A PAN Identifier.
     *
     */
    void SetPanId(Mac::PanId aPanId) { mPanId = aPanId; }

    /**
     * This method notifies TREL radio link that device's extended MAC address has changed for it to update any
     * internal address/state.
     *
     */
    void HandleExtAddressChange(void) { mInterface.HandleExtAddressChange(); }

    /**
     * This method enables the TREL radio link.
     *
     */
    void Enable(void);

    /**
     * This method disables the TREL radio link.
     *
     */
    void Disable(void);

    /**
     * This method requests TREL radio link to transition to Sleep mode
     *
     */
    void Sleep(void);

    /**
     * This method requests TREL radio link to transition to Receive mode on a given channel.
     *
     * `Mac::HandleReceivedFrame()` is used to notify MAC layer upon receiving a frame.
     *
     * @param[in] aChannel   The channel to receive on.
     *
     */
    void Receive(uint8_t aChannel);

    /**
     * This method gets the radio transmit frame for TREL radio link.
     *
     * @returns The transmit frame.
     *
     */
    Mac::TxFrame &GetTransmitFrame(void) { return mTxFrame; }

    /**
     * This method requests a frame to be sent over TREL radio link.
     *
     * The frame should be already placed in `GetTransmitFrame()` frame.
     *
     * `Mac::RecordFrameTransmitStatus()` and `Mac::HandleTransmitDone()` are used to notify the success or error status
     * of frame transmission upon completion of send.
     *
     */
    void Send(void);

private:
    enum
    {
        kMaxHeaderSize   = sizeof(Header),
        k154AckFrameSize = 3 + kFcsSize,

        kAckTimeout = 16,  // Timeout waiting for an ACK (in milliseconds).
        kRxRssi     = -20, // The RSSI value used for received frames on TREL radio link.
    };

    enum State
    {
        kStateDisabled,
        kStateSleep,
        kStateReceive,
        kStateTransmit,
        kStateWaitForAck,
    };

    void SetState(State aState);
    void BeginTransmit(void);
    void InvokeSendDone(otError aError) { InvokeSendDone(aError, NULL); }
    void InvokeSendDone(otError aError, Mac::RxFrame *aAckFrame);
    bool ShouldAckRxFrameWithFramePending(void) const;
    void ProcessReceivedPacket(Packet &aPacket);

    static void HandleTxTasklet(Tasklet &aTasklet);
    void        HandleTxTasklet(void);

    static void HandleAckTimer(Timer &aTimer);
    void        HandleAckTimer(void);

    static const char *StateToString(State aState);

    State        mState;
    uint8_t      mRxChannel;
    Mac::PanId   mPanId;
    Tasklet      mTxTasklet;
    TimerMilli   mAckTimer;
    Interface    mInterface;
    Mac::RxFrame mRxFrame;
    Mac::TxFrame mTxFrame;
    Packet       mTxPacket;
    uint8_t      mTxPacketBuffer[kMaxHeaderSize + kMtuSize];
    uint8_t      mAckFrameBuffer[kMaxHeaderSize + k154AckFrameSize];
};

/**
 * @}
 *
 */

} // namespace Trel
} // namespace ot

#endif // #if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE

#endif // TREL_LINK_HPP_
