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
 *   This file includes definitions for Thread over BLE (ToBLE).
 */

#ifndef TOBLE_LINK_HPP_
#define TOBLE_LINK_HPP_

#include "openthread-core-config.h"

#include "common/locator.hpp"
#include "mac/mac_frame.hpp"
#include "mac/mac_types.hpp"

#if OPENTHREAD_CONFIG_RADIO_LINK_TOBLE_ENABLE

namespace ot {
namespace Toble {

/**
 * @addtogroup core-toble
 *
 * @brief
 *   This module includes definitions for Thread over BLE (ToBLE)
 *
 * @{
 *
 */

/**
 * This class represents a Thread over BLE (ToBLE) link.
 *
 */
class Link : public InstanceLocator
{
    friend class Instance;

public:
    enum
    {
        kMtuSize = OT_RADIO_FRAME_MAX_SIZE, ///< MTU size for ToBLE frame.
        kFcsSize = 2,                       ///< FCS size for ToBLE frame.
    };

    explicit Link(Instance &aInstance);

    void SetPanId(Mac::PanId aPanId) { (void)aPanId; }

    void Enable(void) {}
    void Disable(void) {}

    void Sleep(void) {}
    void Receive(uint8_t aChannel) { (void)aChannel; }
    void Send(void) {}

    Mac::TxFrame &GetTransmitFrame(void) { return mTxFrame; }

private:
    Mac::TxFrame mTxFrame;
    uint8_t      mFrameBuffer[kMtuSize];
};

/**
 * @}
 *
 */

} // namespace Toble
} // namespace ot

#endif // #if OPENTHREAD_CONFIG_RADIO_LINK_TOBLE_ENABLE

#endif // TOBLE_LINK_HPP_
