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
 *   This file includes definitions for MAC radio links.
 */

#ifndef MAC_LINKS_HPP_
#define MAC_LINKS_HPP_

#include "openthread-core-config.h"

#include "common/debug.hpp"
#include "common/locator.hpp"
#include "mac/mac_frame.hpp"
#include "mac/mac_types.hpp"
#include "mac/sub_mac.hpp"
#include "radio/toble.hpp"
#include "radio/trel.hpp"

namespace ot {
namespace Mac {

/**
 * @addtogroup core-mac
 *
 * @brief
 *   This module includes definitions for MAC radio links (multi radio).
 *
 * @{
 *
 */

/**
 * This class represents tx frames for different radio link types.
 *
 */
class TxFrames : InstanceLocator
{
    friend class Links;

public:
#if OPENTHREAD_CONFIG_MULTI_RADIO
    /**
     * This method get a tx frame for a given radio link type.
     *
     * @param[in] aRadioType   A radio link type.
     *
     * @returns A reference to the `TxFrame` for the given radio link type.
     *
     */
    TxFrame &GetTxFrame(RadioType aRadioType);

    /**
     * This method gets a tx frame for sending a broadcast frame.
     *
     * The broadcast frame is the tx frame with smallest MTU size among all radio types.
     *
     * @returns A reference to a `TxFrame` for broadcast.
     *
     */
    TxFrame &GetBroadcastTxFrame(void);

#else // #if OPENTHREAD_CONFIG_MULTI_RADIO

#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    /**
     * This method gets the tx frame.
     *
     * @returns A reference to `TxFrame`.
     *
     */
    TxFrame &GetTxFrame(void) { return mTxFrame802154; }
#elif OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
    /**
     * This method gets the tx frame.
     *
     * @returns A reference to `TxFrame`.
     *
     */
    TxFrame &GetTxFrame(void) { return mTxFrameTrel; }
#elif OPENTHREAD_CONFIG_RADIO_LINK_TOBLE_ENABLE
    /**
     * This method gets the tx frame.
     *
     * @returns A reference to `TxFrame`.
     *
     */
    TxFrame &GetTxFrame(void) { return mTxFrameToble; }
#endif
    /**
     * This method gets a tx frame for sending a broadcast frame.
     *
     * @returns A reference to a `TxFrame` for broadcast.
     *
     */
    TxFrame &GetBroadcastTxFrame(void) { return GetTxFrame(); }

#endif // #if OPENTHREAD_CONFIG_MULTI_RADIO

    /**
     * This method clears all supported radio tx frames (sets the PSDU length to zero).
     *
     */
    void Clear(void)
    {
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
        mTxFrame802154.SetLength(0);
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
        mTxFrameTrel.SetLength(0);
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TOBLE_ENABLE
        mTxFrameToble.SetLength(0);
#endif
    }

    /**
     * This method sets the channel on all supported radio tx frames.
     *
     * @param[in] aChannel  A channel.
     *
     */
    void SetChannel(uint8_t aChannel)
    {
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
        mTxFrame802154.SetChannel(aChannel);
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
        mTxFrameTrel.SetChannel(aChannel);
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TOBLE_ENABLE
        mTxFrameToble.SetChannel(aChannel);
#endif
    }

    /**
     * This method sets the Sequence NUmber value  on all supported radio tx frames.
     *
     * @param[in]  aSequence  The Sequence Number value.
     *
     */
    void SetSequence(uint8_t aSequence)
    {
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
        mTxFrame802154.SetSequence(aSequence);
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
        mTxFrameTrel.SetSequence(aSequence);
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TOBLE_ENABLE
        mTxFrameToble.SetSequence(aSequence);
#endif
    }

    /**
     * This method sets the maximum number of the CSMA-CA backoffs on all supported radio tx
     * frames.
     *
     * @param[in]  aMaxCsmaBackoffs  The maximum number of CSMA-CA backoffs.
     *
     */
    void SetMaxCsmaBackoffs(uint8_t aMaxCsmaBackoffs)
    {
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
        mTxFrame802154.SetMaxCsmaBackoffs(aMaxCsmaBackoffs);
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
        mTxFrameTrel.SetMaxCsmaBackoffs(aMaxCsmaBackoffs);
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TOBLE_ENABLE
        mTxFrameToble.SetMaxCsmaBackoffs(aMaxCsmaBackoffs);
#endif
    }

    /**
     * This method sets the maximum number of retries allowed after a transmission failure on all supported radio tx
     * frames.
     *
     * @param[in]  aMaxFrameRetries  The maximum number of retries allowed after a transmission failure.
     *
     */
    void SetMaxFrameRetries(uint8_t aMaxFrameRetries)
    {
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
        mTxFrame802154.SetMaxFrameRetries(aMaxFrameRetries);
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
        mTxFrameTrel.SetMaxFrameRetries(aMaxFrameRetries);
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TOBLE_ENABLE
        mTxFrameToble.SetMaxFrameRetries(aMaxFrameRetries);
#endif
    }

private:
    explicit TxFrames(Instance &aInstance);

#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    TxFrame &mTxFrame802154;
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
    TxFrame &mTxFrameTrel;
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TOBLE_ENABLE
    TxFrame &mTxFrameToble;
#endif
};

/**
 * This class represents MAC radio links (multi radio).
 *
 */
class Links : public InstanceLocator
{
    friend class ot::Instance;

public:
    enum
    {
        kInvalidRssiValue = SubMac::kInvalidRssiValue, ///< Invalid Received Signal Strength Indicator (RSSI) value.
    };

    /**
     * This constructor initializes the `Links` object.
     *
     * @param[in]  aInstance  A reference to the OpenThread instance.
     *
     */
    explicit Links(Instance &aInstance);

    /**
     * This method sets the PAN ID.
     *
     * @param[in] aPanId  The PAN ID.
     *
     */
    void SetPanId(PanId aPanId)
    {
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
        mSubMac.SetPanId(aPanId);
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
        mTrel.SetPanId(aPanId);
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TOBLE_ENABLE
        mToble.SetPanId(aPanId);
#endif
    }

    /**
     * This method gets the short address.
     *
     * @returns The short address.
     *
     */
    ShortAddress GetShortAddress(void) const
    {
        return
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
            mSubMac.GetShortAddress();
#else
            mShortAddress;
#endif
    }

    /**
     * This method sets the short address.
     *
     * @param[in] aShortAddress   The short address.
     *
     */
    void SetShortAddress(ShortAddress aShortAddress)
    {
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
        mSubMac.SetShortAddress(aShortAddress);
#else
        mShortAddress = aShortAddress;
#endif
    }

    /**
     * This method gets the extended address.
     *
     * @returns A reference to the extended address.
     *
     */
    const ExtAddress &GetExtAddress(void) const
    {
        return
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
            mSubMac.GetExtAddress();
#else
            mExtAddress;
#endif
    }

    /**
     * This method sets extended address.
     *
     * @param[in] aExtAddress  The extended address.
     *
     */
    void SetExtAddress(const ExtAddress &aExtAddress)
    {
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
        mSubMac.SetExtAddress(aExtAddress);
#else
        mExtAddress = aExtAddress;
#endif
    }

    /**
     * This method registers a callback to provide received packet capture for IEEE 802.15.4 frames.
     *
     * @param[in]  aPcapCallback     A pointer to a function that is called when receiving an IEEE 802.15.4 link frame
     *                                or NULL to disable the callback.
     * @param[in]  aCallbackContext  A pointer to application-specific context.
     *
     */
    void SetPcapCallback(otLinkPcapCallback aPcapCallback, void *aCallbackContext)
    {
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
        mSubMac.SetPcapCallback(aPcapCallback, aCallbackContext);
#endif
        OT_UNUSED_VARIABLE(aPcapCallback);
        OT_UNUSED_VARIABLE(aCallbackContext);
    }

    /**
     * This method indicates whether radio should stay in Receive or Sleep during CSMA backoff.
     *
     * @param[in]  aRxOnWhenBackoff  TRUE to keep radio in Receive, FALSE to put to Sleep during CSMA backoff.
     *
     */
    void SetRxOnWhenBackoff(bool aRxOnWhenBackoff)
    {
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
        mSubMac.SetRxOnWhenBackoff(aRxOnWhenBackoff);
#endif
        OT_UNUSED_VARIABLE(aRxOnWhenBackoff);
    }

    /**
     * This method enables all radio links
     *
     */
    void Enable(void)
    {
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
        mSubMac.Enable();
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
        mTrel.Enable();
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TOBLE_ENABLE
        mToble.Enable();
#endif
    }

    /**
     * This method disables all radio links.
     *
     */
    void Disable(void)
    {
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
        mSubMac.Disable();
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
        mTrel.Disable();
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TOBLE_ENABLE
        mToble.Disable();
#endif
    }

    /**
     * This method transitions all radio links to Sleep.
     *
     */
    void Sleep(void)
    {
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
        mSubMac.Sleep();
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
        mTrel.Sleep();
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TOBLE_ENABLE
        mToble.Sleep();
#endif
    }

    /**
     * This method transitions all radio links to Receive.
     *
     * @param[in]  aChannel   The channel to use for receiving.
     *
     */
    void Receive(uint8_t aChannel)
    {
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
        mSubMac.Receive(aChannel);
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
        mTrel.Receive(aChannel);
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TOBLE_ENABLE
        mToble.Receive(aChannel);
#endif
    }

    /**
     * This method gets the radio transmit frames.
     *
     * @returns The transmit frames.
     *
     */
    TxFrames &GetTxFrames(void) { return mTxFrames; }

#if !OPENTHREAD_CONFIG_MULTI_RADIO

    /**
     * This method sends a prepared frame.
     *
     * The prepared frame is from `GetTxFrames()`. This method is available only in single radio link mode.
     *
     */
    void Send(void)
    {
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
        {
            otError error = mSubMac.Send();
            assert(error == OT_ERROR_NONE);
        }
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
        mTrel.Send();
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TOBLE_ENABLE
        mToble.Send();
#endif
    }

#else // #if !OPENTHREAD_CONFIG_MULTI_RADIO

    /**
     * This method sends prepared frames over a given set of radio links.
     *
     * The prepared frame must be from `GetTxFrames()`. This method is available only in multi radio link mode.
     *
     * @param[in] aFrame       A reference to a prepared frame.
     * @param[in] aRadioTypes  A set of radio types to send on.
     *
     */
    void Send(TxFrame &aFrame, RadioTypes aRadioTypes);

#endif // #if !OPENTHREAD_CONFIG_MULTI_RADIO

    /**
     * This method gets the number of transmit retries of last transmitted frame.
     *
     * @returns Number of transmit retries.
     *
     */
    uint8_t GetTransmitRetries(void) const
    {
        return
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
            mSubMac.GetTransmitRetries();
#else
            0;
#endif
    }

    /**
     * This method gets the most recent RSSI measurement from radio link
     *
     * @returns The RSSI in dBm when it is valid. `kInvalidRssiValue` when RSSI is invalid.
     *
     */
    int8_t GetRssi(void) const
    {
        return
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
            mSubMac.GetRssi();
#else
            kInvalidRssiValue;
#endif
    }

    /**
     * This method begins energy scan.
     *
     * @param[in] aScanChannel   The channel to perform the energy scan on.
     * @param[in] aScanDuration  The duration, in milliseconds, for the channel to be scanned.
     *
     * @retval OT_ERROR_NONE             Successfully started scanning the channel.
     * @retval OT_ERROR_INVALID_STATE    The radio was disabled or transmitting.
     * @retval OT_ERROR_NOT_IMPLEMENTED  Energy scan is not supported by radio link.
     *
     */
    otError EnergyScan(uint8_t aScanChannel, uint16_t aScanDuration)
    {
        OT_UNUSED_VARIABLE(aScanChannel);
        OT_UNUSED_VARIABLE(aScanDuration);

        return
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
            mSubMac.EnergyScan(aScanChannel, aScanDuration);
#else
            OT_ERROR_NOT_IMPLEMENTED;
#endif
    }

private:
    SubMac mSubMac;
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
    Trel::Link mTrel;
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TOBLE_ENABLE
    Toble::Link mToble;
#endif

    // `TxFrames` member definition should be after `mSubMac`, `mTrel`
    // and `mToble` definitions to allow it to use their methods from
    // its constructor.
    TxFrames mTxFrames;

#if !OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    ShortAddress mShortAddress;
    ExtAddress   mExtAddress;
#endif
};

/**
 * @}
 *
 */

} // namespace Mac
} // namespace ot

#endif // MAC_LINKS_HPP_
