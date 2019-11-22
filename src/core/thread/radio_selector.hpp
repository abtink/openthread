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
 *   This file includes definitions for radio selector (for multi radio links).
 */

#ifndef RADIO_SELECTOR_HPP_
#define RADIO_SELECTOR_HPP_

#include "openthread-core-config.h"

#include "common/locator.hpp"
#include "common/message.hpp"
#include "mac/mac_frame.hpp"
#include "mac/mac_types.hpp"

#if OPENTHREAD_CONFIG_MULTI_RADIO

namespace ot {

/**
 * @addtogroup core-radio-selector
 *
 * @brief
 *   This module includes definition for radio selector (for multi radio links).
 *
 * @{
 *
 */

class Neighbor;

class RadioSelector : InstanceLocator
{
public:
    /**
     * This class defines all the neighbor info required for multi radio link and radio selection.
     *
     * `Neighbor` class publicly inherits from this class.
     *
     */
    class NeighborInfo
    {
        friend class RadioSelector;

        /**
         * This method returns the supported radio types by the neighbor.
         *
         * @returns The supported radio types set.
         *
         */
        Mac::RadioTypes GetSupportedRadioTypes(void) const { return mSupportedRadioTypes; }

    private:
        void AddSupportedRadioType(Mac::RadioType aType) { mSupportedRadioTypes.Add(aType); }
        void RemoveSupportedRadioType(Mac::RadioType aType) { mSupportedRadioTypes.Remove(aType); }
        void ClearSupportedRadioType(void) { mSupportedRadioTypes.Clear(); }

        uint8_t GetRadioPreference(Mac::RadioType aType) const { return mRadioInfo[aType].mPreference; }
        void    SetRadioPreference(Mac::RadioType aType, uint8_t aValue) { mRadioInfo[aType].mPreference = aValue; }

        uint8_t GetRadioTxAttempts(Mac::RadioType aType) const { return mRadioInfo[aType].mTxAttempts; }
        void    ClearRadioTxAttempts(Mac::RadioType aType) { mRadioInfo[aType].mTxAttempts = 0; }
        void    IncrementRadioTxAttempts(Mac::RadioType aType)
        {
            if (mRadioInfo[aType].mTxAttempts < kMaxRadioTxAttempts)
            {
                mRadioInfo[aType].mTxAttempts++;
            }
        }

        enum
        {
            kMaxRadioTxAttempts = 0xff,
        };

        Mac::RadioTypes mSupportedRadioTypes;
        union RadioInfo
        {
            uint8_t mPreference; // Radio link preference when supported.
            uint8_t mTxAttempts; // Number of tx attempts on radio link when not known if it is supported.
        } mRadioInfo[Mac::kNumRadioTypes];
    };

    /**
     * This constructor initializes the RadioSelector object.
     *
     * @param[in]  aInstance     A reference to the OpenThread instance.
     *
     */
    RadioSelector(Instance &aInstance);

    /**
     * This method updates the neighbor info (for multi radio support) on a received frame event.
     *
     * This method notifies `RadioSelector` of a received secure frame/message on a radio link type for neighbor. If
     * the frame/message happens to be received earlier on another radio link, the `aIsDuplicate` is set to `true`.
     * A duplicate frame/message should have passed the security check (i.e., tag/MIC should be valid).
     *
     * @param[in] aNeighbor     The neighbor for which a frame/message was received.
     * @param[in] aRadioType    The radio link type on which the frame/message was received.
     * @param[in] aIsDuplicate  Indicates whether the received frame/message is a duplicate or not.
     *
     */
    void UpdateOnReceive(Neighbor &aNeighbor, Mac::RadioType aRadioType, bool aIsDuplicate);

    /**
     * This method updates the neighbor info (for multi radio support) on a send done event.
     *
     * This method notifies `RadioSelector` the status of frame transmission on a radio link type. The radio link
     * type is provided by the `aFrame` itself.
     *
     * @param[in] aFrame     A transmitted frame.
     * @param[in] aTxError   The transmission error.
     *
     */
    void UpdateOnSendDone(Mac::TxFrame &aFrame, otError aTxError);

    /**
     * This method selects the radio link type for sending a data poll frame to a given parent neighbor.
     *
     * @param[in] aParent  The parent to which the data poll frame will be sent.
     *
     * @returns The radio type on which the data poll frame should be sent.
     *
     */
    Mac::RadioType SelectPollFrameRadio(const Neighbor &aParent);

    /**
     * This method selects the radio link type for sending a message to a specified MAC destination.
     *
     * The `aMessage` will be updated to store the selected radio type (please see `Message::GetRadioType()`).
     *
     * @param[in] aMessage   A message.
     * @param[in] aDest      The MAC destination address.
     *
     */
    void SelectRadio(Message &aMessage, const Mac::Address &aDest);

    /**
     * This method selects the next radio for retransmission (over different radio links) of a message.
     *
     * This method should be used after `SelectRadio()` is first called on the same `aMessage` and in the case where
     * the transmission on the previously selected radio type does fail. This method would then update the `aMessage`
     * to pick a next radio to send the message on. If all (supported) radio links are already attempted this method
     * returns `OT_ERROR_NOT_FOUND`.
     *
     * @param[in] aMessage   A message.
     * @param[in] aDest      The MAC destination address.
     *
     * @retval OT_ERROR_NONE        The next radio was selected and @p aMessage was updated
     * @retval OT_ERROR_NOT_FOUND   All supported radio links are attempted.
     *
     */
    otError SelectNextRadio(Message &aMessage, const Mac::Address &aDest);

private:
    enum
    {
        kPreferenceChangeOnTxError     = -35, // Preference change on a tx error on a radio link.
        kPreferenceChangeOnTxSuccess   = 25,  // Preference change on tx success on a radio link.
        kPreferenceChangeOnRx          = 15,  // Preference change on new (secure) frame/msg rx on a radio link
        kPreferenceChangeOnRxDuplicate = 15,  // Preference change on new (secure) duplicate frame/msg rx.
        kMinPreference                 = 17,  // Minimum preference value.
        kMaxPreference                 = 255, // Maximum preference value.
        kInitPreference                = 200, // Initial preference value
        kHighPreference                = 220, // High preference.
        kRadioTxAttemptsThreshold      = 10,  // Attempts threshold to always try tx on not yet known supported radio.
        kRadioSelectionProbability     = 10,  // Probability percentage to select a not yet known supported radio.

        kRadioPreferenceStringSize = 50,
    };

    void           UpdateNeighborRadioPreference(Neighbor &aNeighbor, Mac::RadioType aRadioType, int16_t aDifference);
    Mac::RadioType Select(Mac::RadioTypes aRadioOptions, const Neighbor &aNeighbor);
    void           Log(const char *aActionText, Mac::RadioType aType, const Neighbor &aNeighbor);

    static const Mac::RadioType sRadioSelectionOrder[Mac::kNumRadioTypes];
};

/**
 * @}
 *
 */

} // namespace ot

#endif // #if OPENTHREAD_CONFIG_MULTI_RADIO

#endif // RADIO_SELECTOR_HPP_
