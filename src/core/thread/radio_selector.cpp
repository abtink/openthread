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
 *   This file includes implementation of radio selector (for multi radio links).
 */

#include "radio_selector.hpp"

#include "common/code_utils.hpp"
#include "common/instance.hpp"
#include "common/locator-getters.hpp"
#include "common/logging.hpp"
#include "common/random.hpp"

#if OPENTHREAD_CONFIG_MULTI_RADIO

namespace ot {

// This array defines the order in which different radio link types are
// selected for message tx (direct msg).
const Mac::RadioType RadioSelector::sRadioSelectionOrder[Mac::kNumRadioTypes] = {
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
    Mac::kRadioTypeTrel,
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    Mac::kRadioTypeIeee802154,
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TOBLE_ENABLE
    Mac::kRadioTypeToble,
#endif
};

RadioSelector::RadioSelector(Instance &aInstance)
    : InstanceLocator(aInstance)
{
}

void RadioSelector::UpdateNeighborRadioPreference(Neighbor &aNeighbor, Mac::RadioType aRadioType, int16_t aDifference)
{
    int16_t preferecne = static_cast<int16_t>(aNeighbor.GetRadioPreference(aRadioType));

    preferecne += aDifference;

    if (preferecne > kMaxPreference)
    {
        preferecne = kMaxPreference;
    }

    if (preferecne < kMinPreference)
    {
        preferecne = kMinPreference;
    }

    aNeighbor.SetRadioPreference(aRadioType, static_cast<uint8_t>(preferecne));
}

void RadioSelector::UpdateOnReceive(Neighbor &aNeighbor, Mac::RadioType aRadioType, bool aIsDuplicate)
{
    if (aNeighbor.GetSupportedRadioTypes().Contains(aRadioType))
    {
        UpdateNeighborRadioPreference(aNeighbor, aRadioType,
                                      aIsDuplicate ? kPreferenceChangeOnRxDuplicate : kPreferenceChangeOnRx);

        Log(aIsDuplicate ? "UpdateOnDupRx" : "UpdateOnRx", aRadioType, aNeighbor);
    }
    else
    {
        aNeighbor.AddSupportedRadioType(aRadioType);
        aNeighbor.SetRadioPreference(aRadioType, kInitPreference);

        Log("NewRadio(OnRx)", aRadioType, aNeighbor);
    }
}

void RadioSelector::UpdateOnSendDone(Mac::TxFrame &aFrame, otError aTxError)
{
    Mac::RadioType radioType = aFrame.GetRadioType();
    Mac::Address   macDest;
    Neighbor *     neighbor;

    VerifyOrExit(aFrame.GetAckRequest());

    aFrame.GetDstAddr(macDest);
    neighbor = Get<Mle::MleRouter>().FindNeighbor(macDest, Neighbor::kInStateAnyExceptInvalid);
    VerifyOrExit(neighbor != NULL);

    if (neighbor->GetSupportedRadioTypes().Contains(radioType))
    {
        UpdateNeighborRadioPreference(*neighbor, radioType,
                                      (aTxError == OT_ERROR_NONE) ? kPreferenceChangeOnTxSuccess
                                                                  : kPreferenceChangeOnTxError);

        Log((aTxError == OT_ERROR_NONE) ? "UpdateOnTxSucc" : "UpdateOnTxErr", radioType, *neighbor);
    }
    else
    {
        VerifyOrExit(aTxError == OT_ERROR_NONE);
        neighbor->AddSupportedRadioType(radioType);
        neighbor->SetRadioPreference(radioType, kInitPreference);

        Log("NewRadio(OnTx)", radioType, *neighbor);
    }

exit:
    return;
}

// Select (randomly) among given radio options based on neighbor radio preference values.
Mac::RadioType RadioSelector::Select(Mac::RadioTypes aRadioOptions, const Neighbor &aNeighbor)
{
    Mac::RadioType selection = sRadioSelectionOrder[0];

    for (const Mac::RadioType *nextRadio = &sRadioSelectionOrder[0]; nextRadio < OT_ARRAY_END(sRadioSelectionOrder);
         nextRadio++)
    {
        if (aRadioOptions.Contains(*nextRadio))
        {
            uint8_t preference = aNeighbor.GetRadioPreference(*nextRadio);

            aRadioOptions.Remove(*nextRadio);

            // Select the radio if it is the only remaining option, or
            // if it has high preference value. Otherwise choose the
            // radio randomly based on its preference value with
            // selection probability of `preference / kHighPreference`.

            if (aRadioOptions.IsEmpty() || (preference >= kHighPreference) ||
                (Random::NonCrypto::GetUint8InRange(0, kHighPreference) <= preference))
            {
                selection = *nextRadio;
                break;
            }
        }
    }

    return selection;
}

void RadioSelector::SelectRadio(Message &aMessage, const Mac::Address &aDest)
{
    Neighbor *     neighbor;
    Mac::RadioType selection;

    aMessage.ClearTxAttemptRadios();

    neighbor = Get<Mle::MleRouter>().FindNeighbor(aDest, Neighbor::kInStateAnyExceptInvalid);
    VerifyOrExit(neighbor != NULL);

    if (neighbor->GetSupportedRadioTypes().IsEmpty())
    {
        selection = sRadioSelectionOrder[0];
        neighbor->IncrementRadioTxAttempts(selection);
    }
    else
    {
        selection = Select(neighbor->GetSupportedRadioTypes(), *neighbor);
    }

    aMessage.AddToTxAttemptRadios(selection);
    aMessage.SetRadioType(selection);

    Log("SelectRadio", selection, *neighbor);

exit:
    return;
}

otError RadioSelector::SelectNextRadio(Message &aMessage, const Mac::Address &aDest)
{
    otError         error = OT_ERROR_NONE;
    Neighbor *      neighbor;
    Mac::RadioType  selection;
    Mac::RadioTypes remainingRadioOptions;

    neighbor = Get<Mle::MleRouter>().FindNeighbor(aDest, Neighbor::kInStateAnyExceptInvalid);
    VerifyOrExit(neighbor != NULL, error = OT_ERROR_NOT_FOUND);

    remainingRadioOptions = neighbor->GetSupportedRadioTypes() - aMessage.GetTxAttemptRadios();

    if (!remainingRadioOptions.IsEmpty())
    {
        selection = Select(remainingRadioOptions, *neighbor);
    }
    else
    {
        // All radio types known to be supported by the neighbor are
        // already attempted. We try to select a radio type (among
        // ones not yet known whether supported by the neighbor or
        // not). We keep track of number of times a radio type is
        // selected for tx. Up to `kRadioTxAttemptsThreshold` we
        // always try the radio link. After that we randomly select
        // the radio using `kRadioSelectionProbability` as selection
        // probability.

        Mac::RadioTypes       prevTxAttempts = aMessage.GetTxAttemptRadios();
        const Mac::RadioType *nextRadio;

        for (nextRadio = &sRadioSelectionOrder[0]; nextRadio < OT_ARRAY_END(sRadioSelectionOrder); nextRadio++)
        {
            if (!prevTxAttempts.Contains(*nextRadio) &&
                ((neighbor->GetRadioTxAttempts(*nextRadio) < kRadioTxAttemptsThreshold) ||
                 (Random::NonCrypto::GetUint8InRange(0, 100) < kRadioSelectionProbability)))
            {
                break;
            }
        }

        VerifyOrExit(nextRadio < OT_ARRAY_END(sRadioSelectionOrder), error = OT_ERROR_NOT_FOUND);
        selection = *nextRadio;
        neighbor->IncrementRadioTxAttempts(selection);
    }

    aMessage.AddToTxAttemptRadios(selection);
    aMessage.SetRadioType(selection);

    Log("SelectNextRadio", selection, *neighbor);

exit:
    return error;
}

Mac::RadioType RadioSelector::SelectPollFrameRadio(const Neighbor &aParent)
{
    // This array defines the order in which different radio link types
    // are selected for data poll frame tx.
    static const Mac::RadioType selectionOrder[Mac::kNumRadioTypes] = {
#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
        Mac::kRadioTypeIeee802154,
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TOBLE_ENABLE
        Mac::kRadioTypeToble,
#endif
#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
        Mac::kRadioTypeTrel,
#endif
    };

    Mac::RadioType selection = selectionOrder[0];

    for (const Mac::RadioType *nextRadio = &selectionOrder[0]; nextRadio < OT_ARRAY_END(selectionOrder); nextRadio++)
    {
        if (aParent.GetSupportedRadioTypes().Contains(*nextRadio))
        {
            selection = *nextRadio;
            break;
        }
    }

    return selection;
}

// LCOV_EXCL_START

#if (OPENTHREAD_CONFIG_LOG_LEVEL >= OT_LOG_LEVEL_DEBG) && (OPENTHREAD_CONFIG_LOG_MAC == 1)

void RadioSelector::Log(const char *aActionText, Mac::RadioType aType, const Neighbor &aNeighbor)
{
    String<kRadioPreferenceStringSize> preferenceString;
    bool                               isFirstEntry = true;
    const Mac::RadioType *             nextRadio;

    for (nextRadio = &sRadioSelectionOrder[0]; nextRadio < OT_ARRAY_END(sRadioSelectionOrder); nextRadio++)
    {
        if (aNeighbor.GetSupportedRadioTypes().Contains(*nextRadio))
        {
            preferenceString.Append("%s%s:%d", isFirstEntry ? "" : " ", RadioTypeToString(*nextRadio),
                                    aNeighbor.GetRadioPreference(*nextRadio));
            isFirstEntry = false;
        }
    }

    otLogDebgMac("RadioSelector: %s %s - neighbor:[%s rloc16:0x%04x radio-pref:{%s} state:%s]", aActionText,
                 RadioTypeToString(aType), aNeighbor.GetExtAddress().ToString().AsCString(), aNeighbor.GetRloc16(),
                 preferenceString.AsCString(), Neighbor::StateToString(aNeighbor.GetState()));
}

#else // #if (OPENTHREAD_CONFIG_LOG_LEVEL >= OT_LOG_LEVEL_DEBG) && (OPENTHREAD_CONFIG_LOG_MAC == 1)

void RadioSelector::Log(const char *, Mac::RadioType, const Neighbor &)
{
}

#endif // #if (OPENTHREAD_CONFIG_LOG_LEVEL >= OT_LOG_LEVEL_DEBG) && (OPENTHREAD_CONFIG_LOG_MAC == 1)

// LCOV_EXCL_STOP

} // namespace ot

#endif // #if OPENTHREAD_CONFIG_MULTI_RADIO
