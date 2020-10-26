/*
 *  Copyright (c) 2016, The OpenThread Authors.
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
 *   This file implements common methods for manipulating MeshCoP Datasets.
 *
 */

#include "dataset.hpp"

#include <stdio.h>

#include "common/code_utils.hpp"
#include "common/encoding.hpp"
#include "common/instance.hpp"
#include "common/locator-getters.hpp"
#include "common/logging.hpp"
#include "mac/mac_types.hpp"
#include "meshcop/meshcop_tlvs.hpp"
#include "thread/mle_tlvs.hpp"

namespace ot {
namespace MeshCoP {

using ot::Encoding::BigEndian::HostSwap16;
using ot::Encoding::BigEndian::HostSwap32;

//---------------------------------------------------------------------------------------------------------------------
// Dataset::Info

void Dataset::Info::SetActiveTimestamp(uint64_t aTimestamp)
{
    mActiveTimestamp                      = aTimestamp;
    mComponents.mIsActiveTimestampPresent = true;
}

void Dataset::Info::SetPendingTimestamp(uint64_t aTimestamp)
{
    mPendingTimestamp                      = aTimestamp;
    mComponents.mIsPendingTimestampPresent = true;
}

void Dataset::Info::SetMasterKey(const MasterKey &aMasterKey)
{
    mMasterKey                      = aMasterKey;
    mComponents.mIsMasterKeyPresent = true;
}

MasterKey &Dataset::Info::UpdateMasterKey(void)
{
    mComponents.mIsMasterKeyPresent = true;

    return static_cast<MasterKey &>(mMasterKey);
}

void Dataset::Info::SetNetworkName(const Mac::NameData &aNetworkNameData)
{
    IgnoreError(static_cast<Mac::NetworkName &>(mNetworkName).Set(aNetworkNameData));
    mComponents.mIsNetworkNamePresent = true;
}

Mac::NetworkName &Dataset::Info::UpdateNetworkName(void)
{
    mComponents.mIsNetworkNamePresent = true;

    return static_cast<Mac::NetworkName &>(mNetworkName);
}

void Dataset::Info::SetExtendedPanId(const Mac::ExtendedPanId &aExtendedPanId)
{
    mExtendedPanId                      = aExtendedPanId;
    mComponents.mIsExtendedPanIdPresent = true;
}

Mac::ExtendedPanId &Dataset::Info::UpdateExtendedPanId(void)
{
    mComponents.mIsExtendedPanIdPresent = true;

    return static_cast<Mac::ExtendedPanId &>(mExtendedPanId);
}

void Dataset::Info::SetMeshLocalPrefix(const Mle::MeshLocalPrefix &aMeshLocalPrefix)
{
    mMeshLocalPrefix                      = aMeshLocalPrefix;
    mComponents.mIsMeshLocalPrefixPresent = true;
}

Mle::MeshLocalPrefix &Dataset::Info::UpdateMeshLocalPrefix(void)
{
    mComponents.mIsMeshLocalPrefixPresent = true;

    return static_cast<Mle::MeshLocalPrefix &>(mMeshLocalPrefix);
}

void Dataset::Info::SetDelay(uint32_t aDelay)
{
    mDelay                      = aDelay;
    mComponents.mIsDelayPresent = true;
}

void Dataset::Info::SetPanId(Mac::PanId aPanId)
{
    mPanId                      = aPanId;
    mComponents.mIsPanIdPresent = true;
}

void Dataset::Info::SetChannel(uint16_t aChannel)
{
    mChannel                      = aChannel;
    mComponents.mIsChannelPresent = true;
}

void Dataset::Info::SetPskc(const Pskc &aPskc)
{
    mPskc                      = aPskc;
    mComponents.mIsPskcPresent = true;
}

Pskc &Dataset::Info::UpdatePskc(void)
{
    mComponents.mIsPskcPresent = true;

    return static_cast<Pskc &>(mPskc);
}

void Dataset::Info::SetSecurityPolicy(uint16_t aRotationTime, uint8_t aFlags)
{
    mSecurityPolicy.mRotationTime        = aRotationTime;
    mSecurityPolicy.mFlags               = aFlags;
    mComponents.mIsSecurityPolicyPresent = true;
}

void Dataset::Info::SetChannelMask(otChannelMask aChannelMask)
{
    mChannelMask                      = aChannelMask;
    mComponents.mIsChannelMaskPresent = true;
}

//---------------------------------------------------------------------------------------------------------------------
// Dataset

Dataset::Dataset(Type aType)
    : mUpdateTime(0)
    , mLength(0)
    , mType(aType)
{
    memset(mTlvs, 0, sizeof(mTlvs));
}

void Dataset::Clear(void)
{
    mLength = 0;
}

bool Dataset::IsValid(void) const
{
    bool       rval = true;
    const Tlv *end  = GetTlvsEnd();

    for (const Tlv *cur = GetTlvsStart(); cur < end; cur = cur->GetNext())
    {
        VerifyOrExit((cur + 1) <= end && cur->GetNext() <= end && Tlv::IsValid(*cur), rval = false);
    }

exit:
    return rval;
}

const Tlv *Dataset::GetTlv(Tlv::Type aType) const
{
    return Tlv::FindTlv(mTlvs, mLength, aType);
}

void Dataset::ConvertTo(Info &aDatasetInfo) const
{
    aDatasetInfo.Clear();

    for (const Tlv *cur = GetTlvsStart(); cur < GetTlvsEnd(); cur = cur->GetNext())
    {
        switch (cur->GetType())
        {
        case Tlv::kActiveTimestamp:
            aDatasetInfo.SetActiveTimestamp(static_cast<const ActiveTimestampTlv *>(cur)->GetSeconds());
            break;

        case Tlv::kChannel:
            aDatasetInfo.SetChannel(static_cast<const ChannelTlv *>(cur)->GetChannel());
            break;

        case Tlv::kChannelMask:
        {
            uint32_t mask = static_cast<const ChannelMaskTlv *>(cur)->GetChannelMask();

            if (mask != 0)
            {
                aDatasetInfo.SetChannelMask(mask);
            }

            break;
        }

        case Tlv::kDelayTimer:
            aDatasetInfo.SetDelay(static_cast<const DelayTimerTlv *>(cur)->GetDelayTimer());
            break;

        case Tlv::kExtendedPanId:
            aDatasetInfo.SetExtendedPanId(static_cast<const ExtendedPanIdTlv *>(cur)->GetExtendedPanId());
            break;

        case Tlv::kMeshLocalPrefix:
            aDatasetInfo.SetMeshLocalPrefix(static_cast<const MeshLocalPrefixTlv *>(cur)->GetMeshLocalPrefix());
            break;

        case Tlv::kNetworkMasterKey:
            aDatasetInfo.SetMasterKey(static_cast<const NetworkMasterKeyTlv *>(cur)->GetNetworkMasterKey());
            break;

        case Tlv::kNetworkName:
            aDatasetInfo.SetNetworkName(static_cast<const NetworkNameTlv *>(cur)->GetNetworkName());
            break;

        case Tlv::kPanId:
            aDatasetInfo.SetPanId(static_cast<const PanIdTlv *>(cur)->GetPanId());
            break;

        case Tlv::kPendingTimestamp:
            aDatasetInfo.SetPendingTimestamp(static_cast<const PendingTimestampTlv *>(cur)->GetSeconds());
            break;

        case Tlv::kPskc:
            aDatasetInfo.SetPskc(static_cast<const PskcTlv *>(cur)->GetPskc());
            break;

        case Tlv::kSecurityPolicy:
        {
            const SecurityPolicyTlv *tlv = static_cast<const SecurityPolicyTlv *>(cur);
            aDatasetInfo.SetSecurityPolicy(tlv->GetRotationTime(), tlv->GetFlags());
            break;
        }

        default:
            break;
        }
    }
}

void Dataset::ConvertTo(otOperationalDatasetTlvs &aDataset) const
{
    memcpy(aDataset.mTlvs, mTlvs, mLength);
    aDataset.mLength = static_cast<uint8_t>(mLength);
}

void Dataset::Set(const Dataset &aDataset)
{
    memcpy(mTlvs, aDataset.mTlvs, aDataset.mLength);
    mLength = aDataset.mLength;

    if (mType == kActive)
    {
        RemoveTlv(Tlv::kPendingTimestamp);
        RemoveTlv(Tlv::kDelayTimer);
    }

    mUpdateTime = aDataset.GetUpdateTime();
}

void Dataset::SetFrom(const otOperationalDatasetTlvs &aDataset)
{
    mLength = aDataset.mLength;
    memcpy(mTlvs, aDataset.mTlvs, mLength);
}

otError Dataset::SetFrom(const Info &aDatasetInfo)
{
    otError error = OT_ERROR_NONE;

    if (aDatasetInfo.IsActiveTimestampPresent())
    {
        ActiveTimestampTlv tlv;
        tlv.Init();
        tlv.SetSeconds(aDatasetInfo.GetActiveTimestamp());
        tlv.SetTicks(0);
        IgnoreError(SetTlv(tlv));
    }

    if (aDatasetInfo.IsPendingTimestampPresent())
    {
        PendingTimestampTlv tlv;
        tlv.Init();
        tlv.SetSeconds(aDatasetInfo.GetPendingTimestamp());
        tlv.SetTicks(0);
        IgnoreError(SetTlv(tlv));
    }

    if (aDatasetInfo.IsDelayPresent())
    {
        IgnoreError(SetTlv(Tlv::kDelayTimer, aDatasetInfo.GetDelay()));
    }

    if (aDatasetInfo.IsChannelPresent())
    {
        ChannelTlv tlv;
        tlv.Init();
        tlv.SetChannel(aDatasetInfo.GetChannel());
        IgnoreError(SetTlv(tlv));
    }

    if (aDatasetInfo.IsChannelMaskPresent())
    {
        ChannelMaskTlv tlv;
        tlv.Init();
        tlv.SetChannelMask(aDatasetInfo.GetChannelMask());
        IgnoreError(SetTlv(tlv));
    }

    if (aDatasetInfo.IsExtendedPanIdPresent())
    {
        IgnoreError(SetTlv(Tlv::kExtendedPanId, aDatasetInfo.GetExtendedPanId()));
    }

    if (aDatasetInfo.IsMeshLocalPrefixPresent())
    {
        IgnoreError(SetTlv(Tlv::kMeshLocalPrefix, aDatasetInfo.GetMeshLocalPrefix()));
    }

    if (aDatasetInfo.IsMasterKeyPresent())
    {
        IgnoreError(SetTlv(Tlv::kNetworkMasterKey, aDatasetInfo.GetMasterKey()));
    }

    if (aDatasetInfo.IsNetworkNamePresent())
    {
        Mac::NameData nameData = aDatasetInfo.GetNetworkName().GetAsData();

        IgnoreError(SetTlv(Tlv::kNetworkName, nameData.GetBuffer(), nameData.GetLength()));
    }

    if (aDatasetInfo.IsPanIdPresent())
    {
        IgnoreError(SetTlv(Tlv::kPanId, aDatasetInfo.GetPanId()));
    }

    if (aDatasetInfo.IsPskcPresent())
    {
        IgnoreError(SetTlv(Tlv::kPskc, aDatasetInfo.GetPskc()));
    }

    if (aDatasetInfo.IsSecurityPolicyPresent())
    {
        SecurityPolicyTlv tlv;
        tlv.Init();
        tlv.SetRotationTime(aDatasetInfo.GetSecurityPolicy().mRotationTime);
        tlv.SetFlags(aDatasetInfo.GetSecurityPolicy().mFlags);
        IgnoreError(SetTlv(tlv));
    }

    mUpdateTime = TimerMilli::GetNow();

    return error;
}

const Timestamp *Dataset::GetTimestamp(void) const
{
    const Timestamp *timestamp = nullptr;

    if (mType == kActive)
    {
        const ActiveTimestampTlv *tlv = GetTlv<ActiveTimestampTlv>();
        VerifyOrExit(tlv != nullptr);
        timestamp = static_cast<const Timestamp *>(tlv);
    }
    else
    {
        const PendingTimestampTlv *tlv = GetTlv<PendingTimestampTlv>();
        VerifyOrExit(tlv != nullptr);
        timestamp = static_cast<const Timestamp *>(tlv);
    }

exit:
    return timestamp;
}

void Dataset::SetTimestamp(const Timestamp &aTimestamp)
{
    IgnoreError(SetTlv((mType == kActive) ? Tlv::kActiveTimestamp : Tlv::kPendingTimestamp, aTimestamp));
}

otError Dataset::SetTlv(Tlv::Type aType, const void *aValue, uint8_t aLength)
{
    otError  error          = OT_ERROR_NONE;
    uint16_t bytesAvailable = sizeof(mTlvs) - mLength;
    Tlv *    old            = GetTlv(aType);
    Tlv      tlv;

    if (old != nullptr)
    {
        bytesAvailable += sizeof(Tlv) + old->GetLength();
    }

    VerifyOrExit(sizeof(Tlv) + aLength <= bytesAvailable, error = OT_ERROR_NO_BUFS);

    if (old != nullptr)
    {
        RemoveTlv(old);
    }

    tlv.SetType(aType);
    tlv.SetLength(aLength);
    memcpy(mTlvs + mLength, &tlv, sizeof(Tlv));
    mLength += sizeof(Tlv);

    memcpy(mTlvs + mLength, aValue, aLength);
    mLength += aLength;

    mUpdateTime = TimerMilli::GetNow();

exit:
    return error;
}

otError Dataset::SetTlv(const Tlv &aTlv)
{
    return SetTlv(aTlv.GetType(), aTlv.GetValue(), aTlv.GetLength());
}

otError Dataset::Set(const Message &aMessage, uint16_t aOffset, uint8_t aLength)
{
    otError error = OT_ERROR_INVALID_ARGS;

    SuccessOrExit(aMessage.Read(aOffset, mTlvs, aLength));
    mLength = aLength;

    mUpdateTime = TimerMilli::GetNow();
    error       = OT_ERROR_NONE;

exit:
    return error;
}

void Dataset::RemoveTlv(Tlv::Type aType)
{
    Tlv *tlv;

    VerifyOrExit((tlv = GetTlv(aType)) != nullptr);
    RemoveTlv(tlv);

exit:
    return;
}

otError Dataset::AppendMleDatasetTlv(Message &aMessage) const
{
    otError        error = OT_ERROR_NONE;
    Mle::Tlv       tlv;
    Mle::Tlv::Type type;

    VerifyOrExit(mLength > 0);

    type = (mType == kActive ? Mle::Tlv::kActiveDataset : Mle::Tlv::kPendingDataset);

    tlv.SetType(type);
    tlv.SetLength(static_cast<uint8_t>(mLength) - sizeof(Tlv) - sizeof(Timestamp));
    SuccessOrExit(error = aMessage.Append(tlv));

    for (const Tlv *cur = GetTlvsStart(); cur < GetTlvsEnd(); cur = cur->GetNext())
    {
        if (((mType == kActive) && (cur->GetType() == Tlv::kActiveTimestamp)) ||
            ((mType == kPending) && (cur->GetType() == Tlv::kPendingTimestamp)))
        {
            ; // skip Active or Pending Timestamp TLV
        }
        else if (cur->GetType() == Tlv::kDelayTimer)
        {
            uint32_t      elapsed = TimerMilli::GetNow() - mUpdateTime;
            DelayTimerTlv delayTimer(static_cast<const DelayTimerTlv &>(*cur));

            if (delayTimer.GetDelayTimer() > elapsed)
            {
                delayTimer.SetDelayTimer(delayTimer.GetDelayTimer() - elapsed);
            }
            else
            {
                delayTimer.SetDelayTimer(0);
            }

            SuccessOrExit(error = delayTimer.AppendTo(aMessage));
        }
        else
        {
            SuccessOrExit(error = cur->AppendTo(aMessage));
        }
    }

exit:
    return error;
}

void Dataset::RemoveTlv(Tlv *aTlv)
{
    uint8_t *start  = reinterpret_cast<uint8_t *>(aTlv);
    uint16_t length = sizeof(Tlv) + aTlv->GetLength();

    memmove(start, start + length, mLength - (static_cast<uint8_t>(start - mTlvs) + length));
    mLength -= length;
}

otError Dataset::ApplyConfiguration(Instance &aInstance, bool *aIsMasterKeyUpdated) const
{
    Mac::Mac &  mac        = aInstance.Get<Mac::Mac>();
    KeyManager &keyManager = aInstance.Get<KeyManager>();
    otError     error      = OT_ERROR_NONE;

    VerifyOrExit(IsValid(), error = OT_ERROR_PARSE);

    if (aIsMasterKeyUpdated)
    {
        *aIsMasterKeyUpdated = false;
    }

    for (const Tlv *cur = GetTlvsStart(); cur < GetTlvsEnd(); cur = cur->GetNext())
    {
        switch (cur->GetType())
        {
        case Tlv::kChannel:
        {
            uint8_t channel = static_cast<uint8_t>(static_cast<const ChannelTlv *>(cur)->GetChannel());

            error = mac.SetPanChannel(channel);

            if (error != OT_ERROR_NONE)
            {
                otLogWarnMeshCoP("DatasetManager::ApplyConfiguration() Failed to set channel to %d (%s)", channel,
                                 otThreadErrorToString(error));
                ExitNow();
            }

            break;
        }

        case Tlv::kPanId:
            mac.SetPanId(static_cast<const PanIdTlv *>(cur)->GetPanId());
            break;

        case Tlv::kExtendedPanId:
            mac.SetExtendedPanId(static_cast<const ExtendedPanIdTlv *>(cur)->GetExtendedPanId());
            break;

        case Tlv::kNetworkName:
            IgnoreError(mac.SetNetworkName(static_cast<const NetworkNameTlv *>(cur)->GetNetworkName()));
            break;

        case Tlv::kNetworkMasterKey:
        {
            const NetworkMasterKeyTlv *key = static_cast<const NetworkMasterKeyTlv *>(cur);

            if (aIsMasterKeyUpdated && (key->GetNetworkMasterKey() != keyManager.GetMasterKey()))
            {
                *aIsMasterKeyUpdated = true;
            }

            IgnoreError(keyManager.SetMasterKey(key->GetNetworkMasterKey()));
            break;
        }

#if OPENTHREAD_FTD

        case Tlv::kPskc:
            keyManager.SetPskc(static_cast<const PskcTlv *>(cur)->GetPskc());
            break;

#endif

        case Tlv::kMeshLocalPrefix:
            aInstance.Get<Mle::MleRouter>().SetMeshLocalPrefix(
                static_cast<const MeshLocalPrefixTlv *>(cur)->GetMeshLocalPrefix());
            break;

        case Tlv::kSecurityPolicy:
        {
            const SecurityPolicyTlv *securityPolicy = static_cast<const SecurityPolicyTlv *>(cur);
            IgnoreError(keyManager.SetKeyRotation(securityPolicy->GetRotationTime()));
            keyManager.SetSecurityPolicyFlags(securityPolicy->GetFlags());
            break;
        }

        default:
            break;
        }
    }

exit:
    return error;
}

void Dataset::ConvertToActive(void)
{
    RemoveTlv(Tlv::kPendingTimestamp);
    RemoveTlv(Tlv::kDelayTimer);
    mType = kActive;
}

const char *Dataset::TypeToString(Type aType)
{
    return (aType == kActive) ? "Active" : "Pending";
}

} // namespace MeshCoP
} // namespace ot
