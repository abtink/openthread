/*
 *  Copyright (c) 2016-21, The OpenThread Authors.
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
 *   This file implements methods for generating and processing Thread Network Data TLVs.
 */

#include "network_data_tlvs.hpp"

namespace ot {
namespace NetworkData {

//---------------------------------------------------------------------------------------------------------------------
// NetworkDataTlv

const NetworkDataTlv *NetworkDataTlv::Find(const NetworkDataTlv *aStart, const NetworkDataTlv *aEnd, Type aType)
{
    const NetworkDataTlv *tlv;

    for (tlv = aStart; (tlv + 1 <= aEnd) && (tlv->GetNext() <= aEnd); tlv = tlv->GetNext())
    {
        if (tlv->GetType() == aType)
        {
            ExitNow();
        }
    }

    tlv = nullptr;

exit:
    return tlv;
}

const NetworkDataTlv *NetworkDataTlv::Find(const NetworkDataTlv *aStart,
                                           const NetworkDataTlv *aEnd,
                                           Type                  aType,
                                           bool                  aStable)
{
    const NetworkDataTlv *tlv;

    for (tlv = aStart; (tlv + 1 <= aEnd) && (tlv->GetNext() <= aEnd); tlv = tlv->GetNext())
    {
        if ((tlv->GetType() == aType) && (tlv->IsStable() == aStable))
        {
            ExitNow();
        }
    }

    tlv = nullptr;

exit:
    return tlv;
}

//---------------------------------------------------------------------------------------------------------------------
// PrefixTlv

const NetworkDataTlv *PrefixTlv::FindSubTlv(Type aType) const { return Find(GetSubTlvs(), GetNext(), aType); }

const NetworkDataTlv *PrefixTlv::FindSubTlv(Type aType, bool aStable) const
{
    return Find(GetSubTlvs(), GetNext(), aType, aStable);
}

//---------------------------------------------------------------------------------------------------------------------
// ServiceTlv

void ServiceTlv::Init(uint8_t aServiceId, uint32_t aEnterpriseNumber, const ServiceData &aServiceData)
{
    NetworkDataTlv::Init();
    SetType(kTypeService);

    mFlagsServiceId = (aEnterpriseNumber == kThreadEnterpriseNumber) ? kThreadEnterpriseFlag : 0;
    mFlagsServiceId |= (aServiceId & kServiceIdMask);

    if (aEnterpriseNumber != kThreadEnterpriseNumber)
    {
        mShared.mEnterpriseNumber = HostSwap32(aEnterpriseNumber);
        mServiceDataLength        = aServiceData.GetLength();
        aServiceData.CopyBytesTo(&mServiceDataLength + sizeof(uint8_t));
    }
    else
    {
        mShared.mServiceDataLengthThreadEnterprise = aServiceData.GetLength();
        aServiceData.CopyBytesTo(&mShared.mServiceDataLengthThreadEnterprise + sizeof(uint8_t));
    }

    SetLength(GetFieldsLength());
}

//---------------------------------------------------------------------------------------------------------------------
// CommissioningDataTlv

const MeshCoP::Tlv *CommissioningDataTlv::FindSubTlv(MeshCoP::Tlv::Type aType) const
{
    return MeshCoP::Tlv::FindTlv(GetValue(), GetLength(), aType);
}

Error CommissioningDataTlv::ParseDataset(MeshCoP::CommissioningDataset &aDataset) const
{
    Error               error = kErrorNone;
    const MeshCoP::Tlv *cur   = reinterpret_cast<const MeshCoP::Tlv *>(GetValue());
    const MeshCoP::Tlv *end   = reinterpret_cast<const MeshCoP::Tlv *>(GetValue() + GetLength());

    aDataset.Clear();

    for (; cur < end; cur = cur->GetNext())
    {
        VerifyOrExit(((cur + 1) <= end) && !cur->IsExtended() && (cur->GetNext() <= end), error = kErrorParse);

        switch (cur->GetType())
        {
        case MeshCoP::Tlv::kCommissionerSessionId:
        {
            const MeshCoP::CommissionerSessionIdTlv *sessionIdTlv = As<const MeshCoP::CommissionerSessionIdTlv>(cur);

            VerifyOrExit(sessionIdTlv->IsValid(), error = kErrorParse);
            aDataset.SetSessionId(sessionIdTlv->GetCommissionerSessionId());
            break;
        }

        case MeshCoP::Tlv::kBorderAgentLocator:
        {
            const MeshCoP::BorderAgentLocatorTlv *locatorTlv = As<const MeshCoP::BorderAgentLocatorTlv>(cur);

            VerifyOrExit(locatorTlv->IsValid(), error = kErrorParse);
            aDataset.SetLocator(locatorTlv->GetBorderAgentLocator());
            break;
        }

        case MeshCoP::Tlv::kJoinerUdpPort:
        {
            const MeshCoP::JoinerUdpPortTlv *joinerUdpTlv = As<const MeshCoP::JoinerUdpPortTlv>(cur);

            VerifyOrExit(joinerUdpTlv->IsValid(), error = kErrorParse);
            aDataset.SetJoinerUdpPort(joinerUdpTlv->GetUdpPort());
            break;
        }

        case MeshCoP::Tlv::kSteeringData:
        {
            const MeshCoP::SteeringDataTlv *steeringDataTlv = As<const MeshCoP::SteeringDataTlv>(cur);

            VerifyOrExit(steeringDataTlv->IsValid(), error = kErrorParse);
            steeringDataTlv->CopyTo(aDataset.UpdateSteeringData());
            break;
        }

        default:
            break;
        }
    }

exit:
    return error;
}

//---------------------------------------------------------------------------------------------------------------------
// TlvIterator

const NetworkDataTlv *TlvIterator::Iterate(NetworkDataTlv::Type aType)
{
    const NetworkDataTlv *tlv = NetworkDataTlv::Find(mStart, mEnd, aType);

    VerifyOrExit(tlv != nullptr);
    mStart = tlv->GetNext();

exit:
    return tlv;
}

const NetworkDataTlv *TlvIterator::Iterate(NetworkDataTlv::Type aType, bool aStable)
{
    const NetworkDataTlv *tlv = NetworkDataTlv::Find(mStart, mEnd, aType, aStable);

    VerifyOrExit(tlv != nullptr);
    mStart = tlv->GetNext();

exit:
    return tlv;
}

} // namespace NetworkData
} // namespace ot
