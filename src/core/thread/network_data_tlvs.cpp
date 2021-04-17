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
 *   This file implements functionality for generating and processing of Thread Network Data TLVs.
 */

#include "network_data_tlvs.hpp"

namespace ot {
namespace NetworkData {

bool NetworkDataTlv::IsContainedBy(const void *aEnd) const
{
    return ((this + 1) <= reinterpret_cast<const NetworkDataTlv *>(aEnd)) &&
           (GetNext() <= reinterpret_cast<const NetworkDataTlv *>(aEnd));
}


    void HasRouteTlv::Init(void)
    {
        NetworkDataTlv::Init();
        SetType(kTypeHasRoute);
        SetLength(0);
    }


    void PrefixTlv::Init(uint8_t aDomainId, uint8_t aPrefixLength, const uint8_t *aPrefix)
    {
        NetworkDataTlv::Init();
        SetType(kTypePrefix);
        mDomainId     = aDomainId;
        mPrefixLength = aPrefixLength;
        memcpy(GetPrefix(), aPrefix, Ip6::Prefix::SizeForLength(aPrefixLength));
        SetSubTlvsLength(0);
    }

bool PrefixTlv::IsValid(void) const
{
    return ((GetLength() >= sizeof(*this) - sizeof(NetworkDataTlv)) &&
            (GetLength() >= Ip6::Prefix::SizeForLength(mPrefixLength) + sizeof(*this) - sizeof(NetworkDataTlv)) &&
            (Ip6::Prefix::SizeForLength(mPrefixLength) <= sizeof(Ip6::Address)));
}

bool PrefixTlv::IsEqual(const uint8_t *aPrefix, uint8_t aPrefixLength) const
{
    return (aPrefixLength == mPrefixLength) &&
           (Ip6::Prefix::MatchLength(GetPrefix(), aPrefix, Ip6::Prefix::SizeForLength(aPrefixLength)) >=
            mPrefixLength);
}

    void BorderRouterTlv::Init(void)
    {
        NetworkDataTlv::Init();
        SetType(kTypeBorderRouter);
        SetLength(0);
    }


    void ContextTlv::Init(uint8_t aContextId, uint8_t aConextLength)
    {
        NetworkDataTlv::Init();
        SetType(kTypeContext);
        SetLength(sizeof(ContextTlv) - sizeof(NetworkDataTlv));
        mFlags         = ((aContextId << kContextIdOffset) & kContextIdMask);
        mContextLength = aConextLength;
    }

 void ServiceTlv::Init(uint8_t aServiceId, uint32_t aEnterpriseNumber, const uint8_t *aServiceData, uint8_t aServiceDataLength)
{
    NetworkDataTlv::Init();
    SetType(kTypeService);

    mFlagsServiceId = (aEnterpriseNumber == kThreadEnterpriseNumber) ? kThreadEnterpriseFlag : 0;
    mFlagsServiceId |= (aServiceId & kServiceIdMask);

    if (aEnterpriseNumber != kThreadEnterpriseNumber)
    {
        mShared.mEnterpriseNumber = HostSwap32(aEnterpriseNumber);
        mServiceDataLength        = aServiceDataLength;
        memcpy(&mServiceDataLength + sizeof(uint8_t), aServiceData, aServiceDataLength);
    }
    else
    {
        mShared.mServiceDataLengthThreadEnterprise = aServiceDataLength;
        memcpy(&mShared.mServiceDataLengthThreadEnterprise + sizeof(uint8_t), aServiceData, aServiceDataLength);
    }

    SetLength(GetFieldsLength());
}

bool ServiceTlv::IsValid(void) const
{
    uint8_t length = GetLength();

    return (length >= sizeof(mFlagsServiceId)) &&
           (length >= kMinLength + (IsThreadEnterprise() ? 0 : sizeof(uint32_t))) &&
           (static_cast<uint16_t>(length) + sizeof(NetworkDataTlv) >=
            CalculateSize(GetEnterpriseNumber(), GetServiceDataLength()));
}

    void ServerTlv::Init(uint16_t aServer16, const uint8_t *aServerData, uint8_t aServerDataLength)
    {
        NetworkDataTlv::Init();
        SetType(kTypeServer);
        SetServer16(aServer16);
        memcpy(reinterpret_cast<uint8_t *>(this) + sizeof(*this), aServerData, aServerDataLength);
        SetLength(sizeof(*this) - sizeof(NetworkDataTlv) + aServerDataLength);
    }


bool ServerTlv::operator==(const ServerTlv &aOther) const
{
    return (GetLength() == aOther.GetLength()) && (memcmp(GetValue(), aOther.GetValue(), GetLength()) == 0);
}


} // namespace NetworkData
} // namespace ot

