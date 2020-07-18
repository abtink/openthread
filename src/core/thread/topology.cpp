/*
 *  Copyright (c) 2016-2017, The OpenThread Authors.
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
 *   This file includes definitions for maintaining Thread network topologies.
 */

#include "topology.hpp"

#include "common/code_utils.hpp"
#include "common/debug.hpp"
#include "common/instance.hpp"
#include "common/locator-getters.hpp"
#include "common/logging.hpp"

namespace ot {

void Neighbor::Init(Instance &aInstance)
{
    InstanceLocatorInit::Init(aInstance);
    mLinkInfo.Init(aInstance);
    SetState(kStateInvalid);
}

bool Neighbor::IsStateValidOrAttaching(void) const
{
    bool rval = false;

    switch (GetState())
    {
    case kStateInvalid:
    case kStateParentRequest:
    case kStateParentResponse:
        break;

    case kStateRestored:
    case kStateChildIdRequest:
    case kStateLinkRequest:
    case kStateChildUpdateRequest:
    case kStateValid:
        rval = true;
        break;
    }

    return rval;
}

bool Neighbor::MatchesFilter(StateFilter aFilter) const
{
    bool matches = false;

    switch (aFilter)
    {
    case kInStateValid:
        matches = IsStateValid();
        break;

    case kInStateValidOrRestoring:
        matches = IsStateValidOrRestoring();
        break;

    case kInStateChildIdRequest:
        matches = IsStateChildIdRequest();
        break;

    case kInStateValidOrAttaching:
        matches = IsStateValidOrAttaching();
        break;

    case kInStateAnyExceptInvalid:
        matches = !IsStateInvalid();
        break;

    case kInStateAnyExceptValidOrRestoring:
        matches = !IsStateValidOrRestoring();
        break;
    }

    return matches;
}

void Neighbor::GenerateChallenge(void)
{
    IgnoreError(
        Random::Crypto::FillBuffer(mValidPending.mPending.mChallenge, sizeof(mValidPending.mPending.mChallenge)));
}

Child::AddressIterator::AddressIterator(const Child &aChild, otChildIp6AddressIterator aIterIndex)
    : mChild(aChild)
{
    // `aIterIndex` value of zero indicates start or mesh-local IPv6
    // address Non-zero value specifies the index into address array
    // starting from one for first element (i.e, `aIterIndex - 1` gives
    // the array index).

    if (aIterIndex == OT_CHILD_IP6_ADDRESS_ITERATOR_INIT)
    {
        Update(kInit);
    }
    else
    {
        mAddress = &mChild.mIp6Address[aIterIndex - 1];
        Update(kCheck);
    }
}

otChildIp6AddressIterator Child::AddressIterator::ConvertToChildIp6AddressIterator(void) const
{
    otChildIp6AddressIterator iterIndex;

    if (IsMeshLocalAddress())
    {
        iterIndex = 0;
    }
    else
    {
        if (mAddress != nullptr)
        {
            iterIndex = static_cast<uint16_t>(mAddress - mChild.mIp6Address) + 1;
        }
        else
        {
            iterIndex = kNumIp6Addresses + 1;
        }
    }

    return iterIndex;
}

void Child::AddressIterator::Update(Action aAction)
{
    switch (aAction)
    {
    case kInit:
        mAddress = &mMeshLocalAddress;

        if (mChild.GetMeshLocalIp6Address(mMeshLocalAddress) == OT_ERROR_NONE)
        {
            break;
        }

        // Fall through

    case kAdvance:
        if (IsMeshLocalAddress())
        {
            mAddress = &mChild.mIp6Address[0];
        }
        else
        {
            mAddress++;
        }

        // Fall through

    case kCheck:
        if ((mAddress >= OT_ARRAY_END(mChild.mIp6Address)) || mAddress->IsUnspecified())
        {
            mAddress = nullptr;
        }

        break;
    }
}

void Child::Clear(void)
{
    Instance &instance = GetInstance();

    memset(reinterpret_cast<void *>(this), 0, sizeof(Child));
    Init(instance);
}

void Child::ClearIp6Addresses(void)
{
    mMeshLocalIid.Clear();
    memset(mIp6Address, 0, sizeof(mIp6Address));
}

otError Child::GetMeshLocalIp6Address(Ip6::Address &aAddress) const
{
    otError error = OT_ERROR_NONE;

    VerifyOrExit(!mMeshLocalIid.IsUnspecified(), error = OT_ERROR_NOT_FOUND);

    aAddress.SetPrefix(Get<Mle::MleRouter>().GetMeshLocalPrefix());
    aAddress.SetIid(mMeshLocalIid);

exit:
    return error;
}

otError Child::AddIp6Address(const Ip6::Address &aAddress)
{
    otError error = OT_ERROR_NONE;

    VerifyOrExit(!aAddress.IsUnspecified(), error = OT_ERROR_INVALID_ARGS);

    if (Get<Mle::MleRouter>().IsMeshLocalAddress(aAddress))
    {
        VerifyOrExit(mMeshLocalIid.IsUnspecified(), error = OT_ERROR_ALREADY);
        mMeshLocalIid = aAddress.GetIid();
        ExitNow();
    }

    for (uint16_t index = 0; index < kNumIp6Addresses; index++)
    {
        if (mIp6Address[index].IsUnspecified())
        {
            mIp6Address[index] = aAddress;
            ExitNow();
        }

        VerifyOrExit(mIp6Address[index] != aAddress, error = OT_ERROR_ALREADY);
    }

    error = OT_ERROR_NO_BUFS;

exit:
    return error;
}

otError Child::RemoveIp6Address(const Ip6::Address &aAddress)
{
    otError  error = OT_ERROR_NOT_FOUND;
    uint16_t index;

    VerifyOrExit(!aAddress.IsUnspecified(), error = OT_ERROR_INVALID_ARGS);

    if (Get<Mle::MleRouter>().IsMeshLocalAddress(aAddress))
    {
        if (aAddress.GetIid() == mMeshLocalIid)
        {
            mMeshLocalIid.Clear();
            error = OT_ERROR_NONE;
        }

        ExitNow();
    }

    for (index = 0; index < kNumIp6Addresses; index++)
    {
        VerifyOrExit(!mIp6Address[index].IsUnspecified(), OT_NOOP);

        if (mIp6Address[index] == aAddress)
        {
            error = OT_ERROR_NONE;
            break;
        }
    }

    SuccessOrExit(error);

    for (; index < kNumIp6Addresses - 1; index++)
    {
        mIp6Address[index] = mIp6Address[index + 1];
    }

    mIp6Address[kNumIp6Addresses - 1].Clear();

exit:
    return error;
}

bool Child::HasIp6Address(const Ip6::Address &aAddress) const
{
    bool retval = false;

    VerifyOrExit(!aAddress.IsUnspecified(), OT_NOOP);

    if (Get<Mle::MleRouter>().IsMeshLocalAddress(aAddress))
    {
        retval = (aAddress.GetIid() == mMeshLocalIid);
        ExitNow();
    }

    for (uint16_t index = 0; index < kNumIp6Addresses; index++)
    {
        VerifyOrExit(!mIp6Address[index].IsUnspecified(), OT_NOOP);

        if (mIp6Address[index] == aAddress)
        {
            ExitNow(retval = true);
        }
    }

exit:
    return retval;
}

void Child::GenerateChallenge(void)
{
    IgnoreError(Random::Crypto::FillBuffer(mAttachChallenge, sizeof(mAttachChallenge)));
}

void Router::Clear(void)
{
    Instance &instance = GetInstance();

    memset(reinterpret_cast<void *>(this), 0, sizeof(Router));
    Init(instance);
}

} // namespace ot
