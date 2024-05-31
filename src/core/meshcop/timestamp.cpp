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
 *   This file implements common MeshCoP timestamp processing.
 */

#include "timestamp.hpp"

#include "common/code_utils.hpp"
#include "common/num_utils.hpp"

namespace ot {
namespace MeshCoP {

void Timestamp::InitFrom(const otTimestamp &aTimestamp)
{
    mSeconds       = aTimestamp.mSeconds;
    mTicks         = Min(aTimestamp.mTicks, kMaxTicks);
    mAuthoritative = aTimestamp.mAuthoritative;
    mIsSet         = true;
}

void Timestamp::InitForOrphanAnnounce(void)
{
    Clear();
    mAuthoritative = true;
    mIsSet         = true;
}

void Timestamp::ConvertTo(otTimestamp &aTimestamp) const
{
    ClearAllBytes(aTimestamp);
    VerifyOrExit(mIsSet);

    aTimestamp.mSeconds       = mSeconds;
    aTimestamp.mTicks         = mTicks;
    aTimestamp.mAuthoritative = mAuthoritative;

exit:
    return;
}

void Timestamp::AdvanceRandomTicks(void)
{
    if (!mIsSet)
    {
        Clear();
        mIsSet   = true;
        mSeconds = 1;
    }

    mTicks += Random::NonCrypto::GetUint32InRange(1, kMaxRandomTicks);

    if (mTicks > kMaxTicks)
    {
        mSeconds++;
        mTicks -= (kMaxTicks + 1);
    }
}

int Timestamp::Compare(const Timestamp &aFirst, const Timestamp &aSecond)
{
    int rval;

    rval = ThreeWayCompare(aFirst.mIsSet, aSecond.mIsSet);
    VerifyOrExit(rval == 0);

    rval = ThreeWayCompare(aFirst.mSeconds, aSecond.mSeconds);
    VerifyOrExit(rval == 0);

    rval = ThreeWayCompare(aFirst.mTicks, aSecond.mTicks);
    VerifyOrExit(rval == 0);

    rval = ThreeWayCompare(aFirst.mAuthoritative, aSecond.mAuthoritative);

exit:
    return rval;
}

//----------------------------------------------------------------------------------------------------------------------

void TimestampTlvValue::InitFrom(const Timestamp &aTimestamp)
{
    uint16_t ticksAndFlags;

    mSeconds16 = BigEndian::HostSwap16(static_cast<uint16_t>(aTimestamp.mSeconds >> 32));
    mSeconds32 = BigEndian::HostSwap32(static_cast<uint32_t>(aTimestamp.mSeconds & 0xffffffff));

    ticksAndFlags = ((aTimestamp.mTicks << kTicksOffset) & kTicksMask);

    if (aTimestamp.mAuthoritative)
    {
        ticksAndFlags |= kAuthoritativeBit;
    }

    mTicksAndFlags = BigEndian::HostSwap16(ticksAndFlags);
}

void TimestampTlvValue::ConvertTo(Timestamp &aTimestamp) const
{
    aTimestamp.Clear();
    aTimestamp.mSeconds = (static_cast<uint64_t>(BigEndian::HostSwap16(mSeconds16)) << 32);
    aTimestamp.mSeconds += BigEndian::HostSwap32(mSeconds32);

    aTimestamp.mTicks         = (BigEndian::HostSwap16(mTicksAndFlags) >> kTicksOffset);
    aTimestamp.mAuthoritative = (BigEndian::HostSwap16(mTicksAndFlags) & kAuthoritativeBit);
    aTimestamp.mIsSet         = true;
}

} // namespace MeshCoP
} // namespace ot
