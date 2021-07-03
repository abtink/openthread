/*
 *  Copyright (c) 2021, The OpenThread Authors.
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
 *   This file implements the Statistics Collector module.
 */

#include "stat_collector.hpp"

#if OPENTHREAD_CONFIG_STAT_COLLECTOR_ENABLE

#include "common/code_utils.hpp"
#include "common/instance.hpp"
#include "common/locator_getters.hpp"
#include "common/timer.hpp"

namespace ot {
namespace Utils {

//---------------------------------------------------------------------------------------------------------------------
// StatCollector::HistoryListBase

StatCollector::HistoryListBase::HistoryListBase(void)
    : mStartIndex(0)
    , mSize(0)
{
}

void StatCollector::HistoryListBase::Clear(void)
{
    mStartIndex = 0;
    mSize       = 0;
}

uint16_t StatCollector::HistoryListBase::Add(uint16_t aMaxSize, Timestamp aTimestamps[])
{
    // Add a new entry and return its list index. Overwrites the
    // oldest entry if list is full.
    //
    // Entries are saved in the order they are added such that
    // `mStartIndex` is the newest entry and the entries after up
    // to `mSize` are the previously added entries.

    mStartIndex = (mStartIndex == 0) ? aMaxSize - 1 : mStartIndex - 1;
    mSize += (mSize == aMaxSize) ? 0 : 1;

    aTimestamps[mStartIndex] = TimerMilli::GetNow();

    return mStartIndex;
}

Error StatCollector::HistoryListBase::Iterate(uint16_t        aMaxSize,
                                              const Timestamp aTimestamps[],
                                              Iterator &      aIterator,
                                              uint16_t &      aListIndex,
                                              uint32_t &      aEntryAge) const
{
    Error    error = kErrorNone;
    uint32_t index;

    VerifyOrExit(aIterator.GetEntryNumber() < mSize, error = kErrorNotFound);

    // Maps the entry number to a the list index. Entry number value
    // of zero corresponds to the newest (the most recently added)
    // entry and value one to next one and so on.

    index = static_cast<uint32_t>(aIterator.GetEntryNumber()) + mStartIndex;

    if (index >= aMaxSize)
    {
        index -= aMaxSize;
    }

    aListIndex = static_cast<uint16_t>(index);
    aEntryAge  = aIterator.GetInitTime() - aTimestamps[aListIndex];

    aIterator.IncrementEntryNumber();

exit:
    return error;
}

void StatCollector::HistoryListBase::RemoveAgedEntries(const Timestamp aTimestamps[])
{
    TimeMilli now = TimerMilli::GetNow();

    while ((mSize > 0) && (now - aTimestamps[mSize - 1] >= kMaxAge))
    {
        mSize--;
    }
}

//---------------------------------------------------------------------------------------------------------------------
// StatCollector

StatCollector::StatCollector(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mTimer(aInstance, HandleTimer)
{
    mTimer.Start(kOneDayInMsec);
}

Error StatCollector::IterateRoleHisoryList(Iterator &aIterator, Mle::DeviceRole &aRole, uint32_t &aEntryAge) const
{
    Error                  error = kErrorNone;
    const Mle::DeviceRole *role  = mRoleHistory.Iterate(aIterator, aEntryAge);

    VerifyOrExit(role != nullptr, error = kErrorNotFound);
    aRole = *role;

exit:
    return error;
}

void StatCollector::HandleNotifierEvents(Events aEvents)
{
    if (aEvents.Contains(kEventThreadRoleChanged))
    {
        mRoleHistory.AddNewEntry(Get<Mle::Mle>().GetRole());
    }
}

void StatCollector::HandleTimer(Timer &aTimer)
{
    aTimer.Get<StatCollector>().HandleTimer();
}

void StatCollector::HandleTimer(void)
{
    mRoleHistory.RemoveAgedEntries();

    mTimer.Start(kOneDayInMsec);
}

} // namespace Utils
} // namespace ot

#endif // #if OPENTHREAD_CONFIG_STAT_COLLECTOR_ENABLE
