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
 *   This file includes definitions to support Statistics Collector module.
 */

#ifndef STAT_COLLECTOR_HPP_
#define STAT_COLLECTOR_HPP_

#include "openthread-core-config.h"

#if OPENTHREAD_CONFIG_STAT_COLLECTOR_ENABLE

#include "common/locator.hpp"
#include "common/non_copyable.hpp"
#include "common/notifier.hpp"
#include "common/timer.hpp"
#include "thread/mle_types.hpp"

struct otStatCollectorHistoryIterator
{
    uint32_t mData32;
    uint16_t mData16;
};

namespace ot {
namespace Utils {

/**
 * This class implements Statistics Collector.
 *
 */
class StatCollector : public InstanceLocator, private NonCopyable
{
    friend class ot::Notifier;

public:
    class Iterator : public otStatCollectorHistoryIterator
    {
        friend class StatCollector;

    public:
        void Init(void) { ResetEntryNumber(), SetInitTime(); }

    private:
        uint16_t  GetEntryNumber(void) const { return mData16; }
        void      ResetEntryNumber(void) { mData16 = 0; }
        void      IncrementEntryNumber(void) { mData16++; }
        TimeMilli GetInitTime(void) const { return TimeMilli(mData32); }
        void      SetInitTime(void) { mData32 = TimerMilli::GetNow().GetValue(); }
    };

    /**
     * This constructor initializes the `StatCollector`.
     *
     * @param[in]  aInstance     A reference to the OpenThread instance.
     *
     */
    explicit StatCollector(Instance &aInstance);

    Error IterateRoleHisoryList(Iterator &aIterator, Mle::DeviceRole &aRole, uint32_t &aEntryAge) const;

private:
    typedef TimeMilli Timestamp;

    static constexpr uint32_t kOneDayInMsec = 24 * 60 * 60 * 1000u; // 24 hours in msec.
    static constexpr uint32_t kMaxAge       = 48 * kOneDayInMsec;   // 48 days in msec.

    static constexpr uint16_t kRoleHistoryListSize = 32;

    class HistoryListBase : private NonCopyable // An ordered list of timestamped entries
    {
    public:
        void     Clear(void);
        uint16_t GetSize(void) const { return mSize; }

    protected:
        HistoryListBase(void);
        uint16_t Add(uint16_t aMaxSize, Timestamp aTimestamps[]);
        void     RemoveAgedEntries(const Timestamp aTimestamps[]);

        Error Iterate(uint16_t        aMaxSize,
                      const Timestamp aTimestamps[],
                      Iterator &      aIterator,
                      uint16_t &      aListIndex,
                      uint32_t &      aEntryAge) const;

    private:
        uint16_t mStartIndex;
        uint16_t mSize;
    };

    // A list with given max size of timestamped `Entry`
    template <typename Entry, uint16_t kMaxSize> class HistoryList : public HistoryListBase
    {
    public:
        HistoryList(void) {}

        // Adds a new entry to the list or overwrites the oldest entry
        // if list is full. First version returns a reference to the
        // new `Entry` (for caller to populate). Second version copies
        // the given `aEntry`.
        Entry &AddNewEntry(void) { return mEntries[Add(kMaxSize, mTimestamps)]; }
        void   AddNewEntry(const Entry &aEntry) { mEntries[Add(kMaxSize, mTimestamps)] = aEntry; }

        const Entry *Iterate(Iterator &aIterator, uint32_t &aEntryAge) const
        {
            uint16_t index;

            return (HistoryListBase::Iterate(kMaxSize, mTimestamps, aIterator, index, aEntryAge) == kErrorNone)
                       ? &mEntries[index]
                       : nullptr;
        }

        void RemoveAgedEntries(void) { HistoryListBase::RemoveAgedEntries(mTimestamps); }

    private:
        Timestamp mTimestamps[kMaxSize];
        Entry     mEntries[kMaxSize];
    };

    void HandleNotifierEvents(Events aEvents);

    static void HandleTimer(Timer &aTimer);
    void        HandleTimer(void);

    HistoryList<Mle::DeviceRole, kRoleHistoryListSize> mRoleHistory;

    TimerMilli                        mTimer;
};

} // namespace Utils
} // namespace ot

#endif // OPENTHREAD_CONFIG_STAT_COLLECTOR_ENABLE

#endif // STAT_COLLECTOR_HPP_
