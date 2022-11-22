/*
 *  Copyright (c) 2018, The OpenThread Authors.
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

#include "router_table.hpp"

#if OPENTHREAD_FTD

#include "common/code_utils.hpp"
#include "common/instance.hpp"
#include "common/locator_getters.hpp"
#include "common/log.hpp"
#include "common/timer.hpp"
#include "thread/mle.hpp"
#include "thread/mle_router.hpp"
#include "thread/network_data_leader.hpp"
#include "thread/thread_netif.hpp"

namespace ot {

RegisterLogModule("RouterTable");

RouterTable::Iterator::Iterator(Instance &aInstance)
    : InstanceLocator(aInstance)
    , ItemPtrIterator(&aInstance.Get<RouterTable>().mRouters[0])
{
    if (!mItem->IsAllocated())
    {
        Advance();
    }
}

void RouterTable::Iterator::Advance(void)
{
    VerifyOrExit(mItem != nullptr);

    do
    {
        mItem++;
        VerifyOrExit(mItem < GetArrayEnd(Get<RouterTable>().mRouters), mItem = nullptr);
    } while (!mItem->IsAllocated());

exit:
    return;
}

RouterTable::RouterTable(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mRouterIdSequenceLastUpdated(0)
    , mRouterIdSequence(Random::NonCrypto::GetUint8())
    , mActiveRouterCount(0)
#if OPENTHREAD_CONFIG_REFERENCE_DEVICE_ENABLE
    , mMinRouterId(0)
    , mMaxRouterId(Mle::kMaxRouterId)
#endif
{
    for (Router &router : mRouters)
    {
        router.Init(aInstance);
    }

    Clear();
}

void RouterTable::Clear(void)
{
    ClearNeighbors();

    for (RouterId &routerId : mRouterIds)
    {
        routerId.Clear();
    }

    for (Router &router : mRouters)
    {
        router.Clear();
    }

    mActiveRouterCount = 0;
}

void RouterTable::ClearNeighbors(void)
{
    for (Router &router : mRouters)
    {
        if (router.IsStateValid())
        {
            Get<NeighborTable>().Signal(NeighborTable::kRouterRemoved, router);
        }

        router.SetState(Neighbor::kStateInvalid);
    }
}

bool RouterTable::IsAllocated(uint8_t aId) const
{
    return mRouterIds[aId].IsAllocated();
}

void RouterTable::GetRouterIdSet(Mle::RouterIdSet &aRouterIdSet) const
{
    aRouterIdSet.Clear();

    for (uint8_t id = 0; id <= Mle::kMaxRouterId; id++)
    {
        if (mRouterIds[id].IsAllocated())
        {
            aRouterIdSet.Add(id);
        }
    }
}

Router *RouterTable::Add(uint8_t aId)
{
    Router *router = nullptr;

    OT_ASSERT(!mRouterIds[aId].IsAllocated());

    for (uint8_t index = 0; index < GetArrayLength(mRouters); index++)
    {
        if (!mRouters[index].IsAllocated())
        {
            mRouterIds[aId].Allocate(index);

            router = &mRouters[index];
            router->SetRloc16(Mle::Rloc16FromRouterId(aId));
            mActiveRouterCount++;
            break;
        }
    }

    return router;
}

void RouterTable::Remove(uint8_t aId)
{
    OT_ASSERT(mRouterIds[aId].IsAllocated());

    mRouters[mRouterIds[aId].GetIndex()].Clear();
    mRouterIds[aId].Unallocate();
    mActiveRouterCount--;
}

Router *RouterTable::Allocate(void)
{
    Router *router       = nullptr;
    uint8_t numAvailable = 0;
    uint8_t selectedId   = Mle::kInvalidRouterId;

    VerifyOrExit(mActiveRouterCount < Mle::kMaxRouters);

    // count available router ids
#if OPENTHREAD_CONFIG_REFERENCE_DEVICE_ENABLE
    for (uint8_t id = mMinRouterId; id <= mMaxRouterId; id++)
#else
    for (uint8_t id = 0; id <= Mle::kMaxRouterId; id++)
#endif
    {
        if (mRouterIds[id].CanAllocate())
        {
            numAvailable++;

            // Randomly select a router ID as we iterate through the
            // list using Reservoir algorithm: We replace the
            // selected ID with current entry in the list with
            // probably `1/numAvailable`.

            if (Random::NonCrypto::GetUint8InRange(0, numAvailable) == 0)
            {
                selectedId = id;
            }
        }
    }

    VerifyOrExit(selectedId != Mle::kInvalidRouterId);

    router = Allocate(selectedId);
    OT_ASSERT(router != nullptr);

exit:
    return router;
}

Router *RouterTable::Allocate(uint8_t aId)
{
    Router *router = nullptr;

    VerifyOrExit((aId <= Mle::kMaxRouterId) && (mActiveRouterCount < Mle::kMaxRouters));
    VerifyOrExit(mRouterIds[aId].CanAllocate());

    router = Add(aId);
    OT_ASSERT(router != nullptr);

    router->SetLastHeard(TimerMilli::GetNow());

    mRouterIdSequence++;
    mRouterIdSequenceLastUpdated = TimerMilli::GetNow();
    Get<Mle::MleRouter>().ResetAdvertiseInterval();

    LogNote("Allocate router id %d", aId);

exit:
    return router;
}

Error RouterTable::Release(uint8_t aId)
{
    Error     error  = kErrorNone;
    uint16_t  rloc16 = Mle::Rloc16FromRouterId(aId);
    Neighbor *neighbor;

    OT_ASSERT(aId <= Mle::kMaxRouterId);

    VerifyOrExit(Get<Mle::MleRouter>().IsLeader(), error = kErrorInvalidState);
    VerifyOrExit(IsAllocated(aId), error = kErrorNotFound);

    neighbor = &mRouters[mRouterIds[aId].GetIndex()];

    if (neighbor->IsStateValid())
    {
        Get<NeighborTable>().Signal(NeighborTable::kRouterRemoved, *neighbor);
    }

    Remove(aId);

    for (Router &router : mRouters)
    {
        if (router.IsAllocated() && (router.GetNextHop() == aId))
        {
            router.SetNextHop(Mle::kInvalidRouterId);
            router.SetCost(0);
        }
    }

    mRouterIdSequence++;
    mRouterIdSequenceLastUpdated = TimerMilli::GetNow();

    Get<AddressResolver>().Remove(aId);
    Get<NetworkData::Leader>().RemoveBorderRouter(rloc16, NetworkData::Leader::kMatchModeRouterId);
    Get<Mle::MleRouter>().ResetAdvertiseInterval();

    LogNote("Release router id %d", aId);

exit:
    return error;
}

void RouterTable::RemoveRouterLink(Router &aRouter)
{
    if (aRouter.GetLinkQualityOut() != kLinkQuality0)
    {
        aRouter.SetLinkQualityOut(kLinkQuality0);
        aRouter.SetLastHeard(TimerMilli::GetNow());
    }

    for (Router &router : mRouters)
    {
        if (!router.IsAllocated())
        {
            continue;
        }

        if (router.GetNextHop() == aRouter.GetRouterId())
        {
            router.SetNextHop(Mle::kInvalidRouterId);
            router.SetCost(0);

            if (GetLinkCost(router) >= Mle::kMaxRouteCost)
            {
                Get<Mle::MleRouter>().ResetAdvertiseInterval();
            }
        }
    }

    if (aRouter.GetNextHop() == Mle::kInvalidRouterId)
    {
        Get<Mle::MleRouter>().ResetAdvertiseInterval();

        // Clear all EID-to-RLOC entries associated with the router.
        Get<AddressResolver>().Remove(aRouter.GetRouterId());
    }
}

uint8_t RouterTable::GetActiveLinkCount(void) const
{
    uint8_t activeLinks = 0;

    for (const Router &router : mRouters)
    {
        if (router.IsAllocated() && router.IsStateValid())
        {
            activeLinks++;
        }
    }

    return activeLinks;
}

const Router *RouterTable::FindRouter(const Router::AddressMatcher &aMatcher) const
{
    const Router *match = nullptr;

    for (const Router &router : mRouters)
    {
        if (router.IsAllocated() && router.Matches(aMatcher))
        {
            match = &router;
            break;
        }
    }

    return match;
}

Router *RouterTable::GetNeighbor(uint16_t aRloc16)
{
    Router *router = nullptr;

    VerifyOrExit(aRloc16 != Get<Mle::MleRouter>().GetRloc16());
    router = FindRouter(Router::AddressMatcher(aRloc16, Router::kInStateValid));

exit:
    return router;
}

Router *RouterTable::GetNeighbor(const Mac::ExtAddress &aExtAddress)
{
    return FindRouter(Router::AddressMatcher(aExtAddress, Router::kInStateValid));
}

Router *RouterTable::GetNeighbor(const Mac::Address &aMacAddress)
{
    return FindRouter(Router::AddressMatcher(aMacAddress, Router::kInStateValid));
}

const Router *RouterTable::GetRouter(uint8_t aId) const
{
    const Router *router = nullptr;
    uint16_t      rloc16;

    // Skip if invalid router id is passed.
    VerifyOrExit(aId < Mle::kInvalidRouterId);

    rloc16 = Mle::Rloc16FromRouterId(aId);
    router = FindRouter(Router::AddressMatcher(rloc16, Router::kInStateAny));

exit:
    return router;
}

Router *RouterTable::GetRouter(const Mac::ExtAddress &aExtAddress)
{
    return FindRouter(Router::AddressMatcher(aExtAddress, Router::kInStateAny));
}

Error RouterTable::GetRouterInfo(uint16_t aId, Router::Info &aRouterInfo)
{
    Error   error = kErrorNone;
    Router *router;
    uint8_t id;

    if (aId <= Mle::kMaxRouterId)
    {
        id = static_cast<uint8_t>(aId);
    }
    else
    {
        VerifyOrExit(Mle::IsActiveRouter(aId), error = kErrorInvalidArgs);
        id = Mle::RouterIdFromRloc16(aId);
        VerifyOrExit(id <= Mle::kMaxRouterId, error = kErrorInvalidArgs);
    }

    router = GetRouter(id);
    VerifyOrExit(router != nullptr, error = kErrorNotFound);

    aRouterInfo.SetFrom(*router);

exit:
    return error;
}

Router *RouterTable::GetLeader(void)
{
    return GetRouter(Get<Mle::MleRouter>().GetLeaderId());
}

uint32_t RouterTable::GetLeaderAge(void) const
{
    return (mActiveRouterCount > 0) ? Time::MsecToSec(TimerMilli::GetNow() - mRouterIdSequenceLastUpdated) : 0xffffffff;
}

uint8_t RouterTable::GetNeighborCount(void) const
{
    uint8_t count = 0;

    for (const Router &router : mRouters)
    {
        if (router.IsAllocated() && router.IsStateValid())
        {
            count++;
        }
    }

    return count;
}

uint8_t RouterTable::GetLinkCost(Router &aRouter)
{
    uint8_t cost = Mle::kMaxRouteCost;

    VerifyOrExit(aRouter.GetRloc16() != Get<Mle::MleRouter>().GetRloc16() && aRouter.IsStateValid());

    cost = Mle::MleRouter::LinkQualityToCost(aRouter.GetTwoWayLinkQuality());

exit:
    return cost;
}

void RouterTable::UpdateRouterIdSet(uint8_t aRouterIdSequence, const Mle::RouterIdSet &aRouterIdSet)
{
    bool didChange = false;

    mRouterIdSequence            = aRouterIdSequence;
    mRouterIdSequenceLastUpdated = TimerMilli::GetNow();

    for (uint8_t id = 0; id <= Mle::kMaxRouterId; id++)
    {
        if (IsAllocated(id) == aRouterIdSet.Contains(id))
        {
            continue;
        }

        didChange = true;

        if (IsAllocated(id))
        {
            Router &router = mRouters[mRouterIds[id].GetIndex()];

            router.SetNextHop(Mle::kInvalidRouterId);
            RemoveRouterLink(router);
            Remove(id);
        }
        else
        {
            Add(id);
        }
    }

    VerifyOrExit(didChange);
    Get<Mle::MleRouter>().ResetAdvertiseInterval();

exit:
    return;
}

void RouterTable::HandleTimeTick(void)
{
    VerifyOrExit(Get<Mle::MleRouter>().IsLeader());

    if (GetLeaderAge() >= Mle::kRouterIdSequencePeriod)
    {
        mRouterIdSequence++;
        mRouterIdSequenceLastUpdated = TimerMilli::GetNow();
    }

    for (RouterId &routerId : mRouterIds)
    {
        routerId.DecrementReuseDelay();
    }

exit:
    return;
}

#if OPENTHREAD_CONFIG_REFERENCE_DEVICE_ENABLE
void RouterTable::GetRouterIdRange(uint8_t &aMinRouterId, uint8_t &aMaxRouterId) const
{
    aMinRouterId = mMinRouterId;
    aMaxRouterId = mMaxRouterId;
}

Error RouterTable::SetRouterIdRange(uint8_t aMinRouterId, uint8_t aMaxRouterId)
{
    Error error = kErrorNone;

    VerifyOrExit(aMinRouterId <= aMaxRouterId, error = kErrorInvalidArgs);
    VerifyOrExit(aMaxRouterId <= Mle::kMaxRouterId, error = kErrorInvalidArgs);
    mMinRouterId = aMinRouterId;
    mMaxRouterId = aMaxRouterId;

exit:
    return error;
}
#endif

#if OT_SHOULD_LOG_AT(OT_LOG_LEVEL_INFO)
void RouterTable::LogRouteTable(void)
{
    static constexpr uint16_t kStringSize = 128;

    LogInfo("Route table");

    for (Router &router : Iterate())
    {
        String<kStringSize> string;

        string.Append("    %2d 0x%04x", router.GetRouterId(), router.GetRloc16());

        if (router.GetRloc16() == Get<Mle::Mle>().GetRloc16())
        {
            string.Append(" - me");
        }
        else
        {
            if (router.IsStateValid())
            {
                string.Append(" - nbr{lq[i/o]:%d/%d cost:%d}", router.GetLinkQualityIn(), router.GetLinkQualityOut(),
                              GetLinkCost(router));
            }

            if (router.GetNextHop() != Mle::kInvalidRouterId)
            {
                string.Append(" - nexthop{%d cost:%d}", router.GetNextHop(), router.GetCost());
            }
        }

        if (router.GetRouterId() == Get<Mle::Mle>().GetLeaderId())
        {
            string.Append(" - leader");
        }

        LogInfo("%s", string.AsCString());
    }
}
#endif

} // namespace ot

#endif // OPENTHREAD_FTD
