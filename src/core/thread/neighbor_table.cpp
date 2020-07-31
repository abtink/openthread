/*
 *  Copyright (c) 2016-2020, The OpenThread Authors.
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
 *   This file includes definitions for Thread neighbor table.
 */

#include "neighbor_table.hpp"

#include "common/code_utils.hpp"
#include "common/instance.hpp"
#include "common/locator-getters.hpp"

namespace ot {

NeighborTable::NeighborTable(Instance &aInstance)
    : InstanceLocator(aInstance)
{
}

Neighbor *NeighborTable::FindParent(Mac::ShortAddress aShortAddress)
{
    Neighbor *neighbor = nullptr;
    Mle::Mle &mle      = Get<Mle::Mle>();

    if (mle.GetParent().IsStateValidOrRestoring() && (mle.GetParent().GetRloc16() == aShortAddress))
    {
        neighbor = &mle.GetParent();
    }
    else if (mle.GetParentCandidate().IsStateValid() && (mle.GetParentCandidate().GetRloc16() == aShortAddress))
    {
        neighbor = &mle.GetParentCandidate();
    }

    return neighbor;
}

Neighbor *NeighborTable::FindParent(const Mac::ExtAddress &aExtAddress)
{
    Neighbor *neighbor = nullptr;
    Mle::Mle &mle      = Get<Mle::Mle>();

    if (mle.GetParent().IsStateValidOrRestoring() && (mle.GetParent().GetExtAddress() == aExtAddress))
    {
        neighbor = &mle.GetParent();
    }
    else if (mle.GetParentCandidate().IsStateValid() && (mle.GetParentCandidate().GetExtAddress() == aExtAddress))
    {
        neighbor = &mle.GetParentCandidate();
    }

    return neighbor;
}

Neighbor *NeighborTable::FindParent(const Mac::Address &aMacAddress)
{
    Neighbor *neighbor = nullptr;

    switch (aMacAddress.GetType())
    {
    case Mac::Address::kTypeShort:
        neighbor = FindParent(aMacAddress.GetShort());
        break;

    case Mac::Address::kTypeExtended:
        neighbor = FindParent(aMacAddress.GetExtended());
        break;

    default:
        break;
    }

    return neighbor;
}

Neighbor *NeighborTable::FindNeighbor(Mac::ShortAddress aShortAddress)
{
    Neighbor *neighbor = nullptr;

    VerifyOrExit((aShortAddress != Mac::kShortAddrBroadcast) && (aShortAddress != Mac::kShortAddrInvalid), OT_NOOP);

    switch (Get<Mle::Mle>().GetRole())
    {
#if OPENTHREAD_FTD
    case Mle::kRoleRouter:
    case Mle::kRoleLeader:
        neighbor = Get<ChildTable>().FindChild(aShortAddress, Child::kInStateValidOrRestoring);
        VerifyOrExit(neighbor == nullptr, OT_NOOP);

        neighbor = Get<RouterTable>().GetNeighbor(aShortAddress);
        VerifyOrExit(neighbor == nullptr, OT_NOOP);
#endif
        // Fall through

    case Mle::kRoleDetached:
    case Mle::kRoleChild:
        neighbor = FindParent(aShortAddress);
        break;

    default:
        break;
    }

exit:
    return neighbor;
}

Neighbor *NeighborTable::FindNeighbor(const Mac::ExtAddress &aExtAddress)
{
    Neighbor *neighbor = nullptr;

    switch (Get<Mle::Mle>().GetRole())
    {
#if OPENTHREAD_FTD
    case Mle::kRoleRouter:
    case Mle::kRoleLeader:
        neighbor = Get<ChildTable>().FindChild(aExtAddress, Child::kInStateValidOrRestoring);
        VerifyOrExit(neighbor == nullptr, OT_NOOP);

        neighbor = Get<RouterTable>().GetNeighbor(aExtAddress);
        VerifyOrExit(neighbor == nullptr, OT_NOOP);
#endif
        // Fall through

    case Mle::kRoleDetached:
    case Mle::kRoleChild:
        neighbor = FindParent(aExtAddress);
        break;

    default:
        ExitNow();
    }

exit:
    return neighbor;
}

Neighbor *NeighborTable::FindNeighbor(const Mac::Address &aMacAddress)
{
    Neighbor *neighbor = nullptr;

    switch (aMacAddress.GetType())
    {
    case Mac::Address::kTypeShort:
        neighbor = FindNeighbor(aMacAddress.GetShort());
        break;

    case Mac::Address::kTypeExtended:
        neighbor = FindNeighbor(aMacAddress.GetExtended());
        break;

    default:
        break;
    }

    return neighbor;
}

#if OPENTHREAD_FTD

Neighbor *NeighborTable::FindNeighbor(const Ip6::Address &aIp6Address)
{
    Neighbor *neighbor = nullptr;

    if (aIp6Address.IsLinkLocal())
    {
        Mac::Address macAddresss;

        aIp6Address.GetIid().ConvertToMacAddress(macAddresss);
        ExitNow(neighbor = FindNeighbor(macAddresss));
    }

    if (Get<Mle::Mle>().IsRoutingLocator(aIp6Address))
    {
        uint16_t rloc16 = aIp6Address.GetIid().GetLocator();

        neighbor = Get<ChildTable>().FindChild(rloc16, Child::kInStateValidOrRestoring);
        VerifyOrExit(neighbor == nullptr, OT_NOOP);

        neighbor = Get<RouterTable>().GetNeighbor(rloc16);
        ExitNow();
    }

    for (Child &child : Get<ChildTable>().Iterate(Child::kInStateValidOrRestoring))
    {
        if (child.HasIp6Address(aIp6Address))
        {
            ExitNow(neighbor = &child);
        }
    }

exit:
    return neighbor;
}

Neighbor *NeighborTable::FindRxOnlyNeighborRouter(const Mac::Address &aMacAddress)
{
    Neighbor *neighbor = nullptr;

    VerifyOrExit(Get<Mle::Mle>().IsChild(), OT_NOOP);
    neighbor = Get<RouterTable>().GetNeighbor(aMacAddress);

exit:
    return neighbor;
}

otError NeighborTable::GetNextNeighborInfo(otNeighborInfoIterator &aIterator, Neighbor::Info &aNeighInfo)
{
    otError error = OT_ERROR_NONE;
    int16_t index;

    // Non-negative iterator value gives the Child index into child table

    if (aIterator >= 0)
    {
        for (index = aIterator;; index++)
        {
            Child *child = Get<ChildTable>().GetChildAtIndex(static_cast<uint16_t>(index));

            if (child == nullptr)
            {
                break;
            }

            if (child->IsStateValid())
            {
                aNeighInfo.SetFrom(*child);
                aNeighInfo.mIsChild = true;
                index++;
                aIterator = index;
                ExitNow();
            }
        }

        aIterator = 0;
    }

    // Negative iterator value gives the current index into mRouters array

    for (index = -aIterator; index <= Mle::kMaxRouterId; index++)
    {
        Router *router = Get<RouterTable>().GetRouter(static_cast<uint8_t>(index));

        if (router != nullptr && router->IsStateValid())
        {
            aNeighInfo.SetFrom(*router);
            aNeighInfo.mIsChild = false;
            index++;
            aIterator = -index;
            ExitNow();
        }
    }

    aIterator = -index;
    error     = OT_ERROR_NOT_FOUND;

exit:
    return error;
}

#endif // OPENTHREAD_FTD

#if OPENTHREAD_MTD

otError NeighborTable::GetNextNeighborInfo(otNeighborInfoIterator &aIterator, Neighbor::Info &aNeighInfo)
{
    otError error = OT_ERROR_NOT_FOUND;

    VerifyOrExit(aIterator == OT_NEIGHBOR_INFO_ITERATOR_INIT, OT_NOOP);

    aIterator++;
    VerifyOrExit(Get<Mle::Mle>().GetParent().IsStateValid(), OT_NOOP);

    aNeighInfo.SetFrom(Get<Mle::Mle>().GetParent());
    aNeighInfo.mIsChild = false;
    error               = OT_ERROR_NONE;

exit:
    return error;
}

#endif

} // namespace ot
