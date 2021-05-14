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
 *   This file implements the Network Data Publisher.
 *
 */

#include "network_data_publisher.hpp"

#if OPENTHREAD_CONFIG_NETDATA_PUBLISHER_ENABLE

#include "common/code_utils.hpp"
#include "common/instance.hpp"
#include "common/locator_getters.hpp"
#include "common/random.hpp"
#include "thread/network_data_local.hpp"
#include "thread/network_data_service.hpp"

namespace ot {
namespace NetworkData {

//---------------------------------------------------------------------------------------------------------------------
// Publisher

Publisher::Publisher(Instance &aInstance)
    : InstanceLocator(aInstance)
#if OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE
    , mDnsSrpServiceEntry(aInstance)
#endif
    , mTimer(aInstance, Publisher::HandleTimer)
{
#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE
    // Since the `PrefixEntry` type is used in an array,
    // we cannot use a constructor with an argument (e.g.,
    // we cannot use `InstacneLocator`) so we use `IntanceLocatorInit`
    // and `Init()` the entries one by one.

    for (PrefixEntry &entry : mPrefixEntries)
    {
        entry.Init(aInstance);
    }
#endif
}

#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE

Error Publisher::PublishOnMeshPrefix(const OnMeshPrefixConfig &aConfig)
{
    Error        error;
    PrefixEntry *entry;

    VerifyOrExit(aConfig.IsValid(GetInstance()), error = kErrorInvalidArgs);

    SuccessOrExit(error = AllocatePrefixEntry(aConfig.GetPrefix(), entry));
    entry->Publish(aConfig);

exit:
    return error;
}

Error Publisher::PublishExternalRoute(const ExternalRouteConfig &aConfig)
{
    Error        error;
    PrefixEntry *entry;

    VerifyOrExit(aConfig.IsValid(GetInstance()), error = kErrorInvalidArgs);

    SuccessOrExit(error = AllocatePrefixEntry(aConfig.GetPrefix(), entry));
    entry->Publish(aConfig);

exit:
    return error;
}

Error Publisher::UnpublishPrefix(const Ip6::Prefix &aPrefix)
{
    Error        error = kErrorNone;
    PrefixEntry *entry;

    entry = FindMatchingPrefixEntry(aPrefix);
    VerifyOrExit(entry != nullptr, error = kErrorNotFound);

    entry->Unpublish();

exit:
    return error;
}

Error Publisher::AllocatePrefixEntry(const Ip6::Prefix &aPrefix, PrefixEntry *&aEntry)
{
    Error error = kErrorNoBufs;

    VerifyOrExit(FindMatchingPrefixEntry(aPrefix) == nullptr, error = kErrorAlready);

    for (PrefixEntry &entry : mPrefixEntries)
    {
        if (!entry.IsInUse())
        {
            aEntry = &entry;
            ExitNow(error = kErrorNone);
        }
    }

exit:
    return error;
}

Publisher::PrefixEntry *Publisher::FindMatchingPrefixEntry(const Ip6::Prefix &aPrefix)
{
    PrefixEntry *prefixEntry = nullptr;

    for (PrefixEntry &entry : mPrefixEntries)
    {
        if (entry.IsInUse() && entry.Matches(aPrefix))
        {
            prefixEntry = &entry;
            break;
        }
    }

    return prefixEntry;
}

#endif // OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE

void Publisher::HandleNotifierEvents(Events aEvents)
{
    OT_UNUSED_VARIABLE(aEvents);

    bool registerWithLeader = false;

#if OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE
    if (mDnsSrpServiceEntry.HandleNotifierEvents(aEvents))
    {
        registerWithLeader = true;
    }
#endif

#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE
    for (PrefixEntry &entry : mPrefixEntries)
    {
        entry.HandleNotifierEvents(aEvents);
    }
#endif

    if (registerWithLeader)
    {
        Get<Notifier>().HandleServerDataUpdated();
    }
}

void Publisher::HandleTimer(Timer &aTimer)
{
    aTimer.Get<Publisher>().HandleTimer();
}

void Publisher::HandleTimer(void)
{
    bool registerWithLeader = false;

#if OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE
    if (mDnsSrpServiceEntry.HandleTimer())
    {
        registerWithLeader = true;
    }
#endif

#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE
    for (PrefixEntry &entry : mPrefixEntries)
    {
        if (entry.HandleTimer())
        {
            registerWithLeader = true;
        }
    }
#endif

    if (registerWithLeader)
    {
        Get<Notifier>().HandleServerDataUpdated();
    }
}

//---------------------------------------------------------------------------------------------------------------------
// Publisher::Entry

void Publisher::Entry::SetState(State aState)
{
    VerifyOrExit(mState != aState);

    otLogInfoNetData("Publisher: %s - State: %s -> %s", ToString(/* aIncludeState */ false).AsCString(),
                     StateToString(mState), StateToString(aState));
    mState = aState;

exit:
    return;
}

void Publisher::Entry::UpdateState(uint8_t aNumEntries, uint8_t aNumPreferredEntries, uint8_t aDesiredNumEntries)
{
    // This method uses the info about number existing entries (total
    // and preferred) in Network Data along with the desired number of
    // entries we aim to have in the Network Data to decide whether or
    // not to take any action (add or remove our entry).

    otLogInfoNetData("Publisher: %s in netdata - total:%d, preferred:%d, desired:%d", ToString().AsCString(),
                     aNumEntries, aNumPreferredEntries, aDesiredNumEntries);

    switch (GetState())
    {
    case kNoEntry:
        break;

    case kToAdd:
        // Our entry is ready to be added. If there are too few existing
        // entries, we start adding our entry (start the timer with a
        // random wait time before adding the entry).

        if (aNumEntries < aDesiredNumEntries)
        {
            mUpdateTime = TimerMilli::GetNow() + Random::NonCrypto::GetUint32InRange(1, kMaxWaitTimeToAdd);
            SetState(kAdding);
            Get<Publisher>().GetTimer().FireAtIfEarlier(mUpdateTime);
            LogUpdateTime();
        }
        break;

    case kAdding:
        // Our entry is being added (waiting time before we add). If we
        // now see that there are enough entries, we stop adding the
        // entry.

        if (aNumEntries >= aDesiredNumEntries)
        {
            SetState(kToAdd);
        }
        break;

    case kAdded:
        // Our entry is already added in the Network Data. If there are
        // enough entries, do nothing and keep monitoring. If we see now
        // that there are too many entries, we start removing our entry
        // after a random wait time. If our entry itself is preferred
        // over other entries (indicated by `aNumPreferredEntries <
        // aDesiredNumEntries`) we add an extra wait time before removing
        // the entry. This gives higher chance for a non-preferred
        // entry from another device to be removed before our entry.

        if (aNumEntries > aDesiredNumEntries)
        {
            mUpdateTime = TimerMilli::GetNow() + Random::NonCrypto::GetUint32InRange(1, kMaxWaitTimeToAdd);

            if (aNumPreferredEntries < aDesiredNumEntries)
            {
                mUpdateTime += kExtraWaitToRemovePeferred;
            }

            SetState(kRemoving);
            Get<Publisher>().GetTimer().FireAtIfEarlier(mUpdateTime);
            LogUpdateTime();
        }
        break;

    case kRemoving:
        // Our entry is being removed (wait time before remove). If we
        // now see that there are enough or too few entries, we stop
        // removing our entry.

        if (aNumEntries <= aDesiredNumEntries)
        {
            SetState(kAdded);
        }
        break;
    }
}

bool Publisher::Entry::HandleTimer(void)
{
    bool registerWithLeader = false;

    // Timer is used to delay adding/removing the entry. If we have
    // reached `mUpdateTime` add or remove the entry. Otherwise,
    // restart the timer (note that timer can be shared between
    // different published entries). This method returns a `bool`
    // indicating whether or not anything in local Network Data got
    // changed so to notify the leader and register the changes.

    VerifyOrExit((GetState() == kAdding) || (GetState() == kRemoving));

    if (mUpdateTime <= TimerMilli::GetNow())
    {
        registerWithLeader =
            (GetState() == kAdding) ? Add(registerWithLeader) : Remove(registerWithLeader, /* aNextState */ kToAdd);
        ;
    }
    else
    {
        Get<Publisher>().GetTimer().FireAtIfEarlier(mUpdateTime);
    }

exit:
    return registerWithLeader;
}

bool Publisher::Entry::Add(bool aRegisterWithLeader)
{
    bool registerWithLeader = false;

#if OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE
    if (this == &Get<Publisher>().mDnsSrpServiceEntry)
    {
        registerWithLeader = static_cast<DnsSrpServiceEntry *>(this)->Add(aRegisterWithLeader);
        ExitNow();
    }
#endif

#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE
    registerWithLeader = static_cast<PrefixEntry *>(this)->Add(aRegisterWithLeader);
#endif

    ExitNow();

exit:
    return registerWithLeader;
}

bool Publisher::Entry::Remove(bool aRegisterWithLeader, State aNextState)
{
    bool registerWithLeader = false;

#if OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE
    if (this == &Get<Publisher>().mDnsSrpServiceEntry)
    {
        registerWithLeader = static_cast<DnsSrpServiceEntry *>(this)->Remove(aRegisterWithLeader, aNextState);
        ExitNow();
    }
#endif

#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE
    registerWithLeader = static_cast<PrefixEntry *>(this)->Remove(aRegisterWithLeader, aNextState);
#endif

    ExitNow();

exit:
    return registerWithLeader;
}

void Publisher::Entry::LogUpdateTime(void) const
{
    otLogInfoNetData("Publisher: %s - update in %u msec", ToString().AsCString(), mUpdateTime - TimerMilli::GetNow());
}

Publisher::Entry::InfoString Publisher::Entry::ToString(bool aIncludeState) const
{
    InfoString   string;
    StringWriter writer(string);

#if OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE
    if (this == &Get<Publisher>().mDnsSrpServiceEntry)
    {
        writer.Append("DNS/SRP service");
    }
#endif

#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE
    {
        const PrefixEntry &prefixEntry = *static_cast<const PrefixEntry *>(this);

        switch (prefixEntry.mType)
        {
        case PrefixEntry::kTypeOnMeshPrefix:
            writer.Append("OnMeshPrefix ");
            break;

        case PrefixEntry::kTypeExternalRoute:
            writer.Append("ExternalRoute ");
            break;
        }

        writer.Append(prefixEntry.mPrefix.ToString().AsCString());
    }
#endif

    if (aIncludeState)
    {
        writer.Append(" (state:%s)", StateToString(GetState()));
    }

    return string;
}

const char *Publisher::Entry::StateToString(State aState)
{
    static const char *const kStateStrings[] = {
        "NoEntry",  // (0) kNoEntry
        "ToAdd",    // (1) kToAdd
        "Adding",   // (2) kAdding
        "Added",    // (3) kAdded
        "Removing", // (4) kRemoving
    };

    static_assert(0 == kNoEntry, "kNoEntry value is not correct");
    static_assert(1 == kToAdd, "kToAdd value is not correct");
    static_assert(2 == kAdding, "kAdding value is not correct");
    static_assert(3 == kAdded, "kAdded value is not correct");
    static_assert(4 == kRemoving, "kRemoving value is not correct");

    return kStateStrings[aState];
}

#if OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE

//---------------------------------------------------------------------------------------------------------------------
// Publisher::DnsSrpServiceEntry

void Publisher::DnsSrpServiceEntry::PublishAnycast(uint8_t aSequenceNumber)
{
    otLogInfoNetData("Publisher: Publishing DNS/SRP service anycast (seq-num:%d)", aSequenceNumber);

    if (GetState() != kNoEntry)
    {
        if ((mType == kTypeAnycast) && (mInfo.mAnycast.mSequenceNumber == aSequenceNumber))
        {
            otLogInfoNetData("Publisher: %s is already being published", ToString().AsCString());
            ExitNow();
        }

        Remove(/* aRegisterWithLeader */ true);
    }

    mType                          = kTypeAnycast;
    mInfo.mAnycast.mSequenceNumber = aSequenceNumber;
    SetState(kToAdd);

    Process();

exit:
    return;
}

void Publisher::DnsSrpServiceEntry::PublishUnicast(const Ip6::Address &aAddress, uint16_t aPort)
{
    otLogInfoNetData("Publisher: Publishing DNS/SRP service unicast (%s, port:%d)", aAddress.ToString().AsCString(),
                     aPort);

    if (GetState() != kNoEntry)
    {
        if ((mType == kTypeUnicast) && (mInfo.mUnicast.mAddress == aAddress) && (mInfo.mUnicast.mPort == aPort))
        {
            otLogInfoNetData("Publisher: %s is already being published", ToString().AsCString());
            ExitNow();
        }

        Remove(/* aRegisterWithLeader */ true);
    }

    mType                   = kTypeUnicast;
    mInfo.mUnicast.mAddress = aAddress;
    mInfo.mUnicast.mPort    = aPort;
    SetState(kToAdd);

    Process();

exit:
    return;
}

void Publisher::DnsSrpServiceEntry::PublishUnicast(uint16_t aPort)
{
    otLogInfoNetData("Publisher: Publishing DNS/SRP service unicast (ml-eid, port:%d)", aPort);

    if (GetState() != kNoEntry)
    {
        if ((mType == kTypeUincastMeshLocalEid) && (mInfo.mUnicast.mPort == aPort))
        {
            otLogInfoNetData("Publisher: %s is already being published", ToString().AsCString());
            ExitNow();
        }

        Remove(/* aRegisterWithLeader */ true);
    }

    mType                   = kTypeUincastMeshLocalEid;
    mInfo.mUnicast.mAddress = Get<Mle::Mle>().GetMeshLocal64();
    mInfo.mUnicast.mPort    = aPort;
    SetState(kToAdd);

    Process();

exit:
    return;
}

void Publisher::DnsSrpServiceEntry::Unpublish(void)
{
    otLogInfoNetData("Publisher: Unpublishing DNS/SRP service");

    Remove(/* aRegisterWithLeader */ true);
}

bool Publisher::DnsSrpServiceEntry::HandleNotifierEvents(Events aEvents)
{
    bool registerWithLeader = false;

    if ((mType == kTypeUincastMeshLocalEid) && aEvents.Contains(kEventThreadMeshLocalAddrChanged))
    {
        mInfo.mUnicast.mAddress = Get<Mle::Mle>().GetMeshLocal64();

        if (GetState() == kAdded)
        {
            // If the entry is already added, we need to update it
            // so we remove it and add it back immediately with
            // the new mesh-local address.

            Remove(registerWithLeader, /* aNextState */ kAdding);
            Add(registerWithLeader);
            registerWithLeader = true;
        }
    }

    if (aEvents.ContainsAny(kEventThreadNetdataChanged | kEventThreadRoleChanged))
    {
        Process();
    }

    return registerWithLeader;
}

bool Publisher::DnsSrpServiceEntry::Add(bool aRegisterWithLeader)
{
    // Adds the service entry to the network data.

    bool registerWithLeader = false;

    VerifyOrExit(GetState() == kAdding);

    switch (mType)
    {
    case kTypeAnycast:
        SuccessOrExit(Get<Service::Manager>().Add<Service::DnsSrpAnycast>(
            Service::DnsSrpAnycast::ServiceData(mInfo.mAnycast.mSequenceNumber), aRegisterWithLeader));
        break;

    case kTypeUnicast:
        SuccessOrExit(Get<Service::Manager>().Add<Service::DnsSrpUnicast>(
            Service::DnsSrpUnicast::ServiceData(mInfo.mUnicast.mAddress, mInfo.mUnicast.mPort), aRegisterWithLeader));
        break;

    case kTypeUincastMeshLocalEid:
        SuccessOrExit(Get<Service::Manager>().Add<Service::DnsSrpUnicast>(
            Service::DnsSrpUnicast::ServerData(mInfo.mUnicast.mAddress, mInfo.mUnicast.mPort), aRegisterWithLeader));
        break;
    }

    registerWithLeader = !aRegisterWithLeader;
    SetState(kAdded);

exit:
    return registerWithLeader;
}

bool Publisher::DnsSrpServiceEntry::Remove(bool aRegisterWithLeader, State aNextState)
{
    // Removes the service entry from network data (if it was added).

    bool registerWithLeader = false;

    VerifyOrExit((GetState() == kAdded) || (GetState() == kRemoving));

    switch (mType)
    {
    case kTypeAnycast:
        SuccessOrExit(Get<Service::Manager>().Remove<Service::DnsSrpAnycast>(
            Service::DnsSrpAnycast::ServiceData(mInfo.mAnycast.mSequenceNumber), aRegisterWithLeader));
        break;

    case kTypeUnicast:
        SuccessOrExit(Get<Service::Manager>().Remove<Service::DnsSrpUnicast>(
            Service::DnsSrpUnicast::ServiceData(mInfo.mUnicast.mAddress, mInfo.mUnicast.mPort), aRegisterWithLeader));
        break;

    case kTypeUincastMeshLocalEid:
        SuccessOrExit(Get<Service::Manager>().Remove<Service::DnsSrpUnicast>(aRegisterWithLeader));
        break;
    }

    registerWithLeader = !aRegisterWithLeader;

    otLogInfoNetData("Publisher: Removed %s from network data", ToString().AsCString());

exit:
    SetState(aNextState);
    return registerWithLeader;
}

void Publisher::DnsSrpServiceEntry::Process(void)
{
    // This method checks the entries currently present in Network Data
    // based on which it then decides whether or not take action
    // (add/remove or keep monitoring).

    uint8_t numEntries          = 0;
    uint8_t numPreferredEntries = 0;
    uint8_t desiredNumEntries   = 0;

    // Do not make any changes if device is not attached, and wait
    // for role change event.
    VerifyOrExit(Get<Mle::Mle>().IsAttached());

    VerifyOrExit(GetState() != kNoEntry);

    switch (mType)
    {
    case kTypeAnycast:
        CountAnycastEntries(numEntries, numPreferredEntries);
        desiredNumEntries = kDesiredNumAnycast;
        break;

    case kTypeUnicast:
    case kTypeUincastMeshLocalEid:
        CountUnicastEntries(numEntries, numPreferredEntries);
        desiredNumEntries = kDesiredNumUnicast;
        break;
    }

    UpdateState(numEntries, numPreferredEntries, desiredNumEntries);

exit:
    return;
}

void Publisher::DnsSrpServiceEntry::CountAnycastEntries(uint8_t &aNumEntries, uint8_t &aNumPreferredEntries) const
{
    // Count the number of matching "DNS/SRP Anycast" service entries
    // in the Network Data (the match requires the entry to use same
    // "sequence number" value). We prefer the entries associated with
    // smaller RLCO16.

    Service::DnsSrpAnycast::ServiceData serviceData(mInfo.mAnycast.mSequenceNumber);
    const ServiceTlv *                  serviceTlv = nullptr;
    const ServerTlv *                   serverSubTlv;

    while ((serviceTlv = Get<Leader>().FindNextMatchingService(serviceTlv, Service::kThreadEnterpriseNumber,
                                                               reinterpret_cast<const uint8_t *>(&serviceData),
                                                               serviceData.GetLength())) != nullptr)
    {
        for (const NetworkDataTlv *start = serviceTlv->GetSubTlvs();
             (serverSubTlv = NetworkData::FindTlv<ServerTlv>(start, serviceTlv->GetNext())) != nullptr;
             start = serverSubTlv->GetNext())
        {
            aNumEntries++;

            if (serverSubTlv->GetServer16() < Get<Mle::Mle>().GetRloc16())
            {
                aNumPreferredEntries++;
            }
        }
    }
}

void Publisher::DnsSrpServiceEntry::CountUnicastEntries(uint8_t &aNumEntries, uint8_t &aNumPreferredEntries) const
{
    // Count the number of "DNS/SRP Unicast" service entries in
    // the Network Data.

    const ServiceTlv *serviceTlv = nullptr;
    const ServerTlv * serverSubTlv;

    while ((serviceTlv = Get<Leader>().FindNextMatchingService(
                serviceTlv, Service::kThreadEnterpriseNumber, &Service::DnsSrpUnicast::kServiceData,
                sizeof(Service::DnsSrpUnicast::kServiceData))) != nullptr)
    {
        for (const NetworkDataTlv *start = serviceTlv->GetSubTlvs();
             (serverSubTlv = NetworkData::FindTlv<ServerTlv>(start, serviceTlv->GetNext())) != nullptr;
             start = serverSubTlv->GetNext())
        {
            if (serviceTlv->GetServiceDataLength() >= sizeof(Service::DnsSrpUnicast::ServiceData))
            {
                aNumEntries++;

                // Generally, we prefer entries where the SRP/DNS server
                // address/port info is included in the service TLV data
                // over the ones where the info is included in the
                // server TLV data. If our entry itself uses the service
                // TLV data, then we use the IPv6 address (smaller is
                // preferred) first and if the addresses are equal, we
                // use associated RLOC16 (again smaller is preferred).

                if (mType == kTypeUnicast)
                {
                    const Service::DnsSrpUnicast::ServiceData *serviceData =
                        reinterpret_cast<const Service::DnsSrpUnicast::ServiceData *>(serviceTlv->GetServiceData());

                    if ((serviceData->GetAddress() < mInfo.mUnicast.mAddress) ||
                        ((serviceData->GetAddress() == mInfo.mUnicast.mAddress) &&
                         (serverSubTlv->GetServer16() < Get<Mle::Mle>().GetRloc16())))
                    {
                        aNumPreferredEntries++;
                    }
                }
                else
                {
                    aNumPreferredEntries++;
                }
            }

            if (serverSubTlv->GetServerDataLength() >= sizeof(Service::DnsSrpUnicast::ServerData))
            {
                aNumEntries++;

                if (mType == kTypeUincastMeshLocalEid)
                {
                    // If our entry uses the server TLV data, then the
                    // we prefer entries with smaller address.

                    const Service::DnsSrpUnicast::ServerData *serverData =
                        reinterpret_cast<const Service::DnsSrpUnicast::ServerData *>(serverSubTlv->GetServerData());

                    if (serverData->GetAddress() < mInfo.mUnicast.mAddress)
                    {
                        aNumPreferredEntries++;
                    }
                }
            }
        }
    }
}

#endif // OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE

//---------------------------------------------------------------------------------------------------------------------
// Publisher::PrefixEntry

void Publisher::PrefixEntry::Publish(const OnMeshPrefixConfig &aConfig)
{
    otLogInfoNetData("Publisher: Publishing OnMeshPrefix %s", aConfig.GetPrefix().ToString().AsCString());

    mType   = kTypeOnMeshPrefix;
    mPrefix = aConfig.GetPrefix();
    mStable = aConfig.mStable;
    mFlags  = aConfig.ConvertToTlvFlags();

    SetState(kToAdd);

    Process();
}

void Publisher::PrefixEntry::Publish(const ExternalRouteConfig &aConfig)
{
    otLogInfoNetData("Publisher: Publishing ExternalRoute %s", aConfig.GetPrefix().ToString().AsCString());

    mType   = kTypeExternalRoute;
    mPrefix = aConfig.GetPrefix();
    mStable = aConfig.mStable;
    mFlags  = aConfig.ConvertToTlvFlags();

    SetState(kToAdd);

    Process();
}

void Publisher::PrefixEntry::Unpublish(void)
{
    otLogInfoNetData("Publisher: Unpublishing %s", mPrefix.ToString().AsCString());

    Remove(/* aRegisterWithLeader */ true);
}

void Publisher::PrefixEntry::HandleNotifierEvents(Events aEvents)
{
    if (aEvents.ContainsAny(kEventThreadNetdataChanged | kEventThreadRoleChanged))
    {
        Process();
    }
}

bool Publisher::PrefixEntry::Add(bool aRegisterWithLeader)
{
    // Adds the prefix entry to the network data.

    bool registerWithLeader = false;

    union
    {
        OnMeshPrefixConfig  mOnMeshPrefix;
        ExternalRouteConfig mExternalRoute;
    } config;

    switch (mType)
    {
    case kTypeOnMeshPrefix:
        config.mOnMeshPrefix.mPrefix = mPrefix;
        config.mOnMeshPrefix.mStable = mStable;
        config.mOnMeshPrefix.SetFromTlvFlags(mFlags);
        SuccessOrExit(Get<Local>().AddOnMeshPrefix(config.mOnMeshPrefix));
        break;

    case kTypeExternalRoute:
        config.mExternalRoute.mPrefix = mPrefix;
        config.mExternalRoute.mStable = mStable;
        config.mExternalRoute.SetFromTlvFlags(static_cast<uint8_t>(mFlags));
        SuccessOrExit(Get<Local>().AddHasRoutePrefix(config.mExternalRoute));
        break;
    }

    SetState(kAdded);

    if (aRegisterWithLeader)
    {
        Get<Notifier>().HandleServerDataUpdated();
    }
    else
    {
        registerWithLeader = true;
    }

exit:
    return registerWithLeader;
}

bool Publisher::PrefixEntry::Remove(bool aRegisterWithLeader, State aNextState)
{
    // Remove the prefix entry to the network data.

    bool registerWithLeader = false;

    VerifyOrExit((GetState() == kAdded) || (GetState() == kRemoving));

    switch (mType)
    {
    case kTypeOnMeshPrefix:
        IgnoreError(Get<Local>().RemoveOnMeshPrefix(mPrefix));
        break;

    case kTypeExternalRoute:
        IgnoreError(Get<Local>().RemoveHasRoutePrefix(mPrefix));
        break;
    }

    if (aRegisterWithLeader)
    {
        Get<Notifier>().HandleServerDataUpdated();
    }
    else
    {
        registerWithLeader = true;
    }

exit:
    SetState(aNextState);
    return registerWithLeader;
}

void Publisher::PrefixEntry::Process(void)
{
    // This method checks the entries currently present in Network Data
    // based on which it then decides whether or not take action
    // (add/remove or keep monitoring).

    uint8_t numEntries          = 0;
    uint8_t numPreferredEntries = 0;
    uint8_t desiredNumEntries   = 0;

    // Do not make any changes if device is not attached, and wait
    // for role change event.
    VerifyOrExit(Get<Mle::Mle>().IsAttached());

    VerifyOrExit(GetState() != kNoEntry);

    switch (mType)
    {
    case kTypeOnMeshPrefix:
        CountOnMeshPrefixEntries(numEntries, numPreferredEntries);
        desiredNumEntries = kDesiredNumOnMeshPrefix;
        break;
    case kTypeExternalRoute:
        CountExternalRouteEntries(numEntries, numPreferredEntries);
        desiredNumEntries = kDesiredNumExternalRoute;
        break;
    }

    UpdateState(numEntries, numPreferredEntries, desiredNumEntries);

exit:
    return;
}

void Publisher::PrefixEntry::CountOnMeshPrefixEntries(uint8_t &aNumEntries, uint8_t &aNumPreferredEntries) const
{
    const PrefixTlv *      prefixTlv;
    const BorderRouterTlv *brSubTlv;
    int8_t                 preference             = BorderRouterEntry::PreferenceFromFlags(mFlags);
    uint16_t               flagsWithoutPreference = BorderRouterEntry::FlagsWithoutPreference(mFlags);

    prefixTlv = Get<Leader>().FindPrefix(mPrefix);
    VerifyOrExit(prefixTlv != nullptr);

    brSubTlv = NetworkData::FindBorderRouter(*prefixTlv, mStable);
    VerifyOrExit(brSubTlv != nullptr);

    for (const BorderRouterEntry *entry = brSubTlv->GetFirstEntry(); entry <= brSubTlv->GetLastEntry();
         entry                          = entry->GetNext())
    {
        uint16_t entryFlags      = entry->GetFlags();
        int8_t   entryPreference = BorderRouterEntry::PreferenceFromFlags(entryFlags);

        // Count an existing entry in the network data if its flags
        // match ours and and its preference is same or higher than our
        // preference. We do not count matching entries at a lower
        // preference than ours. This ensures that a device with higher
        // preference entry publishes its entry even when there are many
        // lower preference similar entries in the network data
        // (potentially causing a lower preference entry to be removed).

        if ((BorderRouterEntry::FlagsWithoutPreference(entryFlags) == flagsWithoutPreference) &&
            (entryPreference >= preference))
        {
            aNumEntries++;

            // We prefer an entry if it has strictly higher preference
            // than ours or if it has same preference with a smaller
            // RLOC16.

            if ((entryPreference > preference) || (entry->GetRloc() < Get<Mle::Mle>().GetRloc16()))
            {
                aNumPreferredEntries++;
            }
        }
    }

exit:
    return;
}

void Publisher::PrefixEntry::CountExternalRouteEntries(uint8_t &aNumEntries, uint8_t &aNumPreferredEntries) const
{
    const PrefixTlv *  prefixTlv;
    const HasRouteTlv *hrSubTlv;
    int8_t             preference             = HasRouteEntry::PreferenceFromFlags(static_cast<uint8_t>(mFlags));
    uint8_t            flagsWithoutPreference = HasRouteEntry::FlagsWithoutPreference(static_cast<uint8_t>(mFlags));

    prefixTlv = Get<Leader>().FindPrefix(mPrefix);
    VerifyOrExit(prefixTlv != nullptr);

    hrSubTlv = NetworkData::FindHasRoute(*prefixTlv, mStable);
    VerifyOrExit(hrSubTlv != nullptr);

    for (const HasRouteEntry *entry = hrSubTlv->GetFirstEntry(); entry <= hrSubTlv->GetLastEntry();
         entry                      = entry->GetNext())
    {
        uint8_t entryFlags      = entry->GetFlags();
        int8_t  entryPreference = BorderRouterEntry::PreferenceFromFlags(entryFlags);

        // Count an existing entry in the network data if its flags
        // match ours and and its preference is same or higher than our
        // preference. We do not count matching entries at a lower
        // preference than ours. This ensures that a device with higher
        // preference entry publishes its entry even when there are many
        // lower preference similar entries in the network data
        // (potentially causing a lower preference entry to be removed).

        if ((HasRouteEntry::FlagsWithoutPreference(entryFlags) == flagsWithoutPreference) &&
            (entryPreference >= preference))
        {
            aNumEntries++;

            // We prefer an entry if it has strictly higher preference
            // than ours or if it has same preference with a smaller
            // RLOC16.

            if ((entryPreference > preference) || (entry->GetRloc() < Get<Mle::Mle>().GetRloc16()))
            {
                aNumPreferredEntries++;
            }
        }
    }

exit:
    return;
}

} // namespace NetworkData
} // namespace ot

#endif // OPENTHREAD_CONFIG_NETDATA_PUBLISHER_ENABLE
