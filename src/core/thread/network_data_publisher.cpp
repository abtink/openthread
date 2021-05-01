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
}

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

    if (registerWithLeader)
    {
        Get<Notifier>().HandleServerDataUpdated();
    }
}

//---------------------------------------------------------------------------------------------------------------------
// Publisher::Entry

Publisher::Entry::Entry(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mState(kRemoved)
{
}

void Publisher::Entry::SetState(State aState)
{
    VerifyOrExit(mState != aState);

    otLogInfoNetData("Publisher: %s - State: %s -> %s", ToString().AsCString(), StateToString(mState),
                     StateToString(aState));
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

    case kRemoved:
        break;
    }
}

void Publisher::Entry::LogUpdateTime(void) const
{
    otLogInfoNetData("Publisher: %s - update in %u msec", ToString().AsCString(),
                     GetUpdateTime() - TimerMilli::GetNow());
}

Publisher::Entry::InfoString Publisher::Entry::ToString(void) const
{
    InfoString   string;
    StringWriter writer(string);

#if OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE
    if (this == &Get<Publisher>().mDnsSrpServiceEntry)
    {
        writer.Append("DNS/SRP service");
    }
#endif

    return string;
}

const char *Publisher::Entry::StateToString(State aState)
{
    static const char *const kStateStrings[] = {
        "ToAdd",    // (0) kToAdd
        "Adding",   // (1) kAdding
        "Added",    // (2) kAdded
        "Removing", // (3) kRemoving
        "Removed",  // (4) kRemoved
    };

    static_assert(0 == kToAdd, "kToAdd value is not correct");
    static_assert(1 == kAdding, "kAdding value is not correct");
    static_assert(2 == kAdded, "kAdded value is not correct");
    static_assert(3 == kRemoving, "kRemoving value is not correct");
    static_assert(4 == kRemoved, "kRemoved value is not correct");

    return kStateStrings[aState];
}

#if OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE

//---------------------------------------------------------------------------------------------------------------------
// Publisher::DnsSrpServiceEntry

Publisher::DnsSrpServiceEntry::DnsSrpServiceEntry(Instance &aInstance)
    : Entry(aInstance)
{
}

void Publisher::DnsSrpServiceEntry::PublishAnycast(uint8_t aSerialNumber)
{
    Remove(/* aRegisterWithLeader */ true);

    otLogInfoNetData("Publisher: Publishing DNS/SRP service anycast (serial-num:%d)", aSerialNumber);

    mType                        = kTypeAnycast;
    mInfo.mAnycast.mSerialNumber = aSerialNumber;
    SetState(kToAdd);

    Process();
}

void Publisher::DnsSrpServiceEntry::PublishUnicast(const Ip6::Address &aAddress, uint16_t aPort)
{
    Remove(/* aRegisterWithLeader */ true);

    otLogInfoNetData("Publisher: Publishing DNS/SRP service unicast (%s, port:%d)", aAddress.ToString().AsCString(),
                     aPort);

    mType                   = kTypeUnicast;
    mInfo.mUnicast.mAddress = aAddress;
    mInfo.mUnicast.mPort    = aPort;
    SetState(kToAdd);

    Process();
}

void Publisher::DnsSrpServiceEntry::PublishUnicast(uint16_t aPort)
{
    Remove(/* aRegisterWithLeader */ true);

    otLogInfoNetData("Publisher: Publishing DNS/SRP service unicast (ml-eid, port:%d)", aPort);

    mType                   = kTypeUincastMeshLocalEid;
    mInfo.mUnicast.mAddress = Get<Mle::Mle>().GetMeshLocal64();
    mInfo.mUnicast.mPort    = aPort;
    SetState(kToAdd);

    Process();
}

void Publisher::DnsSrpServiceEntry::Unpublish(void)
{
    otLogInfoNetData("Publisher: Unpublishing DNS/SRP service");

    Remove(/* aRegisterWithLeader */ true);
}

bool Publisher::DnsSrpServiceEntry::HandleTimer(void)
{
    bool registerWithLeader = false;

    // Timer is used to delay adding/removing the entry. If we have
    // reached `GetUpdateTime()` add or remove the entry. Otherwise,
    // restart the timer (note that timer can be shared between
    // different published entries). This method returns a `bool`
    // indicating whether or not anything in local Network Data got
    // changed so to notify the leader and register the changes.

    VerifyOrExit((GetState() == kAdding) || (GetState() == kRemoved));

    if (GetUpdateTime() <= TimerMilli::GetNow())
    {
        registerWithLeader = (GetState() == kAdding) ? Add(registerWithLeader) : Remove(registerWithLeader);
    }
    else
    {
        Get<Publisher>().GetTimer().FireAtIfEarlier(GetUpdateTime());
    }

exit:
    return registerWithLeader;
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

            Remove(registerWithLeader);
            SetState(kAdding);
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
            Service::DnsSrpAnycast::ServiceData(mInfo.mAnycast.mSerialNumber), aRegisterWithLeader));
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

bool Publisher::DnsSrpServiceEntry::Remove(bool aRegisterWithLeader)
{
    // Removes the service entry from network data (if it was added).

    bool registerWithLeader = false;

    VerifyOrExit((GetState() == kAdded) || (GetState() == kRemoving));

    switch (mType)
    {
    case kTypeAnycast:
        SuccessOrExit(Get<Service::Manager>().Remove<Service::DnsSrpAnycast>(
            Service::DnsSrpAnycast::ServiceData(mInfo.mAnycast.mSerialNumber), aRegisterWithLeader));
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

exit:
    SetState(kRemoved);
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

    VerifyOrExit(GetState() != kRemoved);

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
    // "serial number" value). We prefer the entries associated with
    // smaller RLCO16.

    Service::DnsSrpAnycast::ServiceData serviceData(mInfo.mAnycast.mSerialNumber);
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

} // namespace NetworkData
} // namespace ot

#endif // OPENTHREAD_CONFIG_NETDATA_PUBLISHER_ENABLE
