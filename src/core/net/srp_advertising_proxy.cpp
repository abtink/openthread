/*
 *  Copyright (c) 2023, The OpenThread Authors.
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
 *   This file includes implementation of SRP Advertising Proxy.
 */

#include "srp_advertising_proxy.hpp"

#if OPENTHREAD_CONFIG_SRP_SERVER_ADVERTISING_PROXY_ENABLE

#include "common/as_core_type.hpp"
#include "common/debug.hpp"
#include "common/instance.hpp"
#include "common/locator_getters.hpp"
#include "common/log.hpp"
#include "common/serial_number.hpp"

namespace ot {
namespace Srp {

RegisterLogModule("SrpAdvProxy");

//---------------------------------------------------------------------------------------------------------------------
// AdvertisingProxy

AdvertisingProxy::AdvertisingProxy(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mState(kStateStopped)
    , mCurrentRequestId(0)
    , mAdvTimeout(kAdvTimeout)
    , mTimer(aInstance)
    , mTasklet(aInstance)
{
    mCounters.Clear();
}

void AdvertisingProxy::Start(void)
{
    VerifyOrExit(mState != kStateRunning);

    mState = kStateRunning;
    mCounters.mStateChanges++;
    LogInfo("Started");

    // Advertise all existing and committed entries on SRP sever.

    for (Host &host : Get<Server>().mHosts)
    {
        LogInfo("Adv existing host '%s'", host.GetFullName());
        Advertise(host);
    }

exit:
    return;
}

void AdvertisingProxy::Stop(void)
{
    VerifyOrExit(mState != kStateStopped);

    mState = kStateStopped;
    mCounters.mStateChanges++;

    while (true)
    {
        OwnedPtr<AdvInfo> advPtr = mAdvInfoList.Pop();

        if (advPtr.IsNull())
        {
            break;
        }

        mCounters.mAdvRejected++;

        advPtr->mError = kErrorAbort;
        advPtr->mHost.mAdvIdRange.Clear();
        advPtr->mBlockingAdv = nullptr;
        advPtr->SignalServerToCommit();
    }

    for (Host &host : Get<Server>().GetHosts())
    {
        host.mAdvIdRange.Clear();
        host.mAdvId        = kInvalidRequestId;
        host.mIsAdvertised = false;

        for (Service &service : host.mServices)
        {
            service.mAdvId        = kInvalidRequestId;
            service.mIsAdvertised = false;
        }
    }

    LogInfo("Stopped");

exit:
    return;
}

void AdvertisingProxy::UpdateState(void)
{
    if (!Get<Dnssd>().IsReady())
    {
        Stop();
        ExitNow();
    }

    switch (Get<Server>().GetState())
    {
    case Server::kStateDisabled:
    case Server::kStateStopped:
        Stop();
        break;

    case Server::kStateRunning:
        Start();
        break;
    }

exit:
    return;
}

AdvertisingProxy::RequestId AdvertisingProxy::AllocateNextRequestId(void)
{
    mCurrentRequestId++;

    if (kInvalidRequestId == mCurrentRequestId)
    {
        mCurrentRequestId++;
    }

    return mCurrentRequestId;
}

void AdvertisingProxy::AdvertiseRemovalOf(Host &aHost)
{
    LogInfo("Adv removal of host '%s'", aHost.GetFullName());
    mCounters.mAdvHostRemovals++;

    VerifyOrExit(mState == kStateRunning);
    VerifyOrExit(aHost.IsDeleted());

    aHost.mShouldAdvertise = !aHost.mIsAdvertised;

    for (Service &service : aHost.mServices)
    {
        if (!service.mIsDeleted)
        {
            service.mIsDeleted    = true;
            service.mIsAdvertised = false;
        }

        service.mShouldAdvertise = !service.mIsAdvertised;
    }

    for (AdvInfo &adv : mAdvInfoList)
    {
        Host &advHost = adv.mHost;

        if (!aHost.Matches(advHost.GetFullName()) || advHost.IsDeleted())
        {
            continue;
        }

        for (Service &advService : advHost.mServices)
        {
            Service *service;

            if (advService.IsDeleted())
            {
                continue;
            }

            service = aHost.FindService(advService.GetInstanceName());

            if (service == nullptr)
            {
                UnregisterService(advService);
            }
            else
            {
                service->mShouldAdvertise = true;
            }

            advService.mAdvId        = kInvalidRequestId;
            advService.mIsReplaced   = true;
            advService.mIsAdvertised = false;
        }

        advHost.mAdvId        = kInvalidRequestId;
        advHost.mIsReplaced   = true;
        advHost.mIsAdvertised = false;
        advHost.mAdvIdRange.Clear();

        adv.mError = kErrorAbort;
        mTasklet.Post();
    }

    for (Service &service : aHost.mServices)
    {
        if (service.mShouldAdvertise)
        {
            UnregisterService(service);
        }
    }

    if (aHost.mShouldAdvertise)
    {
        UnregisterHost(aHost);
    }

exit:
    return;
}

void AdvertisingProxy::AdvertiseRemovalOf(Service &aService)
{
    LogInfo("Adv removal of service '%s' '%s'", aService.GetInstanceLabel(), aService.GetServiceName());
    mCounters.mAdvServiceRemovals++;

    VerifyOrExit((mState == kStateRunning) && !aService.mIsAdvertised);

    aService.mShouldAdvertise = true;

    for (const AdvInfo &adv : mAdvInfoList)
    {
        const Host    &advHost = adv.mHost;
        const Service *advService;

        if (!aService.mHost->Matches(advHost.GetFullName()))
        {
            continue;
        }

        if (advHost.IsDeleted())
        {
            break;
        }

        advService = advHost.FindService(aService.GetInstanceName());

        if ((advService != nullptr) && !advService->IsDeleted())
        {
            aService.mShouldAdvertise = false;
            break;
        }
    }

    if (aService.mShouldAdvertise)
    {
        UnregisterService(aService);
    }

exit:
    return;
}

void AdvertisingProxy::Advertise(Host &aHost, const Server::MessageMetadata &aMetadata)
{
    AdvInfo *advPtr = nullptr;
    Host    *existingHost;

    LogInfo("Adv update for '%s'", aHost.GetFullName());

    mCounters.mAdvTotal++;

    VerifyOrExit(mState == kStateRunning);

    advPtr = AdvInfo::Allocate(aHost, aMetadata, mAdvTimeout);
    VerifyOrExit(advPtr != nullptr);
    mAdvInfoList.Push(*advPtr);

    if (!aHost.IsDeleted() && !HasExternallyReachableAddress(aHost))
    {
        LogInfo("No externally reachable addr on '%s' - skip adv", aHost.GetFullName());
        ExitNow();
    }

    // Compare the new `aHost` with outstanding advertisements and
    // already committed entries on server.

    for (AdvInfo &adv : mAdvInfoList)
    {
        if (!aHost.Matches(adv.mHost.GetFullName()))
        {
            continue;
        }

        if (CompareAndUpdateHostAndServices(aHost, adv.mHost))
        {
            // If the new `aHost` replaces an entry in the outstanding
            // `adv`, we mark the new advertisement as blocked so
            // that it is not committed before the earlier one. This
            // ensures that SRP Updates are committed in the order
            // they are advertised, avoiding issues such as re-adding
            // a removed entry due to a delay in registration on
            // infra DNS-SD.

            if ((advPtr != nullptr) && (advPtr->mBlockingAdv == nullptr))
            {
                mCounters.mAdvReplaced++;
                advPtr->mBlockingAdv = &adv;
            }
        }
    }

    existingHost = Get<Server>().mHosts.FindMatching(aHost.GetFullName());

    if (existingHost != nullptr)
    {
        CompareAndUpdateHostAndServices(aHost, *existingHost);
    }

    Advertise(aHost);

exit:
    if (advPtr != nullptr)
    {
        if (advPtr->IsCompleted())
        {
            mTasklet.Post();
        }
        else
        {
            mTimer.FireAtIfEarlier(advPtr->mExpireTime);
        }
    }
    else
    {
        LogInfo("Adv skipped '%s'", aHost.GetFullName());
        mCounters.mAdvSkipped++;
        Get<Server>().CommitSrpUpdate(kErrorNone, aHost, aMetadata);
    }
}

void AdvertisingProxy::Advertise(Host &aHost)
{
    if (aHost.IsDeleted())
    {
        for (Service &service : aHost.mServices)
        {
            if (!service.mIsAdvertised)
            {
                UnregisterService(service);
            }
        }

        if (!aHost.mIsAdvertised)
        {
            UnregisterHost(aHost);
        }

        ExitNow();
    }

    // Decide whether to advertise the host and its services if not
    // decided yet. We need to determine this before calling
    // `RegisterHost` or `RegisterService`. This ensures that
    // `mAdvIdRange` is properly set on `aHost` before we receive any
    // `HandleRegistered` callbacks (which the DNS-SD platform can
    // invoke from within `RegisterHost()` or `RegisterService()`
    // calls).

    if (!aHost.mIsAdvertised && (aHost.mAdvId == kInvalidRequestId))
    {
        aHost.mShouldAdvertise = true;
        UpdateAdvIdOn(aHost, AllocateNextRequestId());
    }

    for (Service &service : aHost.mServices)
    {
        if (!service.IsDeleted() && !service.mIsAdvertised && (service.mAdvId == kInvalidRequestId))
        {
            service.mShouldAdvertise = true;
            UpdateAdvIdOn(service, AllocateNextRequestId());
        }
    }

    if (!aHost.mIsAdvertised && aHost.mShouldAdvertise)
    {
        RegisterHost(aHost);
    }

    for (Service &service : aHost.mServices)
    {
        if (service.mIsAdvertised)
        {
            continue;
        }

        if (service.IsDeleted())
        {
            UnregisterService(service);
        }
        else if (service.mShouldAdvertise)
        {
            RegisterService(service);
        }
    }

exit:
    return;
}

bool AdvertisingProxy::HasExternallyReachableAddress(const Host &aHost) const
{
    bool hasAddress = false;

    OT_ASSERT(!aHost.IsDeleted());

    for (const Ip6::Address &address : aHost.mAddresses)
    {
        if (!address.IsLinkLocal() && !Get<Mle::Mle>().IsMeshLocalAddress(address))
        {
            hasAddress = true;
            break;
        }
    }

    return hasAddress;
}

bool AdvertisingProxy::CompareAndUpdateHostAndServices(Host &aHost, Host &aExistingHost)
{
    // This method compares and updates flags used by `AdvertisingProxy`
    // on new `aHost` and `aExistingHost` with same host name.
    //
    // It returns a boolean indicating whether the new `aHost` replaced
    // any of entries on `aExistingHost`.
    //
    // The `AdvertisingProxy` uses the following flags and variables
    // on `Host` and `Service` entries:
    //
    // - `mIsAdvertised` indicates whether or not the entry has been
    //   successfully advertised by the proxy.
    //
    // - `mAdvId` specifies the ongoing registration request ID
    //   associated with this entry by the proxy. A value of zero or
    //   `kInvalidRequestId` indicates that there is no ongoing
    //   registration for this entry.
    //
    // - `mIsReplaced` tracks whether this entry has been replaced by
    //   a newer advertisement request that changes some of its
    //   parameters. For example, the address list could have been
    //   changed on a `Host`, or TXT Data, or the list of sub-types,
    //   or port number could have been changed on a `Service`.
    //
    // - `mShouldAdvertise` is only used in the `Advertise()` call
    //   chain to track whether we need to advertise the entry.

    bool replaced = false;

    VerifyOrExit(&aHost != &aExistingHost);

    replaced = CompareAndUpdateHost(aHost, aExistingHost);

    VerifyOrExit(!aHost.IsDeleted());

    // Compare services of `aHost` against services of
    // `aExistingHost`.

    for (Service &service : aHost.mServices)
    {
        Service *existingService = aExistingHost.mServices.FindMatching(service.GetInstanceName());

        if (existingService != nullptr)
        {
            replaced |= CompareAndUpdateService(service, *existingService);
        }
    }

exit:
    return replaced;
}

bool AdvertisingProxy::CompareAndUpdateHost(Host &aHost, Host &aExistingHost)
{
    bool replaced = false;

    if (aHost.IsDeleted())
    {
        // Thew new `aHost` is removing the host and all its services.

        if (aExistingHost.IsDeleted())
        {
            if (!aHost.mShouldAdvertise && !aExistingHost.mIsReplaced && aExistingHost.mIsAdvertised)
            {
                // Existing host already removed the same host and
                // unregistered the entry.

                aHost.mIsAdvertised = true;
            }

            ExitNow();
        }

        // `aExistingHost` is updating the same host that is being
        // removed by the new `aHost`. We need to advertise the new
        // `aHost` to make sure it is unregistered on DNS-SD/mDNS. We
        // should also stop waiting for any outstanding registration
        // requests associated with `aExistingHost` and unregister
        // any services being registered by it that are not included
        // in the new `aHost`.

        aHost.mShouldAdvertise = true;

        if (!aExistingHost.mAdvIdRange.IsEmpty())
        {
            aExistingHost.mAdvIdRange.Clear();
            mTasklet.Post();
        }

        for (Service &existingService : aExistingHost.mServices)
        {
            if (existingService.IsDeleted())
            {
                continue;
            }

            existingService.mAdvId      = kInvalidRequestId;
            existingService.mIsReplaced = true;

            if (!aHost.HasService(existingService.GetInstanceName()))
            {
                UnregisterService(existingService);
                existingService.mIsAdvertised = false;
            }
        }

        aExistingHost.mAdvId        = kInvalidRequestId;
        aExistingHost.mIsReplaced   = true;
        aExistingHost.mIsAdvertised = false;
        replaced                    = true;
        ExitNow();
    }

    // If we determined that `aHost` was previously advertised,
    // no need to update any existing hosts.

    VerifyOrExit(!aHost.mIsAdvertised);

    if (aHost.mShouldAdvertise || aExistingHost.mIsReplaced || !HostsMatch(aHost, aExistingHost))
    {
        // If we previously determined that we should advertise the
        // new `aHost`, we enter this block to mark `aExistingHost`
        // as being replaced.
        //
        // If `aExistingHost` was already marked as replaced, we
        // cannot compare it to the new `aHost`. Therefore, we assume
        // that there may be a change and always advertise the new
        // `aHost`. Otherwise, we compare it to the new `aHost` using
        // `HostsMatch()` and only if there are any differences, we
        // mark that `aHost` needs to be advertised.

        aExistingHost.mIsReplaced = true;
        replaced                  = true;

        if (aHost.mAdvId == kInvalidRequestId)
        {
            aHost.mShouldAdvertise = true;
            UpdateAdvIdOn(aHost, AllocateNextRequestId());
        }

        // If there is an outstanding registration request for
        // `aExistngHost` we replace it with the request ID of the
        // new `aHost` registration.

        if (aExistingHost.mAdvId != kInvalidRequestId)
        {
            UpdateAdvIdOn(aExistingHost, aHost.mAdvId);
        }

        ExitNow();
    }

    // `aHost` fully matches `aExistingHost` and `aExistingHost` was
    // not replaced.

    VerifyOrExit(aHost.mAdvId == kInvalidRequestId);

    if (aExistingHost.mIsAdvertised)
    {
        aHost.mIsAdvertised = true;
    }
    else if (aExistingHost.mAdvId != kInvalidRequestId)
    {
        // There is an outstanding registration request for
        // `aExistingHost`. We use the same ID for the new `aHost`.
        UpdateAdvIdOn(aHost, aExistingHost.mAdvId);
    }
    else
    {
        // The earlier advertisement of `aExistingHost` seems to have
        // failed since there is no outstanding registration request
        // (no ID) and it is not marked as advertised. We mark the
        // new `aHost` to be advertised (to try again) but keep
        // `aExistingHost` as is.

        aHost.mShouldAdvertise = true;
        UpdateAdvIdOn(aHost, AllocateNextRequestId());
    }

exit:
    return replaced;
}

bool AdvertisingProxy::CompareAndUpdateService(Service &aService, Service &aExistingService)
{
    bool replaced = false;

    if (aService.IsDeleted())
    {
        if (aExistingService.IsDeleted())
        {
            if (!aService.mShouldAdvertise && !aExistingService.mIsReplaced && aExistingService.mIsAdvertised)
            {
                aService.mIsAdvertised = true;
            }

            ExitNow();
        }

        aService.mShouldAdvertise = true;

        aExistingService.mIsReplaced = true;
        replaced                     = true;

        if (aExistingService.mAdvId != kInvalidRequestId)
        {
            // If there is an outstanding registration request for the
            // existing service, clear the ID and re-calculate the
            // `mAdvIdRange` to determine if advertisement of this
            // entry is finished and if so post the tasklet to signal
            // this.

            aExistingService.mAdvId        = kInvalidRequestId;
            aExistingService.mIsAdvertised = false;

            aExistingService.mHost->mAdvIdRange.Clear();

            for (Service &service : aExistingService.mHost->mServices)
            {
                if (service.mAdvId != kInvalidRequestId)
                {
                    aExistingService.mHost->mAdvIdRange.Add(service.mAdvId);
                }
            }

            if (aExistingService.mHost->mAdvIdRange.IsEmpty())
            {
                mTasklet.Post();
            }
        }

        ExitNow();
    }

    VerifyOrExit(!aService.mIsAdvertised);

    if (aService.mShouldAdvertise || aExistingService.mIsReplaced || !ServicesMatch(aService, aExistingService))
    {
        aExistingService.mIsReplaced = true;
        replaced                     = true;

        if (aService.mAdvId == kInvalidRequestId)
        {
            aService.mShouldAdvertise = true;
            UpdateAdvIdOn(aService, AllocateNextRequestId());
        }

        if (aExistingService.mAdvId != kInvalidRequestId)
        {
            UpdateAdvIdOn(aExistingService, aService.mAdvId);
        }

        ExitNow();
    }

    VerifyOrExit(aService.mAdvId == kInvalidRequestId);

    if (aExistingService.mIsAdvertised)
    {
        aService.mIsAdvertised = true;
    }
    else if (aExistingService.mAdvId != kInvalidRequestId)
    {
        UpdateAdvIdOn(aService, aExistingService.mAdvId);
    }
    else
    {
        aService.mShouldAdvertise = true;
        UpdateAdvIdOn(aService, AllocateNextRequestId());
    }

exit:
    return replaced;
}

bool AdvertisingProxy::HostsMatch(const Host &aFirstHost, const Host &aSecondHost)
{
    bool match = false;

    VerifyOrExit(aFirstHost.IsDeleted() == aSecondHost.IsDeleted());

    if (aFirstHost.IsDeleted())
    {
        match = true;
        ExitNow();
    }

    VerifyOrExit(aFirstHost.mAddresses.GetLength() == aSecondHost.mAddresses.GetLength());

    for (const Ip6::Address &address : aFirstHost.mAddresses)
    {
        VerifyOrExit(aSecondHost.mAddresses.Contains(address));
    }

    match = true;

exit:
    return match;
}

bool AdvertisingProxy::ServicesMatch(const Service &aFirstService, const Service &aSecondService)
{
    bool match = false;

    VerifyOrExit(aFirstService.IsDeleted() == aSecondService.IsDeleted());

    if (aFirstService.IsDeleted())
    {
        match = true;
        ExitNow();
    }

    VerifyOrExit(aFirstService.GetPort() == aSecondService.GetPort());
    VerifyOrExit(aFirstService.GetWeight() == aSecondService.GetWeight());
    VerifyOrExit(aFirstService.GetPriority() == aSecondService.GetPriority());
    VerifyOrExit(aFirstService.GetTtl() == aSecondService.GetTtl());

    VerifyOrExit(aFirstService.GetNumberOfSubTypes() == aSecondService.GetNumberOfSubTypes());

    for (uint16_t index = 0; index < aFirstService.GetNumberOfSubTypes(); index++)
    {
        VerifyOrExit(aSecondService.HasSubTypeServiceName(aFirstService.GetSubTypeServiceNameAt(index)));
    }

    VerifyOrExit(aFirstService.GetTxtDataLength() == aSecondService.GetTxtDataLength());
    VerifyOrExit(!memcmp(aFirstService.GetTxtData(), aSecondService.GetTxtData(), aFirstService.GetTxtDataLength()));

    match = true;

exit:
    return match;
}

bool AdvertisingProxy::UpdateAdvIdOn(Host &aHost, RequestId aId)
{
    bool didUpdate = false;

    VerifyOrExit(aHost.mAdvId != aId);

    if (aHost.mAdvId != kInvalidRequestId)
    {
        aHost.mAdvIdRange.Remove(aHost.mAdvId);
    }

    aHost.mAdvId = aId;

    if (aId != kInvalidRequestId)
    {
        aHost.mAdvIdRange.Add(aId);
    }

    didUpdate = true;

exit:
    return didUpdate;
}

bool AdvertisingProxy::UpdateAdvIdOn(Service &aService, RequestId aId)
{
    bool didUpdate = false;

    VerifyOrExit(aService.mAdvId != aId);

    if (aService.mAdvId != kInvalidRequestId)
    {
        aService.mHost->mAdvIdRange.Remove(aService.mAdvId);
    }

    aService.mAdvId = aId;

    if (aId != kInvalidRequestId)
    {
        aService.mHost->mAdvIdRange.Add(aId);
    }

    didUpdate = true;

exit:
    return didUpdate;
}

void AdvertisingProxy::RegisterHost(Host &aHost)
{
    Error                     error = kErrorNone;
    Dnssd::Host               hostInfo;
    DnsName                   hostName;
    Heap::Array<Ip6::Address> hostAddresses;

    aHost.mShouldAdvertise = false;

    CopyNameAndRemoveDomain(hostName, aHost.GetFullName());

    SuccessOrExit(error = hostAddresses.ReserveCapacity(aHost.mAddresses.GetLength()));

    for (const Ip6::Address &address : aHost.mAddresses)
    {
        if (!address.IsLinkLocal() && !Get<Mle::Mle>().IsMeshLocalAddress(address))
        {
            IgnoreError(hostAddresses.PushBack(address));
        }
    }

    OT_ASSERT(hostAddresses.GetLength() != 0);

    LogInfo("Registering host '%s', id:%lu", hostName, ToUlong(aHost.mAdvId));

    hostInfo.Clear();
    hostInfo.mHostName     = hostName;
    hostInfo.mAddresses    = hostAddresses.AsCArray();
    hostInfo.mNumAddresses = hostAddresses.GetLength();
    hostInfo.mTtl          = aHost.GetTtl();
    Get<Dnssd>().RegisterHost(hostInfo, aHost.mAdvId, HandleRegistered);

exit:
    if (error != kErrorNone)
    {
        LogWarn("Error %s registering host '%s'", ErrorToString(error), hostName);
    }
}

void AdvertisingProxy::UnregisterHost(Host &aHost)
{
    Dnssd::Host hostInfo;
    DnsName     hostName;

    aHost.mShouldAdvertise = false;
    aHost.mIsAdvertised    = true;

    CopyNameAndRemoveDomain(hostName, aHost.GetFullName());

    LogInfo("Unregistering host '%s'", hostName);

    hostInfo.Clear();
    hostInfo.mHostName = hostName;
    Get<Dnssd>().UnregisterHost(hostInfo, 0, nullptr);
}

void AdvertisingProxy::RegisterService(Service &aService)
{
    Error                     error = kErrorNone;
    Dnssd::Service            serviceInfo;
    DnsName                   hostName;
    DnsName                   serviceName;
    Heap::Array<Heap::String> subTypeHeapStrings;
    Heap::Array<const char *> subTypeLabels;

    aService.mShouldAdvertise = false;

    CopyNameAndRemoveDomain(hostName, aService.GetHost().GetFullName());
    CopyNameAndRemoveDomain(serviceName, aService.GetServiceName());

    SuccessOrExit(error = subTypeHeapStrings.ReserveCapacity(aService.mSubTypes.GetLength()));
    SuccessOrExit(error = subTypeLabels.ReserveCapacity(aService.mSubTypes.GetLength()));

    for (const Heap::String &subTypeName : aService.mSubTypes)
    {
        char         label[Dns::Name::kMaxLabelSize];
        Heap::String labelString;

        IgnoreError(Server::Service::ParseSubTypeServiceName(subTypeName.AsCString(), label, sizeof(label)));
        SuccessOrExit(error = labelString.Set(label));
        IgnoreError(subTypeHeapStrings.PushBack(static_cast<Heap::String &&>(labelString)));
        IgnoreError(subTypeLabels.PushBack(subTypeHeapStrings.Back()->AsCString()));
    }

    LogInfo("Registering service '%s' '%s' on '%s', id:%lu", aService.GetInstanceLabel(), serviceName, hostName,
            ToUlong(aService.mAdvId));

    serviceInfo.Clear();
    serviceInfo.mHostName            = hostName;
    serviceInfo.mServiceInstance     = aService.GetInstanceLabel();
    serviceInfo.mServiceType         = serviceName;
    serviceInfo.mSubTypeLabels       = subTypeLabels.AsCArray();
    serviceInfo.mSubTypeLabelsLength = subTypeLabels.GetLength();
    serviceInfo.mTxtData             = aService.GetTxtData();
    serviceInfo.mTxtDataLength       = aService.GetTxtDataLength();
    serviceInfo.mPort                = aService.GetPort();
    serviceInfo.mWeight              = aService.GetWeight();
    serviceInfo.mPriority            = aService.GetPriority();
    serviceInfo.mTtl                 = aService.GetTtl();
    Get<Dnssd>().RegisterService(serviceInfo, aService.mAdvId, HandleRegistered);

exit:
    if (error != kErrorNone)
    {
        LogWarn("Error %s registering service '%s' '%s'", ErrorToString(error), aService.GetInstanceLabel(),
                serviceName);
    }
}

void AdvertisingProxy::UnregisterService(Service &aService)
{
    Dnssd::Service serviceInfo;
    DnsName        hostName;
    DnsName        serviceName;

    aService.mShouldAdvertise = false;
    aService.mIsAdvertised    = true;

    CopyNameAndRemoveDomain(hostName, aService.GetHost().GetFullName());
    CopyNameAndRemoveDomain(serviceName, aService.GetServiceName());

    LogInfo("Unregistering service '%s' '%s' on '%s'", aService.GetInstanceLabel(), serviceName, hostName);

    serviceInfo.Clear();
    serviceInfo.mHostName        = hostName;
    serviceInfo.mServiceInstance = aService.GetInstanceLabel();
    serviceInfo.mServiceType     = serviceName;
    Get<Dnssd>().UnregisterService(serviceInfo, 0, nullptr);
}

void AdvertisingProxy::CopyNameAndRemoveDomain(DnsName &aName, const char *aFullName)
{
    const char *domain       = Get<Server>().GetDomain();
    uint16_t    length       = StringLength(aFullName, Dns::Name::kMaxNameSize);
    uint16_t    domainLength = StringLength(domain, Dns::Name::kMaxNameSize);

    OT_ASSERT(Dns::Name::IsSubDomainOf(aFullName, domain));

    memcpy(&aName[0], aFullName, length - domainLength);
    aName[length - domainLength - 1] = '\0';
}

void AdvertisingProxy::HandleRegistered(otInstance *aInstance, otPlatDnssdRequestId aRequestId, otError aError)
{
    AsCoreType(aInstance).Get<AdvertisingProxy>().HandleRegistered(aRequestId, aError);
}

void AdvertisingProxy::HandleRegistered(RequestId aRequestId, Error aError)
{
    LogInfo("Register callback, id:%lu, error:%s", ToUlong(aRequestId), ErrorToString(aError));

    VerifyOrExit(mState == kStateRunning);

    for (Host &host : Get<Server>().mHosts)
    {
        HandleRegisteredRequestIdOn(host, aRequestId, aError);
    }

    for (AdvInfo &adv : mAdvInfoList)
    {
        if (HandleRegisteredRequestIdOn(adv.mHost, aRequestId, aError))
        {
            if (adv.mError == kErrorNone)
            {
                adv.mError = aError;
            }

            if (adv.IsCompleted())
            {
                mTasklet.Post();
            }
        }
    }

exit:
    return;
}

bool AdvertisingProxy::HandleRegisteredRequestIdOn(Host &aHost, RequestId aRequestId, Error aError)
{
    // Handles "registration request callback" for `aRequestId` on a
    // given `aHost`. Returns `true`, if the ID matched an entry
    // on `aHost` and `aHost` was updated, `false` otherwise.

    bool didUpdate = false;

    VerifyOrExit(aHost.mAdvIdRange.Contains(aRequestId));

    // Determine the `mAdvIdRange` as we go through all
    // entries.

    aHost.mAdvIdRange.Clear();

    if (aHost.mAdvId == aRequestId)
    {
        aHost.mAdvId        = kInvalidRequestId;
        aHost.mIsAdvertised = (aError == kErrorNone);
        didUpdate           = true;
    }
    else if (aHost.mAdvId != kInvalidRequestId)
    {
        aHost.mAdvIdRange.Add(aHost.mAdvId);
    }

    for (Service &service : aHost.mServices)
    {
        if (service.mAdvId == aRequestId)
        {
            service.mAdvId        = kInvalidRequestId;
            service.mIsAdvertised = (aError == kErrorNone);
            didUpdate             = true;
        }
        else if (service.mAdvId != kInvalidRequestId)
        {
            aHost.mAdvIdRange.Add(service.mAdvId);
        }
    }

exit:
    return didUpdate;
}

void AdvertisingProxy::HandleTimer(void)
{
    TimeMilli           now      = TimerMilli::GetNow();
    TimeMilli           nextTime = now.GetDistantFuture();
    OwningList<AdvInfo> expiredList;

    VerifyOrExit(mState == kStateRunning);

    mAdvInfoList.RemoveAllMatching(AdvInfo::ExpirationChecker(now), expiredList);

    for (AdvInfo &adv : mAdvInfoList)
    {
        nextTime = Min(adv.mExpireTime, nextTime);
    }

    if (nextTime != now.GetDistantFuture())
    {
        mTimer.FireAtIfEarlier(nextTime);
    }

    for (AdvInfo &adv : expiredList)
    {
        adv.mError       = kErrorResponseTimeout;
        adv.mBlockingAdv = nullptr;
        adv.mHost.mAdvIdRange.Clear();
        SignalAdvCompleted(adv);
    }

exit:
    return;
}

void AdvertisingProxy::HandleTasklet(void)
{
    VerifyOrExit(mState == kStateRunning);

    while (true)
    {
        OwningList<AdvInfo> completedList;

        mAdvInfoList.RemoveAllMatching(AdvInfo::CompletionChecker(), completedList);

        VerifyOrExit(!completedList.IsEmpty());

        // `RemoveAllMatching()` reverses the order of removed entries
        // from `mAdvInfoList` (which itself keeps the later requests
        // towards the head of the list). This means that the
        // `completedList` will be sorted from earliest request to
        // latest and this is the order that we want to notify
        // `Srp::Server`.

        for (AdvInfo &adv : completedList)
        {
            SignalAdvCompleted(adv);
        }

        completedList.Clear();
    }

exit:
    return;
}

void AdvertisingProxy::SignalAdvCompleted(AdvInfo &aAdvInfo)
{
    // Check if any outstanding advertisements in the list
    // is blocked by `aAdvInfo` and unblock.

    for (AdvInfo &adv : mAdvInfoList)
    {
        if (adv.mBlockingAdv == &aAdvInfo)
        {
            adv.mBlockingAdv = nullptr;

            if (adv.IsCompleted())
            {
                mTasklet.Post();
            }
        }
    }

    switch (aAdvInfo.mError)
    {
    case kErrorNone:
        mCounters.mAdvSuccessful++;
        break;
    case kErrorResponseTimeout:
        mCounters.mAdvTimeout++;
        break;
    default:
        mCounters.mAdvRejected++;
        break;
    }

    aAdvInfo.SignalServerToCommit();
}

//---------------------------------------------------------------------------------------------------------------------
// AdvertisingProxy::AdvInfo

AdvertisingProxy::AdvInfo::AdvInfo(Host &aHost, const Server::MessageMetadata &aMetadata, uint32_t aTimeout)
    : mNext(nullptr)
    , mBlockingAdv(nullptr)
    , mHost(aHost)
    , mExpireTime(TimerMilli::GetNow() + aTimeout)
    , mMessageMetadata(aMetadata)
    , mError(kErrorNone)
{
    if (aMetadata.mMessageInfo != nullptr)
    {
        // If `mMessageInfo` is not null in the given `aMetadata` keep
        // a copy of it in `AdvInfo` structure and update the
        // `mMessageMetadata` to point to the local copy instead.

        mMessageInfo                  = *aMetadata.mMessageInfo;
        mMessageMetadata.mMessageInfo = &mMessageInfo;
    }
}

void AdvertisingProxy::AdvInfo::SignalServerToCommit(void)
{
    LogInfo("Adv done '%s', error:%s", mHost.GetFullName(), ErrorToString(mError));
    Get<Server>().CommitSrpUpdate(mError, mHost, mMessageMetadata);
}

bool AdvertisingProxy::AdvInfo::IsCompleted(void) const
{
    bool isCompleted = false;

    VerifyOrExit(mBlockingAdv == nullptr);
    isCompleted = (mError != kErrorNone) || mHost.mAdvIdRange.IsEmpty();

exit:
    return isCompleted;
}

} // namespace Srp
} // namespace ot

#endif // OPENTHREAD_CONFIG_SRP_SERVER_ADVERTISING_PROXY_ENABLE
