/*
 *  Copyright (c) 2020, The OpenThread Authors.
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
 *   This file includes implementation for SRP server.
 */

#include "srp_server.hpp"

#if OPENTHREAD_CONFIG_SRP_SERVER_ENABLE

#include "common/instance.hpp"
#include "common/locator-getters.hpp"
#include "common/logging.hpp"
#include "common/new.hpp"
#include "net/dns_headers.hpp"
#include "thread/network_data_local.hpp"
#include "thread/network_data_notifier.hpp"
#include "thread/thread_netif.hpp"
#include "utils/heap.hpp"

namespace ot {

namespace Srp {

static Dns::Header::Response ErrorToDnsResponseCode(otError aError)
{
    Dns::Header::Response responseCode;

    switch (aError)
    {
    case OT_ERROR_NONE:
        responseCode = Dns::Header::kResponseSuccess;
        break;
    case OT_ERROR_NO_BUFS:
        responseCode = Dns::Header::kResponseServerFailure;
        break;
    case OT_ERROR_PARSE:
        responseCode = Dns::Header::kResponseFormatError;
        break;
    case OT_ERROR_DUPLICATED:
        responseCode = Dns::Header::kResponseYxDomain;
        break;
    default:
        responseCode = Dns::Header::kResponseRefused;
        break;
    }

    return responseCode;
}

Server::Server(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mEnabled(true) // The SRP server is enabled by default.
    , mSocket(aInstance)
    , mAdvertisingHandler(nullptr)
    , mAdvertisingHandlerContext(nullptr)
    , mMinLease(kDefaultMinLease)
    , mMaxLease(kDefaultMaxLease)
    , mMinKeyLease(kDefaultMinKeyLease)
    , mMaxKeyLease(kDefaultMaxKeyLease)
    , mLeaseTimer(aInstance, HandleLeaseTimer, this)
    , mOutstandingUpdatesTimer(aInstance, HandleOutstandingUpdatesTimer, this)
{
}

void Server::SetServiceHandler(otSrpServerAdvertisingHandler aServiceHandler, void *aServiceHandlerContext)
{
    mAdvertisingHandler        = aServiceHandler;
    mAdvertisingHandlerContext = aServiceHandlerContext;
}

bool Server::IsRunning(void) const
{
    return mSocket.IsBound();
}

void Server::SetEnabled(bool aEnabled)
{
    mEnabled = aEnabled;

    if (!mEnabled)
    {
        Stop();
    }
    else if (Get<Mle::MleRouter>().IsAttached())
    {
        Start();
    }
}

otError Server::SetLeaseRange(uint32_t aMinLease, uint32_t aMaxLease, uint32_t aMinKeyLease, uint32_t aMaxKeyLease)
{
    otError error = OT_ERROR_NONE;

    VerifyOrExit(aMinLease <= aMaxLease, error = OT_ERROR_INVALID_ARGS);
    VerifyOrExit(aMinKeyLease <= aMaxKeyLease, error = OT_ERROR_INVALID_ARGS);
    VerifyOrExit(aMinLease <= aMinKeyLease, error = OT_ERROR_INVALID_ARGS);
    VerifyOrExit(aMaxLease <= aMaxKeyLease, error = OT_ERROR_INVALID_ARGS);

    mMinLease    = aMinLease;
    mMaxLease    = aMaxLease;
    mMinKeyLease = aMinKeyLease;
    mMaxKeyLease = aMaxKeyLease;

exit:
    return error;
}

uint32_t Server::GrantLease(uint32_t aLease) const
{
    OT_ASSERT(mMinLease <= mMaxLease);

    return (aLease == 0) ? 0 : OT_MAX(mMinLease, OT_MIN(mMaxLease, aLease));
}

uint32_t Server::GrantKeyLease(uint32_t aKeyLease) const
{
    OT_ASSERT(mMinKeyLease <= mMaxKeyLease);

    return (aKeyLease == 0) ? 0 : OT_MAX(mMinKeyLease, OT_MIN(mMaxKeyLease, aKeyLease));
}

const Server::Host *Server::GetNextHost(const Server::Host *aHost)
{
    return (aHost == nullptr) ? mHosts.GetHead() : aHost->GetNext();
}

void Server::AddHost(Host *aHost)
{
    OT_ASSERT(mHosts.FindMatching(aHost->GetFullName()) == nullptr);
    IgnoreError(mHosts.Add(*aHost));
}

void Server::RemoveHost(Host *aHost)
{
    otLogInfoSrp("server: permanently removes host %s", aHost->GetFullName());
    IgnoreError(mHosts.Remove(*aHost));
    Host::Destroy(aHost);
}

Server::Service *Server::FindService(const char *aFullName)
{
    Service *service = nullptr;

    for (auto host = mHosts.GetHead(); host != nullptr; host = host->GetNext())
    {
        service = host->FindService(aFullName);
        if (service != nullptr)
        {
            break;
        }
    }

    return service;
}

bool Server::HasNameConflictsWith(Host &aHost)
{
    bool hasConflicts = false;
    auto existingHost = mHosts.FindMatching(aHost.GetFullName());

    if (existingHost != nullptr && *aHost.GetKey() != *existingHost->GetKey())
    {
        ExitNow(hasConflicts = true);
    }

    // Check not only services of this host but all hosts.
    for (auto service = aHost.GetServices(); service != nullptr; service = service->GetNext())
    {
        auto existingService = FindService(service->GetFullName());
        if (existingService != nullptr && *service->GetHost().GetKey() != *existingService->GetHost().GetKey())
        {
            ExitNow(hasConflicts = true);
        }
    }

exit:
    return hasConflicts;
}

void Server::HandleAdvertisingResult(const Host *aHost, otError aError)
{
    UpdateMetadata *update = mOutstandingUpdates.FindMatching(aHost);

    if (update != nullptr)
    {
        HandleAdvertisingResult(update, aError);
    }
    else
    {
        otLogInfoSrp("server: delayed SRP host update result, the SRP update has been committed");
    }
}

void Server::HandleAdvertisingResult(UpdateMetadata *aUpdate, otError aError)
{
    HandleSrpUpdateResult(aError, aUpdate->GetDnsHeader(), aUpdate->GetHost(), aUpdate->GetMessageInfo());

    IgnoreError(mOutstandingUpdates.Remove(*aUpdate));
    UpdateMetadata::Destroy(aUpdate);

    if (mOutstandingUpdates.IsEmpty())
    {
        mOutstandingUpdatesTimer.Stop();
    }
    else
    {
        mOutstandingUpdatesTimer.StartAt(mOutstandingUpdates.GetTail()->GetExpireTime(), 0);
    }
}

void Server::HandleSrpUpdateResult(otError                 aError,
                                   const Dns::Header &     aDnsHeader,
                                   Host &                  aHost,
                                   const Ip6::MessageInfo &aMessageInfo)
{
    Host *   existingHost;
    uint32_t hostLease;
    uint32_t hostKeyLease;
    uint32_t grantedLease;
    uint32_t grantedKeyLease;

    SuccessOrExit(aError);

    hostLease       = aHost.GetLease();
    hostKeyLease    = aHost.GetKeyLease();
    grantedLease    = GrantLease(hostLease);
    grantedKeyLease = GrantKeyLease(hostKeyLease);

    aHost.SetLease(grantedLease);
    aHost.SetKeyLease(grantedKeyLease);

    existingHost = mHosts.FindMatching(aHost.GetFullName());

    if (aHost.GetLease() == 0)
    {
        otLogInfoSrp("server: removes host %s", aHost.GetFullName());

        if (aHost.GetKeyLease() == 0)
        {
            otLogInfoSrp("server: removes key of host %s", aHost.GetFullName());

            if (existingHost != nullptr)
            {
                RemoveHost(existingHost);
            }
        }
        else if (existingHost != nullptr)
        {
            existingHost->SetLease(aHost.GetLease());
            existingHost->SetKeyLease(aHost.GetKeyLease());

            // Clear all resources associated to this host and its services.
            existingHost->ClearResources();
            for (auto service = existingHost->GetServices(); service != nullptr; service = service->GetNext())
            {
                service->SetDeleted(true);
                service->ClearResources();
            }
        }

        Host::Destroy(&aHost);
    }
    else if (existingHost != nullptr)
    {
        // Merge current updates into existing host.

        otLogInfoSrp("server: updates host %s", existingHost->GetFullName());

        existingHost->CopyResourcesFrom(aHost);

        for (auto service = aHost.GetServices(); service != nullptr; service = service->GetNext())
        {
            auto existingService = existingHost->FindService(service->GetFullName());

            if (service->IsDeleted())
            {
                existingHost->RemoveService(existingService);
            }
            else
            {
                existingService = existingHost->AddService(service->GetFullName());

                VerifyOrExit(existingService != nullptr, aError = OT_ERROR_NO_BUFS);
                SuccessOrExit(aError = existingService->CopyResourcesFrom(*service));

                otLogInfoSrp("server: adds/updates service %s", existingHost->GetFullName());
            }
        }

        Host::Destroy(&aHost);
    }
    else
    {
        otLogInfoSrp("server: adds new host %s", aHost.GetFullName());
        AddHost(&aHost);
    }

    // Re-schedule the lease timer.
    HandleLeaseTimer();

exit:
    if (aError == OT_ERROR_NONE && !(grantedLease == hostLease && grantedKeyLease == hostKeyLease))
    {
        SendResponse(aDnsHeader, grantedLease, grantedKeyLease, aMessageInfo);
    }
    else
    {
        SendResponse(aDnsHeader, ErrorToDnsResponseCode(aError), aMessageInfo);
    }
}

void Server::Start()
{
    otError error;

    VerifyOrExit(!IsRunning(), error = OT_ERROR_ALREADY);

    SuccessOrExit(error = mSocket.Open(HandleUdpReceive, this));
    SuccessOrExit(error = mSocket.Bind(0));

    SuccessOrExit(error = PublishService());

    otLogInfoSrp("server: starts listening on port %hu", mSocket.GetSockName().mPort);

exit:
    if (error != OT_ERROR_NONE)
    {
        otLogCritSrp("server: failed to start SRP server: %s", otThreadErrorToString(error));
        // Cleanup any resources we may have allocated.
        Stop();
    }
}

void Server::Stop()
{
    VerifyOrExit(IsRunning());

    UnpublishService();

    while (!mHosts.IsEmpty())
    {
        Host::Destroy(mHosts.Pop());
    }

    while (!mOutstandingUpdates.IsEmpty())
    {
        UpdateMetadata::Destroy(mOutstandingUpdates.Pop());
    }

    mLeaseTimer.Stop();
    mOutstandingUpdatesTimer.Stop();

    otLogInfoSrp("server: stops listening on %hu", mSocket.GetSockName().mPort);
    IgnoreError(mSocket.Close());

exit:
    return;
}

void Server::HandleNotifierEvents(Events aEvents)
{
    VerifyOrExit(mEnabled);

    if (aEvents.Contains(kEventThreadRoleChanged))
    {
        if (Get<Mle::MleRouter>().IsAttached())
        {
            Start();
        }
        else
        {
            Stop();
        }
    }

exit:
    return;
}

otError Server::PublishService()
{
    otError       error;
    const uint8_t serviceData[] = {kThreadServiceTypeSrpServer};
    uint8_t       serverData[sizeof(uint16_t)];

    OT_ASSERT(mSocket.IsBound());

    Encoding::BigEndian::WriteUint16(mSocket.GetSockName().mPort, serverData);

    SuccessOrExit(error =
                      Get<NetworkData::Local>().AddService(kThreadEnterpriseNumber, serviceData, sizeof(serviceData),
                                                           /* aServerStable */ true, serverData, sizeof(serverData)));
    Get<NetworkData::Notifier>().HandleServerDataUpdated();

exit:
    return error;
}

void Server::UnpublishService()
{
    otError       error;
    const uint8_t serviceData[] = {kThreadServiceTypeSrpServer};

    SuccessOrExit(
        error = Get<NetworkData::Local>().RemoveService(kThreadEnterpriseNumber, serviceData, sizeof(serviceData)));
    Get<NetworkData::Notifier>().HandleServerDataUpdated();

exit:
    if (error != OT_ERROR_NONE)
    {
        otLogWarnSrp("server: failed to unpublish SRP service: %s", otThreadErrorToString(error));
    }
}

void Server::HandleDnsUpdate(Message &               aMessage,
                             const Ip6::MessageInfo &aMessageInfo,
                             const Dns::Header &     aDnsHeader,
                             uint16_t                aOffset)
{
    otError   error = OT_ERROR_NONE;
    Dns::Zone zone;
    Host *    host = nullptr;

    uint16_t headerOffset = aOffset - sizeof(aDnsHeader);

    otLogInfoSrp("server: received DNS update from %s", aMessageInfo.GetPeerAddr().ToString().AsCString());

    SuccessOrExit(error = ProcessZoneSection(aMessage, aDnsHeader, aOffset, zone));

    if (mOutstandingUpdates.FindMatching(aDnsHeader.GetMessageId()) != nullptr)
    {
        otLogInfoSrp("server: drops duplicated SRP update request: messageId=%hu", aDnsHeader.GetMessageId());

        // Silently drop duplicate requests.
        // This could rarely happen, because the outstanding SRP update timer should
        // be much shorter than the SRP update retransmission timer.
        ExitNow(error = OT_ERROR_NONE);
    }

    // Per 2.3.2 of SRP draft 6, no prerequisites should be included in a SRP update.
    VerifyOrExit(aDnsHeader.GetPrerequisiteCount() == 0, error = OT_ERROR_FAILED);

    host = Host::New();
    VerifyOrExit(host != nullptr, error = OT_ERROR_NO_BUFS);
    SuccessOrExit(error = ProcessUpdateSection(*host, aMessage, aDnsHeader, zone, headerOffset, aOffset));

    // Parse lease time and validate signature.
    SuccessOrExit(error = ProcessAdditionalSection(host, aMessage, aDnsHeader, headerOffset, aOffset));

    HandleUpdate(aDnsHeader, host, aMessageInfo);

exit:
    if (error != OT_ERROR_NONE)
    {
        Host::Destroy(host);
        SendResponse(aDnsHeader, ErrorToDnsResponseCode(error), aMessageInfo);
    }
}

otError Server::ProcessZoneSection(const Message &    aMessage,
                                   const Dns::Header &aDnsHeader,
                                   uint16_t &         aOffset,
                                   Dns::Zone &        aZone)
{
    otError   error = OT_ERROR_NONE;
    Dns::Zone zone;

    VerifyOrExit(aDnsHeader.GetZoneCount() == 1, error = OT_ERROR_FAILED);

    SuccessOrExit(Dns::Name::ParseName(aMessage, aOffset));
    SuccessOrExit(aMessage.Read(aOffset, zone));
    aOffset += sizeof(zone);
    VerifyOrExit(zone.GetType() == Dns::ResourceRecord::kTypeSoa, error = OT_ERROR_FAILED);

    aZone = zone;

exit:
    return error;
}

otError Server::ProcessUpdateSection(Host &             aHost,
                                     const Message &    aMessage,
                                     const Dns::Header &aDnsHeader,
                                     const Dns::Zone &  aZone,
                                     uint16_t           aHeaderOffset,
                                     uint16_t &         aOffset)
{
    otError error = OT_ERROR_NONE;

    // Enumerate over all Service Discovery Instructions before processing any other records.
    // So that we will know whether a name is a hostname or service instance name when processing
    // a "Delete All RRsets from a name" record.
    SuccessOrExit(error = HandleDiscoveryInstructions(aHost, aMessage, aDnsHeader, aZone, aHeaderOffset, aOffset));

    for (uint16_t i = 0; i < aDnsHeader.GetUpdateCount(); ++i)
    {
        char                name[Dns::Name::kMaxLength + 1];
        Dns::ResourceRecord record;

        SuccessOrExit(error = Dns::Name::ReadName(aMessage, aOffset, aHeaderOffset, name, sizeof(name)));
        SuccessOrExit(error = aMessage.Read(aOffset, record));

        if (record.GetClass() == Dns::ResourceRecord::kClassAny)
        {
            // Delete All RRsets from a name.
            VerifyOrExit(record.GetType() == Dns::ResourceRecord::kTypeAny && record.GetTtl() == 0 &&
                             record.GetLength() == 0,
                         error = OT_ERROR_FAILED);
            SuccessOrExit(error = HandleDeleteAllResources(aHost, name));

            aOffset += record.GetSize();
            continue;
        }

        VerifyOrExit(record.GetClass() == aZone.GetClass(), error = OT_ERROR_FAILED);

        if (record.GetType() == Dns::ResourceRecord::kTypePtr)
        {
            // Skip, as we have already processed all PTR RRs.
            aOffset += record.GetSize();
        }
        else if (record.GetType() == Dns::ResourceRecord::kTypeSrv)
        {
            Dns::SrvRecord srvRecord;
            Service *      service;
            char           hostName[Dns::Name::kMaxLength + 1];
            uint16_t       hostNameLength = sizeof(hostName);

            SuccessOrExit(error = aMessage.Read(aOffset, srvRecord));
            aOffset += sizeof(srvRecord);

            SuccessOrExit(error = Dns::Name::ReadName(aMessage, aOffset, aHeaderOffset, hostName, hostNameLength));
            VerifyOrExit(aHost.Matches(hostName), error = OT_ERROR_FAILED);

            service = aHost.FindService(name);
            VerifyOrExit(service != nullptr && !service->IsDeleted(), error = OT_ERROR_FAILED);

            // Make sure that this is the first SRV RR for this service.
            VerifyOrExit(service->mPort == 0, error = OT_ERROR_FAILED);
            service->mPriority = srvRecord.GetPriority();
            service->mWeight   = srvRecord.GetWeight();
            service->mPort     = srvRecord.GetPort();
        }
        else if (record.GetType() == Dns::ResourceRecord::kTypeTxt)
        {
            Service *service = aHost.FindService(name);
            VerifyOrExit(service != nullptr && !service->IsDeleted(), error = OT_ERROR_FAILED);

            aOffset += sizeof(record);
            SuccessOrExit(error = service->SetTxtDataFromMessage(aMessage, aOffset, record.GetLength()));
            aOffset += record.GetLength();
        }
        else if (record.GetType() == Dns::ResourceRecord::kTypeAaaa)
        {
            Dns::AaaaRecord aaaaRecord;

            if (aHost.GetFullName() == nullptr)
            {
                SuccessOrExit(error = aHost.SetFullName(name));
            }
            else
            {
                VerifyOrExit(aHost.Matches(name), error = OT_ERROR_FAILED);
            }

            SuccessOrExit(error = aMessage.Read(aOffset, aaaaRecord));
            VerifyOrExit(aaaaRecord.IsValid(), error = OT_ERROR_PARSE);

            // Tolerate OT_ERROR_DROP for AAAA Resources.
            VerifyOrExit(aHost.AddIp6Address(aaaaRecord.GetAddress()) != OT_ERROR_NO_BUFS, error = OT_ERROR_NO_BUFS);

            aOffset += aaaaRecord.GetSize();
        }
        else if (record.GetType() == Dns::ResourceRecord::kTypeA)
        {
            // Ignore IPv4 addresses.
            aOffset += record.GetSize();
        }
        else if (record.GetType() == Dns::ResourceRecord::kTypeKey)
        {
            // We currently support only ECDSA P-256.
            Dns::Ecdsa256KeyRecord key;

            VerifyOrExit(aHost.GetKey() == nullptr, error = OT_ERROR_FAILED);

            SuccessOrExit(error = aMessage.Read(aOffset, key));
            VerifyOrExit(key.IsValid(), error = OT_ERROR_PARSE);

            aHost.SetKey(key);

            aOffset += record.GetSize();
        }
        else
        {
            ExitNow(error = OT_ERROR_FAILED);
        }
    }

    // Verify that we have a complete Host Description Instruction.

    VerifyOrExit(aHost.GetFullName() != nullptr, error = OT_ERROR_FAILED);
    VerifyOrExit(aHost.GetKey() != nullptr, error = OT_ERROR_FAILED);
    {
        uint8_t hostAddressesNum;

        aHost.GetAddresses(hostAddressesNum);

        // There MUST be at least one valid address if we have nonzero lease.
        VerifyOrExit(aHost.GetLease() > 0 || hostAddressesNum > 0, error = OT_ERROR_FAILED);
    }

    // Verify that there are no name conflicts.
    VerifyOrExit(!HasNameConflictsWith(aHost), error = OT_ERROR_DUPLICATED);

exit:
    return error;
}

otError Server::HandleDiscoveryInstructions(Host &             aHost,
                                            const Message &    aMessage,
                                            const Dns::Header &aDnsHeader,
                                            const Dns::Zone &  aZone,
                                            uint16_t           aHeaderOffset,
                                            uint16_t           aOffset)
{
    otError error;

    for (uint16_t i = 0; i < aDnsHeader.GetUpdateCount(); ++i)
    {
        char                name[Dns::Name::kMaxLength + 1];
        Dns::ResourceRecord record;
        char                serviceName[Dns::Name::kMaxLength + 1];
        Service *           service;

        SuccessOrExit(error = Dns::Name::ReadName(aMessage, aOffset, aHeaderOffset, name, sizeof(name)));
        SuccessOrExit(error = aMessage.Read(aOffset, record));

        aOffset += sizeof(record);

        if (record.GetType() == Dns::ResourceRecord::kTypePtr)
        {
            SuccessOrExit(error =
                              Dns::Name::ReadName(aMessage, aOffset, aHeaderOffset, serviceName, sizeof(serviceName)));
        }
        else
        {
            aOffset += record.GetLength();
            continue;
        }

        VerifyOrExit(record.GetClass() == Dns::ResourceRecord::kClassNone || record.GetClass() == aZone.GetClass(),
                     error = OT_ERROR_FAILED);

        // TODO: check if the RR name and the full service name matches.

        service = aHost.FindService(serviceName);
        VerifyOrExit(service == nullptr, error = OT_ERROR_FAILED);
        service = aHost.AddService(serviceName);
        VerifyOrExit(service != nullptr, error = OT_ERROR_NO_BUFS);

        // This RR is a "Delete an RR from an RRset" update when the CLASS is NONE.
        service->SetDeleted(record.GetClass() == Dns::ResourceRecord::kClassNone);
    }

exit:
    return error;
}

otError Server::HandleDeleteAllResources(Host &aHost, const char *aFullName)
{
    otError  error = OT_ERROR_NONE;
    Service *service;

    service = aHost.FindService(aFullName);
    if (service != nullptr)
    {
        service->ClearResources();
    }
    else
    {
        if (aHost.GetFullName())
        {
            VerifyOrExit(strcmp(aFullName, aHost.GetFullName()) == 0, error = OT_ERROR_FAILED);
        }
        else
        {
            SuccessOrExit(error = aHost.SetFullName(aFullName));
        }
        aHost.ClearResources();
    }

exit:
    return error;
}

otError Server::ProcessAdditionalSection(Host *             aHost,
                                         const Message &    aMessage,
                                         const Dns::Header &aDnsHeader,
                                         uint16_t           aHeaderOffset,
                                         uint16_t &         aOffset)
{
    otError                   error = OT_ERROR_NONE;
    char                      name[2]; // The root domain name (".") is expected.
    Dns::UpdateLeaseOptRecord leaseRecord;

    Dns::SigRecord sigRecord;
    uint16_t       sigOffset;
    uint16_t       sigRdataOffset;
    char           signerName[Dns::Name::kMaxLength + 1];
    uint16_t       signerNameLength = sizeof(signerName);
    uint8_t        signature[Dns::SigRecord::kMaxSignatureLength];
    uint16_t       signatureLength;

    VerifyOrExit(aDnsHeader.GetAdditionalRecordsCount() == 2, error = OT_ERROR_FAILED);

    // EDNS(0) Update Lease Option.

    SuccessOrExit(error = Dns::Name::ReadName(aMessage, aOffset, aHeaderOffset, name, sizeof(name)));
    SuccessOrExit(error = aMessage.Read(aOffset, leaseRecord));
    VerifyOrExit(leaseRecord.IsValid(), error = OT_ERROR_PARSE);
    aOffset += leaseRecord.GetSize();

    aHost->SetLease(leaseRecord.GetLeaseInterval());
    aHost->SetKeyLease(leaseRecord.GetKeyLeaseInterval());

    // SIG(0).

    sigOffset = aOffset;
    SuccessOrExit(error = Dns::Name::ReadName(aMessage, aOffset, aHeaderOffset, name, sizeof(name)));
    SuccessOrExit(error = aMessage.Read(aOffset, sigRecord));
    VerifyOrExit(sigRecord.IsValid(), error = OT_ERROR_PARSE);

    sigRdataOffset = aOffset + sizeof(Dns::ResourceRecord);
    aOffset += sizeof(sigRecord);

    // TODO: verify that the signature doesn't expire.

    SuccessOrExit(error = Dns::Name::ReadName(aMessage, aOffset, aHeaderOffset, signerName, signerNameLength));

    signatureLength = sigRecord.GetLength() - (aOffset - sigRdataOffset);
    VerifyOrExit(signatureLength <= sizeof(signature), error = OT_ERROR_NO_BUFS);
    VerifyOrExit(aMessage.ReadBytes(aOffset, signature, signatureLength) == signatureLength, error = OT_ERROR_PARSE);
    aOffset += signatureLength;

    // Verify the signature. Currently supports only ECDSA.

    VerifyOrExit(sigRecord.GetAlgorithm() == Dns::KeyRecord::kAlgorithmEcdsaP256Sha256, error = OT_ERROR_FAILED);
    VerifyOrExit(signatureLength == Crypto::Ecdsa::P256::Signature::kSize, error = OT_ERROR_PARSE);
    VerifyOrExit(sigRecord.GetTypeCovered() == 0, error = OT_ERROR_FAILED);

    SuccessOrExit(error = VerifySignature(*aHost->GetKey(), aMessage, aDnsHeader, sigOffset, sigRdataOffset,
                                          sigRecord.GetLength()));

exit:
    return error;
}

otError Server::VerifySignature(const Dns::Ecdsa256KeyRecord &aKey,
                                const Message &               aMessage,
                                Dns::Header                   aDnsHeader,
                                uint16_t                      aSigOffset,
                                uint16_t                      aSigRdataOffset,
                                uint16_t                      aSigRdataLength)
{
    otError                        error;
    uint16_t                       offset = aMessage.GetOffset();
    uint16_t                       signatureOffset;
    Crypto::Sha256                 sha256;
    Crypto::Sha256::Hash           hash;
    Crypto::Ecdsa::P256::Signature signature;

    VerifyOrExit(aSigRdataLength >= Crypto::Ecdsa::P256::Signature::kSize, error = OT_ERROR_INVALID_ARGS);

    sha256.Start();

    // SIG RDATA less signature.
    sha256.Update(aMessage, aSigRdataOffset, aSigRdataLength - Crypto::Ecdsa::P256::Signature::kSize);

    // We need the DNS header before appending the SIG RR.
    aDnsHeader.SetAdditionalRecordsCount(aDnsHeader.GetAdditionalRecordsCount() - 1);
    sha256.Update(aDnsHeader);
    sha256.Update(aMessage, offset + sizeof(aDnsHeader), aSigOffset - offset - sizeof(aDnsHeader));

    sha256.Finish(hash);

    signatureOffset = aSigRdataOffset + aSigRdataLength - Crypto::Ecdsa::P256::Signature::kSize;
    SuccessOrExit(error = aMessage.Read(signatureOffset, signature));

    error = aKey.GetKey().Verify(hash, signature);

exit:
    return error;
}

void Server::HandleUpdate(const Dns::Header &aDnsHeader, Host *aHost, const Ip6::MessageInfo &aMessageInfo)
{
    if (aHost->GetLease() == 0)
    {
        auto existingHost = mHosts.FindMatching(aHost->GetFullName());

        aHost->ClearResources();

        // The client may not include all services it has registered and we should append
        // those services for current SRP update.
        if (existingHost != nullptr)
        {
            for (auto existingService = existingHost->GetServices(); existingService != nullptr;
                 existingService      = existingService->GetNext())
            {
                if (!existingService->mIsDeleted)
                {
                    auto service = aHost->AddService(existingService->GetFullName());
                    service->SetDeleted(true);
                }
            }
        }
    }

    if (mAdvertisingHandler != nullptr)
    {
        UpdateMetadata *update = UpdateMetadata::New(aDnsHeader, aHost, aMessageInfo);

        IgnoreError(mOutstandingUpdates.Add(*update));
        mOutstandingUpdatesTimer.StartAt(mOutstandingUpdates.GetHead()->GetExpireTime(), 0);

        mAdvertisingHandler(aHost, kDefaultEventsHandlerTimeout, mAdvertisingHandlerContext);
    }
    else
    {
        HandleSrpUpdateResult(OT_ERROR_NONE, aDnsHeader, *aHost, aMessageInfo);
    }
}

void Server::SendResponse(const Dns::Header &     aHeader,
                          Dns::Header::Response   aResponseCode,
                          const Ip6::MessageInfo &aMessageInfo)
{
    otError     error;
    Message *   response = nullptr;
    Dns::Header header;

    header.SetMessageId(aHeader.GetMessageId());
    header.SetType(Dns::Header::kTypeResponse);
    header.SetQueryType(aHeader.GetQueryType());
    header.SetResponseCode(aResponseCode);

    response = Get<Ip6::Udp>().NewMessage(0);
    VerifyOrExit(response != nullptr, error = OT_ERROR_NO_BUFS);
    SuccessOrExit(error = response->Append(header));
    SuccessOrExit(error = mSocket.SendTo(*response, aMessageInfo));

    if (aResponseCode != Dns::Header::kResponseSuccess)
    {
        otLogInfoSrp("server: sent fail response: %d", aResponseCode);
    }
    else
    {
        otLogInfoSrp("server: sent success response");
    }

exit:
    if (error != OT_ERROR_NONE)
    {
        otLogWarnSrp("server: failed to send response: %s", otThreadErrorToString(error));
        FreeMessageOnError(response, error);
    }
}

void Server::SendResponse(const Dns::Header &     aHeader,
                          uint32_t                aLease,
                          uint32_t                aKeyLease,
                          const Ip6::MessageInfo &aMessageInfo)
{
    otError                   error;
    Message *                 response = nullptr;
    Dns::Header               header;
    char                      kRootName[2] = ".";
    Dns::UpdateLeaseOptRecord leaseRecord;

    header.SetMessageId(aHeader.GetMessageId());
    header.SetType(Dns::Header::kTypeResponse);
    header.SetQueryType(aHeader.GetQueryType());
    header.SetResponseCode(Dns::Header::kResponseSuccess);
    header.SetAdditionalRecordsCount(1);

    leaseRecord.Init();
    leaseRecord.SetLeaseInterval(aLease);
    leaseRecord.SetKeyLeaseInterval(aKeyLease);

    response = Get<Ip6::Udp>().NewMessage(0);
    VerifyOrExit(response != nullptr, error = OT_ERROR_NO_BUFS);
    SuccessOrExit(error = response->Append(header));
    SuccessOrExit(error = Dns::Name::AppendName(kRootName, *response));
    SuccessOrExit(error = response->Append(leaseRecord));

    SuccessOrExit(error = mSocket.SendTo(*response, aMessageInfo));

    otLogInfoSrp("server: sent response with granted lease: %u and key lease: %u", aLease, aKeyLease);

exit:
    if (error != OT_ERROR_NONE)
    {
        otLogWarnSrp("server: failed to send response: %s", otThreadErrorToString(error));
        FreeMessageOnError(response, error);
    }
}

void Server::HandleUdpReceive(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    static_cast<Server *>(aContext)->HandleUdpReceive(*static_cast<Message *>(aMessage),
                                                      *static_cast<const Ip6::MessageInfo *>(aMessageInfo));
}

void Server::HandleUdpReceive(Message &aMessage, const Ip6::MessageInfo &aMessageInfo)
{
    otError     error;
    Dns::Header dnsHeader;
    uint16_t    offset = aMessage.GetOffset();

    SuccessOrExit(error = aMessage.Read(offset, dnsHeader));
    offset += sizeof(dnsHeader);

    // Handles only queries.
    VerifyOrExit(dnsHeader.GetType() == Dns::Header::Type::kTypeQuery, error = OT_ERROR_DROP);

    switch (dnsHeader.GetQueryType())
    {
    case Dns::Header::kQueryTypeUpdate:
        HandleDnsUpdate(aMessage, aMessageInfo, dnsHeader, offset);
        break;
    case Dns::Header::kQueryTypeStandard:
        // TODO:
        break;
    default:
        error = OT_ERROR_DROP;
        break;
    }

exit:
    if (error != OT_ERROR_NONE)
    {
        otLogInfoSrp("server: failed to handle DNS message: %s", otThreadErrorToString(error));
    }
}

void Server::HandleLeaseTimer(Timer &aTimer)
{
    aTimer.GetOwner<Server>().HandleLeaseTimer();
}

void Server::HandleLeaseTimer(void)
{
    TimeMilli now                = TimerMilli::GetNow();
    TimeMilli earliestExpireTime = now.GetDistantFuture();
    auto      host               = mHosts.GetHead();

    while (host != nullptr)
    {
        auto nextHost = host->GetNext();

        if (host->GetKeyExpireTime() <= now)
        {
            otLogInfoSrp("server: KEY LEASE of host %s expires", host->GetFullName());

            // Removes the whole host and all services if the KEY RR expires.
            RemoveHost(host);
        }
        else if (host->IsDeleted())
        {
            // The host has been deleted, but the hostname & service instance names retains.

            auto service = host->GetServices();

            earliestExpireTime = OT_MIN(earliestExpireTime, host->GetKeyExpireTime());

            // Check if any service instance name expires.
            while (service != nullptr)
            {
                OT_ASSERT(service->IsDeleted());

                auto nextService = service->GetNext();

                if (service->GetKeyExpireTime() <= now)
                {
                    otLogInfoSrp("server: KEY LEASE of service %s expires", service->GetFullName());
                    host->RemoveService(service);
                }
                else
                {
                    earliestExpireTime = OT_MIN(earliestExpireTime, service->GetKeyExpireTime());
                }

                service = nextService;
            }
        }
        else if (host->GetExpireTime() <= now)
        {
            otLogInfoSrp("server: LEASE of host %s expires", host->GetFullName());

            // If the host expires, delete all resources of this host and its services.
            host->ClearResources();
            for (auto service = host->GetServices(); service != nullptr; service = service->GetNext())
            {
                service->SetDeleted(true);
                service->ClearResources();
            }

            earliestExpireTime = OT_MIN(earliestExpireTime, host->GetKeyExpireTime());
        }
        else
        {
            // The host doesn't expire, check if any service expires or is explicitly removed.

            OT_ASSERT(!host->IsDeleted());

            auto service = host->GetServices();

            earliestExpireTime = OT_MIN(earliestExpireTime, host->GetExpireTime());

            while (service != nullptr)
            {
                auto nextService = service->GetNext();

                if (service->IsDeleted())
                {
                    // The service has been deleted but the name retains.
                    earliestExpireTime = OT_MIN(earliestExpireTime, service->GetKeyExpireTime());
                }
                else if (service->GetExpireTime() <= now)
                {
                    otLogInfoSrp("server: LEASE of service %s expires", service->GetFullName());

                    // The service gets expired, delete it.

                    service->SetDeleted(true);
                    service->ClearResources();

                    earliestExpireTime = OT_MIN(earliestExpireTime, service->GetKeyExpireTime());
                }
                else
                {
                    earliestExpireTime = OT_MIN(earliestExpireTime, service->GetExpireTime());
                }

                service = nextService;
            }
        }

        host = nextHost;
    }

    if (earliestExpireTime != now.GetDistantFuture())
    {
        if (!mLeaseTimer.IsRunning() || earliestExpireTime <= mLeaseTimer.GetFireTime())
        {
            otLogInfoSrp("server: lease timer is scheduled in %u seconds", (earliestExpireTime - now) / 1000);
            mLeaseTimer.StartAt(earliestExpireTime, 0);
        }
    }
    else
    {
        otLogInfoSrp("server: lease timer is stopped");
        mLeaseTimer.Stop();
    }
}

void Server::HandleOutstandingUpdatesTimer(Timer &aTimer)
{
    aTimer.GetOwner<Server>().HandleOutstandingUpdatesTimer();
}

void Server::HandleOutstandingUpdatesTimer(void)
{
    while (!mOutstandingUpdates.IsEmpty() && mOutstandingUpdates.GetTail()->GetExpireTime() <= TimerMilli::GetNow())
    {
        HandleAdvertisingResult(mOutstandingUpdates.GetTail(), OT_ERROR_RESPONSE_TIMEOUT);
    }
}

Server::Service *Server::Service::New(const char *aFullName)
{
    void *   buf;
    Service *service = nullptr;

    buf = Instance::Get().HeapCAlloc(1, sizeof(Service));
    VerifyOrExit(buf != nullptr);

    service = new (buf) Service();
    if (service->SetFullName(aFullName) != OT_ERROR_NONE)
    {
        Destroy(service);
        service = nullptr;
    }

exit:
    return service;
}

void Server::Service::Destroy(Service *aService)
{
    if (aService != nullptr)
    {
        aService->~Service();
        Instance::Get().HeapFree(aService);
    }
}

Server::Service::Service()
{
    mFullName       = nullptr;
    mIsDeleted      = false;
    mPriority       = 0;
    mWeight         = 0;
    mPort           = 0;
    mTxtLength      = 0;
    mTxtData        = nullptr;
    mHost           = nullptr;
    mNext           = nullptr;
    mTimeLastUpdate = TimerMilli::GetNow();
}

Server::Service::~Service()
{
    Instance::Get().HeapFree(mFullName);
    Instance::Get().HeapFree(mTxtData);
}

otError Server::Service::SetFullName(const char *aFullName)
{
    OT_ASSERT(aFullName != nullptr);

    otError error    = OT_ERROR_NONE;
    char *  nameCopy = static_cast<char *>(Instance::Get().HeapCAlloc(1, strlen(aFullName) + 1));

    VerifyOrExit(nameCopy != nullptr, error = OT_ERROR_NO_BUFS);
    strcpy(nameCopy, aFullName);

    Instance::Get().HeapFree(mFullName);
    mFullName = nameCopy;

    mTimeLastUpdate = TimerMilli::GetNow();

exit:
    return error;
}

TimeMilli Server::Service::GetExpireTime(void) const
{
    OT_ASSERT(!IsDeleted());
    OT_ASSERT(!GetHost().IsDeleted());

    return mTimeLastUpdate + GetHost().GetLease() * 1000;
}

TimeMilli Server::Service::GetKeyExpireTime(void) const
{
    return mTimeLastUpdate + GetHost().GetKeyLease() * 1000;
}

otError Server::Service::SetTxtData(const uint8_t *aTxtData, uint16_t aTxtDataLength)
{
    otError  error = OT_ERROR_NONE;
    uint8_t *txtData;

    txtData = static_cast<uint8_t *>(Instance::Get().HeapCAlloc(1, aTxtDataLength));
    VerifyOrExit(txtData != nullptr, error = OT_ERROR_NO_BUFS);

    memcpy(txtData, aTxtData, aTxtDataLength);

    Instance::Get().HeapFree(mTxtData);
    mTxtData   = txtData;
    mTxtLength = aTxtDataLength;

    // If a TXT RR is associated to this service, the service will retain.
    SetDeleted(false);
    mTimeLastUpdate = TimerMilli::GetNow();

exit:
    return error;
}

otError Server::Service::SetTxtDataFromMessage(const Message &aMessage, uint16_t aOffset, uint16_t aLength)
{
    otError  error = OT_ERROR_NONE;
    uint8_t *txtData;

    txtData = static_cast<uint8_t *>(Instance::Get().HeapCAlloc(1, aLength));
    VerifyOrExit(txtData != nullptr, error = OT_ERROR_NO_BUFS);
    VerifyOrExit(aMessage.ReadBytes(aOffset, txtData, aLength) == aLength, error = OT_ERROR_PARSE);

    Instance::Get().HeapFree(mTxtData);
    mTxtData   = txtData;
    mTxtLength = aLength;

    SetDeleted(false);
    mTimeLastUpdate = TimerMilli::GetNow();

exit:
    if (error != OT_ERROR_NONE)
    {
        Instance::Get().HeapFree(txtData);
    }

    return error;
}

void Server::Service::ClearResources(void)
{
    mPort = 0;
    Instance::Get().HeapFree(mTxtData);
    mTxtData   = nullptr;
    mTxtLength = 0;

    mTimeLastUpdate = TimerMilli::GetNow();
}

otError Server::Service::CopyResourcesFrom(const Service &aService)
{
    otError error;

    SuccessOrExit(error = SetTxtData(aService.mTxtData, aService.mTxtLength));
    mPriority = aService.mPriority;
    mWeight   = aService.mWeight;
    mPort     = aService.mPort;

    SetDeleted(false);
    mTimeLastUpdate = TimerMilli::GetNow();

exit:
    return error;
}

bool Server::Service::Matches(const char *aFullName) const
{
    return (mFullName != nullptr) && (strcmp(mFullName, aFullName) == 0);
}

Server::Host *Server::Host::New()
{
    void *buf;
    Host *host = nullptr;

    buf = Instance::Get().HeapCAlloc(1, sizeof(Host));
    VerifyOrExit(buf != nullptr);

    host = new (buf) Host();

exit:
    return host;
}

void Server::Host::Destroy(Host *aHost)
{
    if (aHost != nullptr)
    {
        aHost->~Host();
        Instance::Get().HeapFree(aHost);
    }
}

Server::Host::Host()
    : mFullName(nullptr)
    , mAddressesNum(0)
    , mNext(nullptr)
    , mLease(0)
    , mKeyLease(0)
    , mTimeLastUpdate(TimerMilli::GetNow())
{
    memset(&mKey, 0, sizeof(mKey));
}

Server::Host::~Host()
{
    RemoveAllServices();
    Instance::Get().HeapFree(mFullName);
}

otError Server::Host::SetFullName(const char *aFullName)
{
    OT_ASSERT(aFullName != nullptr);

    otError error    = OT_ERROR_NONE;
    char *  nameCopy = static_cast<char *>(Instance::Get().HeapCAlloc(1, strlen(aFullName) + 1));

    VerifyOrExit(nameCopy != nullptr, error = OT_ERROR_NO_BUFS);
    strcpy(nameCopy, aFullName);

    if (mFullName != nullptr)
    {
        Instance::Get().HeapFree(mFullName);
    }
    mFullName = nameCopy;

    mTimeLastUpdate = TimerMilli::GetNow();

exit:
    return error;
}

void Server::Host::SetKey(Dns::Ecdsa256KeyRecord &aKey)
{
    OT_ASSERT(aKey.IsValid());

    mKey            = aKey;
    mTimeLastUpdate = TimerMilli::GetNow();
}

void Server::Host::SetLease(uint32_t aLease)
{
    mLease          = aLease;
    mTimeLastUpdate = TimerMilli::GetNow();
}

void Server::Host::SetKeyLease(uint32_t aKeyLease)
{
    mKeyLease       = aKeyLease;
    mTimeLastUpdate = TimerMilli::GetNow();
}

TimeMilli Server::Host::GetExpireTime(void) const
{
    OT_ASSERT(!IsDeleted());

    return mTimeLastUpdate + mLease * 1000;
}

TimeMilli Server::Host::GetKeyExpireTime(void) const
{
    return mTimeLastUpdate + mKeyLease * 1000;
}

Server::Service *Server::Host::AddService(const char *aFullName)
{
    Service *service;

    service = FindService(aFullName);
    if (service == nullptr)
    {
        service = Service::New(aFullName);
        if (service != nullptr)
        {
            AddService(service);
        }
    }

    return service;
}

void Server::Host::AddService(Server::Service *aService)
{
    IgnoreError(mServices.Add(*aService));
    aService->mHost = this;
}

void Server::Host::RemoveService(Service *aService)
{
    if (aService != nullptr)
    {
        IgnoreError(mServices.Remove(*aService));
        Service::Destroy(aService);
    }
}

void Server::Host::RemoveAllServices(void)
{
    while (!mServices.IsEmpty())
    {
        RemoveService(mServices.GetHead());
    }
}

void Server::Host::ClearResources(void)
{
    mAddressesNum = 0;

    mTimeLastUpdate = TimerMilli::GetNow();
}

void Server::Host::CopyResourcesFrom(const Host &aHost)
{
    memcpy(mAddresses, aHost.mAddresses, aHost.mAddressesNum * sizeof(mAddresses[0]));
    mAddressesNum = aHost.mAddressesNum;
    mKey          = aHost.mKey;
    mLease        = aHost.mLease;
    mKeyLease     = aHost.mKeyLease;

    mTimeLastUpdate = TimerMilli::GetNow();
}

Server::Service *Server::Host::FindService(const char *aFullName)
{
    return mServices.FindMatching(aFullName);
}

otError Server::Host::AddIp6Address(const Ip6::Address &aIp6Address)
{
    otError error = OT_ERROR_NONE;

    if (aIp6Address.IsMulticast() || aIp6Address.IsUnspecified() || aIp6Address.IsLoopback() ||
        aIp6Address.IsLinkLocal())
    {
        // We don't like those address because they cannot be used for communication
        // with exterior devices.
        ExitNow(error = OT_ERROR_NONE);
    }

    for (const Ip6::Address &addr : mAddresses)
    {
        if (aIp6Address == addr)
        {
            // Silently drop duplicate addresses.
            ExitNow(error = OT_ERROR_NONE);
        }
    }

    if (mAddressesNum >= kMaxAddressesNum)
    {
        otLogWarnSrp("server: too many addresses for host %s", GetFullName());
        ExitNow(error = OT_ERROR_NO_BUFS);
    }

    mAddresses[mAddressesNum++] = aIp6Address;
    mTimeLastUpdate             = TimerMilli::GetNow();

exit:
    return error;
}

bool Server::Host::Matches(const char *aName) const
{
    return mFullName != nullptr && strcmp(mFullName, aName) == 0;
}

Server::UpdateMetadata *Server::UpdateMetadata::New(const Dns::Header &     aHeader,
                                                    Host *                  aHost,
                                                    const Ip6::MessageInfo &aMessageInfo)
{
    void *          buf;
    UpdateMetadata *update = nullptr;

    buf = Instance::Get().HeapCAlloc(1, sizeof(UpdateMetadata));
    VerifyOrExit(buf != nullptr);

    update = new (buf) UpdateMetadata(aHeader, aHost, aMessageInfo);

exit:
    return update;
}

void Server::UpdateMetadata::Destroy(UpdateMetadata *aUpdateMetadata)
{
    if (aUpdateMetadata != nullptr)
    {
        aUpdateMetadata->~UpdateMetadata();
        Instance::Get().HeapFree(aUpdateMetadata);
    }
}

Server::UpdateMetadata::UpdateMetadata(const Dns::Header &aHeader, Host *aHost, const Ip6::MessageInfo &aMessageInfo)
    : mExpireTime(TimerMilli::GetNow() + kDefaultEventsHandlerTimeout)
    , mDnsHeader(aHeader)
    , mHost(aHost)
    , mMessageInfo(aMessageInfo)
    , mNext(nullptr)
{
}

} // namespace Srp

} // namespace ot

#endif // OPENTHREAD_CONFIG_SRP_SERVER_ENABLE
