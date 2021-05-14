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
 *   This file includes definition of Network Data Publisher.
 */

#ifndef NETWORK_DATA_PUBLISHER_HPP_
#define NETWORK_DATA_PUBLISHER_HPP_

#include "openthread-core-config.h"

#if OPENTHREAD_CONFIG_NETDATA_PUBLISHER_ENABLE

#include "common/error.hpp"
#include "common/locator.hpp"
#include "common/non_copyable.hpp"
#include "common/notifier.hpp"
#include "common/string.hpp"
#include "common/timer.hpp"
#include "net/ip6_address.hpp"
#include "thread/network_data_types.hpp"

namespace ot {
namespace NetworkData {

/**
 * This class implements the Network Data Publisher.
 *
 * It provides mechanisms to limit the number of similar Service and/or Prefix (on-mesh prefix or external route)
 * entries in the Thread Network Data by monitoring the Network Data and managing if or when to add or remove entries.
 *
 */
class Publisher : public InstanceLocator, private NonCopyable
{
    friend class ot::Notifier;

public:
    /**
     * This constructor initializes `Publisher` object.
     *
     * @param[in]  aInstance     A reference to the OpenThread instance.
     *
     */
    explicit Publisher(Instance &aInstance);

#if OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE

    /**
     * This method requests "DNS/SRP Service Anycast Address" to be published in the Thread Network Data.
     *
     * A call to this method will remove and replace any previous "DNS/SRP Service" entry that was being published
     * (from earlier call to any of `PublishDnsSrpService{Type}()` methods).
     *
     * @param[in] aSequenceNumber  The sequence number of DNS/SRP Anycast Service.
     *
     */
    void PublishDnsSrpServiceAnycast(uint8_t aSequenceNumber) { mDnsSrpServiceEntry.PublishAnycast(aSequenceNumber); }

    /**
     * This method requests "DNS/SRP Service Unicast Address" to be published in the Thread Network Data.
     *
     * A call to this method will remove and replace any previous "DNS/SRP Service" entry that was being published
     * (from earlier call to any of `PublishDnsSrpService{Type}()` methods).
     *
     * This method publishes the "DNS/SRP Service Unicast Address" by including the address and port info in the
     * Service TLV data.
     *
     * @param[in] aAddress   The DNS/SRP server address to publish.
     * @param[in] aPort      The SRP server port number to publish.
     *
     */
    void PublishDnsSrpServiceUnicast(const Ip6::Address &aAddress, uint16_t aPort)
    {
        mDnsSrpServiceEntry.PublishUnicast(aAddress, aPort);
    }

    /**
     * This method requests "DNS/SRP Service Unicast Address" to be published in the Thread Network Data.
     *
     * A call to this method will remove and replace any previous "DNS/SRP Service" entry that was being published
     * (from earlier call to any of `PublishDnsSrpService{Type}()` methods).
     *
     * Unlike the `PublishDnsSrpServiceUnicast(aAddress, aPort)` which requires the published address to be given and
     * includes the info in the Service TLV data, this method uses the device's mesh-local EID and includes the info
     * in the Server TLV data.
     *
     * @param[in] aPort      The SRP server port number to publish.
     *
     */
    void PublishDnsSrpServiceUnicast(uint16_t aPort) { mDnsSrpServiceEntry.PublishUnicast(aPort); }

    /**
     * This method unpublishes any previously added "DNS/SRP (Anycast or Unicast) Service" entry from the Thread
     * Network Data.
     *
     */
    void UnpublishDnsSrpService(void) { mDnsSrpServiceEntry.Unpublish(); }

#endif // OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE

#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE
    /**
     * This method requests an on-mesh prefix to be published in the Thread Network Data.
     *
     * @param[in] aConfig         The on-mesh prefix config to publish.
     *
     * @retval kErrorNone         The on-mesh prefix is published successfully.
     * @retval kErrorInvalidArgs  The @p aConfig is not valid (bad prefix or invalid flag combinations).
     * @retval kErrorAlready      An entry with the same prefix is already in the published list.
     * @retval kErrorNoBufs       Could not allocate an entry for the new request. Publisher supports a limited number
     *                            of entries (shared between on-mesh prefix and external route) determined by config
     *                            `OPENTHREAD_CONFIG_NETDATA_PUBLISHER_MAX_PREFIX_ENTRIES`.
     *
     *
     */
    Error PublishOnMeshPrefix(const OnMeshPrefixConfig &aConfig);

    /**
     * This method requests an external route prefix to be published in the Thread Network Data.
     *
     * @param[in] aConfig         The external route config to publish.
     *
     * @retval kErrorNone         The external route is published successfully.
     * @retval kErrorInvalidArgs  The @p aConfig is not valid (bad prefix or invalid flag combinations).
     * @retval kErrorAlready      An entry with the same prefix is already in the published list.
     * @retval kErrorNoBufs       Could not allocate an entry for the new request. Publisher supports a limited number
     *                            of entries (shared between on-mesh prefix and external route) determined by config
     *                            `OPENTHREAD_CONFIG_NETDATA_PUBLISHER_MAX_PREFIX_ENTRIES`.
     *
     *
     */
    Error PublishExternalRoute(const ExternalRouteConfig &aConfig);

    /**
     * This method unpublishes a previously published prefix (on-mesh or external route).
     *
     * @param[in] aPrefix       The prefix to unpublish.
     *
     * @retval kErrorNone       The prefix was unpublished successfully.
     * @retval kErrorNotFound   Could not find the prefix in the published list.
     *
     */
    Error UnpublishPrefix(const Ip6::Prefix &aPrefix);
#endif // OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE

private:
    class Entry : public InstanceLocatorInit
    {
    protected:
        enum State : uint8_t
        {
            kNoEntry,  // Entry is unused (there is no entry).
            kToAdd,    // Entry is ready to be added, monitoring network data to decide if/when to add it.
            kAdding,   // Entry is being added in network data (random wait interval before add).
            kAdded,    // Entry is added in network data, monitoring to determine if/when to remove.
            kRemoving, // Entry is being removed from network data (random wait interval before remove).
        };

        enum : uint32_t
        {
            // All intervals are in milliseconds.
            kMaxWaitTimeToAdd          = OPENTHREAD_CONFIG_NETDATA_PUBLISHER_MAX_WAIT_TIME_TO_ADD,
            kMaxWaitTimeToRemov        = OPENTHREAD_CONFIG_NETDATA_PUBLISHER_MAX_WAIT_TIME_TO_REMOVE,
            kExtraWaitToRemovePeferred = OPENTHREAD_CONFIG_NETDATA_PUBLISHER_EXTRA_WAIT_TIME_TO_REMOVE_PREFERRED,
        };

        enum : uint8_t
        {
            kInfoStringSize = 50,
        };

        typedef String<kInfoStringSize> InfoString;

        Entry(void)
            : mState(kNoEntry)
        {
        }

        void Init(Instance &aInstance) { InstanceLocatorInit::Init(aInstance); }

        State GetState(void) const { return mState; }
        void  SetState(State aState);

        const TimeMilli &GetUpdateTime(void) const { return mUpdateTime; }

        void UpdateState(uint8_t aNumEntries, uint8_t aNumPreferredEntries, uint8_t aDesiredNumEntries);
        bool HandleTimer(void);

        void               LogUpdateTime(void) const;
        InfoString         ToString(bool aIncludeState = true) const;
        static const char *StateToString(State aState);

    private:
        bool Add(bool aRegisterWithLeader);
        bool Remove(bool aRegisterWithLeader, State aNextState);

        TimeMilli mUpdateTime;
        State     mState;
    };

#if OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE
    class DnsSrpServiceEntry : public Entry, private NonCopyable
    {
        friend class Entry;

    public:
        explicit DnsSrpServiceEntry(Instance &aInstance) { Init(aInstance); }

        void PublishAnycast(uint8_t aSequenceNumber);
        void PublishUnicast(const Ip6::Address &aAddress, uint16_t aPort);
        void PublishUnicast(uint16_t aPort);
        void Unpublish(void);
        bool HandleTimer(void) { return Entry::HandleTimer(); }
        bool HandleNotifierEvents(Events aEvents);

    private:
        enum : uint8_t
        {
            kDesiredNumAnycast = OPENTHREAD_CONFIG_NETDATA_PUBLISHER_DESIRED_NUM_ANYCAST_DNS_SRP_SERVICE_ENTRIES,
            kDesiredNumUnicast = OPENTHREAD_CONFIG_NETDATA_PUBLISHER_DESIRED_NUM_UNICAST_DNS_SRP_SERVICE_ENTRIES,
        };

        enum Type : uint8_t
        {
            kTypeAnycast,
            kTypeUnicast,
            kTypeUincastMeshLocalEid,
        };

        union Info
        {
            struct
            {
                Ip6::Address mAddress;
                uint16_t     mPort;
            } mUnicast;

            struct
            {
                uint8_t mSequenceNumber;
            } mAnycast;
        };

        bool Add(bool aRegisterWithLeader);
        bool Remove(bool aRegisterWithLeader, State aNextState = kNoEntry);
        void Process(void);
        void CountAnycastEntries(uint8_t &aNumEntries, uint8_t &aNumPreferredEntries) const;
        void CountUnicastEntries(uint8_t &aNumEntries, uint8_t &aNumPreferredEntries) const;

        Type mType;
        Info mInfo;
    };
#endif // OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE

#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE
    enum : uint8_t
    {
        // Max number of prefix (on-mesh or external route) entries.
        kMaxPrefixEntries = OPENTHREAD_CONFIG_NETDATA_PUBLISHER_MAX_PREFIX_ENTRIES,
    };

    class PrefixEntry : public Entry, private NonCopyable
    {
        friend class Entry;

    public:
        void Init(Instance &aInstance) { Entry::Init(aInstance); }

        bool IsInUse(void) const { return GetState() != kNoEntry; }
        bool Matches(const Ip6::Prefix &aPrefix) const { return mPrefix == aPrefix; }

        void Publish(const OnMeshPrefixConfig &aConfig);
        void Publish(const ExternalRouteConfig &aConfig);
        void Unpublish(void);
        bool HandleTimer(void) { return Entry::HandleTimer(); }
        void HandleNotifierEvents(Events aEvents);

    private:
        enum : uint8_t
        {
            kDesiredNumOnMeshPrefix  = OPENTHREAD_CONFIG_NETDATA_PUBLISHER_DESIRED_NUM_ON_MESH_PREFIX_ENTRIES,
            kDesiredNumExternalRoute = OPENTHREAD_CONFIG_NETDATA_PUBLISHER_DESIRED_NUM_EXTERNAL_ROUTE_ENTRIES,
        };

        enum Type : uint8_t
        {
            kTypeOnMeshPrefix,
            kTypeExternalRoute,
        };

        bool Add(bool aRegisterWithLeader);
        bool Remove(bool aRegisterWithLeader, State aNextState = kNoEntry);
        void Process(void);
        void CountOnMeshPrefixEntries(uint8_t &aNumEntries, uint8_t &aNumPreferredEntries) const;
        void CountExternalRouteEntries(uint8_t &aNumEntries, uint8_t &aNumPreferredEntries) const;

        Type        mType;
        Ip6::Prefix mPrefix;
        bool        mStable;
        uint16_t    mFlags;
    };

    Error        AllocatePrefixEntry(const Ip6::Prefix &aPrefix, PrefixEntry *&aEntry);
    PrefixEntry *FindMatchingPrefixEntry(const Ip6::Prefix &aPrefix);
#endif // OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE

    TimerMilli &GetTimer(void) { return mTimer; }
    void        HandleNotifierEvents(Events aEvents);
    static void HandleTimer(Timer &aTimer);
    void        HandleTimer(void);

#if OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE
    DnsSrpServiceEntry mDnsSrpServiceEntry;
#endif

#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE
    PrefixEntry mPrefixEntries[kMaxPrefixEntries];
#endif

    TimerMilli mTimer;
};

} // namespace NetworkData
} // namespace ot

#endif // OPENTHREAD_CONFIG_NETDATA_PUBLISHER_ENABLE

#endif // NETWORK_DATA_PUBLISHER_HPP_
