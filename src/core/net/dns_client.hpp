/*
 *  Copyright (c) 2017, The OpenThread Authors.
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

#ifndef DNS_CLIENT_HPP_
#define DNS_CLIENT_HPP_

#include "openthread-core-config.h"

#include <openthread/dns_client.h>

#include "common/clearable.hpp"
#include "common/message.hpp"
#include "common/non_copyable.hpp"
#include "common/timer.hpp"
#include "net/dns_headers.hpp"
#include "net/ip6.hpp"
#include "net/netif.hpp"

/**
 * @file
 *   This file includes definitions for the DNS client.
 */

/**
 * This struct represents an opaque (and empty) type for a response to address resolution DNS query.
 *
 */
struct otDnsAddressResponse
{
};

namespace ot {
namespace Dns {

/**
 * This class implements DNS client.
 *
 */
class Client : public InstanceLocator, private NonCopyable
{
    typedef Message Query; // `Message` is used to save `Query` related info.

public:
    /**
     * This type represents the function pointer callback which is called when a DNS response for an address resolution
     * query is received.
     *
     */
    typedef otDnsAddressCallback AddressCallback;

    /**
     * This type represent an DNS address resolution query response.
     *
     */
    class AddressResponse : public otDnsAddressResponse, public InstanceLocator
    {
        friend class Client;

    public:
        /**
         * This method gets the host name associated with a DNS address resolution response.
         *
         * This method MUST only be used from `AddressCallback` callback.
         *
         * @param[out] aNameBuffer       A buffer to char array to output the host name.
         * @param[in]  aNameBufferSize   The size of @p aNameBuffer.
         *
         * @retval OT_ERROR_NONE     The host name was read successfully.
         * @retval OT_ERROR_NO_BUFS  The name does not fit in @p aNameBuffer.
         *
         */
        otError GetHostName(char *aNameBuffer, uint16_t aNameBufferSize) const;

        /**
         * This method gets the first IPv6 address associated with a DNS address resolution response.
         *
         * This method MUST only be used from `AddressCallback` callback.
         *
         * @param[out] aAddress      A reference to a IPv6 address to output the address.
         * @param[out] aTtl          A reference to a `uint32_t` to output TTL for the address.
         *
         * @retval OT_ERROR_NONE       The first address was read successfully.
         * @retval OT_ERROR_NOT_FOUND  No address record in @p aResponse at @p aIndex.
         *
         */
        otError GetAddress(uint16_t aIndex, Ip6::Address &aAddress, uint32_t &aTtl) const;

    private:
        explicit AddressResponse(Instance &aInstance, const Message *aMessage = nullptr)
            : InstanceLocator(aInstance)
            , mMessage(aMessage)
        {
        }

        Query *        mQuery;        // The associated query.
        const Message *mMessage;      // The response message (GetOffset() points to header)
        Header         mHeader;       // The header of the response message.
        uint16_t       mAnswerOffset; // Answer section start offset.
    };

    /**
     * This constructor initializes the object.
     *
     * @param[in]  aInstance     A reference to the OpenThread instance.
     *
     */
    explicit Client(Instance &aInstance);

    /**
     * This method starts the DNS client.
     *
     * @retval OT_ERROR_NONE     Successfully started the DNS client.
     * @retval OT_ERROR_ALREADY  The socket is already open.
     *
     */
    otError Start(void);

    /**
     * This method stops the DNS client.
     *
     * @retval OT_ERROR_NONE  Successfully stopped the DNS client.
     *
     */
    otError Stop(void);

    /**
     * This method sends an address resolution DNS query for AAAA (IPv6) record for a given host name.
     *
     * @param[in]  aServerSockAddr  A pointer to server socket address.
     * @param[in]  aHostName        The host name for which to query the address.
     * @param[in]  aNoRecursion     Indicates whether name server can resolve the query recursively or not.
     * @param[in]  aCallback        A callback function pointer to report the result of query.
     * @param[in]  aContext         A pointer to arbitrary context information passed to @p aCallback.
     *
     * @retval OT_ERROR_NONE            Successfully sent DNS query.
     * @retval OT_ERROR_NO_BUFS         Failed to allocate retransmission data.
     * @retval OT_ERROR_INVALID_ARGS    The host name is not valid format.
     * @retval OT_ERROR_INVALID_STATE   Cannot send query since Thread interface is not up.
     *
     */
    otError ResolveAddress(const Ip6::SockAddr &aServerSockAddr,
                           const char *         aHostName,
                           bool                 aNoRecursion,
                           AddressCallback      aCallback,
                           void *               aContext);

private:
    enum
    {
        kResponseTimeout = OPENTHREAD_CONFIG_DNS_RESPONSE_TIMEOUT, // in msec
        kMaxRetransmit   = OPENTHREAD_CONFIG_DNS_MAX_RETRANSMIT,
    };

    typedef MessageQueue QueryList; // List of queries.

    struct Info : public Clearable<Info>
    {
        void ReadFrom(const Query &aQuery) { IgnoreError(aQuery.Read(0, *this)); }

        uint16_t        mMessageId;
        Ip6::SockAddr   mServerSockAddr;
        AddressCallback mCallback;
        void *          mCallbackContext;
        TimeMilli       mRetransmissionTime;
        uint8_t         mRetransmissionCount;
        bool            mNoRecursion;
        // Followed by the host name encoded as a `Dns::Name`.
    };

    otError     AllocateQuery(const Info &aInfo, const char *aHostName, Query *&aQuery);
    void        FreeQuery(Query &aQuery);
    void        UpdateQuery(Query &aQuery, const Info &aInfo) { aQuery.Write(0, aInfo); }
    void        SendQuery(Query &aQuery, bool aUpdateTimer);
    void        FinalizeQuery(Query &aQuery, otError aError);
    void        FinalizeQuery(AddressResponse &Response, otError aError);
    otError     AppendNameFromQuery(const Query &aQuery, Message &aMessage);
    Query *     FindQueryById(uint16_t aMessageId);
    static void HandleUdpReceive(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo);
    void        ProcessResponse(const Message &aMessage);
    static void HandleTimer(Timer &aTimer);
    void        HandleTimer(void);

    Ip6::Udp::Socket mSocket;
    QueryList        mQueries;
    TimerMilli       mTimer;
};

} // namespace Dns
} // namespace ot

#endif // DNS_CLIENT_HPP_
