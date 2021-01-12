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

#include <openthread/dns.h>

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

namespace ot {
namespace Dns {

/**
 * This class implements DNS client.
 *
 */
class Client : private NonCopyable
{
public:
    /**
     * This type represents the function pointer type which is called when a DNS response is received.
     *
     */
    typedef otDnsResponseHandler ResponseHandler;

    /**
     * This constructor initializes the object.
     *
     * @param[in]  aInstance     A reference to the OpenThread instance.
     *
     */
    explicit Client(Instance &aInstance);

    // TODO: convert this into private method and control through the event handler
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
     * This method sends a DNS query.
     *
     * @param[in]  aServerSockAddr  A pointer to server socket address.
     * @param[in]  aHostName        The host name for which to query the address.
     * @param[in]  aNoRecursion     Indicates whether name server can resolve the query recursively or not.
     * @param[in]  aHandler         A function pointer that shall be called on response reception or time-out.
     * @param[in]  aContext         A pointer to arbitrary context information.
     *
     * @retval OT_ERROR_NONE            Successfully sent DNS query.
     * @retval OT_ERROR_NO_BUFS         Failed to allocate retransmission data.
     * @retval OT_ERROR_INVALID_ARGS    The host name is not valid format.
     * @retval OT_ERROR_INVALID_STATE   Cannot send query since Thread interface is not up.
     *
     */
    otError Query(const Ip6::SockAddr &aServerSockAddr,
                  const char *         aHostName,
                  ResponseHandler      aHandler,
                  void *               aContext);

private:
    /**
     * Retransmission parameters.
     *
     */
    enum
    {
        kResponseTimeout = OPENTHREAD_CONFIG_DNS_RESPONSE_TIMEOUT, // in msec
        kMaxRetransmit   = OPENTHREAD_CONFIG_DNS_MAX_RETRANSMIT,
    };

    enum
    {
        kBufSize = 16
    };

    typedef Message      Query;
    typedef MessageQueue QueryList;

    struct Info : public Clearable<Info>
    {
        void ReadFrom(const Query &aQuery) { IgnoreError(aQuery.Read(0, *this)); }

        uint16_t        mMessageId;
        Ip6::SockAddr   mServerSockAddr;
        ResponseHandler mResponseHandler;
        void *          mResponseContext;
        TimeMilli       mRetransmissionTime;
        uint8_t         mRetransmissionCount;
        // Followed by the host name appended as given.
    };

    otError AllocateQuery(const Info &aInfo, const char *aHostName, Query *&aQuery);
    void    FreeQuery(Query &aQuery);
    void    UpdateQuery(Query &aQuery, const Info &aInfo) { aQuery.Write(0, aInfo); }
    void    SendQuery(Query &aQuery);
    otError AppendNameFromQuery(const Query &aQuery, Message &aMessage);
    void    InvokeResponseHandler(Query &aQuery, otError aError);
    Query * FindQueryById(uint16_t aMessageId);

    void    DequeueMessage(Message &aMessage);
    otError SendMessage(Message &aMessage, const Ip6::MessageInfo &aMessageInfo);
    void    SendCopy(const Message &aMessage, const Ip6::MessageInfo &aMessageInfo);

    otError CompareQuestions(Message &aMessageResponse, Message &aMessageQuery, uint16_t &aOffset);

    Message *FindQueryById(uint16_t aMessageId);
    void     FinalizeDnsTransaction(Message &            aQuery,
                                    const QueryMetadata &aQueryMetadata,
                                    const Ip6::Address * aAddress,
                                    uint32_t             aTtl,
                                    otError              aResult);

    static void HandleTimer(Timer &aTimer);
    void        HandleTimer(void);

    static void HandleUdpReceive(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo);
    void        HandleUdpReceive(Message &aMessage, const Ip6::MessageInfo &aMessageInfo);

    Ip6::Udp::Socket mSocket;

    QueryList  mQueries;
    TimerMilli mTimer;
};

} // namespace Dns
} // namespace ot

#endif // DNS_CLIENT_HPP_
