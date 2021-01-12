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

#include "dns_client.hpp"

#include "common/code_utils.hpp"
#include "common/debug.hpp"
#include "common/instance.hpp"
#include "common/locator-getters.hpp"
#include "common/logging.hpp"
#include "net/udp6.hpp"
#include "thread/thread_netif.hpp"

#if OPENTHREAD_CONFIG_DNS_CLIENT_ENABLE

/**
 * @file
 *   This file implements the DNS client.
 */

using ot::Encoding::BigEndian::HostSwap16;

namespace ot {
namespace Dns {

Client::Client(Instance &aInstance)
    : mSocket(aInstance)
    , mTimer(aInstance, Client::HandleTimer, this)
{
}

otError Client::Start(void)
{
    otError error;

    SuccessOrExit(error = mSocket.Open(&Client::HandleUdpReceive, this));
    SuccessOrExit(error = mSocket.Bind());

exit:
    return error;
}

otError Client::Stop(void)
{
    Query *query;
    Info   info;

    while ((query = mQueries.GetHead()) != nullptr)
    {
        InvokeResponseHandler(*query, OT_ERROR_ABORT);
        FreeQuery(*query);
    }

    return mSocket.Close();
}

otError Client::Query(const Ip6::SockAddr &aServerSockAddr,
                      const char *         aHostName,
                      ResponseHandler      aHandler,
                      void *               aContext)
{
    otError error;
    Info    info;
    Query * query;

    VerifyOrExit(mSocket.IsBound(), error = OT_ERROR_INVALID_STATE);

    info.Clear();
    info.mServerSockAddr  = aServerSockAddr;
    info.mResponseHandler = aHandler;
    info.mResponseContext = aContext;

    SuccessOrExit(error = AllocateQuery(info, aHostName, query));
    mQueries.Enqueue(*query);

    SendQuery(*query);

exit:
    return error;
}

otError Client::AllocateQuery(const Info &aInfo, const char *aHostName, Query *&aQuery)
{
    otError error = OT_ERROR_NONE;

    aQuery = Get<MessagePool>().New(Message::kTypeOther, /* aReserveHeader */ 0);
    VerifyOrExit(aQuery != nullptr);

    SuccessOrExit(error = aQuery->Append(aInfo));
    SuccessOrExit(error = Name::AppendName(aHostName, *aQuery));

exit:
    FreeAndNullMessageOnError(aQuery, error);
    return error;
}

void Client::FreeQuery(Query &aQuery)
{
    mQueries.Dequeue(aQuery);
    aQuery.Free();
}

void Client::SendQuery(Query &aQuery)
{
    otError          error   = OT_ERROR_NONE;
    Message *        message = nullptr;
    Info             info;
    Header           header;
    Ip6::MessageInfo messageInfo;

    info.ReadFrom(aQuery);

    info.mRetransmissionTime = TimerMilli::GetNow() + kResponseTimeout;

    if (info.mMessageId == 0)
    {
        do
        {
            SuccessOrExit(error = header.SetRandomMessageId());
        } while (FindQueryById(header.GetMessageId()) != nullptr);

        info.mMessageId = header.GetMessageId();
    }
    else
    {
        header.SetMessageId(info.mMessageId);
    }

    header.SetType(Header::kTypeQuery);
    header.SetQueryType(Header::kQueryTypeStandard);

    if (!info.mNoRecursion)
    {
        header.SetRecursionDesiredFlag();
    }

    header.SetQuestionCount(1);

    message = mSocket.NewMessage(0);
    VerifyOrExit(message != nullptr, error = OT_ERROR_NO_BUFS);

    SuccessOrExit(error = AppendNameFromQuery(aQuery, *message));
    SuccessOrExit(error = message->Append(QuestionAaaa()));

    messageInfo.SetPeerAddr(info.mServerSockAddr.GetAddress());
    messageInfo.SetPeerPort(info.mServerSockAddr.GetPeerPort());

    SuccessOrExit(error = mSocket.SendTo(*message, messageInfo));

exit:
    FreeMessageOnError(message, error);

    UpdateQuery(aQuery, info);
    mTimer.FireAtIfEarlier(info.mRetransmissionTime);
}

otError Client::AppendNameFromQuery(const Query &aQuery, Message &aMessage)
{
    otError  error = OT_ERROR_NONE;
    uint16_t offset;
    uint16_t length;

    // The name is encoded and included after the `Info` in `aQuery. We
    // first calculate the encoded length of the name, then grow the
    // message, and finally copy the encoded name bytes from `aQuery`
    // into `aMessage`.

    length = aQuery.GetLength() - sizeof(Info);

    offset = aMessage.GetLength();
    SuccessOrExit(error = aMessage.SetLength(offset + length));

    aQuery.CopyTo(/* aSourceOffset */ sizeof(Info), /* aDestOffset */ offset, length, aMessage);

exit:
    return error;
}

void Client::InvokeResponseHandler(Query &aQuery, otError aError)
{
    Info info;

    OT_ASSERT(aError != OT_ERROR_NONE);

    info.ReadFrom(aQuery);
    VerifyOrExit(info.mResponseHandler != nullptr);

    info.mResponseHandler(aError, /* host */ nullptr, nullptr, 0, info.mResponseContext);

exit:
    return;
}

Query *Client::FindQueryById(uint16_t aMessageId)
{
    Query *query;
    Info   info;

    for (query = mQueries.GetHead(); query != nullptr; query = query->GetNext())
    {
        info.ReadFrom(*query);

        if (info.mMessageId == aMessageId)
        {
            break;
        }
    }

    return query;
}

















void Client::DequeueMessage(Message &aMessage)
{
    mPendingQueries.Dequeue(aMessage);

    if (mPendingQueries.GetHead() == nullptr)
    {
        mTimer.Stop();
    }

    aMessage.Free();
}

otError Client::CompareQuestions(Message &aMessageResponse, Message &aMessageQuery, uint16_t &aOffset)
{
    otError  error = OT_ERROR_NONE;
    uint8_t  bufQuery[kBufSize];
    uint8_t  bufResponse[kBufSize];
    uint16_t read = 0;

    // Compare question section of the query with the response.
    uint16_t length = aMessageQuery.GetLength() - aMessageQuery.GetOffset() - sizeof(Header) - sizeof(QueryMetadata);
    uint16_t offset = aMessageQuery.GetOffset() + sizeof(Header);

    while (length > 0)
    {
        VerifyOrExit((read = aMessageQuery.ReadBytes(offset, bufQuery,
                                                     length < sizeof(bufQuery) ? length : sizeof(bufQuery))) > 0,
                     error = OT_ERROR_PARSE);
        SuccessOrExit(error = aMessageResponse.Read(aOffset, bufResponse, read));

        VerifyOrExit(memcmp(bufResponse, bufQuery, read) == 0, error = OT_ERROR_NOT_FOUND);

        aOffset += read;
        offset += read;
        length -= read;
    }

exit:
    return error;
}

Message *Client::FindQueryById(uint16_t aMessageId)
{
    uint16_t messageId;
    Message *message;

    for (message = mPendingQueries.GetHead(); message != nullptr; message = message->GetNext())
    {
        // Partially read DNS header to obtain message ID only.
        if (message->Read(message->GetOffset(), messageId) != OT_ERROR_NONE)
        {
            OT_ASSERT(false);
        }

        if (HostSwap16(messageId) == aMessageId)
        {
            break;
        }
    }

    return message;
}

void Client::FinalizeDnsTransaction(Message &            aQuery,
                                    const QueryMetadata &aQueryMetadata,
                                    const Ip6::Address * aAddress,
                                    uint32_t             aTtl,
                                    otError              aResult)
{
    DequeueMessage(aQuery);

    if (aQueryMetadata.mResponseHandler != nullptr)
    {
        aQueryMetadata.mResponseHandler(aQueryMetadata.mResponseContext, aQueryMetadata.mHostname, aAddress, aTtl,
                                        aResult);
    }
}

void Client::HandleTimer(Timer &aTimer)
{
    aTimer.GetOwner<Client>().HandleTimer();
}

void Client::HandleTimer(void)
{
    TimeMilli        now      = TimerMilli::GetNow();
    TimeMilli        nextTime = now.GetDistantFuture();
    QueryMetadata    queryMetadata;
    Message *        message;
    Message *        nextMessage;
    Ip6::MessageInfo messageInfo;

    for (message = mPendingQueries.GetHead(); message != nullptr; message = nextMessage)
    {
        nextMessage = message->GetNext();

        queryMetadata.ReadFrom(*message);

        if (now >= queryMetadata.mTransmissionTime)
        {
            if (queryMetadata.mRetransmissionCount >= kMaxRetransmit)
            {
                FinalizeDnsTransaction(*message, queryMetadata, nullptr, 0, OT_ERROR_RESPONSE_TIMEOUT);

                continue;
            }

            // Increment retransmission counter and timer.
            queryMetadata.mRetransmissionCount++;
            queryMetadata.mTransmissionTime = now + kResponseTimeout;
            queryMetadata.UpdateIn(*message);

            // Retransmit
            messageInfo.SetPeerAddr(queryMetadata.mDestinationAddress);
            messageInfo.SetPeerPort(queryMetadata.mDestinationPort);
            messageInfo.SetSockAddr(queryMetadata.mSourceAddress);

            SendCopy(*message, messageInfo);
        }

        if (nextTime > queryMetadata.mTransmissionTime)
        {
            nextTime = queryMetadata.mTransmissionTime;
        }
    }

    if (nextTime < now.GetDistantFuture())
    {
        mTimer.FireAt(nextTime);
    }
}

void Client::HandleUdpReceive(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    static_cast<Client *>(aContext)->HandleUdpReceive(*static_cast<Message *>(aMessage),
                                                      *static_cast<const Ip6::MessageInfo *>(aMessageInfo));
}

void Client::HandleUdpReceive(Message &aMessage, const Ip6::MessageInfo &aMessageInfo)
{
    // RFC1035 7.3. Resolver cannot rely that a response will come from the same address
    // which it sent the corresponding query to.
    OT_UNUSED_VARIABLE(aMessageInfo);

    otError       error = OT_ERROR_NOT_FOUND;
    Header        responseHeader;
    QueryMetadata queryMetadata;
    AaaaRecord    record;
    Message *     message = nullptr;
    uint16_t      offset;

    SuccessOrExit(aMessage.Read(aMessage.GetOffset(), responseHeader));
    VerifyOrExit(responseHeader.GetType() == Header::kTypeResponse && responseHeader.GetQuestionCount() == 1 &&
                 !responseHeader.IsTruncationFlagSet());

    aMessage.MoveOffset(sizeof(responseHeader));
    offset = aMessage.GetOffset();

    VerifyOrExit((message = FindQueryById(responseHeader.GetMessageId())) != nullptr);
    queryMetadata.ReadFrom(*message);

    VerifyOrExit(responseHeader.GetResponseCode() == Header::kResponseSuccess, error = OT_ERROR_FAILED);

    // Parse and check the question section.
    SuccessOrExit(error = CompareQuestions(aMessage, *message, offset));

    // Parse and check the answer section.
    for (uint32_t index = 0; index < responseHeader.GetAnswerCount(); index++)
    {
        uint32_t newOffset;

        SuccessOrExit(error = Name::ParseName(aMessage, offset));

        SuccessOrExit(error = aMessage.Read(offset, record));

        if (record.Matches(ResourceRecord::kTypeAaaa))
        {
            // Return the first found IPv6 address.
            FinalizeDnsTransaction(*message, queryMetadata, &record.GetAddress(), record.GetTtl(), OT_ERROR_NONE);
            ExitNow(error = OT_ERROR_NONE);
        }

        newOffset = offset + record.GetSize();
        VerifyOrExit(newOffset <= aMessage.GetLength(), error = OT_ERROR_PARSE);
        offset = static_cast<uint16_t>(newOffset);
    }

exit:

    if (message != nullptr && error != OT_ERROR_NONE)
    {
        FinalizeDnsTransaction(*message, queryMetadata, nullptr, 0, error);
    }
}

void Client::QueryMetadata::ReadFrom(const Message &aMessage)
{
    uint16_t length = aMessage.GetLength();

    OT_ASSERT(length >= sizeof(*this));
    IgnoreError(aMessage.Read(length - sizeof(*this), *this));
}

void Client::QueryMetadata::UpdateIn(Message &aMessage) const
{
    aMessage.Write(aMessage.GetLength() - sizeof(*this), *this);
}

} // namespace Dns
} // namespace ot

#endif // OPENTHREAD_CONFIG_DNS_CLIENT_ENABLE
