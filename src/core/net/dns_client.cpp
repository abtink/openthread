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

namespace ot {
namespace Dns {

//---------------------------------------------------------------------------------------------------------------------
// Client::AddressResponse

otError Client::AddressResponse::GetHostName(char *aNameBuffer, uint16_t aNameBufferSize) const
{
    uint16_t offset = sizeof(Info);

    return Name::ReadName(*mQuery, offset, aNameBuffer, aNameBufferSize);
}

otError Client::AddressResponse::GetAddress(uint16_t aIndex, Ip6::Address &aAddress, uint32_t &aTtl) const
{
    otError    error;
    uint16_t   offset = mAnswerOffset;
    AaaaRecord aaaaRecord;

    VerifyOrExit(mMessage != nullptr, error = OT_ERROR_NOT_FOUND);
    VerifyOrExit(aIndex < mHeader.GetAnswerCount(), error = OT_ERROR_NOT_FOUND);

    if (aIndex > 0)
    {
        SuccessOrExit(error = ResourceRecord::ParseRecords(*mMessage, offset, aIndex - 1));
    }

    for (; aIndex < mHeader.GetAnswerCount(); aIndex++)
    {
        SuccessOrExit(error = Name::ParseName(*mMessage, offset));

        error = ResourceRecord::ReadRecord(*mMessage, offset, aaaaRecord);

        switch (error)
        {
        case OT_ERROR_NOT_FOUND:
            break;

        case OT_ERROR_NONE:
            aAddress = aaaaRecord.GetAddress();
            aTtl     = aaaaRecord.GetTtl();

            OT_FALL_THROUGH;

        default:
            ExitNow();
        }
    }

    error = OT_ERROR_NOT_FOUND;

exit:
    return error;
}

//---------------------------------------------------------------------------------------------------------------------
// Client

Client::Client(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mSocket(aInstance)
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
        FinalizeQuery(*query, OT_ERROR_ABORT);
    }

    return mSocket.Close();
}

otError Client::ResolveAddress(const Ip6::SockAddr &aServerSockAddr,
                               const char *         aHostName,
                               bool                 aNoRecursion,
                               AddressCallback      aCallback,
                               void *               aContext)
{
    otError error;
    Info    info;
    Query * query;

    VerifyOrExit(mSocket.IsBound(), error = OT_ERROR_INVALID_STATE);

    info.Clear();
    info.mServerSockAddr  = aServerSockAddr;
    info.mNoRecursion     = aNoRecursion;
    info.mCallback        = aCallback;
    info.mCallbackContext = aContext;

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
    Info info;

    info.ReadFrom(aQuery);

    SendQuery(aQuery, info, /* aUpdateTimer */ true);
}

void Client::SendQuery(Query &aQuery, Info &aInfo, bool aUpdateTimer)
{
    otError          error   = OT_ERROR_NONE;
    Message *        message = nullptr;
    Header           header;
    Ip6::MessageInfo messageInfo;

    aInfo.mRetransmissionTime = TimerMilli::GetNow() + kResponseTimeout;

    if (aInfo.mMessageId == 0)
    {
        do
        {
            SuccessOrExit(error = header.SetRandomMessageId());
        } while (FindQueryById(header.GetMessageId()) != nullptr);

        aInfo.mMessageId = header.GetMessageId();
    }
    else
    {
        header.SetMessageId(aInfo.mMessageId);
    }

    header.SetType(Header::kTypeQuery);
    header.SetQueryType(Header::kQueryTypeStandard);

    if (!aInfo.mNoRecursion)
    {
        header.SetRecursionDesiredFlag();
    }

    header.SetQuestionCount(1);

    message = mSocket.NewMessage(0);
    VerifyOrExit(message != nullptr, error = OT_ERROR_NO_BUFS);

    SuccessOrExit(error = message->Append(header));

    SuccessOrExit(error = AppendNameFromQuery(aQuery, *message));
    SuccessOrExit(error = message->Append(Question(ResourceRecord::kTypeAaaa)));

    messageInfo.SetPeerAddr(aInfo.mServerSockAddr.GetAddress());
    messageInfo.SetPeerPort(aInfo.mServerSockAddr.GetPort());

    SuccessOrExit(error = mSocket.SendTo(*message, messageInfo));

exit:
    FreeMessageOnError(message, error);

    UpdateQuery(aQuery, aInfo);

    if (aUpdateTimer)
    {
        mTimer.FireAtIfEarlier(aInfo.mRetransmissionTime);
    }
}

otError Client::AppendNameFromQuery(const Query &aQuery, Message &aMessage)
{
    otError  error = OT_ERROR_NONE;
    uint16_t offset;
    uint16_t length;

    // The name is encoded and included after the `Info` in `aQuery`. We
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

void Client::FinalizeQuery(Query &aQuery, otError aError)
{
    AddressResponse response(GetInstance());

    response.mQuery = &aQuery;

    FinalizeQuery(response, aError);
}

void Client::FinalizeQuery(AddressResponse &aResponse, otError aError)
{
    Info info;

    info.ReadFrom(*aResponse.mQuery);

    VerifyOrExit(info.mCallback != nullptr);
    info.mCallback(aError, &aResponse, info.mCallbackContext);

exit:
    FreeQuery(*aResponse.mQuery);
}

Client::Query *Client::FindQueryById(uint16_t aMessageId)
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

void Client::HandleUdpReceive(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    OT_UNUSED_VARIABLE(aMessageInfo);

    static_cast<Client *>(aContext)->ProcessResponse(*static_cast<Message *>(aMessage));
}

void Client::ProcessResponse(const Message &aMessage)
{
    otError         error  = OT_ERROR_NONE;
    uint16_t        offset = aMessage.GetOffset();
    AddressResponse response(GetInstance(), &aMessage);

    SuccessOrExit(aMessage.Read(offset, response.mHeader));
    offset += sizeof(Header);

    VerifyOrExit(response.mHeader.GetType() == Header::kTypeResponse &&
                 response.mHeader.GetQueryType() == Header::kQueryTypeStandard);
    VerifyOrExit(!response.mHeader.IsTruncationFlagSet());

    response.mQuery = FindQueryById(response.mHeader.GetMessageId());
    VerifyOrExit(response.mQuery != nullptr);

    // Check the Question Section

    VerifyOrExit(response.mHeader.GetQuestionCount() == 1, error = OT_ERROR_PARSE);

    VerifyOrExit(aMessage.Compare(offset, Question(ResourceRecord::kTypeAaaa)), error = OT_ERROR_PARSE);
    offset += sizeof(Question);

    // The name is encoded after `Info` struct in `query`.
    SuccessOrExit(error = Name::CompareName(aMessage, offset, *response.mQuery, sizeof(Info)));

    if (response.mHeader.GetResponseCode() != Header::kResponseSuccess)
    {
        FinalizeQuery(*response.mQuery, Header::ResponseCodeToError(response.mHeader.GetResponseCode()));
        ExitNow();
    }

    // Check the answer, authority and additional record sections

    response.mAnswerOffset = offset;
    SuccessOrExit(error = ResourceRecord::ParseRecords(aMessage, offset, response.mHeader.GetAnswerCount()));
    SuccessOrExit(error = ResourceRecord::ParseRecords(aMessage, offset, response.mHeader.GetAuthorityRecordCount()));
    SuccessOrExit(error = ResourceRecord::ParseRecords(aMessage, offset, response.mHeader.GetAuthorityRecordCount()));

    FinalizeQuery(response, OT_ERROR_NONE);

exit:
    if (error != OT_ERROR_NONE)
    {
        otLogInfoDns("[client] Failed to process response %s", otThreadErrorToString(error));
    }
}

void Client::HandleTimer(Timer &aTimer)
{
    aTimer.GetOwner<Client>().HandleTimer();
}

void Client::HandleTimer(void)
{
    TimeMilli now      = TimerMilli::GetNow();
    TimeMilli nextTime = now.GetDistantFuture();
    Query *   nextQuery;
    Info      info;

    for (Query *query = mQueries.GetHead(); query != nullptr; query = nextQuery)
    {
        nextQuery = query->GetNext();

        info.ReadFrom(*query);

        if (now >= info.mRetransmissionTime)
        {
            if (info.mRetransmissionCount >= kMaxRetransmit)
            {
                FinalizeQuery(*query, OT_ERROR_RESPONSE_TIMEOUT);
                continue;
            }

            info.mRetransmissionCount++;
            SendQuery(*query, info, /* aUpdateTimer */ false);
        }

        if (nextTime > info.mRetransmissionTime)
        {
            nextTime = info.mRetransmissionTime;
        }
    }

    if (nextTime < now.GetDistantFuture())
    {
        mTimer.FireAt(nextTime);
    }
}

} // namespace Dns
} // namespace ot

#endif // OPENTHREAD_CONFIG_DNS_CLIENT_ENABLE
