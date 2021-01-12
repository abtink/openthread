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

/**
 * @file
 * @brief
 *  This file defines the top-level dns functions for the OpenThread library.
 */

#ifndef OPENTHREAD_DNS_H_
#define OPENTHREAD_DNS_H_

#include <openthread/ip6.h>
#include <openthread/message.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup api-dns
 *
 * @brief
 *   This module includes functions that control DNS communication.
 *
 * @{
 *
 */

#define OT_DNS_MAX_HOSTNAME_SIZE 254 ///< Maximum allowed hostname size (includes null char at end of string).

#define OT_DNS_DEFAULT_SERVER_PORT 53 ///< Defines default DNS Server port.

// TODO: change to a const otSockAddr definition.
#define OT_DNS_DEFAULT_SERVER_IP "2001:4860:4860::8888" ///< Defines default DNS Server address - Google DNS.

/**
 * This function pointer is called when a DNS response is received.
 *
 * @param[in]  aError    The result of the DNS transaction.
 * @param[in]  aHostname  Identifies hots name related with DNS response.
 * @param[in]  aAddress   A pointer to the IPv6 address received in DNS response. May be null.
 * @param[in]  aTtl       Specifies the maximum time in seconds that the resource record may be cached.
 * @param[in]  aContext   A pointer to application-specific context.
 *
 * The @p aError can have the following:
 *
 * -  OT_ERROR_NONE              A response was received successfully and IPv6 address is provided in @p aAddress.
 * -  OT_ERROR_ABORT             A DNS transaction was aborted by stack.
 * -  OT_ERROR_RESPONSE_TIMEOUT  No DNS response has been received within timeout.
 * -  OT_ERROR_NOT_FOUND         A response was received but no IPv6 address has been found.
 * -  OT_ERROR_FAILED            A response was received but status code is different than success.
 *
 */
// TODOD: change this to allow multiple address entries to be reported back to user. If multiple AAAA RR
typedef void (*otDnsResponseHandler)(otError             aError,
                                     const char *        aHostname,
                                     const otIp6Address *aAddress,
                                     uint32_t            aTtl,
                                     void *              aContext);

/**
 * This function sends a DNS query for AAAA (IPv6) record to a given server.
 *
 * This function is available only if feature `OPENTHREAD_CONFIG_DNS_CLIENT_ENABLE` is enabled.
 *
 * @param[in]  aInstance        A pointer to an OpenThread instance.
 * @param[in]  aServerSockAddr  A pointer to server socket address.
 * @param[in]  aHostName        The host name for which to query the address.
 * @param[in]  aNoRecursion     Indicates whether name server can resolve the query recursively or not.
 * @param[in]  aHandler         A function pointer that shall be called on response reception or time-out.
 * @param[in]  aContext         A pointer to arbitrary context information.
 *
 * @retval OT_ERROR_NONE          Query started successfully. @p aHanlder will be invoked to report the status.
 * @retval OT_ERROR_NO_BUFS       Insufficient buffer to prepare and send query.
 *
 */
otError otDnsClientQuery(otInstance *         aInstance,
                         const otSockAddr *   aServerSockAddr,
                         const char *         aHostName,
                         bool                 aNoRecursion,
                         otDnsResponseHandler aHandler,
                         void *               aContext);

/**
 * @}
 *
 */

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPENTHREAD_DNS_H_
