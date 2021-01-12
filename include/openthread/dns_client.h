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
 *  This file defines the top-level DNS functions for the OpenThread library.
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

#define OT_DNS_MAX_NAME_SIZE 255 ///< Maximum name string size (includes null char at the end of string).

#define OT_DNS_MAX_LABEL_SIZE 64 ///< Maximum label string size (include null char at the end of string)

#define OT_DNS_DEFAULT_SERVER_PORT 53 ///< The default DNS Server port.

#define OT_DNS_DEFAULT_SERVER_IP "2001:4860:4860::8888" ///< Defines default DNS Server address - Google DNS.

/**
 * This type represents opaque representation of DNS response to a address resolution query.
 *
 * Pointers to instance of this type are provided from callback `otDnsClientAddressResponseHandler`.
 *
 */
typedef struct otDnsClientAddressResponse otDnsClientAddressResponse;

/**
 * This function pointer is called when a DNS response is received for an address resolution query
 *
 * Within this callback the user can use `otDnsClientGetAddressResponseHostName()` and other response related function
 * along with the @p aResponse pointer to get more info about the response.
 *
 * The @p aResponse pointer can only be used within this callback and after returning from this function it will not
 * stay valid, so the user MUST NOT retain the @p aResponse pointer for later use.
 *
 * @param[in]  aError     The result of the DNS transaction.
 * @param[in]  aResponse  A pointer to the response (it is always non-null).
 * @param[in]  aContext   A pointer to application-specific context.
 *
 * The @p aError can have the following:
 *
 *  - OT_ERROR_NONE              A response was received successfully.
 *  - OT_ERROR_ABORT             A DNS transaction was aborted by stack.
 *  - OT_ERROR_RESPONSE_TIMEOUT  No DNS response has been received within timeout.
 *
 * If the server rejects the address resolution request the error code from server is mapped as follow:
 *
 *  - kResponseFormatError (1)     : Server unable to interpret due to format error  -> OT_ERROR_PARSE
 *  - kResponseServerFailure (2)   : Server encountered an internal failure          -> OT_ERROR_FAILED
 *  - kResponseNameError (3)       : Name that ought to exist, does not exists       -> OT_ERROR_NOT_FOUND
 *  - kResponseNotImplemented (4)  : Server does not support the query type (OpCode) -> OT_ERROR_NOT_IMPLEMENTED
 *  - kResponseRefused (5)         : Server refused for policy/security reasons      -> OT_ERROR_SECURITY
 *  - kResponseNameExists (6)      : Some name that ought not to exist, does exist   -> OT_ERROR_DUPLICATED
 *  - kResponseRecordExists (7)    : Some RRset that ought not to exist, does exist  -> OT_ERROR_DUPLICATED
 *  - kResponseRecordNotExists (8) : Some RRset that ought to exist, does not exist  -> OT_ERROR_NOT_FOUND
 *  - kResponseNotAuth (9)         : Service is not authoritative for zone           -> OT_ERROR_SECURITY
 *  - kResponseNotZone (10)        : A name is not in the zone                       -> OT_ERROR_PARSE
 *  - kResponseBadName (20)        : Bad name                                        -> OT_ERROR_PARSE
 *  - kResponseBadAlg (21)         : Bad algorithm                                   -> OT_ERROR_SECURITY
 *  - kResponseBadTruncation (22)  : Bad truncation                                  -> OT_ERROR_PARSE
 *  - Other error                                                                    -> OT_ERROR_FAILED
 *
 */
typedef void (*otDnsClientAddressResponseHandler)(otError                           aError,
                                                  const otDnsClientAddressResponse *aResponse,
                                                  void *                            aContext);
/**
 * This function gets the host name associated with a DNS address resolution response.
 *
 * This function MUST only be used from `otDnsClientAddressResponseHandler` callback.
 *
 * @param[in]  aResponse         A pointer to a response.
 * @param[out] aNameBuffer       A buffer to char array to output the host name (MUST NOT be NULL).
 * @param[in]  aNameBufferSize   The size of @p aNameBuffer.
 *
 * @retval OT_ERROR_NONE     The host name was read successfully.
 * @retval OT_ERROR_NO_BUFS  The name does not fit in @p aNameBuffer.
 *
 */
otError otDnsClientGetAddressResponseHostName(const otDnsClientAddressResponse *aResponse,
                                              char *                            aNameBuffer,
                                              uint16_t                          aNameBufferSize);

/**
 * This function gets an IPv6 address associated with a DNS address resolution response.
 *
 * This function MUST only be used from `otDnsClientAddressResponseHandler` callback.
 *
 * A response may include multiple IPv6 address records. @p aIndex can be used to iterate through the list of addresses,
 * (index 0 gives the the first address). When we reach end of the list, `OT_ERROR_NOT_FOUND` is returned.
 *
 * @param[in]  aResponse     A pointer to a response.
 * @param[in]  aIndex        The address record index to retrieve.
 * @param[out] aAddress      A pointer to a IPv6 address to output the address (MUST NOT be NULL).
 * @param[out] aTtl          A pointer to an `uint32_t` to output TTL for the address. It can be NULL if caller does not
 *                           want to get the TTL.
 *
 * @retval OT_ERROR_NONE       The first address was read successfully.
 * @retval OT_ERROR_NOT_FOUND  No address record in @p aResponse at @p aIndex.
 *
 */
otError otDnsClientGetAddressResponseAddress(const otDnsClientAddressResponse *aResponse,
                                             uint16_t                          aIndex,
                                             otIp6Address *                    aAddress,
                                             uint32_t *                        aTtl);

/**
 * This function sends an address resolution DNS query for AAAA (IPv6) record(s) for a given host name.
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
otError otDnsClientResolveAddress(otInstance *                      aInstance,
                                  const otSockAddr *                aServerSockAddr,
                                  const char *                      aHostName,
                                  bool                              aNoRecursion,
                                  otDnsClientAddressResponseHandler aHandler,
                                  void *                            aContext);

/**
 * @}
 *
 */

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPENTHREAD_DNS_H_
