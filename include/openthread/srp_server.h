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
 * @brief
 *  This file defines the API for server of the Service Registration Protocol (SRP).
 */

#ifndef OPENTHREAD_SRP_SERVER_H_
#define OPENTHREAD_SRP_SERVER_H_

#include <stdint.h>

#include <openthread/instance.h>
#include <openthread/ip6.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup api-srp
 *
 * @brief
 *  This module includes functions to control service registrations.
 *
 * @{
 *
 */

/**
 * This structure represents a SRP service host.
 *
 */
typedef void otSrpServerHost;

/**
 * This structure represents a SRP service.
 *
 */
struct otSrpServerService
{
    char *              mFullName;  ///< The full service name.
    bool                mIsDeleted; ///< A boolean that indicates whether this service is deleted.
    uint16_t            mPriority;  ///< The priority.
    uint16_t            mWeight;    ///< The weight.
    uint16_t            mPort;      ///< The service port.
    uint16_t            mTxtLength; ///< The TXT record length.
    uint8_t *           mTxtData;   ///< The standard DNS TXT record data.
    otSrpServerHost *   mHost;      ///< The host of this service.
    otSrpServerService *mNext;      ///< The next linked service within the same host.
};

/**
 * This method enables/disables the SRP server.
 *
 * @param[in]  aInstance  A pointer to an OpenThread instance.
 * @param[in]  aEnabled   A boolean to enable/disable the SRP server.
 *
 */
void otSrpServerSetEnabled(otInstance *aInstance, bool aEnabled);

/**
 * This method sets LEASE & KEY-LEASE range that is acceptable by the SRP server.
 *
 * When a LEASE time is requested from a client, the granted value will be
 * limited in range [aMinLease, aMaxLease]; and a KEY-LEASE will be granted
 * in range [aMinKeyLease, aMaxKeyLease].
 *
 */
otError otSrpServerSetLeaseRange(otInstance *aInstance,
                                 uint32_t    aMinLease,
                                 uint32_t    aMaxLease,
                                 uint32_t    aMinKeyLease,
                                 uint32_t    aMaxKeyLease);

/**
 * This method handles SRP service events by advertising the service on multicast-capable link.
 *
 * This function is called by the SRP server to notify a Advertising Proxy to propagate the
 * service updates on the multiple-capable link. The Advertising Proxy should call
 * otSrpServerHandleAdvertisingResult to return the result.
 *
 * @param[in]  aHost            A pointer to the otSrpServerHost object which contains the SRP updates.
 *                              The pointer should be passed back to otSrpServerHandleAdvertisingResult, but
 *                              the content MUST not be accessed after this method returns. The handler
 *                              should publish/un-publish the host and each service point to this host
 *                              with below rules:
 *                              1. If the host has valid addresses, then it should be published or updated
 *                                 with mDNS. Otherwise, resources (AAAA RRs) associated with the host name
 *                                 should be un-published.
 *                               2. For each service points to this host, it must be un-published if the host
 *                                 is un-published. Otherwise, the handler should publish or update the service
 *                                 when it is not deleted (indicated by `otSrpServerService::mIsDeleted`) and
 *                                 un-publish it when deleted.
 * @param[in]  aTimeout  The maximum time in milliseconds for the handler to process the service event.
 * @param[in]  aContext  A pointer to application-specific context.
 *
 * @sa otSrpServerSetAdvertisingHandler
 * @sa otSrpServerHandleAdvertisingResult
 *
 */
typedef void (*otSrpServerAdvertisingHandler)(const otSrpServerHost *aHost, uint32_t aTimeout, void *aContext);

/**
 * This method sets the Advertising Proxy handler on SRP server.
 *
 * @param[in]  aInstance        A pointer to an OpenThread instance.
 * @param[in]  aServiceHandler  A pointer to a service handler. Use NULL to remove the
 *                              Advertising Proxy handler.
 * @param[in]  aContext         A pointer to arbitrary context information.
 *                              May be NULL if not used.
 *
 * @note  This method should be called only when their is a capable Advertising Proxy.
 *        The default behavior of not calling this method is just accepting a SRP update.
 *
 */
void otSrpServerSetAdvertisingHandler(otInstance *                  aInstance,
                                      otSrpServerAdvertisingHandler aServiceHandler,
                                      void *                        aContext);

/**
 * This method reports the result of advertising a SRP update to the SRP server.
 *
 * The Advertising Proxy should call this function to return the result of its
 * processing of a SRP update.
 *
 * @param[in]  aInstance  A pointer to an OpenThread instance.
 * @param[in]  aHost      A pointer to the Host object which represents a SRP update.
 * @param[in]  aError     An error to be returned to the SRP server. Use OT_ERROR_DUPLICATED
 *                        to represent DNS name conflicts.
 *
 */
void otSrpServerHandleAdvertisingResult(otInstance *aInstance, const otSrpServerHost *aHost, otError aError);

/**
 * This method returns the next registered host on the SRP server.
 *
 * @param[in]  aInstance  A pointer to an OpenThread instance.
 * @param[in]  aHost      A pointer to current host. Use NULL to get the first host.
 *
 * @retval  A pointer to the registered host. NULL, if no more hosts can be found.
 *
 */
const otSrpServerHost *otSrpServerGetNextHost(otInstance *aInstance, const otSrpServerHost *aHost);

/**
 * This method returns the full name of a given host.
 *
 * @param[in]  aHost  A pointer to the SRP service host.
 *
 * @retval  A pointer to the null-terminated host name string.
 *
 */
const char *otSrpServerHostGetFullName(const otSrpServerHost *aHost);

/**
 * This method returns the addresses of given host.
 *
 * @param[in]   aHost          A pointer to the SRP service host.
 * @param[out]  aAddressesNum  A pointer to where we should output the number of the addresses to.
 *
 * @retval  A pointer to the array of IPv6 Address.
 *
 */
const otIp6Address *otSrpServerHostGetAddresses(const otSrpServerHost *aHost, uint8_t *aAddressesNum);

/**
 * This method returns the list of services of given host.
 *
 * @param[in]  aHost  A pointer to the SRP service host.
 *
 * @retval  A pointer to the head of the service list.
 *
 */
const otSrpServerService *otSrpServerHostGetServices(const otSrpServerHost *aHost);

/**
 * @}
 *
 */

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPENTHREAD_SRP_SERVER_H_
