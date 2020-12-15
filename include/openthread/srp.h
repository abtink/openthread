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
 *  This file defines the OpenThread SRP (Service Registration Protocol) Client and Server APIs.
 */

#ifndef OPENTHREAD_RSP_H_
#define OPENTHREAD_RSP_H_

#include <openthread/ip6.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup api-srp
 *
 * @brief
 *   This module includes functions that control SRP Client/Server behavior.
 *
 * @{
 *
 */

/**
 * This structure represents a TXT record entry representing a key/value pair (RFC 6763 - section 6.3)
 *
 * The strings buffers pointed to by `mKey` and `mValue` MUST persist and remain unchanged after an instance of such a
 *  structure is passed to OpenThread (as part of `otSrpClientServcie` instance).
 *
 * An array of `otSrpTxtEntry` entries in used in `otSrpClientServcie` to specify the full TXT record (a list of
 * entries). To indicate the end of array, the last entry itself should be NULL or the `mKey` should be NULL.
 *
 */
typedef struct otSrpTxtEntry
{
    const char *mKey;   ///< The TXT record key string.
    const char *mValue; ///< The TXT record value string.
} otSrpTxtEntry;

/**
 * This structure represents an SRP client service.
 *
 * The values in this structure including the string buffers for the names and the TX record entries MUST persist and
 * stay valid and constants after an instance of this structure is passed to OpenThread from `otSrpClientAddService()`
 * or `otSrpClientRemoveService()`.
 *
 */
typedef struct otSrpClientServcie
{
    const char *         mName;         ///< The service name label (not the full name).
    const char *         mInstanceName; ///< The service instance name label (not the full name).
    uint16_t             mPort;         ///< The service port number.
    uint16_t             mPriority;     ///< The service priority.
    uint16_t             mWeight;       ///< The service weight.
    const otSrpTxtEntry *mTxtEntries;   /// Array of TXT entries (see `otSrpTxtEntry` on how the array end is detected).
} otSrpClientServcie;

/**
 * This enumeration represents event item type (for `otSrpClientEvent` emitted by `otSrpClientCallback`).
 *
 */
typedef enum
{
    OT_SRP_CLIENT_EVENT_ITEM_HOST,
    OT_SRP_CLIENT_EVENT_ITEM_IP6_ADDRESS,
    OT_SRP_CLIENT_EVENT_ITEM_SERVICE,
} otSrpClientEventItemType;

/**
 * This enumeration type represents event actions (for `otSrpClientEvent` emitted by `otSrpClientCallback`).
 *
 */
typedef enum
{
    OT_SRP_CLIENT_EVENT_ADDED,       ///< Item was added and accepted by server.
    OT_SRP_CLIENT_EVENT_REMOVED,     ///< Item was removed and the remove is accepted by server.
    OT_SRP_CLIENT_EVENT_REFRESHED,   ///< Item was refreshed and accepted (again) by server.
    OT_SRP_CLIENT_EVENT_REJECETED,   ///< Server rejected the update request.
    OT_SRP_CLIENT_EVENT_NO_RESPONSE, ///< No response from server (after retries).
} otSrpClientEventAction;

/**
 * This structure represents an event entry emitted by `otSrpClientCallback`.
 *
 */
typedef struct otSrpClientEvent
{
    otSrpClientEventItemType mItemType; ///< The item type (host, IPv6 address, service).
    otSrpClientEventAction   mAction;   ///< The even action (added, removed, refreshed, rejected)
    union
    {
        const char *              mHost;       ///< Host name label (if `mItemType` is `ITEM_HOST`).
        const otIp6Address *      aIp6Address; ///< Host IPv6 address (if `mItemType` is `ITEM_IP6_ADDRESS`).
        const otSrpClientServcie *aService;    ///< Pointer to service struct (if `mItemType` is `ITEM_SERVICE`).
    } mItem;
} otSrpClientEvent;

/**
 * This function pointer type defines the callback used to notify user of different events in SRP client.
 *
 * @param[in] aContext    A pointer to an arbitrary context (provided when callback was registered).
 * @param[in] aEvents     A pointer to an array of events of `otSrpClientEvent` type.
 * @param[in] aNumEvents  Number of entries in the @p aEvents array.
 *
 */
typedef void (*otSrpClientCallback)(void *aContext, const otSrpClientEvent *aEvents, uint16_t aNumEvents);

/**
 * This function starts the SRP client operation.
 *
 * SRP client will prepare and send "SRP Update" message to the SRP server once all the following conditions are met:
 *
 *  - The SRP client is started - `otSrpClientStart()` is called.
 *  - Host name is set - `otSrpClientSetHost()` is called.
 *  - At least one host IPv6 address is added - `otSrpClientAddHostAddress()` is called.
 *  - At least one service is added - `otSrpClientAddService()` is called.
 *
 * It does not matter in which order these functions are called. When all conditions are met, the SRP client will
 * wait for a short delay before preparing an "SRP Update" message and sending it to server. This delay allows for user
 * to add multiple services and/or IPv6 addresses before the first SRP Update message is sent (ensuring a single SRP
 * Update is sent containing all the info).
 *
 * @param[in] aInstance        A pointer to the OpenThread instance.
 * @param[in] aServerAddress   The IPv6 address of the SRP server.
 * @param[in] aCallback        The callback which is used to notify events and changes. Can be NULL if not needed.
 * @param[in] aContext         An arbitrary context used with @p aCallback.
 *
 * @retval OT_ERROR_NONE       SRP client operation started successfully.
 * @retval OT_ERROR_ALREADY    SRP client is already started and running.
 *
 */
otError otSrpClientStart(otInstance *        aInstance,
                         const otIp6Address *aServerAddress,
                         otSrpClientCallback aCallback,
                         void *              aContext);

/**
 * This function stops the SRP client operation.
 *
 * This function stops any further interactions with the SRP server. Any pending/ongoing SRP updates will be canceled.
 * Note that this function does not remove any previously registered services/host info with server (i.e., no SRP update
 * message is sent to server).
 *
 * @param[in] aInstance       A pointer to the OpenThread instance.
 *
 */
void otSrpClientStop(otInstance *aInstance);

/**
 * This function sets the host name label on the SRP client.
 *
 * The name string buffers pointer to from @p aHostName MUST persist and stay unchanged after returning from this
 * function. OpenThread will keep the pointer to the string.
 *
 * This function can be called before SRP client is started (before `otSrpClientStart()`), or while it is already
 * running. If it is called while SRP client is running, it will trigger an SRP update to be sent to the SRP server
 * registering all previously added services and associating them with the new host name. In this case, the client
 * callback `otSrpClientCallback` will be called to report the outcome.
 *
 * @param[in] aInstance   A pointer to the OpenThread instance.
 * @param[in] aHostName   A pointer to host name label string (MUST NOT be NULL). Pointer the string buffer MUST
 *                        persist and remain valid and constant after return from this function.
 *
 */
void otSrpClientSetHost(otInstance *aInstance, const char *aHostName);

/**
 * This function gets the host name label of SRP client.
 *
 * @param[in] aInstance        A pointer to the OpenThread instance.
 *
 * @returns The host name label. NULL is returned if no name is yet set.
 *
 */
const char *otSrpClientGetHost(otInstance *aInstance);

/**
 * This function removes the host (and all services) from the SRP client and unregister the host from server.
 *
 * If there is any previous registration with the SRP service (including any pending ones), this function triggers an
 * SRP Update message to be sent to the server to remove the host (which also indicates to the server to remove and all
 * the previously registered services associated with the host). After this, the client callback `otSrpClientCallback`
 * to report the outcome (the `otSrpClientServcie *` would be set to NULL in the callback).
 *
 * This function also removes all internal references stored by OpenThread to the previously added services (i.e.,
 * `otSrpClientServcie` instances).
 *
 * If the host registration is to be permanently removed, @p aRemoveKeyLease should be set to `true` which removes the
 * key lease associated with host/device on server. Otherwise, the key lease record is kept as before, which ensures
 * that the server holds the host name in reserve for when the client once again able to provide and register its
 * service(s).
 *
 * @param[in] aInstance        A pointer to the OpenThread instance.
 * @param[in] aRemoveKeyLease  A boolean indicating whether or not the host key lease should also be removed.
 *
 * @retval OT_ERROR_NONE       The removal of host started successfully. The `otSrpClientCallback` will be called to
 *                             report the status.
 * @retval OT_ERROR_NOT_FOUND  No previous registration with SRP service (nothing to remove).
 *
 */
otError otSrpClientRemoveHostAndServices(otInstance *aInstance, bool aRemoveKeyLease);

/**
 * This function adds a host IPv6 address to the SRP client.
 *
 * @param[in] aInstance        A pointer to the OpenThread instance.
 * @param[in] aIp6Address      A pointer to a host IPv6 address to add (does not need to persist after return).
 *
 * @retval OT_ERROR_NONE       The addition of host IPv6 address started successfully. The `otSrpClientCallback` will
 *                             be called to report the status.
 * @retval OT_ERROR_ALREADY    The same address is already in the list.
 * @retval OT_ERROR_NO_BUFS    The SRP client is storing the maximum allowed host IPv6 addresses (specified by config
 *                             `OPENTHREAD_CONFIG_SRP_CLIENT_MAX_HOST_IP6_ADDRESSES`).
 *
 */
otError otSrpClientAddHostAddress(otInstance *aInstance, const otIp6Address *aIp6Address);

/**
 * This function removes a host IPv6 address from the SRP client.
 *
 * @param[in] aInstance        A pointer to the OpenThread instance.
 * @param[in] aIp6Address      A pointer to a host IPv6 address to remove (does not need to persist after return).
 *
 * @retval OT_ERROR_NONE       The removal of host IPv6 address started successfully. The `otSrpClientCallback` will
 *                             be called to report the status.
 * @retval OT_ERROR_NOT_FOUND  The address could not be found in the list.
 *
 */
otError otSrpClientRemoveHostAddress(otInstance *aInstance, const otIp6Address *aIp6Address);

/**
 * This function adds a service to the SRP client.
 *
 * The `otSrpClientServcie` instance being pointed to by @p aService MUST persist and remain unchanged after returning
 * from this function (with `OT_ERROR_NONE`). OpenThread will save the pointer to the service instance. The instance
 * can be changed, freed, or reused only when
 *
 *  -  It is explicitly removed by a call to `otSrpClientRemoveService()` and only after the `otSrpClientCallback` is
 *     called indicating the service was removed or there was a failure in the remove. Or,
 *  -  A call to `otSrpClientRemoveHostAndServices()` which removes the host and all related services.
 *
 * @param[in] aInstance        A pointer to the OpenThread instance.
 * @param[in] aService         A pointer to a `otSrpClientServcie` instance.

 * @retval OT_ERROR_NONE       The addition of service started successfully. The `otSrpClientCallback` will be called
 *                             to report the status.
 * @retval OT_ERROR_ALREADY    The same service is already in the list.
 * @retval OT_ERROR_NO_BUFS    The SRP client is storing the maximum allowed services (specified by config
 *                             `OPENTHREAD_CONFIG_SRP_CLIENT_MAX_SERVICES`).
 *
 */
otError otSrpClientAddService(otInstance *aInstance, otSrpClientServcie *aService);

/**
 * This function removes a service from the SRP client.
 *
 * The `otSrpClientServcie` instance being pointed to by @p aService MUST persist and remain unchanged after returning
 * from this function (with `OT_ERROR_NONE`). OpenThread will save the pointer to the service instance during the remove
 * process. Only after  only after the `otSrpClientCallback` is called the service instance is removed from  SRP client
 * service list and can be be freed/reused.
 *
 * @param[in] aInstance        A pointer to the OpenThread instance.
 * @param[in] aService         A pointer to a `otSrpClientServcie` instance.
 *
 * @retval OT_ERROR_NONE       The removal of service started successfully. The `otSrpClientCallback` will be called to
 *                             report the status.
 * @retval OT_ERROR_NOT_FOUND  The service could not be found in the list.
 *
 */
otError otSrpClientRemoveService(otInstance *aInstance, otSrpClientServcie *aService);

/**
 * This function sets the domain name to use by SRP client.
 *
 * This is optional function. If not set "default.service.arpa" will be used.
 *
 * The name string buffers pointer to from @p aDomainName MUST persist and stay unchanged after returning from this
 * function. OpenThread will keep the pointer to the string.
 *
 * @param[in] aInstance        A pointer to the OpenThread instance.
 * @param[in] aDomainName      A pointer to the domain name string. If NULL sets it to default "default.service.arpa".
 *
 */
void otSrpClientSetDomainName(otInstance *aInstance, const char *aDomainName);

/**
 * This function gets the domain name being used by SRP client.
 *
 * If domain name is not set, "default.service.arpa" will be used.
 *
 * @param[in] aInstance        A pointer to the OpenThread instance.
 *
 * @returns The domain name string.
 *
 */
const char *otSrpClientGetDomainName(otInstance *aInstance);

/**
 * @}
 *
 */

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPENTHREAD_RSP_H_
