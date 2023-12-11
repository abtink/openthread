/*
 *  Copyright (c) 2024, The OpenThread Authors.
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
 *   This file includes the mDNS related APIs.
 *
 */

#ifndef OPENTHREAD_MULTICAST_DNS_H_
#define OPENTHREAD_MULTICAST_DNS_H_

#include <stdint.h>

#include <openthread/error.h>
#include <openthread/instance.h>
#include <openthread/ip6.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup api-mdns
 *
 * @brief
 *   This module includes APIs for Multicast DNS (mDNS).
 *
 * @{
 *
 * The mDNS APIs are available when `OPENTHREAD_CONFIG_MULTICAST_DNS_ENABLE` is enabled.
 *
 */

/**
 * Represents a request ID for registering a host, a service, or a key service.
 *
 */
typedef uint32_t otMdnsRequestId;

/**
 * Represents the callback function to report outcome of a host, service or key registration request.
 *
 * See `otMdnsRegisterHost()`, `otMdnsRegisterService()`, and `otMdnsUnregisterKey()` for more details about when
 * the callback will be invoked and the `aError` values.
 *
 * @param[in] aInstance     The OpenThread instance.
 * @param[in] aRequestId    The request ID.
 * @param[in] aError        Error indicating the outcome of request.
 *
 */
typedef void (*otMdnsRegisterCallback)(otInstance *aInstance, otMdnsRequestId aRequestId, otError aError);

/**
 * Represents the callback function to report a detected name conflict after successful registration of an entry.
 *
 * If a conflict is detected while registering an entry, it is reported through the provided `otMdnsRegisterCallback`.
 * The `otMdnsConflictCallback` is used only when a name conflict is detected after an entry has been successfully
 * registered.
 *
 * A non-NULL @p aServiceType indicates that conflict is for a service entry. In this case @p aName specifies the
 * service instance label (treated as as single DNS label and can potentially include dot `.` character).
 *
 * A NULL @p aServiceType indicates that conflict is for a host entry. In this case @p Name specifies the host name. It
 * does not include the domain name.
 *
 * @param[in] aInstance      The OpenThread instance.
 * @param[in] aName          The host name or the service instance label.
 * @param[in] aServiceType   The service type (e.g., `_tst._udp`).
 *
 */
typedef void (*otMdnsConflictCallback)(otInstance *aInstance, const char *aName, const char *aServiceType);

/**
 * Represents an mDNS host.
 *
 * This type is used to register or unregister a host (`otMdnsRegisterHost()` and `otMdnsUnregisterHost()`),
 *
 * See the the description of each function/callback for more details on how different fields are used in each case.
 *
 */
typedef struct otMdnsHost
{
    const char         *mHostName;     ///< The host name (e.g., "myhost").
    const otIp6Address *mAddresses;    ///< Array of IPv6 host addresses.
    uint16_t            mNumAddresses; ///< Number of entries in @p mAddresses array.
    uint32_t            mTtl;          ///< The host TTL in seconds.
} otMdnsHost;

/**
 * Represents an mDNS service.
 *
 * This type is used to register or unregister a service (`otMdnsRegisterService()` and `otMdnsRegisterService()`),
 *
 * See the the description of each function/callback for more details on how different fields are used in each case.
 *
 */
typedef struct otMdnsService
{
    const char        *mHostName;            ///< The host name (e.g., "myhost").
    const char        *mServiceInstance;     ///< The service instance name label. Single label and not full name.
    const char        *mServiceType;         ///< The service type (e.g., "_tst._udp").
    const char *const *mSubTypeLabels;       ///< Array of sub-type labels. Can be NULL if no sub-type label.
    uint16_t           mSubTypeLabelsLength; ///< Length of array of sub-type labels.
    const uint8_t     *mTxtData;             ///< Encoded TXT data bytes.
    uint16_t           mTxtDataLength;       ///< Length of TXT data.
    uint16_t           mPort;                ///< The service port number.
    uint16_t           mPriority;            ///< The service priority.
    uint16_t           mWeight;              ///< The service weight.
    uint32_t           mTtl;                 ///< The service TTL in seconds.
} otMdnsService;

/**
 * Represents an mDNS key record.
 *
 * See `otMdnsRegisterKey()`, `otMdnsUnregisterKey()` for more details about fields in each case.
 *
 */
typedef struct otMdnsKey
{
    const char    *mName;          ///< A host or a service instance name (e.g. "myhost").
    const char    *mServiceType;   ///< The service type if key is for a service (e.g. "_tst._udp"), or `NULL`.
    const uint8_t *mKeyData;       ///< Byte array containing the key record data.
    uint16_t       mKeyDataLength; ///< Length of @p mKeyData in bytes.
    uint32_t       mTtl;           ///< The TTL in seconds.
} otMdnsKey;

/**
 * Enables or disables mDNS module.
 *
 * mDNS module should be enabled before registration any host, service, or key entries. Disabling mDNS will immediately
 * stop all operations and any communication (multicast or unicast tx) and remove any previously registered entries
 * without sending any "goodbye" announcements or invoking their callback.
 *
 * @param[in] aInstance     The OpenThread instance.
 * @param[in] aEnable       Boolean to indicate to enable (on `TRUE`) or disable (on `FALSE`).
 *
 */
void otMdnsSetEnabled(otInstance *aInstance, bool aEnable);

/**
 * Indicates whether the mDNS module is enabled.
 *
 * @param[in] aInstance     The OpenThread instance.
 *
 * @retval TRUE  The mDNS module is enabled
 * @retval FALSE The mDNS module is disabled.
 *
 */
bool otMdnsIsEnabled(otInstance *aInstance);

/**
 * Sets whether mDNS module is allowed to send questions requesting unicast responses referred to as "QU" questions.
 *
 * The "QU" questions request unicast responses, in contrast to "QM" questions which request multicast responses.
 *
 * When allowed, the first probe will be sent as a "QU" question. This API can be used to address platform limitation
 * where platform socket cannot accept unicast response received on mDNS port (due to it being already bound).
 *
 * @param[in] aInstance     The OpenThread instance.
 * @param[in] aAllow        Indicates whether or not to allow "QU" questions.
 *
 */
void otMdnsSetQuestionUnicastAllowed(otInstance *aInstance, bool aAllow);

/**
 * Indicates whether mDNS module is allowed to send "QU" questions requesting unicast response.
 *
 * @retval TRUE  The mDNS module is allowed to send "QU" questions.
 * @retval FALSE The mDNS module is not allowed to send "QU" questions.
 *
 */
bool otMdnsIsQuestionUnicastAllowed(otInstance *aInstance);

/**
 * Sets the post-registration conflict callback.
 *
 * If a conflict is detected while registering an entry, it is reported through the provided `otMdnsRegisterCallback`.
 * The `otMdnsConflictCallback` is used only when a name conflict is detected after an entry has been successfully
 * registered.
 *
 * @p aCallback can be set to `NULL` if not needed. Subsequent calls will replace any previously set callback.
 *
 * @param[in] aInstance     The OpenThread instance.
 * @param[in] aCallback     The conflict callback.
 *
 */
void otMdnsSetConflictCallback(otInstance *aInstance, otMdnsConflictCallback aCallback);

/**
 * Registers or updates a host on mDNS.
 *
 * The fields in @p aHost follow these rules:
 *
 * - The `mHostName` field specifies the host name to register (e.g., "myhost"). MUST not contain the domain name.
 * - The `mAddresses` is array of IPv6 addresses to register with the host. `mNumAddresses` provides the number of
 *   entries in `mAddresses` array.
 * - The `mAddresses` array can be empty with zero `mNumAddresses`. In this case, mDNS will treat it as if host is
 *   unregistered and stop advertising any addresses for this the host name.
 * - The `mTtl` specifies the TTL if non-zero. If zero, the mDNS core will choose a default TTL to use.
 *
 * This function can be called again for the same `mHostName` to update a previously registered host entry, for example,
 * to change the list of addresses of the host. In this case, the mDNS module will send "goodbye" announcements for any
 * previously registered and now removed addresses and announce any newly added addresses.
 *
 * The outcome of the registration request is reported back by invoking the provided @p aCallback with @p aRequestId
 * as its input and one of the following `aError` inputs:
 *
 * - `OT_ERROR_NONE` indicates registration was successful
 * - `OT_ERROR_DULICATED` indicates a name conflict, i.e., the name is already claimed by another mDNS responder.
 *
 * For caller convenience, the OpenThread mDNS module guarantees that the callback will be invoked after this function
 * returns, even in cases of immediate registration success. The @p aCallback can be `NULL` if caller does not want to
 * be notified of the outcome.
 *
 * @param[in] aInstance     The OpenThread instance.
 * @param[in] aHost         Information about the host to register.
 * @param[in] aRequestId    The ID associated with this request.
 * @param[in] aCallback     The callback function pointer to report the outcome (can be NULL if no callback needed).
 *
 * @retval OT_ERROR_NONE            Successfully started registration. @p aCallback will report the outcome.
 * @retval OT_ERROR_INVALID_STATE   mDNS module is not enabled.
 *
 */
otError otMdnsRegisterHost(otInstance            *aInstance,
                           const otMdnsHost      *aHost,
                           otMdnsRequestId        aRequestId,
                           otMdnsRegisterCallback aCallback);

/**
 * Unregisters a host on mDNS.
 *
 * The fields in @p aHost follow these rules:
 *
 * - The `mHostName` field specifies the host name to unregister (e.g., "myhost"). MUST not contain the domain name.
 * - The rest of the fields in @p aHost structure are ignored in an `otMdnsUnregisterHost()` call.
 *
 * If there is no previously registered host with the same name, no action is performed.
 *
 * If there is a previously registered host with the same name, the mDNS module will send "goodbye" announcement for
 * all previously advertised address records.
 *
 * @param[in] aInstance     The OpenThread instance.
 * @param[in] aHost         Information about the host to unregister.
 *
 * @retval OT_ERROR_NONE            Successfully unregistered host.
 * @retval OT_ERROR_INVALID_STATE   mDNS module is not enabled.
 *
 */
otError otMdnsUnregisterHost(otInstance *aInstance, const otMdnsHost *aHost);

/**
 * Registers or updates a service on mDNS.
 *
 * The fields in @p aService follow these rules:
 *
 * - The `mServiceInstance` specifies the service instance label. It is treated as a single DNS name label. It may
 *   contain dot `.` character which is allowed in a service instance label.
 * - The `mServiceType` specifies the service type (e.g., "_tst._udp"). It is treated as multiple dot `.` separated
 *   labels. It MUST not contain the domain name.
 * - The `mHostName` field specifies the host name of the service. MUST not contain the domain name.
 * - The `mSubTypeLabels` is an array of strings representing sub-types associated with the service. Each array entry is
 *   a sub-type label. The `mSubTypeLabels can be NULL if there are no sub-types. Otherwise, the array length is
 *   specified by `mSubTypeLabelsLength`.
 * - The `mTxtData` and `mTxtDataLength` specify the encoded TXT data. The `mTxtData` can be NULL or `mTxtDataLength`
 *   can be zero to specify an empty TXT data. In this case mDNS module will use a single zero byte `[ 0 ]` as empty
 *   TXT data.
 * - The `mPort`, `mWeight`, and `mPriority` specify the service's parameters (as specified in DNS SRV record).
 * - The `mTtl` specifies the TTL if non-zero. If zero, the mDNS module will use default TTL for service entry.
 *
 * This function can be called again for the same `mServiceInstance` and `mServiceType` to update a previously
 * registered service entry, for example, to change the sub-types list or update any parameter such as port, weight,
 * priority, TTL, or host name. The mDNS module will send announcements for any changed info, e.g., will send "goodbye"
 * announcements for any removed sub-types and announce any newly added sub-types.
 *
 * Regarding the invocation of the @p aCallback, this function behaves in the same way as described in
 * `otMdnsRegisterHost()`.
 *
 * @param[in] aInstance     The OpenThread instance.
 * @param[in] aService      Information about the service to register.
 * @param[in] aRequestId    The ID associated with this request.
 * @param[in] aCallback     The callback function pointer to report the outcome (can be NULL if no callback needed).
 *
 * @retval OT_ERROR_NONE            Successfully started registration. @p aCallback will report the outcome.
 * @retval OT_ERROR_INVALID_STATE   mDNS module is not enabled.
 *
 */
otError otMdnsRegisterService(otInstance            *aInstance,
                              const otMdnsService   *aService,
                              otMdnsRequestId        aRequestId,
                              otMdnsRegisterCallback aCallback);

/**
 * Unregisters a service on mDNS module.
 *
 * The fields in @p aService follow these rules:

 * - The `mServiceInstance` specifies the service instance label. It is treated as a single DNS name label. It may
 *   contain dot `.` character which is allowed in a service instance label.
 * - The `mServiceType` specifies the service type (e.g., "_tst._udp"). It is treated as multiple dot `.` separated
 *   labels. It MUST not contain the domain name.
 * - The rest of the fields in @p aService structure are ignored in  a`otMdnsUnregisterService()` call.
 *
 * If there is no previously registered service with the same name, no action is performed.
 *
 * If there is a previously registered service with the same name, the mDNS module will send "goodbye" announcements for
 * all related records.
 *
 * @param[in] aInstance     The OpenThread instance.
 * @param[in] aService      Information about the service to unregister.
 *
 * @retval OT_ERROR_NONE            Successfully unregistered service.
 * @retval OT_ERROR_INVALID_STATE   mDNS module is not enabled.
 *
 */
otError otMdnsUnregisterService(otInstance *aInstance, const otMdnsService *aService);

/**
 * Registers or updates a key record on mDNS module.
 *
 * The fields in @p aKey follow these rules:
 *
 * - If the key is associated with a host entry, `mName` specifies the host name and `mServcieType` MUST be NULL.
 * - If the key is associated with a service entry, `mName` specifies the service instance label (always treated as
 *   a single label) and `mServiceType` specifies the service type (e.g., "_tst._udp"). In this case the DNS name for
 *   key record is `<mName>.<mServiceTye>`.
 * - The `mKeyData` field contains the key record's data with `mKeyDataLength` as its length in byes.
 * - The `mTtl` specifies the TTL if non-zero. If zero, the mDNS module will use default TTL for the key entry.
 *
 * This function can be called again for the same name to updated a previously registered key entry, for example, to
 * change the key data or TTL.
 *
 * Regarding the invocation of the @p aCallback, this function behaves in the same way as described in
 * `otMdnsRegisterHost()`.
 *
 * @param[in] aInstance     The OpenThread instance.
 * @param[in] aHost         Information about the key record to register.
 * @param[in] aRequestId    The ID associated with this request.
 * @param[in] aCallback     The callback function pointer to report the outcome (can be NULL if no callback needed).
 *
 * @retval OT_ERROR_NONE            Successfully started registration. @p aCallback will report the outcome.
 * @retval OT_ERROR_INVALID_STATE   mDNS module is not enabled.
 *
 */
otError otMdnsRegisterKey(otInstance            *aInstance,
                          const otMdnsKey       *aKey,
                          otMdnsRequestId        aRequestId,
                          otMdnsRegisterCallback aCallback);

/**
 * Unregisters a key record on mDNS.
 *
 * The fields in @p aKey follow these rules:
 *
 * - If the key is associated with a host entry, `mName` specifies the host name and `mServcieType` MUST be NULL.
 * - If the key is associated with a service entry, `mName` specifies the service instance label (always treated as
 *   a single label) and `mServiceType` specifies the service type (e.g., "_tst._udp"). In this case the DNS name for
 *   key record is `<mName>.<mServiceTye>`.
 * - The rest of the fields in @p aKey structure are ignored in  a`otMdnsUnregisterKey()` call.
 *
 * If there is no previously registered key with the same name, no action is performed.
 *
 * If there is a previously registered key with the same name, the mDNS module will send "goodbye" announcements for
 * the key record.
 *
 * @param[in] aInstance     The OpenThread instance.
 * @param[in] aKey          Information about the key to unregister.
 *
 * @retval OT_ERROR_NONE            Successfully unregistered key
 * @retval OT_ERROR_INVALID_STATE   mDNS module is not enabled.
 *
 */
otError otMdnsUnregisterKey(otInstance *aInstance, const otMdnsKey *aKey);

/**
 * @}
 *
 */

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPENTHREAD_MULTICAST_DNS_H_
