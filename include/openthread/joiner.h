/*
 *  Copyright (c) 2016, The OpenThread Authors.
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
 *   This file includes functions for the Thread Joiner role.
 */

#ifndef OPENTHREAD_JOINER_H_
#define OPENTHREAD_JOINER_H_

#include <openthread/platform/radio.h>
#include <openthread/platform/toolchain.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup api-joiner
 *
 * @brief
 *   This module includes functions for the Thread Joiner role.
 *
 * @note
 *   The functions in this module require `OPENTHREAD_CONFIG_JOINER_ENABLE=1`.
 *
 * @{
 *
 */

/**
 * This enumeration defines the Joiner State.
 *
 */
typedef enum otJoinerState
{
    OT_JOINER_STATE_IDLE      = 0,
    OT_JOINER_STATE_DISCOVER  = 1,
    OT_JOINER_STATE_CONNECT   = 2,
    OT_JOINER_STATE_CONNECTED = 3,
    OT_JOINER_STATE_ENTRUST   = 4,
    OT_JOINER_STATE_JOINED    = 5,
} otJoinerState;

/**
 * This function pointer is called to notify the completion of a join operation.
 *
 * @param[in]  aError    OT_ERROR_NONE if the join process succeeded.
 *                       OT_ERROR_SECURITY if the join process failed due to security credentials.
 *                       OT_ERROR_NOT_FOUND if no joinable network was discovered.
 *                       OT_ERROR_RESPONSE_TIMEOUT if a response timed out.
 * @param[in]  aContext  A pointer to application-specific context.
 *
 */
typedef void (*otJoinerCallback)(otError aError, void *aContext);

/**
 * This function enables the Thread Joiner role.
 *
 * @param[in]  aInstance         A pointer to an OpenThread instance.
 * @param[in]  aPskd             A pointer to the PSKd.
 * @param[in]  aProvisioningUrl  A pointer to the Provisioning URL (may be NULL).
 * @param[in]  aVendorName       A pointer to the Vendor Name (may be NULL).
 * @param[in]  aVendorModel      A pointer to the Vendor Model (may be NULL).
 * @param[in]  aVendorSwVersion  A pointer to the Vendor SW Version (may be NULL).
 * @param[in]  aVendorData       A pointer to the Vendor Data (may be NULL).
 * @param[in]  aCallback         A pointer to a function that is called when the join operation completes.
 * @param[in]  aContext          A pointer to application-specific context.
 *
 * @retval OT_ERROR_NONE              Successfully started the Commissioner role.
 * @retval OT_ERROR_INVALID_ARGS      @p aPskd or @p aProvisioningUrl is invalid.
 *
 */
otError otJoinerStart(otInstance *     aInstance,
                      const char *     aPskd,
                      const char *     aProvisioningUrl,
                      const char *     aVendorName,
                      const char *     aVendorModel,
                      const char *     aVendorSwVersion,
                      const char *     aVendorData,
                      otJoinerCallback aCallback,
                      void *           aContext);

/**
 * This function disables the Thread Joiner role.
 *
 * @param[in]  aInstance  A pointer to an OpenThread instance.
 *
 */
void otJoinerStop(otInstance *aInstance);

/**
 * This function returns the Joiner State.
 *
 * @param[in]  aInstance  A pointer to an OpenThread instance.
 *
 * @retval OT_JOINER_STATE_IDLE
 * @retval OT_JOINER_STATE_DISCOVER
 * @retval OT_JOINER_STATE_CONNECT
 * @retval OT_JOINER_STATE_CONNECTED
 * @retval OT_JOINER_STATE_ENTRUST
 * @retval OT_JOINER_STATE_JOINED
 *
 */
otJoinerState otJoinerGetState(otInstance *aInstance);

/**
 * This function gets the Joiner ID.
 *
 * If the Joiner ID is not explicitly set, by default the SHA-256 hash of factory-assigned IEEE EUI-64 is used.

 * @param[in]   aInstance  A pointer to the OpenThread instance.
 *
 * @returns A pointer to the Joiner ID.
 *
 */
const otExtAddress *otJoinerGetId(otInstance *aInstance);

/**
 * This function sets the Joiner ID.
 *
 * Joiner ID is derived as the first 64 bits of the result of computing SHA-256 over @p aAddress. If @p aAddress is NULL
 * then factory-assigned IEEE EUI-64 is used (i.e. Joiner ID is derived as hash of factory-assigned EUI-64).
 *
 * @param[in] aInstance         A pointer to the OpenThread instance.
 * @param[in] aAddress          A pointer to an Extended Address from which to derive the Joiner ID. If NULL
 *                              factory-assigned IEEE EUI-64 is used.
 *
 * @retval OT_ERROR_NONE             The Joiner ID was successfully updated.
 * @retval OT_ERROR_INVALID_STATE    Joining process is ongoing so cannot change the Joiner ID.
 *
 */
otError otJoinerSetId(otInstance *aInstance, const otExtAddress *aAddress);

/**
 * @}
 *
 */

#ifdef __cplusplus
} // end of extern "C"
#endif

#endif // OPENTHREAD_JOINER_H_
