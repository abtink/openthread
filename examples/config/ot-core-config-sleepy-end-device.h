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
 *   This file includes recommended configurations for a sleepy end-device (SED) type of device
 *
 */

#ifndef OT_CORE_CONFIG_ROUTER_EXAMPLE_H_
#define OT_CORE_CONFIG_ROUTER_EXAMPLE_H_


#define OPENTHREAD_CONFIG_NUM_MESSAGE_BUFFERS               ??

/**
 * @def OPENTHREAD_CONFIG_MAC_DEFAULT_MAX_FRAME_RETRIES_DIRECT
 *
 * The maximum number of retries allowed after a transmission failure for direct transmissions.
 *
 * Equivalent to macMaxFrameRetries, default value is 3.
 *
 */
#define OPENTHREAD_CONFIG_MAC_DEFAULT_MAX_FRAME_RETRIES_DIRECT      15

#define OPENTHREAD_CONFIG_MAC_ATTACH_DATA_POLL_PERIOD           100

#define OPENTHREAD_CONFIG_TMF_ADDRESS_CACHE_ENTRIES             8

#define OPENTHREAD_CONFIG_MPL_CACHE_ENTRIES                 32

/**
 * @def OPENTHREAD_CONFIG_MPL_CACHE_ENTRY_LIFETIME
 *
 * The MPL cache entry lifetime in seconds.
 * Default: 5
 *
 */
#define OPENTHREAD_CONFIG_MPL_CACHE_ENTRY_LIFETIME          5


#define OPENTHREAD_CONFIG_MAC_FILTER_SIZE                   1


#define OPENTHREAD_CONFIG_PLATFORM_ASSERT_MANAGEMENT           1

#define OPENTHREAD_CONFIG_LEGACY_TRANSMIT_DONE 1


/**
 * @def OPENTHREAD_CONFIG_MLE_INFORM_PREVIOUS_PARENT_ON_REATTACH
 *
 * Define as 1 for a child to inform its previous parent when it attaches to a new parent.
 *
 * If this feature is enabled, when a device attaches to a new parent, it will send an IP message (with empty payload
 * and mesh-local IP address as the source address) to its previous parent.
 *
 */
#define OPENTHREAD_CONFIG_MLE_INFORM_PREVIOUS_PARENT_ON_REATTACH    1

/**
 * @def OPENTHREAD_CONFIG_PARENT_SEARCH_ENABLE
 *
 * Define as 1 to enable periodic parent search feature.
 *
 * When this feature is enabled an end-device/child (while staying attached) will periodically search for a possible
 * better parent and will switch parent if a better one is found.
 *
 * The child will periodically check the average RSS value for the current parent, and only if it is below a specific
 * threshold, a parent search is performed. The `OPENTHREAD_CONFIG_PARENT_SEARCH_CHECK_INTERVAL` specifies the the
 * check interval (in seconds) and `OPENTHREAD_CONFIG_PARENT_SEARCH_RSS_THRESHOLD` gives the RSS threshold.
 *
 * Since the parent search process can be power consuming (child needs to stays in RX mode to collect parent response)
 * and to limit its impact on battery-powered devices, after a parent search is triggered, the child will not trigger
 * another one before a specified backoff interval specified by `OPENTHREAD_CONFIG_PARENT_SEARCH_BACKOFF_INTERVAL`
 *
 */
#define OPENTHREAD_CONFIG_PARENT_SEARCH_ENABLE         1
/**
 * @def OPENTHREAD_CONFIG_PARENT_SEARCH_CHECK_INTERVAL
 *
 * Specifies the interval in seconds for a child to check the trigger condition to perform a parent search.
 *
 * Applicable only if periodic parent search feature is enabled (see `OPENTHREAD_CONFIG_PARENT_SEARCH_ENABLE`).
 *
 */
#define OPENTHREAD_CONFIG_PARENT_SEARCH_CHECK_INTERVAL          (9 * 60)
/**
 * @def OPENTHREAD_CONFIG_PARENT_SEARCH_BACKOFF_INTERVAL
 *
 * Specifies the backoff interval in seconds for a child to not perform a parent search after triggering one.
 *
 * Applicable only if periodic parent search feature is enabled (see `OPENTHREAD_CONFIG_PARENT_SEARCH_ENABLE`).
 *
 *
 */
#define OPENTHREAD_CONFIG_PARENT_SEARCH_BACKOFF_INTERVAL        (10 * 60 * 60)
/**
 * @def OPENTHREAD_CONFIG_PARENT_SEARCH_RSS_THRESHOLD
 *
 * Specifies the RSS threshold used to trigger a parent search.
 *
 * Applicable only if periodic parent search feature is enabled (see `OPENTHREAD_CONFIG_PARENT_SEARCH_ENABLE`).
 *
 */
#define OPENTHREAD_CONFIG_PARENT_SEARCH_RSS_THRESHOLD           -45

#define OPENTHREAD_CONFIG_MLE_ATTACH_BACKOFF_ENABLE 1

#define OPENTHREAD_CONFIG_MLE_ATTACH_BACKOFF_MINIMUM_INTERVAL 5000

#define OPENTHREAD_CONFIG_MAC_FILTER_ENABLE 1

#define OPENTHREAD_CONFIG_CHILD_SUPERVISION_ENABLE 1

#define OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE 1

#endif  // OT_CORE_CONFIG_SED_EXAMPLE_H_
