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
 *   This file includes recommended configuration example for a router type of device.
 *
 */

#ifndef OT_CORE_CONFIG_ROUTER_EXAMPLE_H_
#define OT_CORE_CONFIG_ROUTER_EXAMPLE_H_


/* The `PLATFORM_INFO` name is show in the OpenThread or NCP version strings.
 *
 * Recommendation is to set it based on project/product name.
 *
 */
#ifndef OPENTHREAD_CONFIG_PLATFORM_INFO
#define OPENTHREAD_CONFIG_PLATFORM_INFO "ot-router"
#endif

/*
 * The `NUM_MESSAGE_BUFFERS` determines number of messages in the pool.
 *
 * The recommended value of 260 provides 1KB message buffer per child for 32
 * children with a bit of leftover for other exchanges. This is with the
 * assumption of `MESSAGE_BUFFER_SIZE` being 128 (32-bit based platform).
 *
 * Recommendation is to increase this config as much the platform allows
 * (allowing more messages to be buffered for sleepy children).
 *
 */
#ifndef OPENTHREAD_CONFIG_NUM_MESSAGE_BUFFERS
#define OPENTHREAD_CONFIG_NUM_MESSAGE_BUFFERS 260
#endif

/*
 * The next set of config options determine number of frame attempts or
 * retransmission at MAC layer.
 *
 * The recommended values provide a good balance between link reliability and
 * detection of unavailable links.
 *   - 16 attempts (15 retries) for both direct and indirect frame tx.
 *   - 2 attempts for indirect tx per received data poll
 *
 */
#ifndef OPENTHREAD_CONFIG_MAC_DEFAULT_MAX_FRAME_RETRIES_DIRECT
#define OPENTHREAD_CONFIG_MAC_DEFAULT_MAX_FRAME_RETRIES_DIRECT 15
#endif
#ifndef OPENTHREAD_CONFIG_MAC_DEFAULT_MAX_FRAME_RETRIES_INDIRECT
#define OPENTHREAD_CONFIG_MAC_DEFAULT_MAX_FRAME_RETRIES_INDIRECT 1
#endif
#ifndef OPENTHREAD_CONFIG_MAC_MAX_TX_ATTEMPTS_INDIRECT_POLLS
#define OPENTHREAD_CONFIG_MAC_MAX_TX_ATTEMPTS_INDIRECT_POLLS 16
#endif

/*
 * Enabling `MLE_SEND_LINK_REQUEST_ON_ADV_TIMEOUT` is highly recommended on
 * router devices.
 *
 * When enabled, device would send an "MLE Link Request" to a neighboring
 * router when `MAX_NEIGHBOR_AGE` is reached (i.e., no "MLE Advertisement"
 * received from the neighboring router for a while) and before kicking the
 * neighbor out of its neighbor/router table. Note that "MLE Advertisement"
 * is a broadcast message (and therefore more chance of being dropped at MAC
 * layer in a busy environment) compared to to "MLE Link Request" which is a
 * unicast message and therefore would be retried by MAC layer.
 *
 */
#ifndef OPENTHREAD_CONFIG_MLE_SEND_LINK_REQUEST_ON_ADV_TIMEOUT
#define OPENTHREAD_CONFIG_MLE_SEND_LINK_REQUEST_ON_ADV_TIMEOUT  1
#endif

/*
 * Enabling `BORDER_ROUTER` allows device to add prefix/route/service entries
 * to network data.
 *
 */
#ifndef OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE
#define OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE 1
#endif

#ifndef OPENTHREAD_CONFIG_TMF_ADDRESS_CACHE_ENTRIES
#define OPENTHREAD_CONFIG_TMF_ADDRESS_CACHE_ENTRIES  32
#endif

/*
 * The default value for the address query delay is 28800 second (or 8 hours).
 * The recommended value of 120 sec provides a good balance between reducing
 * number of address queries and ensuring devices/addresses are not blocked for
 * long time.
 *
 * A practical situation to consider is when a device is going through a
 * software update and is offline (not available) for some time. Other devices
 * querying for its address can get to very high delay interval causing device
 * address not be reachable for long time after its software update.
 *
 */
#define OPENTHREAD_CONFIG_TMF_ADDRESS_QUERY_MAX_RETRY_DELAY 120


#ifndef OPENTHREAD_CONFIG_MLE_MAX_CHILDREN
#define OPENTHREAD_CONFIG_MLE_MAX_CHILDREN 32
#endif

/**
 * This allows for link-local, mesh-local and two other addresses per child
 *
 */
#ifndef OPENTHREAD_CONFIG_MLE_IP_ADDRS_PER_CHILD
#define OPENTHREAD_CONFIG_MLE_IP_ADDRS_PER_CHILD                4
#endif

#ifndef OPENTHREAD_CONFIG_LOG_LEVEL
#define OPENTHREAD_CONFIG_LOG_LEVEL                         OT_LOG_LEVEL_INFO
#endif

#ifndef
#define OPENTHREAD_CONFIG_LOG_LEVEL_DYNAMIC_ENABLE              1




#define OPENTHREAD_CONFIG_NCP_TX_BUFFER_SIZE                   3500

#define OPENTHREAD_CONFIG_NCP_SPI_BUFFER_SIZE                  1300


#define OPENTHREAD_CONFIG_PLATFORM_ASSERT_MANAGEMENT           1


#define OPENTHREAD_CONFIG_CHILD_SUPERVISION_ENABLE 1

#define OPENTHREAD_CONFIG_CHANNEL_MANAGER_ENABLE 1

#define OPENTHREAD_CONFIG_MAC_FILTER_ENABLE 1

#define OPENTHREAD_CONFIG_CHILD_SUPERVISION_ENABLE 1






/**
 * @def OPENTHREAD_CONFIG_DIAG_OUTPUT_BUFFER_SIZE
 *
 * Define OpenThread diagnostic mode output buffer size.
 * Default: 256
 */
#define OPENTHREAD_CONFIG_DIAG_OUTPUT_BUFFER_SIZE   1290
/**
 * @def OPENTHREAD_CONFIG_DIAG_CMD_LINE_ARGS_MAX
 *
 * Define OpenThread diagnostic mode max command line arguments.
 * Default: 32
 */
#define OPENTHREAD_CONFIG_DIAG_CMD_LINE_ARGS_MAX    64
/**
 * @def OPENTHREAD_CONFIG_DIAG_CMD_LINE_BUFFER_SIZE
 *
 * Define OpenThread diagnostic mode command line buffer size
 * Default: 256
 */
#define OPENTHREAD_CONFIG_DIAG_CMD_LINE_BUFFER_SIZE 1300




