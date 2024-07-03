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

#ifndef OPENTHREAD_HPP_
#define OPENTHREAD_HPP_

#include "openthread-core-config.h"

#include <openthread/platform/alarm-micro.h>
#include <openthread/platform/alarm-milli.h>
#include <openthread/platform/ble.h>
#include <openthread/platform/border_routing.h>
#include <openthread/platform/crypto.h>
#include <openthread/platform/debug_uart.h>
#include <openthread/platform/diag.h>
#include <openthread/platform/dns.h>
#include <openthread/platform/dnssd.h>
#include <openthread/platform/dso_transport.h>
#include <openthread/platform/entropy.h>
#include <openthread/platform/flash.h>
#include <openthread/platform/infra_if.h>
#include <openthread/platform/logging.h>
#include <openthread/platform/mdns_socket.h>
#include <openthread/platform/memory.h>
#include <openthread/platform/messagepool.h>
#include <openthread/platform/misc.h>
#include <openthread/platform/multipan.h>
#include <openthread/platform/otns.h>
#include <openthread/platform/radio.h>
#include <openthread/platform/settings.h>
#include <openthread/platform/spi-slave.h>
#include <openthread/platform/time.h>
#include <openthread/platform/toolchain.h>
#include <openthread/platform/trel.h>
#include <openthread/platform/udp.h>

#include <openthread/backbone_router.h>
#include <openthread/backbone_router_ftd.h>
#include <openthread/ble_secure.h>
#include <openthread/border_agent.h>
#include <openthread/border_router.h>
#include <openthread/border_routing.h>
#include <openthread/channel_manager.h>
#include <openthread/channel_monitor.h>
#include <openthread/child_supervision.h>
#include <openthread/cli.h>
#include <openthread/coap.h>
#include <openthread/coap_secure.h>
#include <openthread/commissioner.h>
#include <openthread/config.h>
#include <openthread/crypto.h>
#include <openthread/dataset.h>
#include <openthread/dataset_ftd.h>
#include <openthread/dataset_updater.h>
#include <openthread/diag.h>
#include <openthread/dns.h>
#include <openthread/dns_client.h>
#include <openthread/dnssd_server.h>
#include <openthread/error.h>
#include <openthread/heap.h>
#include <openthread/history_tracker.h>
#include <openthread/icmp6.h>
#include <openthread/instance.h>
#include <openthread/ip6.h>
#include <openthread/jam_detection.h>
#include <openthread/joiner.h>
#include <openthread/link.h>
#include <openthread/link_metrics.h>
#include <openthread/link_raw.h>
#include <openthread/logging.h>
#include <openthread/mdns.h>
#include <openthread/mesh_diag.h>
#include <openthread/message.h>
#include <openthread/multi_radio.h>
#include <openthread/nat64.h>
#include <openthread/ncp.h>
#include <openthread/netdata.h>
#include <openthread/netdata_publisher.h>
#include <openthread/netdiag.h>
#include <openthread/network_time.h>
#include <openthread/ping_sender.h>
#include <openthread/radio_stats.h>
#include <openthread/random_crypto.h>
#include <openthread/random_noncrypto.h>
#include <openthread/server.h>
#include <openthread/sntp.h>
#include <openthread/srp_client.h>
#include <openthread/srp_client_buffers.h>
#include <openthread/srp_server.h>
#include <openthread/tasklet.h>
#include <openthread/tcat.h>
#include <openthread/tcp.h>
#include <openthread/tcp_ext.h>
#include <openthread/thread.h>
#include <openthread/thread_ftd.h>
#include <openthread/trel.h>
#include <openthread/udp.h>
#include <openthread/verhoeff_checksum.h>

#include "backbone_router/backbone_tmf.hpp"
#include "backbone_router/bbr_leader.hpp"
#include "backbone_router/bbr_local.hpp"
#include "backbone_router/bbr_manager.hpp"
#include "backbone_router/multicast_listeners_table.hpp"
#include "backbone_router/ndproxy_table.hpp"
#include "border_router/infra_if.hpp"
#include "border_router/routing_manager.hpp"
#include "coap/coap.hpp"
#include "coap/coap_message.hpp"
#include "coap/coap_secure.hpp"
#include "common/appender.hpp"
#include "common/arg_macros.hpp"
#include "common/array.hpp"
#include "common/as_core_type.hpp"
#include "common/binary_search.hpp"
#include "common/bit_vector.hpp"
#include "common/callback.hpp"
#include "common/clearable.hpp"
#include "common/code_utils.hpp"
#include "common/const_cast.hpp"
#include "common/crc16.hpp"
#include "common/data.hpp"
#include "common/debug.hpp"
#include "common/encoding.hpp"
#include "common/equatable.hpp"
#include "common/error.hpp"
#include "common/frame_builder.hpp"
#include "common/frame_data.hpp"
#include "common/heap.hpp"
#include "common/heap_allocatable.hpp"
#include "common/heap_array.hpp"
#include "common/heap_data.hpp"
#include "common/heap_string.hpp"
#include "common/iterator_utils.hpp"
#include "common/linked_list.hpp"
#include "common/locator.hpp"
#include "common/log.hpp"
#include "common/logging.hpp"
#include "common/message.hpp"
#include "common/new.hpp"
#include "common/non_copyable.hpp"
#include "common/notifier.hpp"
#include "common/num_utils.hpp"
#include "common/numeric_limits.hpp"
#include "common/offset_range.hpp"
#include "common/owned_ptr.hpp"
#include "common/owning_list.hpp"
#include "common/pool.hpp"
#include "common/preference.hpp"
#include "common/ptr_wrapper.hpp"
#include "common/random.hpp"
#include "common/retain_ptr.hpp"
#include "common/serial_number.hpp"
#include "common/settings.hpp"
#include "common/settings_driver.hpp"
#include "common/string.hpp"
#include "common/tasklet.hpp"
#include "common/time.hpp"
#include "common/time_ticker.hpp"
#include "common/timer.hpp"
#include "common/tlvs.hpp"
#include "common/trickle_timer.hpp"
#include "common/type_traits.hpp"
#include "common/uptime.hpp"
#include "crypto/aes_ccm.hpp"
#include "crypto/aes_ecb.hpp"
#include "crypto/context_size.hpp"
#include "crypto/ecdsa.hpp"
#include "crypto/hkdf_sha256.hpp"
#include "crypto/hmac_sha256.hpp"
#include "crypto/mbedtls.hpp"
#include "crypto/sha256.hpp"
#include "crypto/storage.hpp"
#include "diags/factory_diags.hpp"
#include "instance/extension.hpp"
#include "instance/instance.hpp"
#include "mac/channel_mask.hpp"
#include "mac/data_poll_handler.hpp"
#include "mac/data_poll_sender.hpp"
#include "mac/link_raw.hpp"
#include "mac/mac.hpp"
#include "mac/mac_filter.hpp"
#include "mac/mac_frame.hpp"
#include "mac/mac_links.hpp"
#include "mac/mac_types.hpp"
#include "mac/sub_mac.hpp"
#include "meshcop/announce_begin_client.hpp"
#include "meshcop/border_agent.hpp"
#include "meshcop/commissioner.hpp"
#include "meshcop/dataset.hpp"
#include "meshcop/dataset_manager.hpp"
#include "meshcop/dataset_updater.hpp"
#include "meshcop/energy_scan_client.hpp"
#include "meshcop/extended_panid.hpp"
#include "meshcop/joiner.hpp"
#include "meshcop/joiner_router.hpp"
#include "meshcop/meshcop.hpp"
#include "meshcop/meshcop_leader.hpp"
#include "meshcop/meshcop_tlvs.hpp"
#include "meshcop/network_name.hpp"
#include "meshcop/panid_query_client.hpp"
#include "meshcop/secure_transport.hpp"
#include "meshcop/tcat_agent.hpp"
#include "meshcop/timestamp.hpp"
#include "net/checksum.hpp"
#include "net/dhcp6.hpp"
#include "net/dhcp6_client.hpp"
#include "net/dhcp6_server.hpp"
#include "net/dns_client.hpp"
#include "net/dns_dso.hpp"
#include "net/dns_types.hpp"
#include "net/dnssd.hpp"
#include "net/dnssd_server.hpp"
#include "net/icmp6.hpp"
#include "net/ip4_types.hpp"
#include "net/ip6.hpp"
#include "net/ip6_address.hpp"
#include "net/ip6_filter.hpp"
#include "net/ip6_headers.hpp"
#include "net/ip6_mpl.hpp"
#include "net/ip6_types.hpp"
#include "net/mdns.hpp"
#include "net/nat64_translator.hpp"
#include "net/nd6.hpp"
#include "net/nd_agent.hpp"
#include "net/netif.hpp"
#include "net/sntp_client.hpp"
#include "net/socket.hpp"
#include "net/srp_advertising_proxy.hpp"
#include "net/srp_client.hpp"
#include "net/srp_server.hpp"
#include "net/tcp6.hpp"
#include "net/tcp6_ext.hpp"
#include "net/udp6.hpp"
#include "radio/ble_secure.hpp"
#include "radio/max_power_table.hpp"
#include "radio/radio.hpp"
#include "radio/trel_interface.hpp"
#include "radio/trel_link.hpp"
#include "radio/trel_packet.hpp"
#include "thread/address_resolver.hpp"
#include "thread/announce_begin_server.hpp"
#include "thread/announce_sender.hpp"
#include "thread/anycast_locator.hpp"
#include "thread/child.hpp"
#include "thread/child_mask.hpp"
#include "thread/child_supervision.hpp"
#include "thread/child_table.hpp"
#include "thread/csl_tx_scheduler.hpp"
#include "thread/discover_scanner.hpp"
#include "thread/dua_manager.hpp"
#include "thread/energy_scan_server.hpp"
#include "thread/indirect_sender.hpp"
#include "thread/indirect_sender_frame_context.hpp"
#include "thread/key_manager.hpp"
#include "thread/link_metrics.hpp"
#include "thread/link_metrics_tlvs.hpp"
#include "thread/link_metrics_types.hpp"
#include "thread/link_quality.hpp"
#include "thread/lowpan.hpp"
#include "thread/mesh_forwarder.hpp"
#include "thread/mle.hpp"
#include "thread/mle_router.hpp"
#include "thread/mle_tlvs.hpp"
#include "thread/mle_types.hpp"
#include "thread/mlr_manager.hpp"
#include "thread/mlr_types.hpp"
#include "thread/neighbor.hpp"
#include "thread/neighbor_table.hpp"
#include "thread/network_data.hpp"
#include "thread/network_data_leader.hpp"
#include "thread/network_data_local.hpp"
#include "thread/network_data_notifier.hpp"
#include "thread/network_data_publisher.hpp"
#include "thread/network_data_service.hpp"
#include "thread/network_data_tlvs.hpp"
#include "thread/network_data_types.hpp"
#include "thread/network_diagnostic.hpp"
#include "thread/network_diagnostic_tlvs.hpp"
#include "thread/panid_query_server.hpp"
#include "thread/radio_selector.hpp"
#include "thread/router.hpp"
#include "thread/router_table.hpp"
#include "thread/src_match_controller.hpp"
#include "thread/thread_netif.hpp"
#include "thread/thread_tlvs.hpp"
#include "thread/time_sync_service.hpp"
#include "thread/tmf.hpp"
#include "thread/uri_paths.hpp"
#include "thread/version.hpp"
#include "utils/channel_manager.hpp"
#include "utils/channel_monitor.hpp"
#include "utils/flash.hpp"
#include "utils/heap.hpp"
#include "utils/history_tracker.hpp"
#include "utils/jam_detector.hpp"
#include "utils/link_metrics_manager.hpp"
#include "utils/mesh_diag.hpp"
#include "utils/otns.hpp"
#include "utils/parse_cmdline.hpp"
#include "utils/ping_sender.hpp"
#include "utils/power_calibration.hpp"
#include "utils/slaac_address.hpp"
#include "utils/srp_client_buffers.hpp"
#include "utils/verhoeff_checksum.hpp"

#include "common/locator_getters.hpp"


#endif // OPENTHREAD_HPP_
