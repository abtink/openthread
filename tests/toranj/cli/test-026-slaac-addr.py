#!/usr/bin/env python3
#
#  Copyright (c) 2023, The OpenThread Authors.
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. Neither the name of the copyright holder nor the
#     names of its contributors may be used to endorse or promote products
#     derived from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.

from cli import verify
from cli import verify_within
import cli
import time

# -----------------------------------------------------------------------------------------------------------------------
# Test description:
#
# Validates adding/removing/updating SLAAC addresses.
#
# Network Topology
#
#   leader ---  router
#     |
#    fed

test_name = __file__[:-3] if __file__.endswith('.py') else __file__
print('-' * 120)
print('Starting \'{}\''.format(test_name))

# -----------------------------------------------------------------------------------------------------------------------
# Creating `cli.Node` instances

speedup = 40
cli.Node.set_time_speedup_factor(speedup)

leader = cli.Node()
router = cli.Node()
fed = cli.Node()

nodes = [leader, router, fed]

# -----------------------------------------------------------------------------------------------------------------------
# Test Implementation

leader.form('slaac-addr')
fed.join(leader, cli.JOIN_TYPE_REED)
router.join(leader)

verify(leader.get_state() == 'leader')
verify(router.get_state() == 'router')

# Register two preifxes, one from `leader` and one from `router`.
# Both prefixes include preferred ('p'), on-mesh ('o'), slaac ('a')
# and stable ('s') flags.

leader.add_prefix('fd00:1::/64', 'paos', 'med')
router.add_prefix('fd00:2::/64', 'paso', 'med')

router.register_netdata()
leader.register_netdata()


def check_netdata_on_all_nodes():
    for node in nodes:
        netdata = node.get_netdata()
        prefixes = netdata['prefixes']
        verify(len(prefixes) == 2)


verify_within(check_netdata_on_all_nodes, 10)

# Validate that all nodes have proper SLAAC addresses
# for both prefixes.

for node in nodes:
    addrs = node.get_ip_addrs_info()
    for slaac_prefix in ['fd00:1:0:0:', 'fd00:2:0:0:']:
        for addr in addrs:
            info = addrs[addr]
            if info['origin'] == 'slaac' and addr.startswith(slaac_prefix):
                verify(int(info['plen']) == 64)
                verify(int(info['preferred']) == 1)
                verify(int(info['valid']) == 1)
                break
        else:
            print('Did not find address matching slaac prefix ', slaac_prefix)
            verify(False)

# Change `fd00::1/64` prefix, removing its preferred ('p') flag, keeping
# the other flags unchanged.

leader.add_prefix('fd00:1::/64', 'aos', 'med')
leader.register_netdata()


def check_netdata_on_all_nodes_after_flag_change():
    for node in nodes:
        netdata = node.get_netdata()
        prefixes = netdata['prefixes']
        verify(len(prefixes) == 2)
        for prefix in prefixes:
            verify(prefix.startswith('fd00:1:0:0::/64 aos med') or prefix.startswith('fd00:2:0:0::/64 paos med'))


verify_within(check_netdata_on_all_nodes_after_flag_change, 10)

# Validate that all nodes now updated the 'preferred' flag on
# the related SLAAC address.

for node in nodes:
    addrs = node.get_ip_addrs_info()
    for slaac_prefix in ['fd00:1:0:0:', 'fd00:2:0:0:']:
        for addr in addrs:
            info = addrs[addr]
            if info['origin'] == 'slaac' and addr.startswith(slaac_prefix):
                verify(int(info['plen']) == 64)
                verify(int(info['preferred']) == (slaac_prefix != 'fd00:1:0:0:'))
                verify(int(info['valid']) == 1)
                break
        else:
            print('Did not find address matching slaac prefix ', slaac_prefix)
            verify(False)

# Remove `fd00::1/64` prefix from Network Data.

leader.remove_prefix('fd00:1::/64')
leader.register_netdata()


def check_netdata_on_all_nodes_after_remove():
    for node in nodes:
        netdata = node.get_netdata()
        prefixes = netdata['prefixes']
        verify(len(prefixes) == 1)


verify_within(check_netdata_on_all_nodes_after_remove, 10)

# Validate that the related SLAAC address for the removed
# prefix is also removed on all nodes.

for node in nodes:
    addrs = node.get_ip_addrs_info()
    for addr in addrs:
        info = addrs[addr]
        if info['origin'] == 'slaac':
            verify(addr.startswith('fd00:2:0:0:'))
            verify(int(info['plen']) == 64)
            verify(int(info['preferred']) == 1)
            verify(int(info['valid']) == 1)

# -----------------------------------------------------------------------------------------------------------------------
# Test finished

cli.Node.finalize_all_nodes()

print('\'{}\' passed.'.format(test_name))
