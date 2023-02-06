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
import random

# -----------------------------------------------------------------------------------------------------------------------
# Test description:
#
# Check new leader election with different leader wights.
#
#

test_name = __file__[:-3] if __file__.endswith('.py') else __file__
print('-' * 120)
print('Starting \'{}\''.format(test_name))

# -----------------------------------------------------------------------------------------------------------------------
# Creating `cli.Nodes` instances

speedup = 120
cli.Node.set_time_speedup_factor(speedup)

r1 = cli.Node()
r2 = cli.Node()
r3 = cli.Node()
r4 = cli.Node()
r5 = cli.Node()
r6 = cli.Node()

# -----------------------------------------------------------------------------------------------------------------------
# Form topology

# Select different typologies,
TOPOLOGY = 2

if TOPOLOGY == 1:
    # All routers can see each other.
    # No entries in allowlist
    print("Using TOPOLOGY 1")
    print("All routers see each other")

elif TOPOLOGY == 2:

    #     r1 ------ r2 ---- r6
    #      \        /
    #       \      /
    #        \    /
    #          r3 ------ r4 ----- r5

    print("Using TOPOLOGY 2")
    print(" r1 ------ r2 ---- r6")
    print("  \\        /")
    print("   \\      /")
    print("    \\    /")
    print("      r3 ------ r4 ----- r5")

    r1.allowlist_node(r2)
    r1.allowlist_node(r3)

    r2.allowlist_node(r1)
    r2.allowlist_node(r3)
    r2.allowlist_node(r6)

    r3.allowlist_node(r1)
    r3.allowlist_node(r2)
    r3.allowlist_node(r4)

    r4.allowlist_node(r3)
    r4.allowlist_node(r5)

    r5.allowlist_node(r4)

    r6.allowlist_node(r2)

else:
    print('Unknown TOPPLOGY')

# All nodes expect r1 (current leader)
nodes = [r2, r3, r4, r5, r6]

r1.form("topo")
for node in nodes:
    node.join(r1)

verify(r1.get_state() == 'leader')
for node in nodes:
    verify(node.get_state() == 'router')

# -----------------------------------------------------------------------------------------------------------------------
# Test Implementation


def check_new_leader():
    # Wait till we have one leader and all other nodes are router
    states = [node.get_state() for node in nodes]
    verify(states.count('leader') == 1)
    verify(states.count('router') == len(nodes) - 1)


# Assign random weight to nodes
for node in nodes:
    node.cli('leaderweight', random.randint(40, 70))

# Remove current leader
r1.thread_stop()
r1.interface_down()

# Wait till new leader is elected
verify_within(check_new_leader, 150)

# Get leader wights and state
weight_state = []
index = 2
for node in nodes:
    weight = int(node.cli('leaderweight')[0])
    state = node.get_state()
    weight_state.append((weight, state, index))
    index += 1

# Sort based on weight (high to low)
weight_state = sorted(weight_state, reverse=True)

print('All nodes after new leader is elected')
for item in weight_state:
    print('r{} - leaderweight {} - role {}'.format(item[2], item[0], item[1]))

# -----------------------------------------------------------------------------------------------------------------------
# Test finished

cli.Node.finalize_all_nodes()

print('\'{}\' passed.'.format(test_name))
