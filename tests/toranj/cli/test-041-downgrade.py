#!/usr/bin/env python3
#
#  Copyright (c) 2026, The OpenThread Authors.
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
# Test description: Next hop and path cost calculation.
#

test_name = __file__[:-3] if __file__.endswith('.py') else __file__
print('-' * 120)
print('Starting \'{}\''.format(test_name))

# -----------------------------------------------------------------------------------------------------------------------
# Creating `cli.Node` instances

speedup = 40
cli.Node.set_time_speedup_factor(speedup)

leader = cli.Node()
r1 = cli.Node()
r2 = cli.Node()

# -----------------------------------------------------------------------------------------------------------------------
# Form topology

leader.allowlist_node(r1)
r1.allowlist_node(leader)

r1.allowlist_node(r2)
r2.allowlist_node(r1)

leader.form('downgrade')
r1.join(leader)
r2.join(r1)

verify(leader.get_state() == 'leader')
verify(r1.get_state() == 'router')
verify(r2.get_state() == 'router')

# -----------------------------------------------------------------------------------------------------------------------
# Test Implementation

leader_rloc = int(leader.get_rloc16(), 16)
r1_rloc = int(r1.get_rloc16(), 16)
r2_rloc = int(r2.get_rloc16(), 16)

leader.get_ext_addr()
r1.get_ext_addr()
r2.get_ext_addr()

leader.get_router_table()
r2.get_router_table()

# We want to force r2 to downgrade and become a child instead.


r2.set_router_upgrade_threshold(1)
r2.set_router_downgrade_threshold(1)
verify(r2.get_router_downgrade_threshold() == '1')

time.sleep(5)

r2.get_state()
r2.get_parent_info()
r2.get_router_table()




# -----------------------------------------------------------------------------------------------------------------------
# Test finished

cli.Node.finalize_all_nodes()

print('\'{}\' passed.'.format(test_name))
