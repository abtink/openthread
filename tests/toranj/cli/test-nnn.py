#!/usr/bin/env python3
#
#  Copyright (c) 2021, The OpenThread Authors.
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
# Test description: joining (as router, end-device, sleepy) - two node network

test_name = __file__[:-3] if __file__.endswith('.py') else __file__
print('-' * 120)
print('Starting \'{}\''.format(test_name))

# -----------------------------------------------------------------------------------------------------------------------
# Creating `cli.Nodes` instances

speedup = 80
cli.Node.set_time_speedup_factor(speedup)

leader = cli.Node()
#r1 = cli.Node()
r2 = cli.Node()

# -----------------------------------------------------------------------------------------------------------------------
# Test implementation

#leader.allowlist_node(r1)
leader.allowlist_node(r2)

#r1.allowlist_node(leader)
r2.allowlist_node(leader)

leader.form('test')

#r1.join(leader)
r2.join(leader)

verify(leader.get_state() == 'leader')
verify(r2.get_state() == 'router')

prefix1 = '2001:0db8:0001::/64'
prefix2 = '2001:0db8:0002::/64'

leader.add_prefix(prefix1, 'paosr')
leader.register_netdata()

r2.add_prefix(prefix1, 'paro')
r2.register_netdata()

time.sleep(0.1)

leader.get_netdata()

#~~~~~~~~~~~~~

r2.cli('partitionid preferred 1')
r2.cli('networkidtimeout 50')

r2.un_allowlist_node(leader)
leader.un_allowlist_node(r2)

time.sleep(1)

verify(r2.get_state() == 'leader')

r2.remove_prefix(prefix1)
r2.add_prefix(prefix2, 'paros')
r2.register_netdata()

r2.allowlist_node(leader)
leader.allowlist_node(r2)

time.sleep(2)

verify(r2.get_state() == 'router')
leader.get_netdata()


# -----------------------------------------------------------------------------------------------------------------------
# Test finished

cli.Node.finalize_all_nodes()

print('\'{}\' passed.'.format(test_name))
