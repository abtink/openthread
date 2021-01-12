/*
 *  Copyright (c) 2017, The OpenThread Authors.
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
 *   This file implements the OpenThread DNSv6 API.
 */

#include "openthread-core-config.h"

#include <openthread/dns_client.h>

#include "common/instance.hpp"
#include "common/locator-getters.hpp"
#include "net/dns_client.hpp"

using namespace ot;

#if OPENTHREAD_CONFIG_DNS_CLIENT_ENABLE

otError otDnsClientGetAddressResponseHostName(const otDnsClientAddressResponse *aResponse,
                                              char *                            aNameBuffer,
                                              uint16_t                          aNameBufferSize)
{
    const Dns::Client::AddressResponse &response = *static_cast<const Dns::Client::AddressResponse *>(aResponse);

    return response.GetHostName(aNameBuffer, aNameBufferSize);
}

otError otDnsClientGetAddressResponseAddress(const otDnsClientAddressResponse *aResponse,
                                             uint16_t                          aIndex,
                                             otIp6Address *                    aAddress,
                                             uint32_t *                        aTtl)
{
    const Dns::Client::AddressResponse &response = *static_cast<const Dns::Client::AddressResponse *>(aResponse);
    uint32_t                            ttl;

    return response.GetAddress(aIndex, *static_cast<Ip6::Address *>(aAddress), (aTtl != nullptr) ? *aTtl : ttl);
}

otError otDnsClientResolveAddress(otInstance *                      aInstance,
                                  const otSockAddr *                aServerSockAddr,
                                  const char *                      aHostName,
                                  bool                              aNoRecursion,
                                  otDnsClientAddressResponseHandler aHandler,
                                  void *                            aContext)
{
    Instance &instance = *static_cast<Instance *>(aInstance);

    return instance.Get<Dns::Client>().ResolveAddress(*static_cast<const Ip6::SockAddr *>(aServerSockAddr), aHostName,
                                                      aNoRecursion, aHandler, aContext);
}

#endif // OPENTHREAD_CONFIG_DNS_CLIENT_ENABLE
