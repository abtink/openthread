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
 *   This file implements Thread Management Framework (TMF) functionalities.
 */

#include "thread/tmf.hpp"

#include "common/locator_getters.hpp"

namespace ot {
namespace Tmf {

//----------------------------------------------------------------------------------------------------------------------
// MessageInfo

void MessageInfo::SetSockAddrToRloc(void)
{
    SetSockAddr(Get<Mle::MleRouter>().GetMeshLocal16());
}

Error MessageInfo::SetSockAddrToRlocPeerAddrToLeaderAloc(void)
{
    SetSockAddrToRloc();
    return Get<Mle::MleRouter>().GetLeaderAloc(GetPeerAddr());
}

Error MessageInfo::SetSockAddrToRlocPeerAddrToLeaderRloc(void)
{
    SetSockAddrToRloc();
    return Get<Mle::MleRouter>().GetLeaderAddress(GetPeerAddr());
}

void MessageInfo::SetSockAddrToRlocPeerAddrToRealmLocalAllRoutersMulticast(void)
{
    SetSockAddrToRloc();
    GetPeerAddr().SetToRealmLocalAllRoutersMulticast();
}

void MessageInfo::SetSockAddrToRlocPeerAddrTo(uint16_t aRloc16)
{
    SetSockAddrToRloc();
    SetPeerAddr(Get<Mle::MleRouter>().GetMeshLocal16());
    GetPeerAddr().GetIid().SetLocator(aRloc16);
}

void MessageInfo::SetSockAddrToRlocPeerAddrTo(const Ip6::Address &aPeerAddress)
{
    SetSockAddrToRloc();
    SetPeerAddr(aPeerAddress);
}

//----------------------------------------------------------------------------------------------------------------------
// Agent

Agent::Agent(Instance &aInstance)
    : Coap::Coap(aInstance)
{
    SetInterceptor(&Filter, this);
    SetResourceHandler(&HandleResource);
}

Error Agent::Start(void)
{
    return Coap::Start(kUdpPort, Ip6::kNetifThread);
}

bool Agent::HandleResource(CoapBase &              aCoapBase,
                           const char *            aUriPath,
                           Message &               aMessage,
                           const Ip6::MessageInfo &aMessageInfo)
{
    return static_cast<Agent &>(aCoapBase).HandleResource(aUriPath, aMessage, aMessageInfo);
}

bool Agent::HandleResource(const char *aUriPath, Message &aMessage, const Ip6::MessageInfo &aMessageInfo)
{
    bool didHandle = true;
    Uri  uri       = UriFromPath(aUriPath);

    switch (uri)
    {
    case kUriAddressError:
        Get<AddressResolver>().HandleAddressError(aMessage, aMessageInfo);
        break;
    case kUriEnergyScan:
        Get<EnergyScanServer>().HandleRequest(aMessage, aMessageInfo);
        break;
    case kUriActiveGet:
        Get<MeshCoP::ActiveDatasetManager>().HandleGet(aMessage, aMessageInfo);
        break;
    case kUriPendingGet:
        Get<MeshCoP::PendingDatasetManager>().HandleGet(aMessage, aMessageInfo);
        break;
#if OPENTHREAD_CONFIG_JOINER_ENABLE
    case kUriJoinerEntrust:
        Get<MeshCoP::Joiner>().HandleJoinerEntrust(aMessage, aMessageInfo);
        break;
#endif
#if OPENTHREAD_CONFIG_TMF_ANYCAST_LOCATOR_ENABLE
    case kUriAnycastLocate:
        Get<AnycastLocator>().HandleAnycastLocate(aMessage, aMessageInfo);
        break;
#endif

#if OPENTHREAD_FTD
    case kUriAddressQuery:
        Get<AddressResolver>().HandleAddressQuery(aMessage, aMessageInfo);
        break;
    case kUriAddressNotify:
        Get<AddressResolver>().HandleAddressNotification(aMessage, aMessageInfo);
        break;
    case kUriAddressSolicit:
        Get<Mle::MleRouter>().HandleAddressSolicit(aMessage, aMessageInfo);
        break;
    case kUriAddressRelease:
        Get<Mle::MleRouter>().HandleAddressRelease(aMessage, aMessageInfo);
        break;
    case kUriActiveSet:
        Get<MeshCoP::ActiveDatasetManager>().HandleSet(aMessage, aMessageInfo);
        break;
    case kUriPendingSet:
        Get<MeshCoP::PendingDatasetManager>().HandleSet(aMessage, aMessageInfo);
        break;
    case kUriLeaderPetition:
        Get<MeshCoP::Leader>().HandlePetition(aMessage, aMessageInfo);
        break;
    case kUriLeaderKeepAlive:
        Get<MeshCoP::Leader>().HandleKeepAlive(aMessage, aMessageInfo);
        break;
    case kUriServerData:
        Get<NetworkData::Leader>().HandleServerData(aMessage, aMessageInfo);
        break;
    case kUriCommissionerGet:
        Get<NetworkData::Leader>().HandleCommissioningGet(aMessage, aMessageInfo);
        break;
    case kUriCommissionerSet:
        Get<NetworkData::Leader>().HandleCommissioningSet(aMessage, aMessageInfo);
        break;
    case kUriAnnounceBegin:
        Get<AnnounceBeginServer>().HandleRequest(aMessage, aMessageInfo);
        break;
    case kUriPanIdQuery:
        Get<PanIdQueryServer>().HandleQuery(aMessage, aMessageInfo);
        break;
    case kUriRelayTx:
        Get<MeshCoP::JoinerRouter>().HandleRelayTransmit(aMessage, aMessageInfo);
        break;
#endif // OPENTHREAD_FTD

#if OPENTHREAD_CONFIG_COMMISSIONER_ENABLE && OPENTHREAD_FTD
    case kUriPanIdConflict:
        Get<MeshCoP::Commissioner>().GetPanIdQueryClient().HandleConflict(aMessage, aMessageInfo);
        break;
    case kUriEnergyReport:
        Get<MeshCoP::Commissioner>().GetEnergyScanClient().HandleReport(aMessage, aMessageInfo);
        break;
    case kUriDatasetChanged:
        Get<MeshCoP::Commissioner>().HandleDatasetChanged(aMessage, aMessageInfo);
        break;
    // kUriRelayRx is handled below
#endif

#if OPENTHREAD_CONFIG_BORDER_AGENT_ENABLE || (OPENTHREAD_FTD && OPENTHREAD_CONFIG_COMMISSIONER_ENABLE)
     case kUriRelayRx:
#if (OPENTHREAD_FTD && OPENTHREAD_CONFIG_COMMISSIONER_ENABLE)
        Get<MeshCoP::Commissioner>().HandleRelayReceive(aMessage, aMessageInfo);
#endif
#if OPENTHREAD_CONFIG_BORDER_AGENT_ENABLE
        Get<MeshCoP::BorderAgent>().HandleRelayReceive(aMessage);
#endif
        break;
#endif

#if OPENTHREAD_CONFIG_DUA_ENABLE || (OPENTHREAD_FTD && OPENTHREAD_CONFIG_TMF_PROXY_DUA_ENABLE)
    case kUriDuaRegistrationNotify:
        Get<DuaManager>().HandleDuaNotification(aMessage, aMessageInfo);
        break;
#endif

#if OPENTHREAD_FTD || OPENTHREAD_CONFIG_TMF_NETWORK_DIAG_MTD_ENABLE
    case kUriDiagnosticGetRequest:
        Get<NetworkDiagnostic::NetworkDiagnostic>().HandleDiagnosticGetRequest(aMessage, aMessageInfo);
        break;
    case kUriDiagnosticGetQuery:
        Get<NetworkDiagnostic::NetworkDiagnostic>().HandleDiagnosticGetQuery(aMessage, aMessageInfo);
        break;
    case kUriDiagnosticGetAnswer:
        Get<NetworkDiagnostic::NetworkDiagnostic>().HandleDiagnosticGetAnswer(aMessage, aMessageInfo);
        break;
    case kUriDiagnosticReset:
        Get<NetworkDiagnostic::NetworkDiagnostic>().HandleDiagnosticReset(aMessage, aMessageInfo);
        break;
#endif

    default:
        didHandle = false;
        break;
    }

    return didHandle;
}

Error Agent::Filter(const Message &aMessage, const Ip6::MessageInfo &aMessageInfo, void *aContext)
{
    OT_UNUSED_VARIABLE(aMessage);

    return static_cast<Agent *>(aContext)->IsTmfMessage(aMessageInfo.GetPeerAddr(), aMessageInfo.GetSockAddr(),
                                                        aMessageInfo.GetSockPort())
               ? kErrorNone
               : kErrorNotTmf;
}

bool Agent::IsTmfMessage(const Ip6::Address &aSourceAddress, const Ip6::Address &aDestAddress, uint16_t aDestPort) const
{
    bool isTmf = false;

    VerifyOrExit(aDestPort == kUdpPort);

    if (aSourceAddress.IsLinkLocal())
    {
        isTmf = aDestAddress.IsLinkLocal() || aDestAddress.IsLinkLocalMulticast();
        ExitNow();
    }

    VerifyOrExit(Get<Mle::Mle>().IsMeshLocalAddress(aSourceAddress));
    VerifyOrExit(Get<Mle::Mle>().IsMeshLocalAddress(aDestAddress) || aDestAddress.IsLinkLocalMulticast() ||
                 aDestAddress.IsRealmLocalMulticast());

    isTmf = true;

exit:
    return isTmf;
}

} // namespace Tmf
} // namespace ot
