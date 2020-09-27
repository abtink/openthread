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
 *   This file implements the CLI interpreter.
 */

#include "cli.hpp"

#include <stdio.h>
#include <stdlib.h>
#include "mac/channel_mask.hpp"

#include <openthread/icmp6.h>
#include <openthread/link.h>
#include <openthread/ncp.h>
#include <openthread/thread.h>
#if OPENTHREAD_CONFIG_TIME_SYNC_ENABLE
#include <openthread/network_time.h>
#endif

#if OPENTHREAD_FTD
#include <openthread/dataset_ftd.h>
#include <openthread/thread_ftd.h>
#endif

#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE
#include <openthread/border_router.h>
#endif
#if OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE
#include <openthread/server.h>
#endif

#include <openthread/diag.h>
#include <openthread/icmp6.h>
#include <openthread/logging.h>
#include <openthread/platform/uart.h>
#if OPENTHREAD_CONFIG_PLATFORM_NETIF_ENABLE
#include <openthread/platform/misc.h>
#endif

#include "common/new.hpp"
#include "net/ip6.hpp"
#include "utils/otns.hpp"

#if (OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2)
#include <openthread/backbone_router.h>
#if OPENTHREAD_FTD && OPENTHREAD_CONFIG_BACKBONE_ROUTER_ENABLE
#include <openthread/backbone_router_ftd.h>
#endif
#if OPENTHREAD_CONFIG_MLE_LINK_METRICS_ENABLE
#include <openthread/link_metrics.h>
#endif
#endif

#include "cli_dataset.hpp"

#if OPENTHREAD_CONFIG_CHANNEL_MANAGER_ENABLE && OPENTHREAD_FTD
#include <openthread/channel_manager.h>
#endif

#if OPENTHREAD_CONFIG_CHANNEL_MONITOR_ENABLE
#include <openthread/channel_monitor.h>
#endif

#if (OPENTHREAD_CONFIG_LOG_OUTPUT == OPENTHREAD_CONFIG_LOG_OUTPUT_DEBUG_UART) && OPENTHREAD_POSIX
#include <openthread/platform/debug_uart.h>
#endif

#include "common/encoding.hpp"
#include "common/string.hpp"

using ot::Encoding::BigEndian::HostSwap16;
using ot::Encoding::BigEndian::HostSwap32;

namespace ot {

namespace Cli {

constexpr Interpreter::Command Interpreter::sCommands[];

Interpreter *Interpreter::sInterpreter = nullptr;

Interpreter::Interpreter(Instance *aInstance)
    : Utils::CmdLineParser::Args()
    , mUserCommands(nullptr)
    , mUserCommandsLength(0)
    , mPingLength(kDefaultPingLength)
    , mPingCount(kDefaultPingCount)
    , mPingInterval(kDefaultPingInterval)
    , mPingHopLimit(0)
    , mPingAllowZeroHopLimit(false)
    , mPingIdentifier(0)
    , mPingTimer(*aInstance, Interpreter::HandlePingTimer, this)
#if OPENTHREAD_CONFIG_DNS_CLIENT_ENABLE
    , mResolvingInProgress(0)
#endif
#if OPENTHREAD_CONFIG_SNTP_CLIENT_ENABLE
    , mSntpQueryingInProgress(false)
#endif
    , mDataset(*this)
    , mNetworkData(*this)
    , mUdp(*this)
#if OPENTHREAD_CONFIG_COAP_API_ENABLE
    , mCoap(*this)
#endif
#if OPENTHREAD_CONFIG_COAP_SECURE_API_ENABLE
    , mCoapSecure(*this)
#endif
#if OPENTHREAD_CONFIG_COMMISSIONER_ENABLE && OPENTHREAD_FTD
    , mCommissioner(*this)
#endif
#if OPENTHREAD_CONFIG_JOINER_ENABLE
    , mJoiner(*this)
#endif
    , mInstance(aInstance)
{
#if OPENTHREAD_FTD || OPENTHREAD_CONFIG_TMF_NETWORK_DIAG_MTD_ENABLE
    otThreadSetReceiveDiagnosticGetCallback(mInstance, &Interpreter::HandleDiagnosticGetResponse, this);
#endif
#if OPENTHREAD_FTD
    otThreadSetDiscoveryRequestCallback(mInstance, &Interpreter::HandleDiscoveryRequest, this);
#endif

    mIcmpHandler.mReceiveCallback = Interpreter::HandleIcmpReceive;
    mIcmpHandler.mContext         = this;
    IgnoreError(otIcmp6RegisterHandler(mInstance, &mIcmpHandler));

#if OPENTHREAD_CONFIG_DNS_CLIENT_ENABLE
    memset(mResolvingHostname, 0, sizeof(mResolvingHostname));
#endif
}

int Interpreter::Hex2Bin(const char *aHex, uint8_t *aBin, uint16_t aBinLength, bool aAllowTruncate)
{
    size_t      hexLength = strlen(aHex);
    const char *hexEnd    = aHex + hexLength;
    uint8_t *   cur       = aBin;
    uint8_t     numChars  = hexLength & 1;
    uint8_t     byte      = 0;
    int         len       = 0;
    int         rval;

    if (!aAllowTruncate)
    {
        VerifyOrExit((hexLength + 1) / 2 <= aBinLength, rval = -1);
    }

    while (aHex < hexEnd)
    {
        if ('A' <= *aHex && *aHex <= 'F')
        {
            byte |= 10 + (*aHex - 'A');
        }
        else if ('a' <= *aHex && *aHex <= 'f')
        {
            byte |= 10 + (*aHex - 'a');
        }
        else if ('0' <= *aHex && *aHex <= '9')
        {
            byte |= *aHex - '0';
        }
        else
        {
            ExitNow(rval = -1);
        }

        aHex++;
        numChars++;

        if (numChars >= 2)
        {
            numChars = 0;
            *cur++   = byte;
            byte     = 0;
            len++;

            if (len == aBinLength)
            {
                ExitNow(rval = len);
            }
        }
        else
        {
            byte <<= 4;
        }
    }

    rval = len;

exit:
    return rval;
}

void Interpreter::OutputResult(otError aError)
{
    switch (aError)
    {
    case OT_ERROR_NONE:
        OutputLine("Done");
        break;

    case OT_ERROR_PENDING:
        break;

    default:
        OutputLine("Error %d: %s", aError, otThreadErrorToString(aError));
    }
}

void Interpreter::OutputBytes(const uint8_t *aBytes, uint8_t aLength)
{
    for (int i = 0; i < aLength; i++)
    {
        OutputFormat("%02x", aBytes[i]);
    }
}

int Interpreter::OutputIp6Address(const otIp6Address &aAddress)
{
    return OutputFormat(
        "%x:%x:%x:%x:%x:%x:%x:%x", HostSwap16(aAddress.mFields.m16[0]), HostSwap16(aAddress.mFields.m16[1]),
        HostSwap16(aAddress.mFields.m16[2]), HostSwap16(aAddress.mFields.m16[3]), HostSwap16(aAddress.mFields.m16[4]),
        HostSwap16(aAddress.mFields.m16[5]), HostSwap16(aAddress.mFields.m16[6]), HostSwap16(aAddress.mFields.m16[7]));
}

otError Interpreter::ParseLong(char *aString, long &aLong)
{
    char *endptr;
    aLong = strtol(aString, &endptr, 0);
    return (*endptr == '\0') ? OT_ERROR_NONE : OT_ERROR_INVALID_ARGS;
}

otError Interpreter::ParseUnsignedLong(char *aString, unsigned long &aUnsignedLong)
{
    char *endptr;
    aUnsignedLong = strtoul(aString, &endptr, 0);
    return (*endptr == '\0') ? OT_ERROR_NONE : OT_ERROR_INVALID_ARGS;
}

otError Interpreter::ParseJoinerDiscerner(char *aString, otJoinerDiscerner &aDiscerner)
{
    otError       error     = OT_ERROR_NONE;
    char *        separator = strstr(aString, "/");
    unsigned long length;

    VerifyOrExit(separator != nullptr, error = OT_ERROR_NOT_FOUND);

    SuccessOrExit(error = ParseUnsignedLong(separator + 1, length));
    VerifyOrExit(length > 0 && length <= 64, error = OT_ERROR_INVALID_ARGS);

    {
        char *             end;
        unsigned long long value = strtoull(aString, &end, 0);
        aDiscerner.mValue        = value;
        VerifyOrExit(end == separator, error = OT_ERROR_INVALID_ARGS);
    }

    aDiscerner.mLength = static_cast<uint8_t>(length);

exit:
    return error;
}

otError Interpreter::ParsePingInterval(const char *aString, uint32_t &aInterval)
{
    otError        error    = OT_ERROR_NONE;
    const uint32_t msFactor = 1000;
    uint32_t       factor   = msFactor;

    aInterval = 0;

    while (*aString)
    {
        if ('0' <= *aString && *aString <= '9')
        {
            // In the case of seconds, change the base of already calculated value.
            if (factor == msFactor)
            {
                aInterval *= 10;
            }

            aInterval += static_cast<uint32_t>(*aString - '0') * factor;

            // In the case of milliseconds, change the multiplier factor.
            if (factor != msFactor)
            {
                factor /= 10;
            }
        }
        else if (*aString == '.')
        {
            // Accept only one dot character.
            VerifyOrExit(factor == msFactor, error = OT_ERROR_INVALID_ARGS);

            // Start analyzing hundreds of milliseconds.
            factor /= 10;
        }
        else
        {
            ExitNow(error = OT_ERROR_INVALID_ARGS);
        }

        aString++;
    }

exit:
    return error;
}

otError Interpreter::ProcessHelp(void)
{
    static_assert(IsArraySorted(sCommands, OT_ARRAY_LENGTH(sCommands)), "Command list is not sorted");

    for (const Command &command : sCommands)
    {
        OutputLine(command.mName);
    }

    for (uint8_t i = 0; i < mUserCommandsLength; i++)
    {
        OutputLine(mUserCommands[i].mName);
    }

    return OT_ERROR_NONE;
}

#if (OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2)
otError Interpreter::ProcessBackboneRouter(void)
{
    otError                error = OT_ERROR_NONE;
    otBackboneRouterConfig config;

    if (IsArgsEmpty())
    {
        if (otBackboneRouterGetPrimary(mInstance, &config) == OT_ERROR_NONE)
        {
            OutputLine("BBR Primary:");
            OutputLine("server16: 0x%04X", config.mServer16);
            OutputLine("seqno:    %d", config.mSequenceNumber);
            OutputLine("delay:    %d secs", config.mReregistrationDelay);
            OutputLine("timeout:  %d secs", config.mMlrTimeout);
        }
        else
        {
            OutputLine("BBR Primary: None");
        }

        ExitNow();
    }

#if OPENTHREAD_FTD && OPENTHREAD_CONFIG_BACKBONE_ROUTER_ENABLE
#if OPENTHREAD_CONFIG_REFERENCE_DEVICE_ENABLE
    if (IsNextArgEqual("mgmt"))
    {
        if (IsNextArgEqual("dua"))
        {
            otIp6InterfaceIdentifier *mlIid = nullptr;
            otIp6InterfaceIdentifier  iid;
            uint8_t status;

            SuccessOrExit(error = ParseCurArgAsUint8(status));

            if (!IsArgsEmpty())
            {
                SuccessOrExit(error = ParseCurArgAsFixedSizeHexString(iid.mFields.m8));
                mlIid = &iid;
            }

            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

            otBackboneRouterConfigNextDuaRegistrationResponse(mInstance, mlIid, status);
            ExitNow();
        }

        if (IsNextArgEqual("mlr"))
        {
            ExitNow(error = ProcessBackboneRouterMgmtMlr());
        }

        ExitNow(error = OT_ERROR_INVALID_COMMAND);
    }
#endif // OPENTHREAD_CONFIG_REFERENCE_DEVICE_ENABLE

    error = ProcessBackboneRouterLocal();
#else
    error = OT_ERROR_INVALID_COMMAND;
#endif // OPENTHREAD_FTD && OPENTHREAD_CONFIG_BACKBONE_ROUTER_ENABLE

exit:
    return error;
}

#if OPENTHREAD_FTD && OPENTHREAD_CONFIG_BACKBONE_ROUTER_ENABLE

#if OPENTHREAD_CONFIG_REFERENCE_DEVICE_ENABLE
otError Interpreter::ProcessBackboneRouterMgmtMlr(void)
{
    otError error = OT_ERROR_NONE;

    if (IsNextArgEqual("listener"))
    {
        if (IsArgsEmpty())
        {
            ExitNow(PrintMulticastListenersTable());
        }

        if (IsNextArgEqual("clear"))
        {
            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
            ExitNow(otBackboneRouterMulticastListenerClear(mInstance));
        }

        if (IsNextArgEqual("add"))
        {
            otIp6Address address;
            uint32_t     timeout = 0;

            SuccessOrExit(error = ParseCurArgAsIp6Address(address));

            if (!IsArgsEmpty())
            {
                SuccessOrExit(error = ParseCurArgAsUint32(timeout));
            }

            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

            ExitNow(error = otBackboneRouterMulticastListenerAdd(mInstance, &address, timeout));
        }

        ExitNow(error = OT_ERROR_INVALID_COMMAND);
    }

    if (IsNextArgEqual("response"))
    {
        uint8_t status;

        SuccessOrExit(error = ParseCurArgAsUint8(status));
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

        otBackboneRouterConfigNextMulticastListenerRegistrationResponse(mInstance, status);
        ExitNow();
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

void Interpreter::PrintMulticastListenersTable(void)
{
    otBackboneRouterMulticastListenerIterator iter = OT_BACKBONE_ROUTER_MULTICAST_LISTENER_ITERATOR_INIT;
    otBackboneRouterMulticastListenerInfo     listenerInfo;

    while (otBackboneRouterMulticastListenerGetNext(mInstance, &iter, &listenerInfo) == OT_ERROR_NONE)
    {
        OutputIp6Address(listenerInfo.mAddress);
        OutputLine(" %u", listenerInfo.mTimeout);
    }
}

#endif // OPENTHREAD_CONFIG_REFERENCE_DEVICE_ENABLE

otError Interpreter::ProcessBackboneRouterLocal(void)
{
    otError error = OT_ERROR_NONE;

    if (IsNextArgEqual("disable"))
    {
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        ExitNow(otBackboneRouterSetEnabled(mInstance, false));
    }

    if (IsNextArgEqual("enable"))
    {
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        ExitNow(otBackboneRouterSetEnabled(mInstance, true));
    }

    if (IsNextArgEqual("jitter"))
    {
        uint8_t jitter;

        if (IsArgsEmpty())
        {
            ExitNow(OutputLine("%d", otBackboneRouterGetRegistrationJitter(mInstance)));
        }

        SuccessOrExit(error = ParseCurArgAsUint8(jitter));
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

        ExitNow(otBackboneRouterSetRegistrationJitter(mInstance, jitter));
    }

    if (IsNextArgEqual("register"))
    {
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        ExitNow(error = otBackboneRouterRegister(mInstance));
    }

    if (IsNextArgEqual("state"))
    {
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

        switch (otBackboneRouterGetState(mInstance))
        {
        case OT_BACKBONE_ROUTER_STATE_DISABLED:
            OutputLine("Disabled");
            break;
        case OT_BACKBONE_ROUTER_STATE_SECONDARY:
            OutputLine("Secondary");
            break;
        case OT_BACKBONE_ROUTER_STATE_PRIMARY:
            OutputLine("Primary");
            break;
        }

        ExitNow();
    }

    if (IsNextArgEqual("config"))
    {
        otBackboneRouterConfig config;

        otBackboneRouterGetConfig(mInstance, &config);

        if (IsArgsEmpty())
        {
            OutputLine("seqno:    %d", config.mSequenceNumber);
            OutputLine("delay:    %d secs", config.mReregistrationDelay);
            OutputLine("timeout:  %d secs", config.mMlrTimeout);
            ExitNow();
        }

        do
        {
            if (IsNextArgEqual("seqno"))
            {
                SuccessOrExit(error = ParseCurArgAsUint8(config.mSequenceNumber));
            }
            else if (IsNextArgEqual("delay"))
            {
                SuccessOrExit(error = ParseCurArgAsUint16(config.mReregistrationDelay));
            }
            else if (IsNextArgEqual("timeout"))
            {
                SuccessOrExit(error = ParseCurArgAsUint32(config.mMlrTimeout));
            }
            else
            {
                ExitNow(error = OT_ERROR_INVALID_ARGS);
            }
        } while (!IsArgsEmpty());

        ExitNow(error = otBackboneRouterSetConfig(mInstance, &config));
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}
#endif // OPENTHREAD_FTD && OPENTHREAD_CONFIG_BACKBONE_ROUTER_ENABLE

otError Interpreter::ProcessDomainName(void)
{
    otError     error = OT_ERROR_NONE;
    char *name;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine(otThreadGetDomainName(mInstance)));
    }

    SuccessOrExit(error = ParseCurArgAsString(name));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
    error = otThreadSetDomainName(mInstance, name);

exit:
    return error;
}

#if OPENTHREAD_CONFIG_DUA_ENABLE
otError Interpreter::ProcessDua(void)
{
    otError error = OT_ERROR_NONE;

    if (IsNextArgEqual("iid"))
    {
        otIp6InterfaceIdentifier iid;

        if (IsArgsEmpty())
        {
            const otIp6InterfaceIdentifier *duaIid = otThreadGetFixedDuaInterfaceIdentifier(mInstance);

            VerifyOrExit(duaIid != nullptr, OT_NOOP);
            OutputBytes(duaIid->mFields.m8, sizeof(otIp6InterfaceIdentifier));
            OutputLine("");
            ExitNow();
        }

        if (IsNextArgEqual("clear"))
        {
            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
            ExitNow(error = otThreadSetFixedDuaInterfaceIdentifier(mInstance, nullptr));
        }

        SuccessOrExit(error = ParseCurArgAsFixedSizeHexString(iid.mFields.m8));
        ExitNow(error = otThreadSetFixedDuaInterfaceIdentifier(mInstance, &iid));
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}
#endif // OPENTHREAD_CONFIG_DUA_ENABLE

#endif // (OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2)

otError Interpreter::ProcessBufferInfo(void)
{
    otBufferInfo bufferInfo;

    otMessageGetBufferInfo(mInstance, &bufferInfo);

    OutputLine("total: %d", bufferInfo.mTotalBuffers);
    OutputLine("free: %d", bufferInfo.mFreeBuffers);
    OutputLine("6lo send: %d %d", bufferInfo.m6loSendMessages, bufferInfo.m6loSendBuffers);
    OutputLine("6lo reas: %d %d", bufferInfo.m6loReassemblyMessages, bufferInfo.m6loReassemblyBuffers);
    OutputLine("ip6: %d %d", bufferInfo.mIp6Messages, bufferInfo.mIp6Buffers);
    OutputLine("mpl: %d %d", bufferInfo.mMplMessages, bufferInfo.mMplBuffers);
    OutputLine("mle: %d %d", bufferInfo.mMleMessages, bufferInfo.mMleBuffers);
    OutputLine("arp: %d %d", bufferInfo.mArpMessages, bufferInfo.mArpBuffers);
    OutputLine("coap: %d %d", bufferInfo.mCoapMessages, bufferInfo.mCoapBuffers);
    OutputLine("coap secure: %d %d", bufferInfo.mCoapSecureMessages, bufferInfo.mCoapSecureBuffers);
    OutputLine("application coap: %d %d", bufferInfo.mApplicationCoapMessages, bufferInfo.mApplicationCoapBuffers);

    return OT_ERROR_NONE;
}

otError Interpreter::ProcessCcaThreshold(void)
{
    otError error = OT_ERROR_NONE;
    int8_t  cca;

    if (IsArgsEmpty())
    {
        SuccessOrExit(error = otPlatRadioGetCcaEnergyDetectThreshold(mInstance, &cca));
        ExitNow(OutputLine("%d dBm", cca));
    }

    SuccessOrExit(error = ParseCurArgAsInt8(cca));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    error = otPlatRadioSetCcaEnergyDetectThreshold(mInstance, cca);

exit:
    return error;
}

otError Interpreter::ProcessChannel(void)
{
    otError error = OT_ERROR_NONE;
    uint8_t channel;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine("%d", otLinkGetChannel(mInstance)));
    }

    if (IsNextArgEqual("supported"))
    {
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        ExitNow(OutputLine("0x%x", otPlatRadioGetSupportedChannelMask(mInstance)));
    }

    if (IsNextArgEqual("preferred"))
    {
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        ExitNow(OutputLine("0x%x", otPlatRadioGetPreferredChannelMask(mInstance)));
    }

#if OPENTHREAD_CONFIG_CHANNEL_MONITOR_ENABLE
    if (IsNextArgEqual("monitor"))
    {
        if (IsArgsEmpty())
        {
            OutputLine("enabled: %d", otChannelMonitorIsEnabled(mInstance));

            if (otChannelMonitorIsEnabled(mInstance))
            {
                uint32_t channelMask = otLinkGetSupportedChannelMask(mInstance);
                uint8_t  channelNum  = sizeof(channelMask) * CHAR_BIT;

                OutputLine("interval: %u", otChannelMonitorGetSampleInterval(mInstance));
                OutputLine("threshold: %d", otChannelMonitorGetRssiThreshold(mInstance));
                OutputLine("window: %u", otChannelMonitorGetSampleWindow(mInstance));
                OutputLine("count: %u", otChannelMonitorGetSampleCount(mInstance));

                OutputLine("occupancies:");
                for (channel = 0; channel < channelNum; channel++)
                {
                    uint32_t occupancy = 0;

                    if (!((1UL << channel) & channelMask))
                    {
                        continue;
                    }

                    occupancy = otChannelMonitorGetChannelOccupancy(mInstance, channel);

                    OutputFormat("ch %d (0x%04x) ", channel, occupancy);
                    occupancy = (occupancy * 10000) / 0xffff;
                    OutputLine("%2d.%02d%% busy", occupancy / 100, occupancy % 100);
                }
                OutputLine("");
            }

            ExitNow();
        }

        if (IsNextArgEqual("start"))
        {
            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
            ExitNow(error = otChannelMonitorSetEnabled(mInstance, true));
        }

        if (IsNextArgEqual("stop"))
        {
            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
            ExitNow(error = otChannelMonitorSetEnabled(mInstance, false));
        }

        ExitNow(error = OT_ERROR_INVALID_COMMAND);
    }
#endif // OPENTHREAD_CONFIG_CHANNEL_MONITOR_ENABLE

#if OPENTHREAD_CONFIG_CHANNEL_MANAGER_ENABLE && OPENTHREAD_FTD
    if (IsNextArgEqual("manager"))
    {
        if (IsArgsEmpty())
        {
            OutputLine("channel: %d", otChannelManagerGetRequestedChannel(mInstance));
            OutputLine("auto: %d", otChannelManagerGetAutoChannelSelectionEnabled(mInstance));

            if (otChannelManagerGetAutoChannelSelectionEnabled(mInstance))
            {
                Mac::ChannelMask supportedMask(otChannelManagerGetSupportedChannels(mInstance));
                Mac::ChannelMask favoredMask(otChannelManagerGetFavoredChannels(mInstance));

                OutputLine("delay: %d", otChannelManagerGetDelay(mInstance));
                OutputLine("interval: %u", otChannelManagerGetAutoChannelSelectionInterval(mInstance));
                OutputLine("supported: %s", supportedMask.ToString().AsCString());
                OutputLine("favored: %s", supportedMask.ToString().AsCString());
            }

            ExitNow();
        }

        if (IsNextArgEqual("change"))
        {
            SuccessOrExit(error = ParseCurArgAsUint8(channel));
            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
            otChannelManagerRequestChannelChange(mInstance, channel);
            ExitNow();
        }

#if OPENTHREAD_CONFIG_CHANNEL_MONITOR_ENABLE
        if (IsNextArgEqual("select"))
        {
            bool skipQualityCheck;

            SuccessOrExit(error = ParseCurArgAsBool(skipQualityCheck));
            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
            ExitNow(error = otChannelManagerRequestChannelSelect(mInstance, skipQualityCheck));
        }
#endif
        if (IsNextArgEqual("auto"))
        {
            bool enabled;

            SuccessOrExit(error = ParseCurArgAsBool(enabled));
            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
            ExitNow(otChannelManagerSetAutoChannelSelectionEnabled(mInstance, enabled));
        }

        if (IsNextArgEqual("delay"))
        {
            uint8_t delay;

            SuccessOrExit(error = ParseCurArgAsUint8(delay));
            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
            ExitNow(error = otChannelManagerSetDelay(mInstance, delay));
        }

        if (IsNextArgEqual("interval"))
        {
            uint32_t interval;

            SuccessOrExit(error = ParseCurArgAsUint32(interval));
            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
            ExitNow(error = otChannelManagerSetAutoChannelSelectionInterval(mInstance, interval));
        }

        if (IsNextArgEqual("supported"))
        {
            uint32_t mask;

            SuccessOrExit(error = ParseCurArgAsUint32(mask));
            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
            ExitNow(otChannelManagerSetSupportedChannels(mInstance, mask));
        }

        else if (IsNextArgEqual("favored"))
        {
            uint32_t mask;

            SuccessOrExit(error = ParseCurArgAsUint32(mask));
            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
            ExitNow(otChannelManagerSetFavoredChannels(mInstance, mask));
        }

        ExitNow(error = OT_ERROR_INVALID_COMMAND);
    }
#endif // OPENTHREAD_CONFIG_CHANNEL_MANAGER_ENABLE && OPENTHREAD_FTD

    SuccessOrExit(error = ParseCurArgAsUint8(channel));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
    error = otLinkSetChannel(mInstance, channel);

exit:
    return error;
}

#if OPENTHREAD_FTD
otError Interpreter::ProcessChild(void)
{
    otError     error = OT_ERROR_NONE;
    otChildInfo childInfo;
    uint16_t    id;

    if (IsNextArgEqual("table"))
    {
        uint16_t maxChildren = otThreadGetMaxAllowedChildren(mInstance);

        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

        OutputLine("| ID  | RLOC16 | Timeout    | Age        | LQ In | C_VN |R|S|D|N| Extended MAC     |");
        OutputLine("+-----+--------+------------+------------+-------+------+-+-+-+-+------------------+");

        for (uint16_t i = 0; i < maxChildren; i++)
        {
            if ((otThreadGetChildInfoByIndex(mInstance, i, &childInfo) != OT_ERROR_NONE) || childInfo.mIsStateRestoring)
            {
                continue;
            }

            OutputFormat("| %3d ", childInfo.mChildId);
            OutputFormat("| 0x%04x ", childInfo.mRloc16);
            OutputFormat("| %10d ", childInfo.mTimeout);
            OutputFormat("| %10d ", childInfo.mAge);
            OutputFormat("| %5d ", childInfo.mLinkQualityIn);
            OutputFormat("| %4d ", childInfo.mNetworkDataVersion);
            OutputFormat("|%1d", childInfo.mRxOnWhenIdle);
            OutputFormat("|%1d", childInfo.mSecureDataRequest);
            OutputFormat("|%1d", childInfo.mFullThreadDevice);
            OutputFormat("|%1d", childInfo.mFullNetworkData);
            OutputFormat("| ");
            OutputBytes(childInfo.mExtAddress.m8, sizeof(otExtAddress));
            OutputLine(" |");
        }

        OutputLine("");
        ExitNow();
    }

    if (IsNextArgEqual("list"))
    {
        uint16_t maxChildren = otThreadGetMaxAllowedChildren(mInstance);

        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

        for (uint16_t i = 0; i < maxChildren; i++)
        {
            if ((otThreadGetChildInfoByIndex(mInstance, i, &childInfo) != OT_ERROR_NONE) || childInfo.mIsStateRestoring)
            {
                continue;
            }

            OutputFormat("%d ", childInfo.mChildId);
        }

        OutputLine("");
        ExitNow();
    }

    SuccessOrExit(error = ParseCurArgAsUint16(id));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    SuccessOrExit(error = otThreadGetChildInfoById(mInstance, id, &childInfo));

    OutputLine("Child ID: %d", childInfo.mChildId);
    OutputLine("Rloc: %04x", childInfo.mRloc16);
    OutputFormat("Ext Addr: ");
    OutputBytes(childInfo.mExtAddress.m8, sizeof(otExtAddress));
    OutputLine("");
    OutputFormat("Mode: ");

    if (childInfo.mRxOnWhenIdle)
    {
        OutputFormat("r");
    }

    if (childInfo.mSecureDataRequest)
    {
        OutputFormat("s");
    }

    if (childInfo.mFullThreadDevice)
    {
        OutputFormat("d");
    }

    if (childInfo.mFullNetworkData)
    {
        OutputFormat("n");
    }

    OutputLine("");

    OutputLine("Net Data: %d", childInfo.mNetworkDataVersion);
    OutputLine("Timeout: %d", childInfo.mTimeout);
    OutputLine("Age: %d", childInfo.mAge);
    OutputLine("Link Quality In: %d", childInfo.mLinkQualityIn);
    OutputLine("RSSI: %d", childInfo.mAverageRssi);

exit:
    return error;
}

otError Interpreter::ProcessChildIp(void)
{
    otError error = OT_ERROR_NONE;

    if (IsArgsEmpty())
    {
        uint16_t maxChildren = otThreadGetMaxAllowedChildren(mInstance);

        for (uint16_t childIndex = 0; childIndex < maxChildren; childIndex++)
        {
            otChildIp6AddressIterator iterator = OT_CHILD_IP6_ADDRESS_ITERATOR_INIT;
            otIp6Address              ip6Address;
            otChildInfo               childInfo;

            if ((otThreadGetChildInfoByIndex(mInstance, childIndex, &childInfo) != OT_ERROR_NONE) ||
                childInfo.mIsStateRestoring)
            {
                continue;
            }

            iterator = OT_CHILD_IP6_ADDRESS_ITERATOR_INIT;

            while (otThreadGetChildNextIp6Address(mInstance, childIndex, &iterator, &ip6Address) == OT_ERROR_NONE)
            {
                OutputFormat("%04x: ", childInfo.mRloc16);
                OutputIp6Address(ip6Address);
                OutputLine("");
            }
        }

        ExitNow();
    }

    if (IsNextArgEqual("max"))
    {
        if (IsArgsEmpty())
        {
            ExitNow(OutputLine("%d", otThreadGetMaxChildIpAddresses(mInstance)));
        }

#if OPENTHREAD_CONFIG_REFERENCE_DEVICE_ENABLE
        {
            uint8_t maxIpAddresses;

            SuccessOrExit(error = ParseCurArgAsUint8(maxIpAddresses));
            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
            ExitNow(error = otThreadSetMaxChildIpAddresses(mInstance, maxIpAddresses));
        }
#else
        ExitNow(error = OT_ERROR_INVALID_ARGS);
#endif
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

otError Interpreter::ProcessChildMax(void)
{
    otError  error = OT_ERROR_NONE;
    uint16_t maxChildren;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine("%d", otThreadGetMaxAllowedChildren(mInstance)));
    }

    SuccessOrExit(error = ParseCurArgAsUint16(maxChildren));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    error = otThreadSetMaxAllowedChildren(mInstance, maxChildren);

exit:
    return error;
}
#endif // OPENTHREAD_FTD

otError Interpreter::ProcessChildTimeout(void)
{
    otError  error = OT_ERROR_NONE;
    uint32_t timeout;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine("%d", otThreadGetChildTimeout(mInstance)));
    }

    SuccessOrExit(error = ParseCurArgAsUint32(timeout));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    otThreadSetChildTimeout(mInstance, timeout);

exit:
    return error;
}

#if OPENTHREAD_CONFIG_COAP_API_ENABLE
otError Interpreter::ProcessCoap(void)
{
    return mCoap.Process(GetArgsLength(), GetArgs());
}
#endif

#if OPENTHREAD_CONFIG_COAP_SECURE_API_ENABLE
otError Interpreter::ProcessCoapSecure(void)
{
    return mCoapSecure.Process(GetArgsLength(), GetArgs());
}
#endif

#if OPENTHREAD_CONFIG_PLATFORM_RADIO_COEX_ENABLE
otError Interpreter::ProcessCoexMetrics(void)
{
    otError error = OT_ERROR_NONE;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine("%s", otPlatRadioIsCoexEnabled(mInstance) ? "Enabled" : "Disabled"));
    }

    // All the following sub-command have no argument
    VerifyOrExit(GetArgsLength() == 1, error = OT_ERROR_INVALID_ARGS);

    if (IsNextArgEqual("enable"))
    {
        ExitNow(error = otPlatRadioSetCoexEnabled(mInstance, true));
    }

    if (IsNextArgEqual("disable"))
    {
        ExitNow(error = otPlatRadioSetCoexEnabled(mInstance, false));
    }

    if (IsNextArgEqual("metrics"))
    {
        otRadioCoexMetrics metrics;

        SuccessOrExit(error = otPlatRadioGetCoexMetrics(mInstance, &metrics));

        OutputLine("Stopped: %s", metrics.mStopped ? "true" : "false");
        OutputLine("Grant Glitch: %u", metrics.mNumGrantGlitch);
        OutputLine("Transmit metrics");
        OutputLine("    Request: %u", metrics.mNumTxRequest);
        OutputLine("    Grant Immediate: %u", metrics.mNumTxGrantImmediate);
        OutputLine("    Grant Wait: %u", metrics.mNumTxGrantWait);
        OutputLine("    Grant Wait Activated: %u", metrics.mNumTxGrantWaitActivated);
        OutputLine("    Grant Wait Timeout: %u", metrics.mNumTxGrantWaitTimeout);
        OutputLine("    Grant Deactivated During Request: %u", metrics.mNumTxGrantDeactivatedDuringRequest);
        OutputLine("    Delayed Grant: %u", metrics.mNumTxDelayedGrant);
        OutputLine("    Average Request To Grant Time: %u", metrics.mAvgTxRequestToGrantTime);
        OutputLine("Receive metrics");
        OutputLine("    Request: %u", metrics.mNumRxRequest);
        OutputLine("    Grant Immediate: %u", metrics.mNumRxGrantImmediate);
        OutputLine("    Grant Wait: %u", metrics.mNumRxGrantWait);
        OutputLine("    Grant Wait Activated: %u", metrics.mNumRxGrantWaitActivated);
        OutputLine("    Grant Wait Timeout: %u", metrics.mNumRxGrantWaitTimeout);
        OutputLine("    Grant Deactivated During Request: %u", metrics.mNumRxGrantDeactivatedDuringRequest);
        OutputLine("    Delayed Grant: %u", metrics.mNumRxDelayedGrant);
        OutputLine("    Average Request To Grant Time: %u", metrics.mAvgRxRequestToGrantTime);
        OutputLine("    Grant None: %u", metrics.mNumRxGrantNone);
        ExitNow();
    }

    error = OT_ERROR_INVALID_ARGS;

exit:
    return error;
}
#endif // OPENTHREAD_CONFIG_PLATFORM_RADIO_COEX_ENABLE

#if OPENTHREAD_FTD
otError Interpreter::ProcessContextIdReuseDelay(void)
{
    otError  error = OT_ERROR_NONE;
    uint32_t delay;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine("%d", otThreadGetContextIdReuseDelay(mInstance)));
    }

    SuccessOrExit(error = ParseCurArgAsUint32(delay));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    otThreadSetContextIdReuseDelay(mInstance, delay);

exit:
    return error;
}
#endif

otError Interpreter::ProcessCounters(void)
{
    otError error = OT_ERROR_NONE;

    if (IsArgsEmpty())
    {
        OutputLine("mac");
        OutputLine("mle");
        ExitNow();
    }

    if (IsNextArgEqual("mac"))
    {
        if (IsArgsEmpty())
        {
            const otMacCounters *macCounters = otLinkGetCounters(mInstance);

            OutputLine("TxTotal: %d", macCounters->mTxTotal);
            OutputLine("    TxUnicast: %d", macCounters->mTxUnicast);
            OutputLine("    TxBroadcast: %d", macCounters->mTxBroadcast);
            OutputLine("    TxAckRequested: %d", macCounters->mTxAckRequested);
            OutputLine("    TxAcked: %d", macCounters->mTxAcked);
            OutputLine("    TxNoAckRequested: %d", macCounters->mTxNoAckRequested);
            OutputLine("    TxData: %d", macCounters->mTxData);
            OutputLine("    TxDataPoll: %d", macCounters->mTxDataPoll);
            OutputLine("    TxBeacon: %d", macCounters->mTxBeacon);
            OutputLine("    TxBeaconRequest: %d", macCounters->mTxBeaconRequest);
            OutputLine("    TxOther: %d", macCounters->mTxOther);
            OutputLine("    TxRetry: %d", macCounters->mTxRetry);
            OutputLine("    TxErrCca: %d", macCounters->mTxErrCca);
            OutputLine("    TxErrBusyChannel: %d", macCounters->mTxErrBusyChannel);
            OutputLine("RxTotal: %d", macCounters->mRxTotal);
            OutputLine("    RxUnicast: %d", macCounters->mRxUnicast);
            OutputLine("    RxBroadcast: %d", macCounters->mRxBroadcast);
            OutputLine("    RxData: %d", macCounters->mRxData);
            OutputLine("    RxDataPoll: %d", macCounters->mRxDataPoll);
            OutputLine("    RxBeacon: %d", macCounters->mRxBeacon);
            OutputLine("    RxBeaconRequest: %d", macCounters->mRxBeaconRequest);
            OutputLine("    RxOther: %d", macCounters->mRxOther);
            OutputLine("    RxAddressFiltered: %d", macCounters->mRxAddressFiltered);
            OutputLine("    RxDestAddrFiltered: %d", macCounters->mRxDestAddrFiltered);
            OutputLine("    RxDuplicated: %d", macCounters->mRxDuplicated);
            OutputLine("    RxErrNoFrame: %d", macCounters->mRxErrNoFrame);
            OutputLine("    RxErrNoUnknownNeighbor: %d", macCounters->mRxErrUnknownNeighbor);
            OutputLine("    RxErrInvalidSrcAddr: %d", macCounters->mRxErrInvalidSrcAddr);
            OutputLine("    RxErrSec: %d", macCounters->mRxErrSec);
            OutputLine("    RxErrFcs: %d", macCounters->mRxErrFcs);
            OutputLine("    RxErrOther: %d", macCounters->mRxErrOther);
            ExitNow();
        }

        if (IsNextArgEqual("reset"))
        {
            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
            otLinkResetCounters(mInstance);
            ExitNow();
        }

        ExitNow(error = OT_ERROR_INVALID_ARGS);
    }

    if (IsNextArgEqual("mle"))
    {
        if (IsArgsEmpty())
        {
            const otMleCounters *mleCounters = otThreadGetMleCounters(mInstance);

            OutputLine("Role Disabled: %d", mleCounters->mDisabledRole);
            OutputLine("Role Detached: %d", mleCounters->mDetachedRole);
            OutputLine("Role Child: %d", mleCounters->mChildRole);
            OutputLine("Role Router: %d", mleCounters->mRouterRole);
            OutputLine("Role Leader: %d", mleCounters->mLeaderRole);
            OutputLine("Attach Attempts: %d", mleCounters->mAttachAttempts);
            OutputLine("Partition Id Changes: %d", mleCounters->mPartitionIdChanges);
            OutputLine("Better Partition Attach Attempts: %d", mleCounters->mBetterPartitionAttachAttempts);
            OutputLine("Parent Changes: %d", mleCounters->mParentChanges);
            ExitNow();
        }

        if (IsNextArgEqual("reset"))
        {
            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
            otThreadResetMleCounters(mInstance);
            ExitNow();
        }

        ExitNow(error = OT_ERROR_INVALID_ARGS);
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

#if OPENTHREAD_CONFIG_MAC_CSL_RECEIVER_ENABLE
otError Interpreter::ProcessCsl(void)
{
    otError error = OT_ERROR_NONE;

    if (IsArgsEmpty())
    {
        OutputLine("Channel: %u", otLinkCslGetChannel(mInstance));
        OutputLine("Period: %u(in units of 10 symbols), %ums", otLinkCslGetPeriod(mInstance),
                   otLinkCslGetPeriod(mInstance) * kUsPerTenSymbols / 1000);
        OutputLine("Timeout: %us", otLinkCslGetTimeout(mInstance));
        ExitNow();
    }

    // All sub-command require a single argument.
    VerifyOrExit(GetArgsLength() == 2, error = OT_ERROR_INVALID_ARGS);

    if (IsNextArgEqual("channel"))
    {
        uint8_t channel;

        SuccessOrExit(error = ParseCurArgAsUint8(channel));
        ExitNow(error = otLinkCslSetChannel(mInstance, channel));
    }

    if (IsNextArgEqual("period"))
    {
        uint16_t period;

        SuccessOrExit(error = ParseCurArgAsUint16(period));
        ExitNow(error = otLinkCslSetPeriod(mInstance, period));
    }

    if (IsNextArgEqual("timeout"))
    {
        uint32_t timeout;

        SuccessOrExit(error = ParseCurArgAsUint32(timeout));
        ExitNow(error = otLinkCslSetTimeout(mInstance, timeout));
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}
#endif // OPENTHREAD_CONFIG_MAC_CSL_RECEIVER_ENABLE

#if OPENTHREAD_FTD
otError Interpreter::ProcessDelayTimerMin(void)
{
    otError  error = OT_ERROR_NONE;
    uint32_t delayTimerMinimal;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine("%d", (otDatasetGetDelayTimerMinimal(mInstance) / 1000)));
    }

    SuccessOrExit(error = ParseCurArgAsUint32(delayTimerMinimal));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    error = otDatasetSetDelayTimerMinimal(mInstance, static_cast<uint32_t>(delayTimerMinimal * 1000));

exit:
    return error;
}
#endif

otError Interpreter::ProcessDiscover(void)
{
    otError  error        = OT_ERROR_NONE;
    uint32_t scanChannels = 0;

    if (GetArgsLength() == 1)
    {
        uint8_t channel;

        SuccessOrExit(error = ParseCurArgAsUint8(channel));
        VerifyOrExit((channel < sizeof(scanChannels) * CHAR_BIT), error = OT_ERROR_INVALID_ARGS);
        scanChannels = 1 << channel;
    }

    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    SuccessOrExit(error = otThreadDiscover(mInstance, scanChannels, OT_PANID_BROADCAST, false, false,
                                           &Interpreter::HandleActiveScanResult, this));
    OutputLine("| J | Network Name     | Extended PAN     | PAN  | MAC Address      | Ch | dBm | LQI |");
    OutputLine("+---+------------------+------------------+------+------------------+----+-----+-----+");

    error = OT_ERROR_PENDING;

exit:
    return error;
}

#if OPENTHREAD_CONFIG_DNS_CLIENT_ENABLE
otError Interpreter::ProcessDns(void)
{
    otError       error = OT_ERROR_NONE;
    otMessageInfo messageInfo;
    otDnsQuery    query;

    if (IsNextArgEqual("resolve"))
    {
        VerifyOrExit(!mResolvingInProgress, error = OT_ERROR_BUSY);
        VerifyOrExit(!IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        VerifyOrExit(strlen(GetCurArg()) < OT_DNS_MAX_HOSTNAME_LENGTH, error = OT_ERROR_INVALID_ARGS);

        strcpy(mResolvingHostname, GetCurArg());
        AdvanceArg();

        if (!IsArgsEmpty())
        {
            SuccessOrExit(error = ParseCurArgAsIp6Address(messageInfo.mPeerAddr));
        }
        else
        {
            // Use IPv6 address of default DNS server.
            SuccessOrExit(error = otIp6AddressFromString(OT_DNS_DEFAULT_SERVER_IP, &messageInfo.mPeerAddr));
        }

        if (!IsArgsEmpty())
        {
            SuccessOrExit(error = ParseCurArgAsUint16(messageInfo.mPeerPort));
            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        }
        else
        {
            messageInfo.mPeerPort = OT_DNS_DEFAULT_SERVER_PORT;
        }

        query.mHostname    = mResolvingHostname;
        query.mMessageInfo = &messageInfo;
        query.mNoRecursion = false;

        SuccessOrExit(error = otDnsClientQuery(mInstance, &query, &Interpreter::HandleDnsResponse, this));

        mResolvingInProgress = true;
        ExitNow(error = OT_ERROR_PENDING);
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

void Interpreter::HandleDnsResponse(void *              aContext,
                                    const char *        aHostname,
                                    const otIp6Address *aAddress,
                                    uint32_t            aTtl,
                                    otError             aResult)
{
    static_cast<Interpreter *>(aContext)->HandleDnsResponse(aHostname, static_cast<const Ip6::Address *>(aAddress),
                                                            aTtl, aResult);
}

void Interpreter::HandleDnsResponse(const char *aHostname, const Ip6::Address *aAddress, uint32_t aTtl, otError aResult)
{
    OutputFormat("DNS response for %s - ", aHostname);

    if (aResult == OT_ERROR_NONE)
    {
        if (aAddress != nullptr)
        {
            OutputIp6Address(*aAddress);
        }
        OutputLine(" TTL: %d", aTtl);
    }

    OutputResult(aResult);

    mResolvingInProgress = false;
}
#endif

#if OPENTHREAD_FTD
otError Interpreter::ProcessEidCache(void)
{
    otError              error = OT_ERROR_NONE;
    otCacheEntryIterator iterator;
    otCacheEntryInfo     entry;

    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    memset(&iterator, 0, sizeof(iterator));

    while (otThreadGetNextCacheEntry(mInstance, &entry, &iterator) == OT_ERROR_NONE)
    {
        OutputIp6Address(entry.mTarget);
        OutputLine(" %04x", entry.mRloc16);
    }

exit:
    return error;
}
#endif

otError Interpreter::ProcessEui64(void)
{
    otError      error = OT_ERROR_NONE;
    otExtAddress extAddress;

    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    otLinkGetFactoryAssignedIeeeEui64(mInstance, &extAddress);
    OutputBytes(extAddress.m8, OT_EXT_ADDRESS_SIZE);
    OutputLine("");

exit:
    return error;
}

otError Interpreter::ProcessExtAddress(void)
{
    otError      error = OT_ERROR_NONE;
    otExtAddress extAddress;

    if (IsArgsEmpty())
    {
        OutputBytes(otLinkGetExtendedAddress(mInstance)->m8, OT_EXT_ADDRESS_SIZE);
        OutputLine("");
        ExitNow();
    }

    SuccessOrExit(error = ParseCurArgAsFixedSizeHexString(extAddress.m8));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    error = otLinkSetExtendedAddress(mInstance, &extAddress);

exit:
    return error;
}

#if OPENTHREAD_POSIX
otError Interpreter::ProcessExit(void)
{
    exit(EXIT_SUCCESS);

    return OT_ERROR_NONE;
}
#endif

otError Interpreter::ProcessLog(void)
{
    otError error = OT_ERROR_NONE;

    if (IsNextArgEqual("level"))
    {
        if (IsArgsEmpty())
        {
            ExitNow(OutputLine("%d", otLoggingGetLevel()));
        }

#if OPENTHREAD_CONFIG_LOG_LEVEL_DYNAMIC_ENABLE
        {
            uint8_t logLevel;

            SuccessOrExit(error = ParseCurArgAsUint8(logLevel));
            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
            ExitNow(error = otLoggingSetLevel(static_cast<otLogLevel>(logLevel)));
        }
#else
        ExitNow(error = OT_ERROR_INVALID_ARGS);
#endif
    }

#if (OPENTHREAD_CONFIG_LOG_OUTPUT == OPENTHREAD_CONFIG_LOG_OUTPUT_DEBUG_UART) && OPENTHREAD_POSIX
    if (IsNextArgEqual("filename"))
    {
        VerifyOrExit(GetArgsLength() == 1, error = OT_ERROR_INVALID_ARGS);
        ExitNow(error = otPlatDebugUart_logfile(GetCurArg()));
    }
#endif

    error = OT_ERROR_INVALID_ARGS;

exit:
    return error;
}

otError Interpreter::ProcessExtPanId(void)
{
    otError         error = OT_ERROR_NONE;
    otExtendedPanId extPanId;

    if (IsArgsEmpty())
    {
        OutputBytes(otThreadGetExtendedPanId(mInstance)->m8, OT_EXT_PAN_ID_SIZE);
        OutputLine("");
        ExitNow();
    }

    SuccessOrExit(error = ParseCurArgAsFixedSizeHexString(extPanId.m8));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    error = otThreadSetExtendedPanId(mInstance, &extPanId);

exit:
    return error;
}

otError Interpreter::ProcessFactoryReset(void)
{
    otInstanceFactoryReset(mInstance);

    return OT_ERROR_NONE;
}

#if OPENTHREAD_FTD && OPENTHREAD_CONFIG_REFERENCE_DEVICE_ENABLE
otError Interpreter::ProcessFake(void)
{
    otError error = OT_ERROR_NONE;

    if (IsNextArgEqual("/a/an"))
    {
        otIp6Address             destination, target;
        otIp6InterfaceIdentifier mlIid;

        SuccessOrExit(error = ParseCurArgAsIp6Address(destination));
        SuccessOrExit(error = ParseCurArgAsIp6Address(target));
        SuccessOrExit(error = ParseCurArgAsFixedSizeHexString(mlIid.mFields.m8));

        otThreadSendAddressNotification(mInstance, &destination, &target, &mlIid);
        ExitNow();
    }

    error = OT_ERROR_INVALID_ARGS;

exit:
    return error;
}
#endif

otError Interpreter::ProcessIfconfig(void)
{
    otError error = OT_ERROR_NONE;

    if (IsArgsEmpty())
    {
        OutputLine(otIp6IsEnabled(mInstance) ? "up" : "down");
        ExitNow();
    }

    VerifyOrExit(GetArgsLength() == 1, error = OT_ERROR_INVALID_ARGS);

    if (IsNextArgEqual("up"))
    {
        ExitNow(error = otIp6SetEnabled(mInstance, true));
    }

    if (IsNextArgEqual("down"))
    {
        ExitNow(error = otIp6SetEnabled(mInstance, false));
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

otError Interpreter::ProcessIpAddrAdd(void)
{
    otError        error;
    otNetifAddress address;

    SuccessOrExit(error = ParseCurArgAsIp6Address(address.mAddress));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    address.mPrefixLength  = 64;
    address.mPreferred     = true;
    address.mValid         = true;
    address.mAddressOrigin = OT_ADDRESS_ORIGIN_MANUAL;

    error = otIp6AddUnicastAddress(mInstance, &address);

exit:
    return error;
}

otError Interpreter::ProcessIpAddrDel(void)
{
    otError      error;
    otIp6Address address;

    SuccessOrExit(error = ParseCurArgAsIp6Address(address));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    error = otIp6RemoveUnicastAddress(mInstance, &address);

exit:
    return error;
}

otError Interpreter::ProcessIpAddr(void)
{
    otError error = OT_ERROR_NONE;

    if (IsArgsEmpty())
    {
        for (const otNetifAddress *addr = otIp6GetUnicastAddresses(mInstance); addr; addr = addr->mNext)
        {
            OutputIp6Address(addr->mAddress);
            OutputLine("");
        }

        ExitNow();
    }

    if (IsNextArgEqual("add"))
    {
        ExitNow(error = ProcessIpAddrAdd());
    }

    if (IsNextArgEqual("del"))
    {
        ExitNow(error = ProcessIpAddrDel());
    }

    if (IsNextArgEqual("linklocal"))
    {
        OutputIp6Address(*otThreadGetLinkLocalIp6Address(mInstance));
        OutputLine("");
        ExitNow();
    }

    if (IsNextArgEqual("rloc"))
    {
        OutputIp6Address(*otThreadGetRloc(mInstance));
        OutputLine("");
        ExitNow();
    }

    if (IsNextArgEqual("mleid"))
    {
        OutputIp6Address(*otThreadGetMeshLocalEid(mInstance));
        OutputLine("");
        ExitNow();
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

otError Interpreter::ProcessIpMulticastAddrAdd(void)
{
    otError      error;
    otIp6Address address;

    SuccessOrExit(error = ParseCurArgAsIp6Address(address));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    error = otIp6SubscribeMulticastAddress(mInstance, &address);

exit:
    return error;
}

otError Interpreter::ProcessIpMulticastAddrDel(void)
{
    otError      error;
    otIp6Address address;

    SuccessOrExit(error = ParseCurArgAsIp6Address(address));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    error = otIp6UnsubscribeMulticastAddress(mInstance, &address);

exit:
    return error;
}

otError Interpreter::ProcessMulticastPromiscuous(void)
{
    otError error = OT_ERROR_NONE;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine(otIp6IsMulticastPromiscuousEnabled(mInstance) ? "Enabled" : "Disabled"));
    }

    VerifyOrExit(GetArgsLength() == 1, error = OT_ERROR_INVALID_ARGS);

    if (IsNextArgEqual("enable"))
    {
        ExitNow(otIp6SetMulticastPromiscuousEnabled(mInstance, true));
    }

    if (IsNextArgEqual("disable"))
    {
        ExitNow(otIp6SetMulticastPromiscuousEnabled(mInstance, false));
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

otError Interpreter::ProcessIpMulticastAddr(void)
{
    otError error = OT_ERROR_NONE;

    if (IsArgsEmpty())
    {
        for (const otNetifMulticastAddress *addr = otIp6GetMulticastAddresses(mInstance); addr; addr = addr->mNext)
        {
            OutputIp6Address(addr->mAddress);
            OutputLine("");
        }

        ExitNow();
    }

    if (IsNextArgEqual("add"))
    {
        ExitNow(error = ProcessIpMulticastAddrAdd());
    }

    if (IsNextArgEqual("del"))
    {
        ExitNow(error = ProcessIpMulticastAddrDel());
    }

    if (IsNextArgEqual("promiscuous"))
    {
        ExitNow(error = ProcessMulticastPromiscuous());
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

otError Interpreter::ProcessKeySequence(void)
{
    otError error = OT_ERROR_NONE;

    if (IsNextArgEqual("counter"))
    {
        uint32_t counter;

        if (IsArgsEmpty())
        {
            ExitNow(OutputLine("%d", otThreadGetKeySequenceCounter(mInstance)));
        }

        SuccessOrExit(error = ParseCurArgAsUint32(counter));
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        ExitNow(otThreadSetKeySequenceCounter(mInstance, counter));
    }

    if (IsNextArgEqual("guardtime"))
    {
        uint32_t guardTime;

        if (IsArgsEmpty())
        {
            ExitNow(OutputLine("%d", otThreadGetKeySwitchGuardTime(mInstance)));
        }

        SuccessOrExit(error = ParseCurArgAsUint32(guardTime));
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        ExitNow(otThreadSetKeySwitchGuardTime(mInstance, guardTime));
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

otError Interpreter::ProcessLeaderData(void)
{
    otError      error;
    otLeaderData leaderData;

    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    SuccessOrExit(error = otThreadGetLeaderData(mInstance, &leaderData));

    OutputLine("Partition ID: %u", leaderData.mPartitionId);
    OutputLine("Weighting: %d", leaderData.mWeighting);
    OutputLine("Data Version: %d", leaderData.mDataVersion);
    OutputLine("Stable Data Version: %d", leaderData.mStableDataVersion);
    OutputLine("Leader Router ID: %d", leaderData.mLeaderRouterId);

exit:
    return error;
}

#if OPENTHREAD_FTD
otError Interpreter::ProcessLeaderPartitionId(void)
{
    otError  error = OT_ERROR_NONE;
    uint32_t partitionId;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine("%u", otThreadGetLocalLeaderPartitionId(mInstance)));
    }

    SuccessOrExit(error = ParseCurArgAsUint32(partitionId));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    otThreadSetLocalLeaderPartitionId(mInstance, partitionId);

exit:
    return error;
}

otError Interpreter::ProcessLeaderWeight(void)
{
    otError error = OT_ERROR_NONE;
    uint8_t leaderWeight;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine("%d", otThreadGetLocalLeaderWeight(mInstance)));
    }

    SuccessOrExit(error = ParseCurArgAsUint8(leaderWeight));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    otThreadSetLocalLeaderWeight(mInstance, leaderWeight);

exit:
    return error;
}

otError Interpreter::ProcessPskc(void)
{
    otError error = OT_ERROR_NONE;
    otPskc  pskc;

    if (IsArgsEmpty())
    {
        OutputBytes(otThreadGetPskc(mInstance)->m8, sizeof(otPskc));
        OutputLine("");
        ExitNow();
    }

    if (IsNextArgEqual("-p"))
    {
        VerifyOrExit(GetArgsLength() == 1, error = OT_ERROR_INVALID_ARGS);
        SuccessOrExit(error = otDatasetGeneratePskc(
                          GetCurArg(), reinterpret_cast<const otNetworkName *>(otThreadGetNetworkName(mInstance)),
                          otThreadGetExtendedPanId(mInstance), &pskc));
    }
    else
    {
        SuccessOrExit(error = ParseCurArgAsFixedSizeHexString(pskc.m8));
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
    }

    error = otThreadSetPskc(mInstance, &pskc);

exit:
    return error;
}
#endif // OPENTHREAD_FTD

#if OPENTHREAD_CONFIG_MLE_LINK_METRICS_ENABLE
void Interpreter::HandleLinkMetricsReport(const otIp6Address *       aAddress,
                                          const otLinkMetricsValues *aMetricsValues,
                                          void *                     aContext)
{
    static_cast<Interpreter *>(aContext)->HandleLinkMetricsReport(aAddress, aMetricsValues);
}

void Interpreter::HandleLinkMetricsReport(const otIp6Address *aAddress, const otLinkMetricsValues *aMetricsValues)
{
    const char kLinkMetricsTypeCount[]   = "(Count/Summation)";
    const char kLinkMetricsTypeAverage[] = "(Exponential Moving Average)";

    OutputFormat("Received Link Metrics Report from: ");
    OutputIp6Address(*aAddress);
    OutputLine("");

    if (aMetricsValues->mMetrics.mPduCount)
    {
        OutputLine(" - PDU Counter: %d %s", aMetricsValues->mPduCountValue, kLinkMetricsTypeCount);
    }

    if (aMetricsValues->mMetrics.mLqi)
    {
        OutputLine(" - LQI: %d %s", aMetricsValues->mLqiValue, kLinkMetricsTypeAverage);
    }

    if (aMetricsValues->mMetrics.mLinkMargin)
    {
        OutputLine(" - Margin: %d (dB) %s", aMetricsValues->mLinkMarginValue, kLinkMetricsTypeAverage);
    }

    if (aMetricsValues->mMetrics.mRssi)
    {
        OutputLine(" - RSSI: %d (dBm) %s", aMetricsValues->mRssiValue, kLinkMetricsTypeAverage);
    }
}

otError Interpreter::ProcessLinkMetrics(void)
{
    otError error = OT_ERROR_NONE;

    if (IsNextArgEqual("query"))
    {
        ExitNow(error = ProcessLinkMetricsQuery());
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

otError Interpreter::ProcessLinkMetricsQuery(void)
{
    otError       error = OT_ERROR_INVALID_ARGS;
    otIp6Address  address;
    otLinkMetrics linkMetrics;
    long          seriesId = 0;

    SuccessOrExit(error = ParseCurArgAsIp6Address(address));

    memset(&linkMetrics, 0, sizeof(otLinkMetrics));

    if (IsNextArgEqual("single"))
    {
        VerifyOrExit(GetArgsLength() == 1, error = OT_ERROR_INVALID_ARGS);

        for (char *flag = GetCurArg(); *flag != '\0'; flag++)
        {
            switch (*flag)
            {
            case 'p':
                linkMetrics.mPduCount = 1;
                break;

            case 'q':
                linkMetrics.mLqi = 1;
                break;

            case 'm':
                linkMetrics.mLinkMargin = 1;
                break;

            case 'r':
                linkMetrics.mRssi = 1;
                break;

            default:
                ExitNow(error = OT_ERROR_INVALID_ARGS);
            }
        }

        error = otLinkMetricsQuery(mInstance, &address, static_cast<uint8_t>(seriesId), &linkMetrics,
                                   &Interpreter::HandleLinkMetricsReport, this);
    }

exit:
    return error;
}

#endif // OPENTHREAD_CONFIG_MLE_LINK_METRICS_ENABLE

otError Interpreter::ProcessMasterKey(void)
{
    otError     error = OT_ERROR_NONE;
    otMasterKey key;

    if (IsArgsEmpty())
    {
        OutputBytes(otThreadGetMasterKey(mInstance)->m8, OT_MASTER_KEY_SIZE);
        OutputLine("");
        ExitNow();
    }

    SuccessOrExit(error = ParseCurArgAsFixedSizeHexString(key.m8));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    error = otThreadSetMasterKey(mInstance, &key);

exit:
    return error;
}

#if OPENTHREAD_CONFIG_TMF_PROXY_MLR_ENABLE && OPENTHREAD_CONFIG_COMMISSIONER_ENABLE

otError Interpreter::ProcessMlr(void)
{
    otError error = OT_ERROR_INVALID_COMMAND;

    if (IsNextArgEqual("reg"))
    {
        ExitNow(error = ProcessMlrReg());
    }

exit:
    return error;
}

otError Interpreter::ProcessMlrReg(void)
{
    otError      error = OT_ERROR_NONE;
    otIp6Address addresses[kIPv6AddressesNumMax];
    uint8_t      index      = 0;
    bool         hasTimeout = false;
    uint32_t     timeout;

    while (!IsArgsEmpty() && (ParseCurArgAsIp6Address(addresses[index]) == OT_ERROR_NONE))
    {
        index++;
        VerifyOrExit(index < kIPv6AddressesNumMax; error = OT_ERROR_INVALID_ARGS);
    }

    // Parse the last argument (if any) as timeout in seconds
    if (!IsArgsEmpty())
    {
        SuccessOrExit(error = ParseCurArgAsUint32(timeout));
        hasTimeout = true;
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
    }

    VerifyOrExit(index > 0, error = OT_ERROR_INVALID_ARGS);

    SuccessOrExit(error = otIp6RegisterMulticastListeners(mInstance, addresses, index, hasTimeout ? &timeout : nullptr,
                                                          Interpreter::HandleMlrRegResult, this));

    error = OT_ERROR_PENDING;

exit:
    return error;
}

void Interpreter::HandleMlrRegResult(void *              aContext,
                                     otError             aError,
                                     uint8_t             aMlrStatus,
                                     const otIp6Address *aFailedAddresses,
                                     uint8_t             aFailedAddressNum)
{
    static_cast<Interpreter *>(aContext)->HandleMlrRegResult(aError, aMlrStatus, aFailedAddresses, aFailedAddressNum);
}

void Interpreter::HandleMlrRegResult(otError             aError,
                                     uint8_t             aMlrStatus,
                                     const otIp6Address *aFailedAddresses,
                                     uint8_t             aFailedAddressNum)
{
    if (aError == OT_ERROR_NONE)
    {
        OutputLine("status %d, %d failed", aMlrStatus, aFailedAddressNum);

        for (uint8_t i = 0; i < aFailedAddressNum; i++)
        {
            OutputIp6Address(aFailedAddresses[i]);
            OutputLine("");
        }
    }

    OutputResult(aError);
}

#endif // OPENTHREAD_CONFIG_TMF_PROXY_MLR_ENABLE && OPENTHREAD_CONFIG_COMMISSIONER_ENABLE

otError Interpreter::ProcessMode(void)
{
    otError          error = OT_ERROR_NONE;
    otLinkModeConfig linkMode;

    if (IsArgsEmpty())
    {
        linkMode = otThreadGetLinkMode(mInstance);

        if (linkMode.mRxOnWhenIdle)
        {
            OutputFormat("r");
        }

        if (linkMode.mSecureDataRequests)
        {
            OutputFormat("s");
        }

        if (linkMode.mDeviceType)
        {
            OutputFormat("d");
        }

        if (linkMode.mNetworkData)
        {
            OutputFormat("n");
        }

        OutputLine("");
        ExitNow();
    }

    memset(&linkMode, 0, sizeof(otLinkModeConfig));
    VerifyOrExit(GetArgsLength() == 1, error = OT_ERROR_INVALID_ARGS);

    for (char *flag = GetCurArg(); *flag != '\0'; flag++)
    {
        switch (*flag)
        {
        case 'r':
            linkMode.mRxOnWhenIdle = true;
            break;

        case 's':
            linkMode.mSecureDataRequests = true;
            break;

        case 'd':
            linkMode.mDeviceType = true;
            break;

        case 'n':
            linkMode.mNetworkData = true;
            break;

        default:
            ExitNow(error = OT_ERROR_INVALID_ARGS);
        }
    }

    error = otThreadSetLinkMode(mInstance, linkMode);

exit:
    return error;
}

#if OPENTHREAD_FTD
otError Interpreter::ProcessNeighbor(void)
{
    otError                error = OT_ERROR_NONE;
    otNeighborInfo         neighborInfo;
    otNeighborInfoIterator iterator = OT_NEIGHBOR_INFO_ITERATOR_INIT;

    if (IsNextArgEqual("table"))
    {
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

        OutputLine("| Role | RLOC16 | Age | Avg RSSI | Last RSSI |R|S|D|N| Extended MAC     |");
        OutputLine("+------+--------+-----+----------+-----------+-+-+-+-+------------------+");

        while (otThreadGetNextNeighborInfo(mInstance, &iterator, &neighborInfo) == OT_ERROR_NONE)
        {
            OutputFormat("| %3c  ", neighborInfo.mIsChild ? 'C' : 'R');
            OutputFormat("| 0x%04x ", neighborInfo.mRloc16);
            OutputFormat("| %3d ", neighborInfo.mAge);
            OutputFormat("| %8d ", neighborInfo.mAverageRssi);
            OutputFormat("| %9d ", neighborInfo.mLastRssi);
            OutputFormat("|%1d", neighborInfo.mRxOnWhenIdle);
            OutputFormat("|%1d", neighborInfo.mSecureDataRequest);
            OutputFormat("|%1d", neighborInfo.mFullThreadDevice);
            OutputFormat("|%1d", neighborInfo.mFullNetworkData);
            OutputFormat("| ");
            OutputBytes(neighborInfo.mExtAddress.m8, sizeof(otExtAddress));
            OutputLine(" |");
        }

        OutputLine("");
        ExitNow();
    }

    if (IsNextArgEqual("list"))
    {
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

        while (otThreadGetNextNeighborInfo(mInstance, &iterator, &neighborInfo) == OT_ERROR_NONE)
        {
            OutputFormat("0x%04x ", neighborInfo.mRloc16);
        }

        OutputLine("");
        ExitNow();
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}
#endif

#if OPENTHREAD_CONFIG_PLATFORM_NETIF_ENABLE
otError Interpreter::ProcessNetif(void)
{
    otError      error    = OT_ERROR_NONE;
    const char * netif    = nullptr;
    unsigned int netifidx = 0;

    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    SuccessOrExit(error = otPlatGetNetif(mInstance, &netif, &netifidx));

    OutputLine("%s:%u", netif ? netif : "(null)", netifidx);

exit:
    return error;
}
#endif

otError Interpreter::ProcessNetstat(void)
{
    otError      error  = OT_ERROR_NONE;
    otUdpSocket *socket = otUdpGetSockets(mInstance);

    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    OutputLine("|                 Local Address                 |                  Peer Address                 |");
    OutputLine("+-----------------------------------------------+-----------------------------------------------+");

    while (socket)
    {
        constexpr int kMaxOutputLength = 45;
        int           outputLength;

        OutputFormat("| ");

        outputLength = OutputSocketAddress(socket->mSockName);
        for (int i = outputLength; 0 <= i && i < kMaxOutputLength; ++i)
        {
            OutputFormat(" ");
        }
        OutputFormat(" | ");

        outputLength = OutputSocketAddress(socket->mPeerName);
        for (int i = outputLength; 0 <= i && i < kMaxOutputLength; ++i)
        {
            OutputFormat(" ");
        }
        OutputLine(" |");

        socket = socket->mNext;
    }

exit:
    return error;
}

int Interpreter::OutputSocketAddress(const otSockAddr &aAddress)
{
    int outputLength;
    int result = 0;

    VerifyOrExit((outputLength = OutputIp6Address(aAddress.mAddress)) >= 0, result = -1);
    result += outputLength;

    VerifyOrExit((outputLength = OutputFormat(":")) >= 0, result = -1);
    result += outputLength;
    if (aAddress.mPort == 0)
    {
        VerifyOrExit((outputLength = OutputFormat("*")) >= 0, result = -1);
        result += outputLength;
    }
    else
    {
        VerifyOrExit((outputLength = OutputFormat("%d", aAddress.mPort)) >= 0, result = -1);
        result += outputLength;
    }

exit:
    return result;
}

#if OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE
otError Interpreter::ProcessServiceList(void)
{
    otNetworkDataIterator iterator = OT_NETWORK_DATA_ITERATOR_INIT;
    otServiceConfig       config;

    while (otServerGetNextService(mInstance, &iterator, &config) == OT_ERROR_NONE)
    {
        mNetworkData.OutputService(config);
    }

    return OT_ERROR_NONE;
}

otError Interpreter::ProcessService(void)
{
    otError         error = OT_ERROR_NONE;
    otServiceConfig config;
    uint16_t        dataLength;
    enum
    {
        kAddService,
        kRemoveService,
    } operation;

    if (IsArgsEmpty())
    {
        ExitNow(error = ProcessServiceList());
    }

    if (IsNextArgEqual("add"))
    {
        operation = kAddService;
    }
    else if (IsNextArgEqual("remove"))
    {
        operation = kRemoveService;
    }
    else
    {
        ExitNow(error = OT_ERROR_INVALID_COMMAND);
    }

    memset(&config, 0, sizeof(config));
    SuccessOrExit(error = ParseCurArgAsUint32(config.mEnterpriseNumber));

    dataLength = sizeof(config.mServiceData);
    SuccessOrExit(error = ParseCurArgAsHexString(config.mServiceData, dataLength));
    VerifyOrExit(dataLength > 0, error = OT_ERROR_INVALID_ARGS);
    config.mServiceDataLength = static_cast<uint8_t>(dataLength);

    switch (operation)
    {
    case kAddService:
        dataLength = sizeof(config.mServerConfig.mServerData);
        SuccessOrExit(error = ParseCurArgAsHexString(config.mServerConfig.mServerData, dataLength));
        VerifyOrExit(dataLength > 0, error = OT_ERROR_INVALID_ARGS);
        config.mServerConfig.mServerDataLength = static_cast<uint8_t>(dataLength);
        config.mServerConfig.mStable           = true;
        error                                  = otServerAddService(mInstance, &config);
        break;

    case kRemoveService:
        error =
            otServerRemoveService(mInstance, config.mEnterpriseNumber, config.mServiceData, config.mServiceDataLength);
    }

exit:
    return error;
}
#endif // OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE

otError Interpreter::ProcessNetworkData(void)
{
    return mNetworkData.Process(GetArgsLength(), GetArgs());
}

#if OPENTHREAD_FTD
otError Interpreter::ProcessNetworkIdTimeout(void)
{
    otError error = OT_ERROR_NONE;
    uint8_t timeout;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine("%d", otThreadGetNetworkIdTimeout(mInstance)));
    }

    SuccessOrExit(error = ParseCurArgAsUint8(timeout));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
    otThreadSetNetworkIdTimeout(mInstance, timeout);

exit:
    return error;
}
#endif

otError Interpreter::ProcessNetworkName(void)
{
    otError error = OT_ERROR_NONE;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine(otThreadGetNetworkName(mInstance)));
    }

    VerifyOrExit(GetArgsLength() == 1, error = OT_ERROR_INVALID_ARGS);
    error = otThreadSetNetworkName(mInstance, GetCurArg());

exit:
    return error;
}

#if OPENTHREAD_CONFIG_TIME_SYNC_ENABLE
otError Interpreter::ProcessNetworkTime(void)
{
    otError  error = OT_ERROR_NONE;
    uint16_t syncPeriod;
    uint16_t xtalThreshold;

    if (IsArgsEmpty())
    {
        uint64_t            time;
        otNetworkTimeStatus networkTimeStatus;

        networkTimeStatus = otNetworkTimeGet(mInstance, &time);

        OutputFormat("Network Time:     %luus", time);

        switch (networkTimeStatus)
        {
        case OT_NETWORK_TIME_UNSYNCHRONIZED:
            OutputLine(" (unsynchronized)");
            break;

        case OT_NETWORK_TIME_RESYNC_NEEDED:
            OutputLine(" (resync needed)");
            break;

        case OT_NETWORK_TIME_SYNCHRONIZED:
            OutputLine(" (synchronized)");
            break;

        default:
            break;
        }

        OutputLine("Time Sync Period: %ds", otNetworkTimeGetSyncPeriod(mInstance));
        OutputLine("XTAL Threshold:   %dppm", otNetworkTimeGetXtalThreshold(mInstance));
        ExitNow();
    }

    SuccessOrExit(error = ParseCurArgAsUint16(syncPeriod));
    SuccessOrExit(error = ParseCurArgAsUint16(xtalThreshold));

    SuccessOrExit(error = otNetworkTimeSetSyncPeriod(mInstance, syncPeriod));
    SuccessOrExit(error = otNetworkTimeSetXtalThreshold(mInstance, xtalThreshold));

exit:
    return error;
}
#endif // OPENTHREAD_CONFIG_TIME_SYNC_ENABLE

otError Interpreter::ProcessPanId(void)
{
    otError error = OT_ERROR_NONE;
    otPanId panId;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine("0x%04x", otLinkGetPanId(mInstance)));
    }

    SuccessOrExit(error = ParseCurArgAsUint16(panId));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    error = otLinkSetPanId(mInstance, panId);

exit:
    return error;
}

otError Interpreter::ProcessParent(void)
{
    otError      error = OT_ERROR_NONE;
    otRouterInfo parentInfo;

    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    SuccessOrExit(error = otThreadGetParentInfo(mInstance, &parentInfo));
    OutputFormat("Ext Addr: ");
    OutputBytes(parentInfo.mExtAddress.m8, sizeof(otExtAddress));
    OutputLine("");

    OutputLine("Rloc: %x", parentInfo.mRloc16);
    OutputLine("Link Quality In: %d", parentInfo.mLinkQualityIn);
    OutputLine("Link Quality Out: %d", parentInfo.mLinkQualityOut);
    OutputLine("Age: %d", parentInfo.mAge);

exit:
    return error;
}

#if OPENTHREAD_FTD
otError Interpreter::ProcessParentPriority(void)
{
    otError error = OT_ERROR_NONE;
    int8_t  priority;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine("%d", otThreadGetParentPriority(mInstance)));
    }

    SuccessOrExit(error = ParseCurArgAsInt8(priority));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    error = otThreadSetParentPriority(mInstance, priority);

exit:
    return error;
}
#endif

void Interpreter::HandleIcmpReceive(void *               aContext,
                                    otMessage *          aMessage,
                                    const otMessageInfo *aMessageInfo,
                                    const otIcmp6Header *aIcmpHeader)
{
    static_cast<Interpreter *>(aContext)->HandleIcmpReceive(aMessage, aMessageInfo, aIcmpHeader);
}

void Interpreter::HandleIcmpReceive(otMessage *          aMessage,
                                    const otMessageInfo *aMessageInfo,
                                    const otIcmp6Header *aIcmpHeader)
{
    uint32_t timestamp = 0;
    uint16_t dataSize;

    VerifyOrExit(aIcmpHeader->mType == OT_ICMP6_TYPE_ECHO_REPLY, OT_NOOP);
    VerifyOrExit((mPingIdentifier != 0) && (mPingIdentifier == HostSwap16(aIcmpHeader->mData.m16[0])), OT_NOOP);

    dataSize = otMessageGetLength(aMessage) - otMessageGetOffset(aMessage);
    OutputFormat("%u bytes from ", dataSize + static_cast<uint16_t>(sizeof(otIcmp6Header)));

    OutputIp6Address(aMessageInfo->mPeerAddr);

    OutputFormat(": icmp_seq=%d hlim=%d", HostSwap16(aIcmpHeader->mData.m16[1]), aMessageInfo->mHopLimit);

    if (otMessageRead(aMessage, otMessageGetOffset(aMessage), &timestamp, sizeof(uint32_t)) == sizeof(uint32_t))
    {
        OutputFormat(" time=%dms", TimerMilli::GetNow().GetValue() - HostSwap32(timestamp));
    }

    OutputLine("");

    SignalPingReply(static_cast<const Ip6::MessageInfo *>(aMessageInfo)->GetPeerAddr(), dataSize, HostSwap32(timestamp),
                    aMessageInfo->mHopLimit);

exit:
    return;
}

otError Interpreter::ProcessPing(void)
{
    otError error = OT_ERROR_NONE;

    if (IsNextArgEqual("stop"))
    {
        mPingIdentifier = 0;
        VerifyOrExit(mPingTimer.IsRunning(), error = OT_ERROR_INVALID_STATE);
        mPingTimer.Stop();
        ExitNow();
    }

    VerifyOrExit(!mPingTimer.IsRunning(), error = OT_ERROR_BUSY);

    SuccessOrExit(error = ParseCurArgAsIp6Address(mPingDestAddress));

    if (!IsArgsEmpty())
    {
        SuccessOrExit(error = ParseCurArgAsUint16(mPingLength));
    }
    else
    {
        mPingLength = kDefaultPingLength;
    }

    if (!IsArgsEmpty())
    {
        SuccessOrExit(error = ParseCurArgAsUint16(mPingCount));
    }
    else
    {
        mPingCount = kDefaultPingCount;
    }

    if (!IsArgsEmpty())
    {
        SuccessOrExit(error = ParsePingInterval(GetCurArg(), mPingInterval));
        VerifyOrExit(0 < mPingInterval && mPingInterval <= Timer::kMaxDelay, error = OT_ERROR_INVALID_ARGS);
        AdvanceArg();
    }
    else
    {
        mPingInterval = kDefaultPingInterval;
    }

    if (!IsArgsEmpty())
    {
        SuccessOrExit(error = ParseCurArgAsUint8(mPingHopLimit));
        mPingAllowZeroHopLimit = (mPingHopLimit == 0);
    }
    else
    {
        mPingHopLimit          = 0;
        mPingAllowZeroHopLimit = false;
    }

    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    mPingIdentifier++;

    if (mPingIdentifier == 0)
    {
        mPingIdentifier++;
    }

    SendPing();

exit:
    return error;
}

void Interpreter::HandlePingTimer(Timer &aTimer)
{
    GetOwner(aTimer).SendPing();
}

void Interpreter::SendPing(void)
{
    uint32_t      timestamp = HostSwap32(TimerMilli::GetNow().GetValue());
    otMessage *   message   = nullptr;
    otMessageInfo messageInfo;

    memset(&messageInfo, 0, sizeof(messageInfo));
    messageInfo.mPeerAddr          = mPingDestAddress;
    messageInfo.mHopLimit          = mPingHopLimit;
    messageInfo.mAllowZeroHopLimit = mPingAllowZeroHopLimit;

    message = otIp6NewMessage(mInstance, nullptr);
    VerifyOrExit(message != nullptr, OT_NOOP);

    SuccessOrExit(otMessageAppend(message, &timestamp, sizeof(timestamp)));
    SuccessOrExit(otMessageSetLength(message, mPingLength));
    SuccessOrExit(otIcmp6SendEchoRequest(mInstance, message, &messageInfo, mPingIdentifier));

    SignalPingRequest(static_cast<Ip6::MessageInfo *>(&messageInfo)->GetPeerAddr(), mPingLength, HostSwap32(timestamp),
                      messageInfo.mHopLimit);

    message = nullptr;

exit:
    if (message != nullptr)
    {
        otMessageFree(message);
    }

    if (--mPingCount)
    {
        mPingTimer.Start(mPingInterval);
    }
}

otError Interpreter::ProcessPollPeriod(void)
{
    otError  error = OT_ERROR_NONE;
    uint32_t pollPeriod;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine("%d", otLinkGetPollPeriod(mInstance)));
    }

    SuccessOrExit(error = ParseCurArgAsUint32(pollPeriod));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    error = otLinkSetPollPeriod(mInstance, pollPeriod);

exit:
    return error;
}

otError Interpreter::ProcessPromiscuous(void)
{
    otError error = OT_ERROR_NONE;

    if (IsArgsEmpty())
    {
        bool isPromiscuous = (otLinkIsPromiscuous(mInstance) && otPlatRadioGetPromiscuous(mInstance));

        OutputLine(isPromiscuous ? "Enabled" : "Disabled");
        ExitNow();
    }

    VerifyOrExit(GetArgsLength() == 1, error = OT_ERROR_INVALID_ARGS);

    if (IsNextArgEqual("enable"))
    {
        SuccessOrExit(error = otLinkSetPromiscuous(mInstance, true));
        ExitNow(otLinkSetPcapCallback(mInstance, &HandleLinkPcapReceive, this));
    }

    if (IsNextArgEqual("disable"))
    {
        otLinkSetPcapCallback(mInstance, nullptr, nullptr);
        ExitNow(SuccessOrExit(error = otLinkSetPromiscuous(mInstance, false)));
    }

    error = OT_ERROR_INVALID_ARGS;

exit:
    return error;
}

void Interpreter::HandleLinkPcapReceive(const otRadioFrame *aFrame, bool aIsTx, void *aContext)
{
    static_cast<Interpreter *>(aContext)->HandleLinkPcapReceive(aFrame, aIsTx);
}

void Interpreter::HandleLinkPcapReceive(const otRadioFrame *aFrame, bool aIsTx)
{
    OT_UNUSED_VARIABLE(aIsTx);

    OutputLine("");

    for (size_t i = 0; i < 44; i++)
    {
        OutputFormat("=");
    }

    OutputFormat("[len = %3u]", aFrame->mLength);

    for (size_t i = 0; i < 28; i++)
    {
        OutputFormat("=");
    }

    OutputLine("");

    for (size_t i = 0; i < aFrame->mLength; i += 16)
    {
        OutputFormat("|");

        for (size_t j = 0; j < 16; j++)
        {
            if (i + j < aFrame->mLength)
            {
                OutputFormat(" %02X", aFrame->mPsdu[i + j]);
            }
            else
            {
                OutputFormat(" ..");
            }
        }

        OutputFormat("|");

        for (size_t j = 0; j < 16; j++)
        {
            if (i + j < aFrame->mLength)
            {
                if (31 < aFrame->mPsdu[i + j] && aFrame->mPsdu[i + j] < 127)
                {
                    OutputFormat(" %c", aFrame->mPsdu[i + j]);
                }
                else
                {
                    OutputFormat(" ?");
                }
            }
            else
            {
                OutputFormat(" .");
            }
        }

        OutputLine("|");
    }

    for (size_t i = 0; i < 83; i++)
    {
        OutputFormat("-");
    }

    OutputLine("");
}

#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE
otError Interpreter::ProcessPrefixAdd(void)
{
    otError              error = OT_ERROR_NONE;
    otBorderRouterConfig config;

    memset(&config, 0, sizeof(otBorderRouterConfig));

    SuccessOrExit(error = ParseCurArgAsIp6Prefix(config.mPrefix));

    while (!IsArgsEmpty())
    {
        if (IsNextArgEqual("high"))
        {
            config.mPreference = OT_ROUTE_PREFERENCE_HIGH;
        }
        else if (IsNextArgEqual("med"))
        {
            config.mPreference = OT_ROUTE_PREFERENCE_MED;
        }
        else if (IsNextArgEqual("low"))
        {
            config.mPreference = OT_ROUTE_PREFERENCE_LOW;
        }
        else
        {
            for (char *flag = GetCurArg(); *flag != '\0'; flag++)
            {
                switch (*flag)
                {
                case 'p':
                    config.mPreferred = true;
                    break;

                case 'a':
                    config.mSlaac = true;
                    break;

                case 'd':
                    config.mDhcp = true;
                    break;

                case 'c':
                    config.mConfigure = true;
                    break;

                case 'r':
                    config.mDefaultRoute = true;
                    break;

                case 'o':
                    config.mOnMesh = true;
                    break;

                case 's':
                    config.mStable = true;
                    break;

                case 'n':
                    config.mNdDns = true;
                    break;

#if OPENTHREAD_FTD && OPENTHREAD_CONFIG_BACKBONE_ROUTER_ENABLE
                case 'D':
                    config.mDp = true;
                    break;
#endif
                default:
                    ExitNow(error = OT_ERROR_INVALID_ARGS);
                }
            }

            AdvanceArg();
        }
    }

    error = otBorderRouterAddOnMeshPrefix(mInstance, &config);

exit:
    return error;
}

otError Interpreter::ProcessPrefixRemove(void)
{
    otError     error = OT_ERROR_NONE;
    otIp6Prefix prefix;

    SuccessOrExit(error = ParseCurArgAsIp6Prefix(prefix));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    error = otBorderRouterRemoveOnMeshPrefix(mInstance, &prefix);

exit:
    return error;
}

otError Interpreter::ProcessPrefixList(void)
{
    otNetworkDataIterator iterator = OT_NETWORK_DATA_ITERATOR_INIT;
    otBorderRouterConfig  config;

    while (otBorderRouterGetNextOnMeshPrefix(mInstance, &iterator, &config) == OT_ERROR_NONE)
    {
        mNetworkData.OutputPrefix(config);
    }

#if OPENTHREAD_FTD && OPENTHREAD_CONFIG_BACKBONE_ROUTER_ENABLE
    if (otBackboneRouterGetState(mInstance) == OT_BACKBONE_ROUTER_STATE_DISABLED)
    {
        SuccessOrExit(otBackboneRouterGetDomainPrefix(mInstance, &config));
        OutputFormat("- ");
        mNetworkData.OutputPrefix(config);
    }
    // Else already printed via above while loop.
exit:
#endif

    return OT_ERROR_NONE;
}

otError Interpreter::ProcessPrefix(void)
{
    otError error = OT_ERROR_NONE;

    if (IsArgsEmpty())
    {
        ExitNow(error = ProcessPrefixList());
    }

    if (IsNextArgEqual("add"))
    {
        ExitNow(error = ProcessPrefixAdd());
    }

    if (IsNextArgEqual("remove"))
    {
        ExitNow(error = ProcessPrefixRemove());
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}
#endif // OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE

#if OPENTHREAD_FTD
otError Interpreter::ProcessPreferRouterId(void)
{
    otError error = OT_ERROR_NONE;
    uint8_t preferredRouterId;

    SuccessOrExit(error = ParseCurArgAsUint8(preferredRouterId));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
    error = otThreadSetPreferredRouterId(mInstance, preferredRouterId);

exit:
    return error;
}
#endif

otError Interpreter::ProcessRcp(void)
{
    otError error = OT_ERROR_NONE;

    if (IsNextArgEqual("version"))
    {
        const char *version = otPlatRadioGetVersionString(mInstance);

        VerifyOrExit(version != otGetVersionString(), error = OT_ERROR_NOT_IMPLEMENTED);
        OutputLine(version);
        ExitNow();
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

#if OPENTHREAD_FTD
otError Interpreter::ProcessReleaseRouterId(void)
{
    otError error = OT_ERROR_NONE;
    uint8_t routerId;

    SuccessOrExit(error = ParseCurArgAsUint8(routerId));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    error = otThreadReleaseRouterId(mInstance, routerId);

exit:
    return error;
}
#endif

otError Interpreter::ProcessReset(void)
{
    otInstanceReset(mInstance);

    return OT_ERROR_NONE;
}

otError Interpreter::ProcessRloc16(void)
{
    OutputLine("%04x", otThreadGetRloc16(mInstance));

    return OT_ERROR_NONE;
}

#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE
otError Interpreter::ProcessRouteAdd(void)
{
    otError               error = OT_ERROR_NONE;
    otExternalRouteConfig config;

    memset(&config, 0, sizeof(otExternalRouteConfig));

    SuccessOrExit(error = ParseCurArgAsIp6Prefix(config.mPrefix));

    while (!IsArgsEmpty())
    {
        if (IsNextArgEqual("s"))
        {
            config.mStable = true;
        }
        else if (IsNextArgEqual("high"))
        {
            config.mPreference = OT_ROUTE_PREFERENCE_HIGH;
        }
        else if (IsNextArgEqual("med"))
        {
            config.mPreference = OT_ROUTE_PREFERENCE_MED;
        }
        else if (IsNextArgEqual("low"))
        {
            config.mPreference = OT_ROUTE_PREFERENCE_LOW;
        }
        else
        {
            ExitNow(error = OT_ERROR_INVALID_ARGS);
        }
    }

    error = otBorderRouterAddRoute(mInstance, &config);

exit:
    return error;
}

otError Interpreter::ProcessRouteRemove(void)
{
    otError            error = OT_ERROR_NONE;
    struct otIp6Prefix prefix;

    SuccessOrExit(error = ParseCurArgAsIp6Prefix(prefix));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    error = otBorderRouterRemoveRoute(mInstance, &prefix);

exit:
    return error;
}

otError Interpreter::ProcessRouteList(void)
{
    otNetworkDataIterator iterator = OT_NETWORK_DATA_ITERATOR_INIT;
    otExternalRouteConfig config;

    while (otBorderRouterGetNextRoute(mInstance, &iterator, &config) == OT_ERROR_NONE)
    {
        mNetworkData.OutputRoute(config);
    }

    return OT_ERROR_NONE;
}

otError Interpreter::ProcessRoute(void)
{
    otError error = OT_ERROR_NONE;

    if (IsArgsEmpty())
    {
        ExitNow(error = ProcessRouteList());
    }

    if (IsNextArgEqual("add"))
    {
        ExitNow(error = ProcessRouteAdd());
    }

    if (IsNextArgEqual("remove"))
    {
        ExitNow(error = ProcessRouteRemove());
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}
#endif // OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE

#if OPENTHREAD_FTD
otError Interpreter::ProcessRouter(void)
{
    otError      error = OT_ERROR_NONE;
    otRouterInfo routerInfo;
    uint16_t     id;

    if (IsNextArgEqual("table"))
    {
        uint8_t maxRouterId = otThreadGetMaxRouterId(mInstance);

        OutputLine("| ID | RLOC16 | Next Hop | Path Cost | LQ In | LQ Out | Age | Extended MAC     |");
        OutputLine("+----+--------+----------+-----------+-------+--------+-----+------------------+");

        for (uint8_t i = 0; i <= maxRouterId; i++)
        {
            if (otThreadGetRouterInfo(mInstance, i, &routerInfo) != OT_ERROR_NONE)
            {
                continue;
            }

            OutputFormat("| %2d ", routerInfo.mRouterId);
            OutputFormat("| 0x%04x ", routerInfo.mRloc16);
            OutputFormat("| %8d ", routerInfo.mNextHop);
            OutputFormat("| %9d ", routerInfo.mPathCost);
            OutputFormat("| %5d ", routerInfo.mLinkQualityIn);
            OutputFormat("| %6d ", routerInfo.mLinkQualityOut);
            OutputFormat("| %3d ", routerInfo.mAge);
            OutputFormat("| ");
            OutputBytes(routerInfo.mExtAddress.m8, sizeof(otExtAddress));
            OutputLine(" |");
        }

        OutputLine("");
        ExitNow();
    }

    if (IsNextArgEqual("list"))
    {
        uint8_t maxRouterId = otThreadGetMaxRouterId(mInstance);

        for (uint8_t i = 0; i <= maxRouterId; i++)
        {
            if (otThreadGetRouterInfo(mInstance, i, &routerInfo) != OT_ERROR_NONE)
            {
                continue;
            }

            OutputFormat("%d ", i);
        }

        OutputLine("");
        ExitNow();
    }

    SuccessOrExit(error = ParseCurArgAsUint16(id));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    SuccessOrExit(error = otThreadGetRouterInfo(mInstance, id, &routerInfo));

    OutputLine("Alloc: %d", routerInfo.mAllocated);

    if (routerInfo.mAllocated)
    {
        OutputLine("Router ID: %d", routerInfo.mRouterId);
        OutputLine("Rloc: %04x", routerInfo.mRloc16);
        OutputLine("Next Hop: %04x", static_cast<uint16_t>(routerInfo.mNextHop) << 10);
        OutputLine("Link: %d", routerInfo.mLinkEstablished);

        if (routerInfo.mLinkEstablished)
        {
            OutputFormat("Ext Addr: ");
            OutputBytes(routerInfo.mExtAddress.m8, sizeof(otExtAddress));
            OutputLine("");
            OutputLine("Cost: %d", routerInfo.mPathCost);
            OutputLine("Link Quality In: %d", routerInfo.mLinkQualityIn);
            OutputLine("Link Quality Out: %d", routerInfo.mLinkQualityOut);
            OutputLine("Age: %d", routerInfo.mAge);
        }
    }

exit:
    return error;
}

otError Interpreter::ProcessRouterDowngradeThreshold(void)
{
    otError error = OT_ERROR_NONE;
    uint8_t threshold;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine("%d", otThreadGetRouterDowngradeThreshold(mInstance)));
    }

    SuccessOrExit(error = ParseCurArgAsUint8(threshold));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
    otThreadSetRouterDowngradeThreshold(mInstance, threshold);

exit:
    return error;
}

otError Interpreter::ProcessRouterEligible(void)
{
    otError error = OT_ERROR_NONE;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine(otThreadIsRouterEligible(mInstance) ? "Enabled" : "Disabled"));
    }

    VerifyOrExit(GetArgsLength() == 1, error = OT_ERROR_INVALID_ARGS);

    if (IsNextArgEqual("enable"))
    {
        ExitNow(error = otThreadSetRouterEligible(mInstance, true));
    }

    if (IsNextArgEqual("disable"))
    {
        ExitNow(error = otThreadSetRouterEligible(mInstance, false));
    }

    error = OT_ERROR_INVALID_ARGS;

exit:
    return error;
}

otError Interpreter::ProcessRouterSelectionJitter(void)
{
    otError error = OT_ERROR_NONE;
    uint8_t jitter;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine("%d", otThreadGetRouterSelectionJitter(mInstance)));
    }

    SuccessOrExit(error = ParseCurArgAsUint8(jitter));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
    otThreadSetRouterSelectionJitter(mInstance, jitter);

exit:
    return error;
}

otError Interpreter::ProcessRouterUpgradeThreshold(void)
{
    otError error = OT_ERROR_NONE;
    uint8_t threshold;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine("%d", otThreadGetRouterUpgradeThreshold(mInstance)));

        SuccessOrExit(error = ParseCurArgAsUint8(threshold));
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        otThreadSetRouterUpgradeThreshold(mInstance, threshold);
    }

exit:
    return error;
}
#endif // OPENTHREAD_FTD

otError Interpreter::ProcessScan(void)
{
    otError  error        = OT_ERROR_NONE;
    uint32_t scanChannels = 0;
    uint16_t scanDuration = 0;

    if (IsNextArgEqual("energy"))
    {
        if (!IsArgsEmpty())
        {
            SuccessOrExit(error = ParseCurArgAsUint16(scanDuration));
            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        }

        OutputLine("| Ch | RSSI |");
        OutputLine("+----+------+");
        SuccessOrExit(error = otLinkEnergyScan(mInstance, scanChannels, scanDuration,
                                               &Interpreter::HandleEnergyScanResult, this));
        ExitNow(error = OT_ERROR_PENDING);
    }

    if (!IsArgsEmpty())
    {
        uint8_t channel;

        SuccessOrExit(error = ParseCurArgAsUint8(channel));
        VerifyOrExit(channel < sizeof(scanChannels) * CHAR_BIT, error = OT_ERROR_INVALID_ARGS);
        scanChannels = 1 << channel;

        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
    }

    OutputLine("| J | Network Name     | Extended PAN     | PAN  | MAC Address      | Ch | dBm | LQI |");
    OutputLine("+---+------------------+------------------+------+------------------+----+-----+-----+");
    SuccessOrExit(
        error = otLinkActiveScan(mInstance, scanChannels, scanDuration, &Interpreter::HandleActiveScanResult, this));

    error = OT_ERROR_PENDING;

exit:
    return error;
}

void Interpreter::HandleActiveScanResult(otActiveScanResult *aResult, void *aContext)
{
    static_cast<Interpreter *>(aContext)->HandleActiveScanResult(aResult);
}

void Interpreter::HandleActiveScanResult(otActiveScanResult *aResult)
{
    if (aResult == nullptr)
    {
        OutputResult(OT_ERROR_NONE);
        ExitNow();
    }

    OutputFormat("| %d ", aResult->mIsJoinable);

    OutputFormat("| %-16s ", aResult->mNetworkName.m8);

    OutputFormat("| ");
    OutputBytes(aResult->mExtendedPanId.m8, OT_EXT_PAN_ID_SIZE);
    OutputFormat(" ");

    OutputFormat("| %04x | ", aResult->mPanId);
    OutputBytes(aResult->mExtAddress.m8, OT_EXT_ADDRESS_SIZE);
    OutputFormat(" | %2d ", aResult->mChannel);
    OutputFormat("| %3d ", aResult->mRssi);
    OutputLine("| %3d |", aResult->mLqi);

exit:
    return;
}

void Interpreter::HandleEnergyScanResult(otEnergyScanResult *aResult, void *aContext)
{
    static_cast<Interpreter *>(aContext)->HandleEnergyScanResult(aResult);
}

void Interpreter::HandleEnergyScanResult(otEnergyScanResult *aResult)
{
    if (aResult == nullptr)
    {
        OutputResult(OT_ERROR_NONE);
        ExitNow();
    }

    OutputLine("| %2d | %4d |", aResult->mChannel, aResult->mMaxRssi);

exit:
    return;
}

otError Interpreter::ProcessSingleton(void)
{
    otError error = OT_ERROR_NONE;

    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

    OutputLine(otThreadIsSingleton(mInstance) ? "true" : "false");

exit:
    return error;
}

#if OPENTHREAD_CONFIG_SNTP_CLIENT_ENABLE
otError Interpreter::ProcessSntp(void)
{
    otError       error = OT_ERROR_NONE;
    otMessageInfo messageInfo;
    otSntpQuery   query;

    if (IsNextArgEqual("query"))
    {
        VerifyOrExit(!mSntpQueryingInProgress, error = OT_ERROR_BUSY);

        if (!IsArgsEmpty())
        {
            SuccessOrExit(error = ParseCurArgAsIp6Address(messageInfo.mPeerAddr));
        }
        else
        {
            // Use IPv6 address of default SNTP server.
            SuccessOrExit(error = otIp6AddressFromString(OT_SNTP_DEFAULT_SERVER_IP, &messageInfo.mPeerAddr));
        }

        if (!IsArgsEmpty())
        {
            SuccessOrExit(error = ParseCurArgAsUint16(messageInfo.mPeerPort));
        }
        else
        {
            messageInfo.mPeerPort = OT_SNTP_DEFAULT_SERVER_PORT;
        }

        query.mMessageInfo = &messageInfo;

        SuccessOrExit(error = otSntpClientQuery(mInstance, &query, &Interpreter::HandleSntpResponse, this));

        mSntpQueryingInProgress = true;
        ExitNow(error = OT_ERROR_PENDING);
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

void Interpreter::HandleSntpResponse(void *aContext, uint64_t aTime, otError aResult)
{
    static_cast<Interpreter *>(aContext)->HandleSntpResponse(aTime, aResult);
}

void Interpreter::HandleSntpResponse(uint64_t aTime, otError aResult)
{
    if (aResult == OT_ERROR_NONE)
    {
        // Some Embedded C libraries do not support printing of 64-bit unsigned integers.
        // To simplify, unix epoch time and era number are printed separately.
        OutputLine("SNTP response - Unix time: %u (era: %u)", static_cast<uint32_t>(aTime),
                   static_cast<uint32_t>(aTime >> 32));
    }
    else
    {
        OutputLine("SNTP error - %s", otThreadErrorToString(aResult));
    }

    mSntpQueryingInProgress = false;

    OutputResult(OT_ERROR_NONE);
}
#endif

otError Interpreter::ProcessState(void)
{
    otError error = OT_ERROR_NONE;

    if (IsArgsEmpty())
    {
        switch (otThreadGetDeviceRole(mInstance))
        {
        case OT_DEVICE_ROLE_DISABLED:
            OutputLine("disabled");
            break;

        case OT_DEVICE_ROLE_DETACHED:
            OutputLine("detached");
            break;

        case OT_DEVICE_ROLE_CHILD:
            OutputLine("child");
            break;

#if OPENTHREAD_FTD
        case OT_DEVICE_ROLE_ROUTER:
            OutputLine("router");
            break;

        case OT_DEVICE_ROLE_LEADER:
            OutputLine("leader");
            break;
#endif

        default:
            OutputLine("invalid state");
            break;
        }

        ExitNow();
    }

    VerifyOrExit(GetArgsLength() == 1, error = OT_ERROR_INVALID_ARGS);

    if (IsNextArgEqual("detached"))
    {
        ExitNow(error = otThreadBecomeDetached(mInstance));
    }

    if (IsNextArgEqual("child"))
    {
        ExitNow(error = otThreadBecomeChild(mInstance));
    }

#if OPENTHREAD_FTD
    if (IsNextArgEqual("router"))
    {
        ExitNow(error = otThreadBecomeRouter(mInstance));
    }

    if (IsNextArgEqual("leader"))
    {
        ExitNow(error = otThreadBecomeLeader(mInstance));
    }
#endif

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

otError Interpreter::ProcessThread(void)
{
    otError error = OT_ERROR_NONE;

    VerifyOrExit(GetArgsLength() == 1, error = OT_ERROR_INVALID_ARGS);

    if (IsNextArgEqual("start"))
    {
        ExitNow(error = otThreadSetEnabled(mInstance, true));
    }

    if (IsNextArgEqual("stop"))
    {
        ExitNow(error = otThreadSetEnabled(mInstance, false));
    }

    if (IsNextArgEqual("version"))
    {
        ExitNow(OutputLine("%u", otThreadGetVersion()));
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

otError Interpreter::ProcessDataset(void)
{
    return mDataset.Process(GetArgsLength(), GetArgs());
}

otError Interpreter::ProcessTxPower(void)
{
    otError error = OT_ERROR_NONE;
    int8_t  power;

    if (IsArgsEmpty())
    {
        SuccessOrExit(error = otPlatRadioGetTransmitPower(mInstance, &power));
        ExitNow(OutputLine("%d dBm", power));
    }

    SuccessOrExit(error = ParseCurArgAsInt8(power));
    VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
    error = otPlatRadioSetTransmitPower(mInstance, power);

exit:
    return error;
}

otError Interpreter::ProcessUdp(void)
{
    return mUdp.Process(GetArgsLength(), GetArgs());
}

otError Interpreter::ProcessUnsecurePort(void)
{
    otError error = OT_ERROR_NONE;

    if (IsNextArgEqual("add"))
    {
        uint16_t port;

        SuccessOrExit(error = ParseCurArgAsUint16(port));
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        ExitNow(error = otIp6AddUnsecurePort(mInstance, port));
    }

    if (IsNextArgEqual("remove"))
    {
        uint16_t port;

        if (IsNextArgEqual("all"))
        {
            ExitNow(otIp6RemoveAllUnsecurePorts(mInstance));
        }

        SuccessOrExit(error = ParseCurArgAsUint16(port));
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        ExitNow(error = otIp6RemoveUnsecurePort(mInstance, port));
    }

    if (IsNextArgEqual("get"))
    {
        const uint16_t *ports;
        uint8_t         numPorts;

        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

        ports = otIp6GetUnsecurePorts(mInstance, &numPorts);

        if (ports != NULL)
        {
            for (uint8_t i = 0; i < numPorts; i++)
            {
                OutputFormat("%d ", ports[i]);
            }
        }

        OutputLine("");
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

otError Interpreter::ProcessVersion(void)
{
    otError error = OT_ERROR_NONE;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine("%s", otGetVersionString()));
    }

    if (IsNextArgEqual("api"))
    {
        ExitNow(OutputLine("%d", OPENTHREAD_API_VERSION));
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

#if OPENTHREAD_CONFIG_COMMISSIONER_ENABLE && OPENTHREAD_FTD
otError Interpreter::ProcessCommissioner(void)
{
    return mCommissioner.Process(GetArgsLength(), GetArgs());
}
#endif

#if OPENTHREAD_CONFIG_JOINER_ENABLE
otError Interpreter::ProcessJoiner(void)
{
    return mJoiner.Process(GetArgsLength(), GetArgs());
}
#endif

#if OPENTHREAD_FTD
otError Interpreter::ProcessJoinerPort(void)
{
    otError  error = OT_ERROR_NONE;
    uint16_t port;

    if (IsArgsEmpty())
    {
        ExitNow(OutputLine("%d", otThreadGetJoinerUdpPort(mInstance)));
    }

    SuccessOrExit(error = ParseCurArgAsUint16(port));
    error = otThreadSetJoinerUdpPort(mInstance, port);

exit:
    return error;
}
#endif

#if OPENTHREAD_CONFIG_MAC_FILTER_ENABLE
otError Interpreter::ProcessMacFilter(void)
{
    otError error = OT_ERROR_NONE;

    if (IsArgsEmpty())
    {
        ExitNow(PrintMacFilter());
    }

    VerifyOrExit(GetArgsLength() == 1, error = OT_ERROR_INVALID_ARGS);

    if (IsNextArgEqual("addr"))
    {
        ExitNow(error = ProcessMacFilterAddress());
    }

    if (IsNextArgEqual("rss"))
    {
        ExitNow(error = ProcessMacFilterRss());
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

void Interpreter::PrintMacFilter(void)
{
    otMacFilterEntry       entry;
    otMacFilterIterator    iterator = OT_MAC_FILTER_ITERATOR_INIT;
    otMacFilterAddressMode mode     = otLinkFilterGetAddressMode(mInstance);

    if (mode == OT_MAC_FILTER_ADDRESS_MODE_DISABLED)
    {
        OutputLine("Address Mode: Disabled");
    }
    else if (mode == OT_MAC_FILTER_ADDRESS_MODE_ALLOWLIST)
    {
        OutputLine("Address Mode: Allowlist");
    }
    else if (mode == OT_MAC_FILTER_ADDRESS_MODE_DENYLIST)
    {
        OutputLine("Address Mode: Denylist");
    }

    while (otLinkFilterGetNextAddress(mInstance, &iterator, &entry) == OT_ERROR_NONE)
    {
        OutputBytes(entry.mExtAddress.m8, OT_EXT_ADDRESS_SIZE);

        if (entry.mRssIn != OT_MAC_FILTER_FIXED_RSS_DISABLED)
        {
            OutputFormat(" : rss %d (lqi %d)", entry.mRssIn, otLinkConvertRssToLinkQuality(mInstance, entry.mRssIn));
        }

        OutputLine("");
    }

    iterator = OT_MAC_FILTER_ITERATOR_INIT;
    OutputLine("RssIn List:");

    while (otLinkFilterGetNextRssIn(mInstance, &iterator, &entry) == OT_ERROR_NONE)
    {
        uint8_t i = 0;

        for (; i < OT_EXT_ADDRESS_SIZE; i++)
        {
            if (entry.mExtAddress.m8[i] != 0xff)
            {
                break;
            }
        }

        if (i == OT_EXT_ADDRESS_SIZE)
        {
            OutputLine("Default rss : %d (lqi %d)", entry.mRssIn,
                       otLinkConvertRssToLinkQuality(mInstance, entry.mRssIn));
        }
        else
        {
            OutputBytes(entry.mExtAddress.m8, OT_EXT_ADDRESS_SIZE);
            OutputLine(" : rss %d (lqi %d)", entry.mRssIn, otLinkConvertRssToLinkQuality(mInstance, entry.mRssIn));
        }
    }
}

otError Interpreter::ProcessMacFilterAddress(void)
{
    otError error = OT_ERROR_NONE;

    if (IsArgsEmpty())
    {
        otMacFilterAddressMode mode     = otLinkFilterGetAddressMode(mInstance);
        otMacFilterIterator    iterator = OT_MAC_FILTER_ITERATOR_INIT;
        otMacFilterEntry       entry;

        if (mode == OT_MAC_FILTER_ADDRESS_MODE_DISABLED)
        {
            OutputLine("Disabled");
        }
        else if (mode == OT_MAC_FILTER_ADDRESS_MODE_ALLOWLIST)
        {
            OutputLine("Allowlist");
        }
        else if (mode == OT_MAC_FILTER_ADDRESS_MODE_DENYLIST)
        {
            OutputLine("Denylist");
        }

        while (otLinkFilterGetNextAddress(mInstance, &iterator, &entry) == OT_ERROR_NONE)
        {
            OutputBytes(entry.mExtAddress.m8, OT_EXT_ADDRESS_SIZE);

            if (entry.mRssIn != OT_MAC_FILTER_FIXED_RSS_DISABLED)
            {
                OutputFormat(" : rss %d (lqi %d)", entry.mRssIn,
                             otLinkConvertRssToLinkQuality(mInstance, entry.mRssIn));
            }

            OutputLine("");
        }

        ExitNow();
    }

    if (IsNextArgEqual("disable"))
    {
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        ExitNow(otLinkFilterSetAddressMode(mInstance, OT_MAC_FILTER_ADDRESS_MODE_DISABLED));
    }

    if (IsNextArgEqual("allowlist"))
    {
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        ExitNow(otLinkFilterSetAddressMode(mInstance, OT_MAC_FILTER_ADDRESS_MODE_ALLOWLIST));
    }

    if (IsNextArgEqual("denylist"))
    {
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        ExitNow(otLinkFilterSetAddressMode(mInstance, OT_MAC_FILTER_ADDRESS_MODE_DENYLIST));
    }

    if (IsNextArgEqual("add"))
    {
        otExtAddress extAddr;
        bool         hasRss = false;
        int8_t       rss;

        SuccessOrExit(error = ParseCurArgAsFixedSizeHexString(extAddr.m8));

        if (!IsArgsEmpty())
        {
            SuccessOrExit(error = ParseCurArgAsInt8(rss));
            VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
            hasRss = true;
        }

        error = otLinkFilterAddAddress(mInstance, &extAddr);
        VerifyOrExit(error == OT_ERROR_NONE || error == OT_ERROR_ALREADY, OT_NOOP);

        if (hasRss)
        {
            error = otLinkFilterAddRssIn(mInstance, &extAddr, rss);
        }

        ExitNow();
    }

    if (IsNextArgEqual("remove"))
    {
        otExtAddress extAddr;

        SuccessOrExit(error = ParseCurArgAsFixedSizeHexString(extAddr.m8));
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        ExitNow(otLinkFilterRemoveAddress(mInstance, &extAddr));
    }

    if (IsNextArgEqual("clear"))
    {
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        ExitNow(otLinkFilterClearAddresses(mInstance));
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

otError Interpreter::ProcessMacFilterRss(void)
{
    otError error = OT_ERROR_NONE;

    if (IsArgsEmpty())
    {
        otMacFilterIterator iterator = OT_MAC_FILTER_ITERATOR_INIT;
        otMacFilterEntry    entry;

        while (otLinkFilterGetNextRssIn(mInstance, &iterator, &entry) == OT_ERROR_NONE)
        {
            uint8_t i = 0;

            for (; i < OT_EXT_ADDRESS_SIZE; i++)
            {
                if (entry.mExtAddress.m8[i] != 0xff)
                {
                    break;
                }
            }

            if (i == OT_EXT_ADDRESS_SIZE)
            {
                OutputLine("Default rss: %d (lqi %d)", entry.mRssIn,
                           otLinkConvertRssToLinkQuality(mInstance, entry.mRssIn));
            }
            else
            {
                OutputBytes(entry.mExtAddress.m8, OT_EXT_ADDRESS_SIZE);
                OutputLine(" : rss %d (lqi %d)", entry.mRssIn, otLinkConvertRssToLinkQuality(mInstance, entry.mRssIn));
            }
        }

        ExitNow();
    }

    if (IsNextArgEqual("add-lqi"))
    {
        otExtAddress extAddr;
        uint8_t      linkQuality;
        int8_t       rss;
        bool         defaultRssIn = false;

        if (IsNextArgEqual("*"))
        {
            defaultRssIn = true;
        }
        else
        {
            SuccessOrExit(error = ParseCurArgAsFixedSizeHexString(extAddr.m8));
        }

        SuccessOrExit(error = ParseCurArgAsUint8(linkQuality));
        VerifyOrExit(linkQuality <= 3, error = OT_ERROR_INVALID_ARGS);
        rss = otLinkConvertLinkQualityToRss(mInstance, linkQuality);
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

        if (defaultRssIn)
        {
            otLinkFilterSetDefaultRssIn(mInstance, rss);
        }
        else
        {
            error = otLinkFilterAddRssIn(mInstance, &extAddr, rss);
        }

        ExitNow();
    }

    if (IsNextArgEqual("add"))
    {
        otExtAddress extAddr;
        int8_t       rss;
        bool         defaultRssIn = false;

        if (IsNextArgEqual("*"))
        {
            defaultRssIn = true;
        }
        else
        {
            SuccessOrExit(error = ParseCurArgAsFixedSizeHexString(extAddr.m8));
        }

        SuccessOrExit(error = ParseCurArgAsInt8(rss));
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);

        if (defaultRssIn)
        {
            otLinkFilterSetDefaultRssIn(mInstance, rss);
        }
        else
        {
            error = otLinkFilterAddRssIn(mInstance, &extAddr, rss);
        }

        ExitNow();
    }

    if (IsNextArgEqual("remove"))
    {
        otExtAddress extAddr;

        VerifyOrExit(GetArgsLength() == 1, error = OT_ERROR_INVALID_ARGS);

        if (IsNextArgEqual("*"))
        {
            otLinkFilterClearDefaultRssIn(mInstance);
        }
        else
        {
            SuccessOrExit(error = ParseCurArgAsFixedSizeHexString(extAddr.m8));
            otLinkFilterRemoveRssIn(mInstance, &extAddr);
        }

        ExitNow();
    }

    if (IsNextArgEqual("clear"))
    {
        ExitNow(otLinkFilterClearAllRssIn(mInstance));
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

#endif // OPENTHREAD_CONFIG_MAC_FILTER_ENABLE

otError Interpreter::ProcessMac(void)
{
    otError error = OT_ERROR_NONE;

    if (IsNextArgEqual("retries"))
    {
        ExitNow(error = ProcessMacRetries());
    }

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

otError Interpreter::ProcessMacRetries(void)
{
    otError error = OT_ERROR_NONE;

    if (IsNextArgEqual("direct"))
    {
        uint8_t retries;

        if (IsArgsEmpty())
        {
            ExitNow(OutputLine("%d", otLinkGetMaxFrameRetriesDirect(mInstance)));
        }

        SuccessOrExit(error = ParseCurArgAsUint8(retries));
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        ExitNow(otLinkSetMaxFrameRetriesDirect(mInstance, retries));
    }

#if OPENTHREAD_FTD
    if (IsNextArgEqual("indirect"))
    {
        uint8_t retries;

        if (IsArgsEmpty())
        {
            ExitNow(OutputLine("%d", otLinkGetMaxFrameRetriesIndirect(mInstance)));
        }

        SuccessOrExit(error = ParseCurArgAsUint8(retries));
        VerifyOrExit(IsArgsEmpty(), error = OT_ERROR_INVALID_ARGS);
        otLinkSetMaxFrameRetriesIndirect(mInstance, retries);
    }
#endif

    error = OT_ERROR_INVALID_COMMAND;

exit:
    return error;
}

#if OPENTHREAD_CONFIG_DIAG_ENABLE
otError Interpreter::ProcessDiag(void)
{
    otError error;
    char    output[OPENTHREAD_CONFIG_DIAG_OUTPUT_BUFFER_SIZE];

    // all diagnostics related features are processed within diagnostics module
    output[0]                  = '\0';
    output[sizeof(output) - 1] = '\0';

    error = otDiagProcessCmd(mInstance, GetArgsLength(), GetArgs(), output, sizeof(output) - 1);
    Output(output, static_cast<uint16_t>(strlen(output)));

    return error;
}
#endif

const Interpreter::Command *Interpreter::FindCommand(const char *aName) const
{
    const Command *rval  = nullptr;
    uint16_t       left  = 0;
    uint16_t       right = OT_ARRAY_LENGTH(sCommands);

    while (left < right)
    {
        uint16_t middle  = (left + right) / 2;
        int      compare = strcmp(aName, sCommands[middle].mName);

        if (compare == 0)
        {
            rval = &sCommands[middle];
            break;
        }
        else if (compare > 0)
        {
            left = middle + 1;
        }
        else
        {
            right = middle;
        }
    }

    return rval;
}

void Interpreter::ProcessLine(char *aBuf, uint16_t aBufLength)
{
    char *argsArray[kMaxArgs];
    const Command *                           command;

    VerifyOrExit(aBuf != nullptr && StringLength(aBuf, aBufLength + 1) <= aBufLength, OT_NOOP);

    VerifyOrExit(ParseCmd(aBuf, argsArray) == OT_ERROR_NONE,
                 OutputLine("Error: too many args (max %d)", kMaxArgs));
    VerifyOrExit(!IsArgsEmpty(), OutputLine("Error: no given command."));

#if OPENTHREAD_CONFIG_DIAG_ENABLE
    VerifyOrExit(!otDiagIsEnabled(mInstance) || IsNextArgEqual("diag"),
                 OutputLine("under diagnostics mode, execute 'diag stop' before running any other commands."));
#endif

    command = FindCommand(GetCurArg());

    if (command != nullptr)
    {
        AdvanceArg();
        OutputResult((this->*command->mCommand)());
        ExitNow();
    }

    // Check user defined commands if built-in command has not been found
    for (uint8_t i = 0; i < mUserCommandsLength; i++)
    {
        if (IsNextArgEqual(mUserCommands[i].mName))
        {
            AdvanceArg();
            mUserCommands[i].mCommand(GetArgsLength(), GetArgs());
            ExitNow();
        }
    }

    OutputResult(OT_ERROR_INVALID_COMMAND);

exit:
    return;
}

#if OPENTHREAD_FTD || OPENTHREAD_CONFIG_TMF_NETWORK_DIAG_MTD_ENABLE
otError Interpreter::ProcessNetworkDiagnostic(void)
{
    otError      error = OT_ERROR_NONE;
    otIp6Address address;
    uint8_t      tlvTypes[OT_NETWORK_DIAGNOSTIC_TYPELIST_MAX_ENTRIES];
    uint8_t      count = 0;
    enum
    {
        kGet,
        kReset,
    } operation;

    if (IsNextArgEqual("get"))
    {
        operation = kGet;
    }
    else if (IsNextArgEqual("reset"))
    {
        operation = kReset;
    }
    else
    {
        ExitNow(error = OT_ERROR_INVALID_COMMAND);
    }

    SuccessOrExit(error = ParseCurArgAsIp6Address(address));

    while (!IsArgsEmpty())
    {
        VerifyOrExit(count < OT_ARRAY_LENGTH(tlvTypes), error = OT_ERROR_INVALID_ARGS);
        SuccessOrExit(error = ParseCurArgAsUint8(tlvTypes[count]));
        count++;
    }

    switch (operation)
    {
    case kGet:
        IgnoreError(otThreadSendDiagnosticGet(mInstance, &address, tlvTypes, count));
        break;

    case kReset:
        IgnoreError(otThreadSendDiagnosticReset(mInstance, &address, tlvTypes, count));
        break;
    }

exit:
    return error;
}

void Interpreter::HandleDiagnosticGetResponse(otMessage *aMessage, const otMessageInfo *aMessageInfo, void *aContext)
{
    static_cast<Interpreter *>(aContext)->HandleDiagnosticGetResponse(
        *aMessage, *static_cast<const Ip6::MessageInfo *>(aMessageInfo));
}

void Interpreter::HandleDiagnosticGetResponse(const otMessage &aMessage, const Ip6::MessageInfo &)
{
    uint8_t               buf[16];
    uint16_t              bytesToPrint;
    uint16_t              bytesPrinted = 0;
    uint16_t              length       = otMessageGetLength(&aMessage) - otMessageGetOffset(&aMessage);
    otNetworkDiagTlv      diagTlv;
    otNetworkDiagIterator iterator = OT_NETWORK_DIAGNOSTIC_ITERATOR_INIT;
    otError               error    = OT_ERROR_NONE;

    OutputFormat("DIAG_GET.rsp/ans: ");

    while (length > 0)
    {
        bytesToPrint = (length < sizeof(buf)) ? length : sizeof(buf);
        otMessageRead(&aMessage, otMessageGetOffset(&aMessage) + bytesPrinted, buf, bytesToPrint);

        OutputBytes(buf, static_cast<uint8_t>(bytesToPrint));

        length -= bytesToPrint;
        bytesPrinted += bytesToPrint;
    }

    OutputLine("");

    // Output Network Diagnostic TLV values in standard YAML format.
    while ((error = otThreadGetNextDiagnosticTlv(&aMessage, &iterator, &diagTlv)) == OT_ERROR_NONE)
    {
        uint16_t column = 0;
        switch (diagTlv.mType)
        {
        case OT_NETWORK_DIAGNOSTIC_TLV_EXT_ADDRESS:
            OutputFormat("Ext Address: '");
            OutputBytes(diagTlv.mData.mExtAddress.m8, sizeof(diagTlv.mData.mExtAddress.m8));
            OutputLine("'");
            break;
        case OT_NETWORK_DIAGNOSTIC_TLV_SHORT_ADDRESS:
            OutputLine("Rloc16: 0x%04x", diagTlv.mData.mAddr16);
            break;
        case OT_NETWORK_DIAGNOSTIC_TLV_MODE:
            OutputLine("Mode:");
            OutputMode(diagTlv.mData.mMode, column + kIndentationSize);
            break;
        case OT_NETWORK_DIAGNOSTIC_TLV_TIMEOUT:
            OutputLine("Timeout: %u", diagTlv.mData.mTimeout);
            break;
        case OT_NETWORK_DIAGNOSTIC_TLV_CONNECTIVITY:
            OutputLine("Connectivity:");
            OutputConnectivity(diagTlv.mData.mConnectivity, column + kIndentationSize);
            break;
        case OT_NETWORK_DIAGNOSTIC_TLV_ROUTE:
            OutputLine("Route:");
            OutputRoute(diagTlv.mData.mRoute, column + kIndentationSize);
            break;
        case OT_NETWORK_DIAGNOSTIC_TLV_LEADER_DATA:
            OutputLine("Leader Data:");
            OutputLeaderData(diagTlv.mData.mLeaderData, column + kIndentationSize);
            break;
        case OT_NETWORK_DIAGNOSTIC_TLV_NETWORK_DATA:
            OutputFormat("Network Data: '");
            OutputBytes(diagTlv.mData.mNetworkData.m8, diagTlv.mData.mNetworkData.mCount);
            OutputLine("'");
            break;
        case OT_NETWORK_DIAGNOSTIC_TLV_IP6_ADDR_LIST:
            OutputLine("IP6 Address List:");
            for (uint16_t i = 0; i < diagTlv.mData.mIp6AddrList.mCount; ++i)
            {
                OutputSpaces(column + kIndentationSize);
                OutputFormat("- ");
                OutputIp6Address(diagTlv.mData.mIp6AddrList.mList[i]);
                OutputLine("");
            }
            break;
        case OT_NETWORK_DIAGNOSTIC_TLV_MAC_COUNTERS:
            OutputLine("MAC Counters:");
            OutputNetworkDiagMacCounters(diagTlv.mData.mMacCounters, column + kIndentationSize);
            break;
        case OT_NETWORK_DIAGNOSTIC_TLV_BATTERY_LEVEL:
            OutputLine("Battery Level: %u%%", diagTlv.mData.mBatteryLevel);
            break;
        case OT_NETWORK_DIAGNOSTIC_TLV_SUPPLY_VOLTAGE:
            OutputLine("Supply Voltage: %umV", diagTlv.mData.mSupplyVoltage);
            break;
        case OT_NETWORK_DIAGNOSTIC_TLV_CHILD_TABLE:
            OutputLine("Child Table:");
            for (uint16_t i = 0; i < diagTlv.mData.mChildTable.mCount; ++i)
            {
                OutputSpaces(column + kIndentationSize);
                OutputFormat("- ");
                OutputChildTableEntry(diagTlv.mData.mChildTable.mTable[i], column + kIndentationSize + 2);
            }
            break;
        case OT_NETWORK_DIAGNOSTIC_TLV_CHANNEL_PAGES:
            OutputFormat("Channel Pages: '");
            OutputBytes(diagTlv.mData.mChannelPages.m8, diagTlv.mData.mChannelPages.mCount);
            OutputLine("'");
            break;
        case OT_NETWORK_DIAGNOSTIC_TLV_MAX_CHILD_TIMEOUT:
            OutputLine("Max Child Timeout: %u", diagTlv.mData.mMaxChildTimeout);
            break;
        }
    }

    OutputResult(error == OT_ERROR_NOT_FOUND ? OT_ERROR_NONE : error);
}

void Interpreter::OutputSpaces(uint16_t aCount)
{
    static const uint16_t kSpaceStrLen = 16;
    char                  spaceStr[kSpaceStrLen + 1];

    memset(spaceStr, ' ', kSpaceStrLen);
    spaceStr[kSpaceStrLen] = '\0';

    for (uint16_t i = 0; i < aCount; i += kSpaceStrLen)
    {
        uint16_t idx = (i + kSpaceStrLen <= aCount) ? 0 : (i + kSpaceStrLen - aCount);
        OutputFormat(&spaceStr[idx]);
    }
}

void Interpreter::OutputMode(const otLinkModeConfig &aMode, uint16_t aColumn)
{
    OutputSpaces(aColumn);
    OutputLine("RxOnWhenIdle: %d", aMode.mRxOnWhenIdle);

    OutputSpaces(aColumn);
    OutputLine("SecureDataRequests: %d", aMode.mSecureDataRequests);

    OutputSpaces(aColumn);
    OutputLine("DeviceType: %d", aMode.mDeviceType);

    OutputSpaces(aColumn);
    OutputLine("NetworkData: %d", aMode.mNetworkData);
}

void Interpreter::OutputConnectivity(const otNetworkDiagConnectivity &aConnectivity, uint16_t aColumn)
{
    OutputSpaces(aColumn);
    OutputLine("ParentPriority: %d", aConnectivity.mParentPriority);

    OutputSpaces(aColumn);
    OutputLine("LinkQuality3: %u", aConnectivity.mLinkQuality3);

    OutputSpaces(aColumn);
    OutputLine("LinkQuality2: %u", aConnectivity.mLinkQuality2);

    OutputSpaces(aColumn);
    OutputLine("LinkQuality1: %u", aConnectivity.mLinkQuality1);

    OutputSpaces(aColumn);
    OutputLine("LeaderCost: %u", aConnectivity.mLeaderCost);

    OutputSpaces(aColumn);
    OutputLine("IdSequence: %u", aConnectivity.mIdSequence);

    OutputSpaces(aColumn);
    OutputLine("ActiveRouters: %u", aConnectivity.mActiveRouters);

    OutputSpaces(aColumn);
    OutputLine("SedBufferSize: %u", aConnectivity.mSedBufferSize);

    OutputSpaces(aColumn);
    OutputLine("SedDatagramCount: %u", aConnectivity.mSedDatagramCount);
}

void Interpreter::OutputRoute(const otNetworkDiagRoute &aRoute, uint16_t aColumn)
{
    OutputSpaces(aColumn);
    OutputLine("IdSequence: %u", aRoute.mIdSequence);

    OutputSpaces(aColumn);
    OutputLine("RouteData:");

    aColumn += kIndentationSize;
    for (uint16_t i = 0; i < aRoute.mRouteCount; ++i)
    {
        OutputSpaces(aColumn);
        OutputFormat("- ");

        OutputRouteData(aRoute.mRouteData[i], aColumn + 2);
    }
}

void Interpreter::OutputRouteData(const otNetworkDiagRouteData &aRouteData, uint16_t aColumn)
{
    OutputLine("RouteId: 0x%02x", aRouteData.mRouterId);

    OutputSpaces(aColumn);
    OutputLine("LinkQualityOut: %u", aRouteData.mLinkQualityOut);

    OutputSpaces(aColumn);
    OutputLine("LinkQualityIn: %u", aRouteData.mLinkQualityIn);

    OutputSpaces(aColumn);
    OutputLine("RouteCost: %u", aRouteData.mRouteCost);
}

void Interpreter::OutputLeaderData(const otLeaderData &aLeaderData, uint16_t aColumn)
{
    OutputSpaces(aColumn);
    OutputLine("PartitionId: 0x%08x", aLeaderData.mPartitionId);

    OutputSpaces(aColumn);
    OutputLine("Weighting: %u", aLeaderData.mWeighting);

    OutputSpaces(aColumn);
    OutputLine("DataVersion: %u", aLeaderData.mDataVersion);

    OutputSpaces(aColumn);
    OutputLine("StableDataVersion: %u", aLeaderData.mStableDataVersion);

    OutputSpaces(aColumn);
    OutputLine("LeaderRouterId: 0x%02x", aLeaderData.mLeaderRouterId);
}

void Interpreter::OutputNetworkDiagMacCounters(const otNetworkDiagMacCounters &aMacCounters, uint16_t aColumn)
{
    OutputSpaces(aColumn);
    OutputLine("IfInUnknownProtos: %u", aMacCounters.mIfInUnknownProtos);

    OutputSpaces(aColumn);
    OutputLine("IfInErrors: %u", aMacCounters.mIfInErrors);

    OutputSpaces(aColumn);
    OutputLine("IfOutErrors: %u", aMacCounters.mIfOutErrors);

    OutputSpaces(aColumn);
    OutputLine("IfInUcastPkts: %u", aMacCounters.mIfInUcastPkts);

    OutputSpaces(aColumn);
    OutputLine("IfInBroadcastPkts: %u", aMacCounters.mIfInBroadcastPkts);

    OutputSpaces(aColumn);
    OutputLine("IfInDiscards: %u", aMacCounters.mIfInDiscards);

    OutputSpaces(aColumn);
    OutputLine("IfOutUcastPkts: %u", aMacCounters.mIfOutUcastPkts);

    OutputSpaces(aColumn);
    OutputLine("IfOutBroadcastPkts: %u", aMacCounters.mIfOutBroadcastPkts);

    OutputSpaces(aColumn);
    OutputLine("IfOutDiscards: %u", aMacCounters.mIfOutDiscards);
}

void Interpreter::OutputChildTableEntry(const otNetworkDiagChildEntry &aChildEntry, uint16_t aColumn)
{
    OutputLine("ChildId: 0x%04x", aChildEntry.mChildId);

    OutputSpaces(aColumn);
    OutputLine("Timeout: %u", aChildEntry.mTimeout);

    OutputSpaces(aColumn);
    OutputLine("Mode:");

    OutputMode(aChildEntry.mMode, aColumn + kIndentationSize);
}
#endif // OPENTHREAD_FTD || OPENTHREAD_CONFIG_TMF_NETWORK_DIAG_MTD_ENABLE

void Interpreter::SetUserCommands(const otCliCommand *aCommands, uint8_t aLength)
{
    mUserCommands       = aCommands;
    mUserCommandsLength = aLength;
}

Interpreter &Interpreter::GetOwner(OwnerLocator &aOwnerLocator)
{
#if OPENTHREAD_CONFIG_MULTIPLE_INSTANCE_ENABLE
    Interpreter &interpreter = (aOwnerLocator.GetOwner<Interpreter>());
#else
    OT_UNUSED_VARIABLE(aOwnerLocator);

    Interpreter &interpreter = Interpreter::GetInterpreter();
#endif
    return interpreter;
}

void Interpreter::SignalPingRequest(const Ip6::Address &aPeerAddress,
                                    uint16_t            aPingLength,
                                    uint32_t            aTimestamp,
                                    uint8_t             aHopLimit)
{
    OT_UNUSED_VARIABLE(aPeerAddress);
    OT_UNUSED_VARIABLE(aPingLength);
    OT_UNUSED_VARIABLE(aTimestamp);
    OT_UNUSED_VARIABLE(aHopLimit);

#if OPENTHREAD_CONFIG_OTNS_ENABLE
    mInstance->Get<Utils::Otns>().EmitPingRequest(aPeerAddress, aPingLength, aTimestamp, aHopLimit);
#endif
}

void Interpreter::SignalPingReply(const Ip6::Address &aPeerAddress,
                                  uint16_t            aPingLength,
                                  uint32_t            aTimestamp,
                                  uint8_t             aHopLimit)
{
    OT_UNUSED_VARIABLE(aPeerAddress);
    OT_UNUSED_VARIABLE(aPingLength);
    OT_UNUSED_VARIABLE(aTimestamp);
    OT_UNUSED_VARIABLE(aHopLimit);

#if OPENTHREAD_CONFIG_OTNS_ENABLE
    mInstance->Get<Utils::Otns>().EmitPingReply(aPeerAddress, aPingLength, aTimestamp, aHopLimit);
#endif
}

void Interpreter::HandleDiscoveryRequest(const otThreadDiscoveryRequestInfo &aInfo)
{
    OutputFormat("~ Discovery Request from ");
    OutputBytes(aInfo.mExtAddress.m8, sizeof(aInfo.mExtAddress.m8));
    OutputLine(": version=%u,joiner=%d", aInfo.mVersion, aInfo.mIsJoiner);
}

int Interpreter::OutputFormat(const char *aFormat, ...)
{
    int     rval;
    va_list ap;

    va_start(ap, aFormat);
    rval = OutputFormatV(aFormat, ap);
    va_end(ap);

    return rval;
}

void Interpreter::OutputLine(const char *aFormat, ...)
{
    va_list args;

    va_start(args, aFormat);
    OutputFormatV(aFormat, args);
    va_end(args);

    OutputFormat("\r\n");
}

int Interpreter::OutputFormatV(const char *aFormat, va_list aArguments)
{
    char buf[kMaxLineLength];

    vsnprintf(buf, sizeof(buf), aFormat, aArguments);

    return Output(buf, static_cast<uint16_t>(strlen(buf)));
}

extern "C" void otCliSetUserCommands(const otCliCommand *aUserCommands, uint8_t aLength)
{
    Interpreter::GetInterpreter().SetUserCommands(aUserCommands, aLength);
}

extern "C" void otCliOutputBytes(const uint8_t *aBytes, uint8_t aLength)
{
    Interpreter::GetInterpreter().OutputBytes(aBytes, aLength);
}

extern "C" void otCliOutputFormat(const char *aFmt, ...)
{
    va_list aAp;
    va_start(aAp, aFmt);
    Interpreter::GetInterpreter().OutputFormatV(aFmt, aAp);
    va_end(aAp);
}

extern "C" void otCliOutput(const char *aString, uint16_t aLength)
{
    Interpreter::GetInterpreter().Output(aString, aLength);
}

extern "C" void otCliAppendResult(otError aError)
{
    Interpreter::GetInterpreter().OutputResult(aError);
}

extern "C" void otCliPlatLogv(otLogLevel aLogLevel, otLogRegion aLogRegion, const char *aFormat, va_list aArgs)
{
    OT_UNUSED_VARIABLE(aLogLevel);
    OT_UNUSED_VARIABLE(aLogRegion);

    VerifyOrExit(Interpreter::IsInitialized(), OT_NOOP);

    Interpreter::GetInterpreter().OutputFormatV(aFormat, aArgs);
    Interpreter::GetInterpreter().OutputLine("");
exit:
    return;
}

} // namespace Cli
} // namespace ot

#if OPENTHREAD_CONFIG_LEGACY_ENABLE
OT_TOOL_WEAK void otNcpRegisterLegacyHandlers(const otNcpLegacyHandlers *aHandlers)
{
    OT_UNUSED_VARIABLE(aHandlers);
}

OT_TOOL_WEAK void otNcpHandleDidReceiveNewLegacyUlaPrefix(const uint8_t *aUlaPrefix)
{
    OT_UNUSED_VARIABLE(aUlaPrefix);
}

OT_TOOL_WEAK void otNcpHandleLegacyNodeDidJoin(const otExtAddress *aExtAddr)
{
    OT_UNUSED_VARIABLE(aExtAddr);
}
#endif
