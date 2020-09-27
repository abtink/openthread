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
 *   This file contains definitions for the CLI interpreter.
 */

#ifndef CLI_HPP_
#define CLI_HPP_

#include "openthread-core-config.h"

#include "cli_config.h"

#include <stdarg.h>

#include <openthread/cli.h>
#include <openthread/ip6.h>
#include <openthread/udp.h>

#include "cli/cli_commissioner.hpp"
#include "cli/cli_dataset.hpp"
#include "cli/cli_joiner.hpp"
#include "cli/cli_network_data.hpp"
#include "cli/cli_udp.hpp"

#if OPENTHREAD_CONFIG_COAP_API_ENABLE
#include "cli/cli_coap.hpp"
#endif

#if OPENTHREAD_CONFIG_COAP_SECURE_API_ENABLE
#include "cli/cli_coap_secure.hpp"
#endif

#include "common/code_utils.hpp"
#include "common/instance.hpp"

#include <openthread/dns.h>
#include <openthread/sntp.h>
#include "common/timer.hpp"
#include "net/icmp6.hpp"
#include "utils/parse_cmdline.hpp"

namespace ot {

/**
 * @namespace ot::Cli
 *
 * @brief
 *   This namespace contains definitions for the CLI interpreter.
 *
 */
namespace Cli {

/**
 * This class implements the CLI interpreter.
 *
 */
class Interpreter : protected Utils::CmdLineParser::Args
{
    friend class Coap;
    friend class CoapSecure;
    friend class Commissioner;
    friend class Dataset;
    friend class Joiner;
    friend class NetworkData;
    friend class UdpExample;

public:
    /**
     * Constructor
     *
     * @param[in]  aInstance  The OpenThread instance structure.
     */
    explicit Interpreter(Instance *aInstance);

    /**
     * This method returns a reference to the interpreter object.
     *
     * @returns A reference to the interpreter object.
     *
     */
    static Interpreter &GetInterpreter(void)
    {
        OT_ASSERT(sInterpreter != nullptr);

        return *sInterpreter;
    }

    /**
     * This method returns whether the interpreter is initialized.
     *
     * @returns  Whether the interpreter is initialized.
     *
     */
    static bool IsInitialized(void) { return sInterpreter != nullptr; }

    /**
     * This method interprets a CLI command.
     *
     * @param[in]  aBuf        A pointer to a string.
     * @param[in]  aBufLength  The length of the string in bytes.
     *
     */
    void ProcessLine(char *aBuf, uint16_t aBufLength);

    /**
     * This method parses an ASCII string as a long.
     *
     * @param[in]   aString  A pointer to the ASCII string.
     * @param[out]  aLong    A reference to where the parsed long is placed.
     *
     * @retval OT_ERROR_NONE          Successfully parsed the ASCII string.
     * @retval OT_ERROR_INVALID_ARGS  @p aString is not a valid long integer.
     *
     */
    static otError ParseLong(char *aString, long &aLong);

    /**
     * This method parses an ASCII string as an unsigned long.
     *
     * @param[in]   aString          A pointer to the ASCII string.
     * @param[out]  aUnsignedLong    A reference to where the parsed unsigned long is placed.
     *
     * @retval OT_ERROR_NONE          Successfully parsed the ASCII string.
     * @retval OT_ERROR_INVALID_ARGS  @p aString is not a valid unsigned long integer.
     *
     */
    static otError ParseUnsignedLong(char *aString, unsigned long &aUnsignedLong);

    /**
     * This method converts a hex string to binary.
     *
     * @param[in]   aHex            A pointer to the hex string.
     * @param[out]  aBin            A pointer to where the binary representation is placed.
     * @param[in]   aBinLength      Maximum length of the binary representation.
     * @param[in]   aAllowTruncate  TRUE if @p aBinLength may be less than what is required
     *                              to convert @p aHex to binary representation, FALSE otherwise.
     *
     * @returns  The number of bytes in the binary representation, or -1 if @p aHex is not a valid hex string
     *
     */
    static int Hex2Bin(const char *aHex, uint8_t *aBin, uint16_t aBinLength, bool aAllowTruncate = false);

    /**
     * This method delivers raw characters to the client.
     *
     * @param[in]  aBuf        A pointer to a buffer.
     * @param[in]  aBufLength  Number of bytes in the buffer.
     *
     * @returns The number of bytes placed in the output queue.
     *
     * @retval  -1  Driver is broken.
     *
     */
    int Output(const char *aBuf, uint16_t aBufLength);

    /**
     * Write a number of bytes to the CLI console as a hex string.
     *
     * @param[in]  aBytes   A pointer to data which should be printed.
     * @param[in]  aLength  @p aBytes length.
     */
    void OutputBytes(const uint8_t *aBytes, uint8_t aLength);

    /**
     * This method delivers formatted output to the client.
     *
     * @param[in]  aFormat  A pointer to the format string.
     * @param[in]  ...      A variable list of arguments to format.
     *
     * @returns The number of bytes placed in the output queue.
     *
     * @retval  -1  Driver is broken.
     *
     */
    int OutputFormat(const char *aFormat, ...);

    /**
     * This method delivers formatted output to the client.
     *
     * @param[in]  aFormat      A pointer to the format string.
     * @param[in]  aArguments   A variable list of arguments for format.
     *
     * @returns The number of bytes placed in the output queue.
     *
     */
    int OutputFormatV(const char *aFormat, va_list aArguments);

    /**
     * This method delivers formatted output (to which it also appends newline `\r\n`) to the client.
     *
     * @param[in]  aFormat  A pointer to the format string.
     * @param[in]  ...      A variable list of arguments to format.
     *
     */
    void OutputLine(const char *aFormat, ...);

    /**
     * Write an IPv6 address to the CLI console.
     *
     * @param[in]  aAddress  A reference to the IPv6 address.
     *
     * @returns The number of bytes placed in the output queue.
     *
     * @retval  -1  Driver is broken.
     *
     */
    int OutputIp6Address(const otIp6Address &aAddress);

    /**
     * This method delivers a success or error message the client.
     *
     * If the @p aError is `OT_ERROR_PENDING` nothing will be outputted.
     *
     * @param[in]  aError  The error code.
     *
     */
    void OutputResult(otError aError);

    /**
     * This method sets the user command table.
     *
     * @param[in]  aUserCommands  A pointer to an array with user commands.
     * @param[in]  aLength        @p aUserCommands length.
     *
     */
    void SetUserCommands(const otCliCommand *aCommands, uint8_t aLength);

protected:
    static Interpreter *sInterpreter;

private:
    enum
    {
        kIndentationSize  = 4,
        kMaxArgs          = 32,
        kMaxAutoAddresses = 8,

        kDefaultPingInterval = 1000, // (in mses)
        kDefaultPingLength   = 8,    // (in bytes)
        kDefaultPingCount    = 1,

        kMaxLineLength = OPENTHREAD_CONFIG_CLI_MAX_LINE_LENGTH,
    };

    typedef Utils::CmdLineParser::Args Args;

    struct Command
    {
        const char *mName;
        otError (Interpreter::*mCommand)(void);
    };

    const Command *FindCommand(const char *aName) const;
    otError        ParsePingInterval(const char *aString, uint32_t &aInterval);
    static otError ParseJoinerDiscerner(char *aString, otJoinerDiscerner &aJoinerDiscerner);

    otError ProcessHelp(void);
    otError ProcessCcaThreshold(void);
    otError ProcessBufferInfo(void);
    otError ProcessChannel(void);
#if (OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2)
    otError ProcessBackboneRouter(void);

#if OPENTHREAD_FTD && OPENTHREAD_CONFIG_BACKBONE_ROUTER_ENABLE
    otError ProcessBackboneRouterLocal(void);
#if OPENTHREAD_CONFIG_REFERENCE_DEVICE_ENABLE
    otError ProcessBackboneRouterMgmtMlr(void);
    void    PrintMulticastListenersTable(void);
#endif
#endif

    otError ProcessDomainName(void);

#if OPENTHREAD_CONFIG_DUA_ENABLE
    otError ProcessDua(void);
#endif

#endif // (OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2)

#if OPENTHREAD_FTD
    otError ProcessChild(void);
    otError ProcessChildIp(void);
    otError ProcessChildMax(void);
#endif
    otError ProcessChildTimeout(void);
#if OPENTHREAD_CONFIG_COAP_API_ENABLE
    otError ProcessCoap(void);
#endif
#if OPENTHREAD_CONFIG_COAP_SECURE_API_ENABLE
    otError ProcessCoapSecure(void);
#endif
#if OPENTHREAD_CONFIG_PLATFORM_RADIO_COEX_ENABLE
    otError ProcessCoexMetrics(void);
#endif
#if OPENTHREAD_CONFIG_COMMISSIONER_ENABLE && OPENTHREAD_FTD
    otError ProcessCommissioner(void);
#endif
#if OPENTHREAD_FTD
    otError ProcessContextIdReuseDelay(void);
#endif
    otError ProcessCounters(void);
    otError ProcessCsl(void);
#if OPENTHREAD_FTD
    otError ProcessDelayTimerMin(void);
#endif
#if OPENTHREAD_CONFIG_DIAG_ENABLE
    otError ProcessDiag(void);
#endif
    otError ProcessDiscover(void);
#if OPENTHREAD_CONFIG_DNS_CLIENT_ENABLE
    otError ProcessDns(void);
#endif
#if OPENTHREAD_FTD
    otError ProcessEidCache(void);
#endif
    otError ProcessEui64(void);
#if OPENTHREAD_POSIX
    otError ProcessExit(void);
#endif
    otError ProcessLog(void);
    otError ProcessExtAddress(void);
    otError ProcessExtPanId(void);
    otError ProcessFactoryReset(void);
#if OPENTHREAD_FTD && OPENTHREAD_CONFIG_REFERENCE_DEVICE_ENABLE
    otError ProcessFake(void);
#endif
    otError ProcessIfconfig(void);
    otError ProcessIpAddr(void);
    otError ProcessIpAddrAdd(void);
    otError ProcessIpAddrDel(void);
    otError ProcessIpMulticastAddr(void);
    otError ProcessIpMulticastAddrAdd(void);
    otError ProcessIpMulticastAddrDel(void);
    otError ProcessMulticastPromiscuous(void);
#if OPENTHREAD_CONFIG_JOINER_ENABLE
    otError ProcessJoiner(void);
#endif
#if OPENTHREAD_FTD
    otError ProcessJoinerPort(void);
#endif
    otError ProcessKeySequence(void);
    otError ProcessLeaderData(void);
#if OPENTHREAD_FTD
    otError ProcessLeaderPartitionId(void);
    otError ProcessLeaderWeight(void);
#endif
    otError ProcessMasterKey(void);
#if OPENTHREAD_CONFIG_MLE_LINK_METRICS_ENABLE
    otError ProcessLinkMetrics(void);
    otError ProcessLinkMetricsQuery(void);
#endif
#if OPENTHREAD_CONFIG_TMF_PROXY_MLR_ENABLE
    otError ProcessMlr(void);

#if OPENTHREAD_CONFIG_COMMISSIONER_ENABLE
    otError ProcessMlrReg(void);

    static void HandleMlrRegResult(void *              aContext,
                                   otError             aError,
                                   uint8_t             aMlrStatus,
                                   const otIp6Address *aFailedAddresses,
                                   uint8_t             aFailedAddressNum);
    void        HandleMlrRegResult(otError             aError,
                                   uint8_t             aMlrStatus,
                                   const otIp6Address *aFailedAddresses,
                                   uint8_t             aFailedAddressNum);
#endif
#endif
    otError ProcessMode(void);
#if OPENTHREAD_FTD
    otError ProcessNeighbor(void);
#endif
    otError ProcessNetworkData(void);
    otError ProcessNetworkDataPrefix(void);
    otError ProcessNetworkDataRoute(void);
    otError ProcessNetworkDataService(void);
    void    OutputPrefix(const otBorderRouterConfig &aConfig);
    void    OutputRoute(const otExternalRouteConfig &aConfig);
    void    OutputService(const otServiceConfig &aConfig);

#if OPENTHREAD_CONFIG_PLATFORM_NETIF_ENABLE
    otError ProcessNetif(void);
#endif
    otError ProcessNetstat(void);
    int     OutputSocketAddress(const otSockAddr &aAddress);
#if OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE
    otError ProcessService(void);
    otError ProcessServiceList(void);
#endif
#if OPENTHREAD_FTD || OPENTHREAD_CONFIG_TMF_NETWORK_DIAG_MTD_ENABLE
    otError ProcessNetworkDiagnostic(void);
#endif
#if OPENTHREAD_FTD
    otError ProcessNetworkIdTimeout(void);
#endif
    otError ProcessNetworkName(void);
#if OPENTHREAD_CONFIG_TIME_SYNC_ENABLE
    otError ProcessNetworkTime(void);
#endif
    otError ProcessPanId(void);
    otError ProcessParent(void);
#if OPENTHREAD_FTD
    otError ProcessParentPriority(void);
#endif
    otError ProcessPing(void);
    otError ProcessPollPeriod(void);
    void    SignalPingRequest(const Ip6::Address &aPeerAddress,
                              uint16_t            aPingLength,
                              uint32_t            aTimestamp,
                              uint8_t             aHopLimit);
    void    SignalPingReply(const Ip6::Address &aPeerAddress,
                            uint16_t            aPingLength,
                            uint32_t            aTimestamp,
                            uint8_t             aHopLimit);

#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE
    otError ProcessPrefix(void);
    otError ProcessPrefixAdd(void);
    otError ProcessPrefixRemove(void);
    otError ProcessPrefixList(void);
#endif
    otError ProcessPromiscuous(void);
#if OPENTHREAD_FTD
    otError ProcessPreferRouterId(void);
    otError ProcessPskc(void);
#endif
    otError ProcessRcp(void);
#if OPENTHREAD_FTD
    otError ProcessReleaseRouterId(void);
#endif
    otError ProcessReset(void);
#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE
    otError ProcessRoute(void);
    otError ProcessRouteAdd(void);
    otError ProcessRouteRemove(void);
    otError ProcessRouteList(void);
#endif
#if OPENTHREAD_FTD
    otError ProcessRouter(void);
    otError ProcessRouterDowngradeThreshold(void);
    otError ProcessRouterEligible(void);
    otError ProcessRouterSelectionJitter(void);
    otError ProcessRouterUpgradeThreshold(void);
#endif
    otError ProcessRloc16(void);
    otError ProcessScan(void);
    otError ProcessSingleton(void);
#if OPENTHREAD_CONFIG_SNTP_CLIENT_ENABLE
    otError ProcessSntp(void);
#endif
    otError ProcessState(void);
    otError ProcessThread(void);
    otError ProcessDataset(void);
    otError ProcessTxPower(void);
    otError ProcessUdp(void);
    otError ProcessUnsecurePort(void);
    otError ProcessVersion(void);
#if OPENTHREAD_CONFIG_MAC_FILTER_ENABLE
    otError ProcessMacFilter(void);
    void    PrintMacFilter(void);
    otError ProcessMacFilterAddress(void);
    otError ProcessMacFilterRss(void);
#endif
    otError ProcessMac(void);
    otError ProcessMacRetries(void);

    static void HandleIcmpReceive(void *               aContext,
                                  otMessage *          aMessage,
                                  const otMessageInfo *aMessageInfo,
                                  const otIcmp6Header *aIcmpHeader);
    static void HandlePingTimer(Timer &aTimer);
    static void HandleActiveScanResult(otActiveScanResult *aResult, void *aContext);
    static void HandleEnergyScanResult(otEnergyScanResult *aResult, void *aContext);
    static void HandleLinkPcapReceive(const otRadioFrame *aFrame, bool aIsTx, void *aContext);

#if OPENTHREAD_FTD || OPENTHREAD_CONFIG_TMF_NETWORK_DIAG_MTD_ENABLE
    void        HandleDiagnosticGetResponse(const otMessage &aMessage, const Ip6::MessageInfo &aMessageInfo);
    static void HandleDiagnosticGetResponse(otMessage *aMessage, const otMessageInfo *aMessageInfo, void *aContext);
    void        OutputSpaces(uint16_t aCount);
    void        OutputMode(const otLinkModeConfig &aMode, uint16_t aColumn);
    void        OutputConnectivity(const otNetworkDiagConnectivity &aConnectivity, uint16_t aColumn);
    void        OutputRoute(const otNetworkDiagRoute &aRoute, uint16_t aColumn);
    void        OutputRouteData(const otNetworkDiagRouteData &aRouteData, uint16_t aColumn);
    void        OutputLeaderData(const otLeaderData &aLeaderData, uint16_t aColumn);
    void        OutputNetworkDiagMacCounters(const otNetworkDiagMacCounters &aMacCounters, uint16_t aColumn);
    void        OutputChildTableEntry(const otNetworkDiagChildEntry &aChildEntry, uint16_t aColumn);
#endif

#if OPENTHREAD_CONFIG_DNS_CLIENT_ENABLE
    static void HandleDnsResponse(void *              aContext,
                                  const char *        aHostname,
                                  const otIp6Address *aAddress,
                                  uint32_t            aTtl,
                                  otError             aResult);
#endif

#if OPENTHREAD_CONFIG_SNTP_CLIENT_ENABLE
    static void HandleSntpResponse(void *aContext, uint64_t aTime, otError aResult);
#endif

    void HandleIcmpReceive(otMessage *aMessage, const otMessageInfo *aMessageInfo, const otIcmp6Header *aIcmpHeader);
    void SendPing(void);
    void HandleActiveScanResult(otActiveScanResult *aResult);
    void HandleEnergyScanResult(otEnergyScanResult *aResult);
    void HandleLinkPcapReceive(const otRadioFrame *aFrame, bool aIsTx);
#if OPENTHREAD_CONFIG_DNS_CLIENT_ENABLE
    void HandleDnsResponse(const char *aHostname, const Ip6::Address *aAddress, uint32_t aTtl, otError aResult);
#endif
#if OPENTHREAD_CONFIG_SNTP_CLIENT_ENABLE
    void HandleSntpResponse(uint64_t aTime, otError aResult);
#endif
#if OPENTHREAD_CONFIG_MLE_LINK_METRICS_ENABLE
    static void HandleLinkMetricsReport(const otIp6Address *       aAddress,
                                        const otLinkMetricsValues *aMetricsValues,
                                        void *                     aContext);

    void HandleLinkMetricsReport(const otIp6Address *aAddress, const otLinkMetricsValues *aMetricsValues);
#endif

    static Interpreter &GetOwner(OwnerLocator &aOwnerLocator);

    static void HandleDiscoveryRequest(const otThreadDiscoveryRequestInfo *aInfo, void *aContext)
    {
        static_cast<Interpreter *>(aContext)->HandleDiscoveryRequest(*aInfo);
    }
    void HandleDiscoveryRequest(const otThreadDiscoveryRequestInfo &aInfo);

    constexpr static bool AreSorted(const char *aFirst, const char *aSecond)
    {
        return (*aFirst < *aSecond) ? true : ((*aFirst > *aSecond) ? false : AreSorted(aFirst + 1, aSecond + 1));
    }

    constexpr static bool IsArraySorted(const Interpreter::Command *aList, uint16_t aLength)
    {
        return (aLength <= 1) ? true
                              : AreSorted(aList[0].mName, aList[1].mName) && IsArraySorted(aList + 1, aLength - 1);
    }

    static constexpr Command sCommands[] = {
#if (OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2)
        {"bbr", &Interpreter::ProcessBackboneRouter},
#endif
        {"bufferinfo", &Interpreter::ProcessBufferInfo},
        {"ccathreshold", &Interpreter::ProcessCcaThreshold},
        {"channel", &Interpreter::ProcessChannel},
#if OPENTHREAD_FTD
        {"child", &Interpreter::ProcessChild},
        {"childip", &Interpreter::ProcessChildIp},
        {"childmax", &Interpreter::ProcessChildMax},
#endif
        {"childtimeout", &Interpreter::ProcessChildTimeout},
#if OPENTHREAD_CONFIG_COAP_API_ENABLE
        {"coap", &Interpreter::ProcessCoap},
#endif
#if OPENTHREAD_CONFIG_COAP_SECURE_API_ENABLE
        {"coaps", &Interpreter::ProcessCoapSecure},
#endif
#if OPENTHREAD_CONFIG_PLATFORM_RADIO_COEX_ENABLE
        {"coex", &Interpreter::ProcessCoexMetrics},
#endif
#if OPENTHREAD_CONFIG_COMMISSIONER_ENABLE && OPENTHREAD_FTD
        {"commissioner", &Interpreter::ProcessCommissioner},
#endif
#if OPENTHREAD_FTD
        {"contextreusedelay", &Interpreter::ProcessContextIdReuseDelay},
#endif
        {"counters", &Interpreter::ProcessCounters},
#if OPENTHREAD_CONFIG_MAC_CSL_RECEIVER_ENABLE
        {"csl", &Interpreter::ProcessCsl},
#endif
        {"dataset", &Interpreter::ProcessDataset},
#if OPENTHREAD_FTD
        {"delaytimermin", &Interpreter::ProcessDelayTimerMin},
#endif
#if OPENTHREAD_CONFIG_DIAG_ENABLE
        {"diag", &Interpreter::ProcessDiag},
#endif
        {"discover", &Interpreter::ProcessDiscover},
#if OPENTHREAD_CONFIG_DNS_CLIENT_ENABLE
        {"dns", &Interpreter::ProcessDns},
#endif
#if (OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2)
        {"domainname", &Interpreter::ProcessDomainName},
#endif
#if OPENTHREAD_CONFIG_DUA_ENABLE
        {"dua", &Interpreter::ProcessDua},
#endif
#if OPENTHREAD_FTD
        {"eidcache", &Interpreter::ProcessEidCache},
#endif
        {"eui64", &Interpreter::ProcessEui64},
#if OPENTHREAD_POSIX
        {"exit", &Interpreter::ProcessExit},
#endif
        {"extaddr", &Interpreter::ProcessExtAddress},
        {"extpanid", &Interpreter::ProcessExtPanId},
        {"factoryreset", &Interpreter::ProcessFactoryReset},
#if OPENTHREAD_FTD && OPENTHREAD_CONFIG_REFERENCE_DEVICE_ENABLE
        {"fake", &Interpreter::ProcessFake},
#endif
        {"help", &Interpreter::ProcessHelp},
        {"ifconfig", &Interpreter::ProcessIfconfig},
        {"ipaddr", &Interpreter::ProcessIpAddr},
        {"ipmaddr", &Interpreter::ProcessIpMulticastAddr},
#if OPENTHREAD_CONFIG_JOINER_ENABLE
        {"joiner", &Interpreter::ProcessJoiner},
#endif
#if OPENTHREAD_FTD
        {"joinerport", &Interpreter::ProcessJoinerPort},
#endif
        {"keysequence", &Interpreter::ProcessKeySequence},
        {"leaderdata", &Interpreter::ProcessLeaderData},
#if OPENTHREAD_FTD
        {"leaderpartitionid", &Interpreter::ProcessLeaderPartitionId},
        {"leaderweight", &Interpreter::ProcessLeaderWeight},
#endif
#if OPENTHREAD_CONFIG_MLE_LINK_METRICS_ENABLE
        {"linkmetrics", &Interpreter::ProcessLinkMetrics},
#endif
        {"log", &Interpreter::ProcessLog},
        {"mac", &Interpreter::ProcessMac},
#if OPENTHREAD_CONFIG_MAC_FILTER_ENABLE
        {"macfilter", &Interpreter::ProcessMacFilter},
#endif
        {"masterkey", &Interpreter::ProcessMasterKey},
#if OPENTHREAD_CONFIG_TMF_PROXY_MLR_ENABLE && OPENTHREAD_CONFIG_COMMISSIONER_ENABLE
        {"mlr", &Interpreter::ProcessMlr},
#endif
        {"mode", &Interpreter::ProcessMode},
#if OPENTHREAD_FTD
        {"neighbor", &Interpreter::ProcessNeighbor},
#endif
        {"netdata", &Interpreter::ProcessNetworkData},
#if OPENTHREAD_CONFIG_PLATFORM_NETIF_ENABLE
        {"netif", &Interpreter::ProcessNetif},
#endif
        {"netstat", &Interpreter::ProcessNetstat},
#if OPENTHREAD_FTD || OPENTHREAD_CONFIG_TMF_NETWORK_DIAG_MTD_ENABLE
        {"networkdiagnostic", &Interpreter::ProcessNetworkDiagnostic},
#endif
#if OPENTHREAD_FTD
        {"networkidtimeout", &Interpreter::ProcessNetworkIdTimeout},
#endif
        {"networkname", &Interpreter::ProcessNetworkName},
#if OPENTHREAD_CONFIG_TIME_SYNC_ENABLE
        {"networktime", &Interpreter::ProcessNetworkTime},
#endif
        {"panid", &Interpreter::ProcessPanId},
        {"parent", &Interpreter::ProcessParent},
#if OPENTHREAD_FTD
        {"parentpriority", &Interpreter::ProcessParentPriority},
#endif
        {"ping", &Interpreter::ProcessPing},
        {"pollperiod", &Interpreter::ProcessPollPeriod},
#if OPENTHREAD_FTD
        {"preferrouterid", &Interpreter::ProcessPreferRouterId},
#endif
#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE
        {"prefix", &Interpreter::ProcessPrefix},
#endif
        {"promiscuous", &Interpreter::ProcessPromiscuous},
#if OPENTHREAD_FTD
        {"pskc", &Interpreter::ProcessPskc},
#endif
        {"rcp", &Interpreter::ProcessRcp},
#if OPENTHREAD_FTD
        {"releaserouterid", &Interpreter::ProcessReleaseRouterId},
#endif
        {"reset", &Interpreter::ProcessReset},
        {"rloc16", &Interpreter::ProcessRloc16},
#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE
        {"route", &Interpreter::ProcessRoute},
#endif
#if OPENTHREAD_FTD
        {"router", &Interpreter::ProcessRouter},
        {"routerdowngradethreshold", &Interpreter::ProcessRouterDowngradeThreshold},
        {"routereligible", &Interpreter::ProcessRouterEligible},
        {"routerselectionjitter", &Interpreter::ProcessRouterSelectionJitter},
        {"routerupgradethreshold", &Interpreter::ProcessRouterUpgradeThreshold},
#endif
        {"scan", &Interpreter::ProcessScan},
#if OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE
        {"service", &Interpreter::ProcessService},
#endif
        {"singleton", &Interpreter::ProcessSingleton},
#if OPENTHREAD_CONFIG_SNTP_CLIENT_ENABLE
        {"sntp", &Interpreter::ProcessSntp},
#endif
        {"state", &Interpreter::ProcessState},
        {"thread", &Interpreter::ProcessThread},
        {"txpower", &Interpreter::ProcessTxPower},
        {"udp", &Interpreter::ProcessUdp},
        {"unsecureport", &Interpreter::ProcessUnsecurePort},
        {"version", &Interpreter::ProcessVersion},
    };

    const otCliCommand *mUserCommands;
    uint8_t             mUserCommandsLength;
    uint16_t            mPingLength;
    uint16_t            mPingCount;
    uint32_t            mPingInterval;
    uint8_t             mPingHopLimit;
    bool                mPingAllowZeroHopLimit;
    uint16_t            mPingIdentifier;
    otIp6Address        mPingDestAddress;
    TimerMilli          mPingTimer;
    otIcmp6Handler      mIcmpHandler;
#if OPENTHREAD_CONFIG_DNS_CLIENT_ENABLE
    bool mResolvingInProgress;
    char mResolvingHostname[OT_DNS_MAX_HOSTNAME_LENGTH];
#endif

#if OPENTHREAD_CONFIG_SNTP_CLIENT_ENABLE
    bool mSntpQueryingInProgress;
#endif

    Dataset     mDataset;
    NetworkData mNetworkData;
    UdpExample  mUdp;

#if OPENTHREAD_CONFIG_COAP_API_ENABLE
    Coap mCoap;
#endif

#if OPENTHREAD_CONFIG_COAP_SECURE_API_ENABLE
    CoapSecure mCoapSecure;
#endif

#if OPENTHREAD_CONFIG_COMMISSIONER_ENABLE && OPENTHREAD_FTD
    Commissioner mCommissioner;
#endif

#if OPENTHREAD_CONFIG_JOINER_ENABLE
    Joiner mJoiner;
#endif

    Instance *mInstance;
};

} // namespace Cli
} // namespace ot

#endif // CLI_HPP_
