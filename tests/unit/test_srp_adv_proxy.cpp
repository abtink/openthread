/*
 *  Copyright (c) 2023, The OpenThread Authors.
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

#include <openthread/config.h>

#include "test_platform.h"
#include "test_util.hpp"

#include <openthread/dataset_ftd.h>
#include <openthread/srp_client.h>
#include <openthread/srp_server.h>
#include <openthread/thread.h>

#include "common/arg_macros.hpp"
#include "common/array.hpp"
#include "common/instance.hpp"
#include "common/string.hpp"
#include "common/time.hpp"

#if OPENTHREAD_CONFIG_SRP_SERVER_ENABLE && OPENTHREAD_CONFIG_SRP_CLIENT_ENABLE &&                   \
    OPENTHREAD_CONFIG_SRP_SERVER_ADVERTISING_PROXY_ENABLE && !OPENTHREAD_CONFIG_TIME_SYNC_ENABLE && \
    !OPENTHREAD_PLATFORM_POSIX
#define ENABLE_ADV_PROXY_TEST 1
#else
#define ENABLE_ADV_PROXY_TEST 0
#endif

#if ENABLE_ADV_PROXY_TEST

using namespace ot;

// Logs a message and adds current time (sNow) as "<hours>:<min>:<secs>.<msec>"
#define Log(...)                                                                                          \
    printf("%02u:%02u:%02u.%03u " OT_FIRST_ARG(__VA_ARGS__) "\n", (sNow / 36000000), (sNow / 60000) % 60, \
           (sNow / 1000) % 60, sNow % 1000 OT_REST_ARGS(__VA_ARGS__))

static constexpr uint16_t kMaxRaSize = 800;

static ot::Instance *sInstance;

static uint32_t sNow = 0;
static uint32_t sAlarmTime;
static bool     sAlarmOn = false;

static otRadioFrame sRadioTxFrame;
static uint8_t      sRadioTxFramePsdu[OT_RADIO_FRAME_MAX_SIZE];
static bool         sRadioTxOngoing = false;

//----------------------------------------------------------------------------------------------------------------------
// Function prototypes

void ProcessRadioTxAndTasklets(void);
void AdvanceTime(uint32_t aDuration);

//----------------------------------------------------------------------------------------------------------------------
// `otPlatRadio`

extern "C" {

otRadioCaps otPlatRadioGetCaps(otInstance *) { return OT_RADIO_CAPS_ACK_TIMEOUT | OT_RADIO_CAPS_CSMA_BACKOFF; }

otError otPlatRadioTransmit(otInstance *, otRadioFrame *)
{
    sRadioTxOngoing = true;

    return OT_ERROR_NONE;
}

otRadioFrame *otPlatRadioGetTransmitBuffer(otInstance *) { return &sRadioTxFrame; }

//----------------------------------------------------------------------------------------------------------------------
// `otPlatAlarm`

void otPlatAlarmMilliStop(otInstance *) { sAlarmOn = false; }

void otPlatAlarmMilliStartAt(otInstance *, uint32_t aT0, uint32_t aDt)
{
    sAlarmOn   = true;
    sAlarmTime = aT0 + aDt;
}

uint32_t otPlatAlarmMilliGetNow(void) { return sNow; }

//----------------------------------------------------------------------------------------------------------------------
// `otPlatDnssd`

static constexpr uint16_t kDnssdArraySize = 128;

struct DnssdRequest
{
    DnssdRequest(void) = default;

    DnssdRequest(otPlatDnssdRequestId aId, otPlatDnssdRegisterCallback aCallback)
        : mId(aId)
        , mCallback(aCallback)
    {
    }

    otPlatDnssdRequestId        mId;
    otPlatDnssdRegisterCallback mCallback;
};

static Array<DnssdRequest, kDnssdArraySize> sDnssdRegHostRequests;
static Array<DnssdRequest, kDnssdArraySize> sDnssdUnregHostRequests;
static Array<DnssdRequest, kDnssdArraySize> sDnssdRegServiceRequests;
static Array<DnssdRequest, kDnssdArraySize> sDnssdUnregServiceRequests;

static bool             sDnssdShouldCheckWithClient = true;
static Error            sDnssdCallbackError         = kErrorPending;
static otPlatDnssdState sDnssdState                 = OT_PLAT_DNSSD_READY;

otPlatDnssdState otPlatDnssdGetState(otInstance *aInstance)
{
    OT_UNUSED_VARIABLE(aInstance);

    Log("otPlatDnssdGetState()");

    return sDnssdState;
}

void otPlatDnssdRegisterService(otInstance                 *aInstance,
                                const otPlatDnssdService   *aService,
                                otPlatDnssdRequestId        aRequestId,
                                otPlatDnssdRegisterCallback aCallback)
{
    Log("otPlatDnssdRegisterService(aRequestId: %lu)", ToUlong(aRequestId));
    Log("   hostName       : %s", aService->mHostName);
    Log("   serviceInstance: %s", aService->mServiceInstance);
    Log("   serviceType    : %s", aService->mServiceType);
    Log("   num sub-types  : %u", aService->mSubTypeLabelsLength);

    for (uint16_t index = 0; index < aService->mSubTypeLabelsLength; index++)
    {
        Log("   sub-type %-4u  : %s", index, aService->mSubTypeLabels[index]);
    }

    Log("   TXT data len   : %u", aService->mTxtDataLength);
    Log("   port           : %u", aService->mPort);
    Log("   priority       : %u", aService->mPriority);
    Log("   weight         : %u", aService->mWeight);
    Log("   TTL            : %u", aService->mTtl);

    VerifyOrQuit(aInstance == sInstance);

    if (sDnssdShouldCheckWithClient)
    {
        Srp::Client &srpClient = AsCoreType(aInstance).Get<Srp::Client>();
        bool         didFind   = false;

        VerifyOrQuit(StringMatch(srpClient.GetHostInfo().GetName(), aService->mHostName));

        didFind = false;

        for (const Srp::Client::Service &service : srpClient.GetServices())
        {
            if (StringMatch(service.GetInstanceName(), aService->mServiceInstance))
            {
                didFind = true;
                VerifyOrQuit(StringMatch(service.GetName(), aService->mServiceType));
                VerifyOrQuit(service.GetPort() == aService->mPort);
                VerifyOrQuit(service.GetWeight() == aService->mWeight);
                VerifyOrQuit(service.GetPriority() == aService->mPriority);
                VerifyOrQuit(service.HasSubType() == (aService->mSubTypeLabelsLength != 0));
            }
        }

        VerifyOrQuit(didFind);
    }

    SuccessOrQuit(sDnssdRegServiceRequests.PushBack(DnssdRequest(aRequestId, aCallback)));

    if ((sDnssdCallbackError != kErrorPending) && (aCallback != nullptr))
    {
        aCallback(aInstance, aRequestId, sDnssdCallbackError);
    }
}

void otPlatDnssdUnregisterService(otInstance                 *aInstance,
                                  const otPlatDnssdService   *aService,
                                  otPlatDnssdRequestId        aRequestId,
                                  otPlatDnssdRegisterCallback aCallback)
{
    Log("otPlatDnssdUnregisterService(aRequestId: %lu)", ToUlong(aRequestId));
    Log("   hostName       : %s", aService->mHostName);
    Log("   serviceInstance: %s", aService->mServiceInstance);
    Log("   serviceName    : %s", aService->mServiceType);

    VerifyOrQuit(aInstance == sInstance);

    if (sDnssdShouldCheckWithClient)
    {
        // Validate the received service info matches one of the services
        // on SRP client.

        Srp::Client &srpClient = AsCoreType(aInstance).Get<Srp::Client>();
        bool         didFind   = false;

        VerifyOrQuit(StringMatch(srpClient.GetHostInfo().GetName(), aService->mHostName));

        for (const Srp::Client::Service &service : srpClient.GetServices())
        {
            if (StringMatch(service.GetInstanceName(), aService->mServiceInstance))
            {
                didFind = true;
                VerifyOrQuit(StringMatch(service.GetName(), aService->mServiceType));
            }
        }

        VerifyOrQuit(didFind);
    }

    SuccessOrQuit(sDnssdUnregServiceRequests.PushBack(DnssdRequest(aRequestId, aCallback)));

    if ((sDnssdCallbackError != kErrorPending) && (aCallback != nullptr))
    {
        aCallback(aInstance, aRequestId, sDnssdCallbackError);
    }
}

void otPlatDnssdRegisterHost(otInstance                 *aInstance,
                             const otPlatDnssdHost      *aHost,
                             otPlatDnssdRequestId        aRequestId,
                             otPlatDnssdRegisterCallback aCallback)
{
    Log("otPlatDnssdRegisterHost(aRequestId: %lu)", ToUlong(aRequestId));
    Log("   hostName       : %s", aHost->mHostName);
    Log("   numAddresses   : %u", aHost->mNumAddresses);

    for (uint16_t index = 0; index < aHost->mNumAddresses; index++)
    {
        Log("   Address %-4u   : %s", index, AsCoreType(&aHost->mAddresses[index]).ToString().AsCString());
    }

    Log("   TTL            : %u", aHost->mTtl);

    VerifyOrQuit(aInstance == aInstance);

    if (sDnssdShouldCheckWithClient)
    {
        VerifyOrQuit(StringMatch(AsCoreType(aInstance).Get<Srp::Client>().GetHostInfo().GetName(), aHost->mHostName));
    }

    SuccessOrQuit(sDnssdRegHostRequests.PushBack(DnssdRequest(aRequestId, aCallback)));

    if ((sDnssdCallbackError != kErrorPending) && (aCallback != nullptr))
    {
        aCallback(aInstance, aRequestId, sDnssdCallbackError);
    }
}

void otPlatDnssdUnregisterHost(otInstance                 *aInstance,
                               const otPlatDnssdHost      *aHost,
                               otPlatDnssdRequestId        aRequestId,
                               otPlatDnssdRegisterCallback aCallback)
{
    Log("otPlatDnssdUnregisterHost(aRequestId: %lu)", ToUlong(aRequestId));
    Log("   hostName       : %s", aHost->mHostName);

    VerifyOrQuit(sInstance == aInstance);

    if (sDnssdShouldCheckWithClient)
    {
        VerifyOrQuit(StringMatch(AsCoreType(aInstance).Get<Srp::Client>().GetHostInfo().GetName(), aHost->mHostName));
    }

    SuccessOrQuit(sDnssdUnregHostRequests.PushBack(DnssdRequest(aRequestId, aCallback)));

    if ((sDnssdCallbackError != kErrorPending) && (aCallback != nullptr))
    {
        aCallback(aInstance, aRequestId, sDnssdCallbackError);
    }
}

//----------------------------------------------------------------------------------------------------------------------

Array<void *, 500> sHeapAllocatedPtrs;

#if OPENTHREAD_CONFIG_HEAP_EXTERNAL_ENABLE
void *otPlatCAlloc(size_t aNum, size_t aSize)
{
    void *ptr = calloc(aNum, aSize);

    SuccessOrQuit(sHeapAllocatedPtrs.PushBack(ptr));

    return ptr;
}

void otPlatFree(void *aPtr)
{
    if (aPtr != nullptr)
    {
        void **entry = sHeapAllocatedPtrs.Find(aPtr);

        VerifyOrQuit(entry != nullptr, "A heap allocated item is freed twice");
        sHeapAllocatedPtrs.Remove(*entry);
    }

    free(aPtr);
}
#endif

#if OPENTHREAD_CONFIG_LOG_OUTPUT == OPENTHREAD_CONFIG_LOG_OUTPUT_PLATFORM_DEFINED
void otPlatLog(otLogLevel aLogLevel, otLogRegion aLogRegion, const char *aFormat, ...)
{
    OT_UNUSED_VARIABLE(aLogLevel);
    OT_UNUSED_VARIABLE(aLogRegion);

    va_list args;

    printf("   ");
    va_start(args, aFormat);
    vprintf(aFormat, args);
    va_end(args);
    printf("\n");
}
#endif

} // extern "C"

//---------------------------------------------------------------------------------------------------------------------

void ProcessRadioTxAndTasklets(void)
{
    do
    {
        if (sRadioTxOngoing)
        {
            sRadioTxOngoing = false;
            otPlatRadioTxStarted(sInstance, &sRadioTxFrame);
            otPlatRadioTxDone(sInstance, &sRadioTxFrame, nullptr, OT_ERROR_NONE);
        }

        otTaskletsProcess(sInstance);
    } while (otTaskletsArePending(sInstance));
}

void AdvanceTime(uint32_t aDuration)
{
    uint32_t time = sNow + aDuration;

    Log("AdvanceTime for %u.%03u", aDuration / 1000, aDuration % 1000);

    while (TimeMilli(sAlarmTime) <= TimeMilli(time))
    {
        ProcessRadioTxAndTasklets();
        sNow = sAlarmTime;
        otPlatAlarmMilliFired(sInstance);
    }

    ProcessRadioTxAndTasklets();
    sNow = time;
}

void InitTest(void)
{
    //- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    // Initialize OT instance.

    sNow      = 0;
    sAlarmOn  = false;
    sInstance = static_cast<Instance *>(testInitInstance());

    memset(&sRadioTxFrame, 0, sizeof(sRadioTxFrame));
    sRadioTxFrame.mPsdu = sRadioTxFramePsdu;
    sRadioTxOngoing     = false;

    sDnssdShouldCheckWithClient = true;
    sDnssdState                 = OT_PLAT_DNSSD_READY;
    sDnssdCallbackError         = kErrorPending;
    sDnssdRegHostRequests.Clear();
    sDnssdUnregHostRequests.Clear();
    sDnssdRegServiceRequests.Clear();
    sDnssdUnregServiceRequests.Clear();

    //- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    // Initialize Border Router and start Thread operation.

    otOperationalDataset     dataset;
    otOperationalDatasetTlvs datasetTlvs;

    SuccessOrQuit(otDatasetCreateNewNetwork(sInstance, &dataset));
    SuccessOrQuit(otDatasetConvertToTlvs(&dataset, &datasetTlvs));
    SuccessOrQuit(otDatasetSetActiveTlvs(sInstance, &datasetTlvs));

    SuccessOrQuit(otIp6SetEnabled(sInstance, true));
    SuccessOrQuit(otThreadSetEnabled(sInstance, true));

    //- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    // Ensure device starts as leader.

    AdvanceTime(10000);

    VerifyOrQuit(otThreadGetDeviceRole(sInstance) == OT_DEVICE_ROLE_LEADER);
}

void FinalizeTest(void)
{
    SuccessOrQuit(otIp6SetEnabled(sInstance, false));
    SuccessOrQuit(otThreadSetEnabled(sInstance, false));
    SuccessOrQuit(otInstanceErasePersistentInfo(sInstance));
    testFreeInstance(sInstance);
}

//---------------------------------------------------------------------------------------------------------------------
// SRP Client callback

static bool  sProcessedClientCallback = false;
static Error sLastClientCallbackError = kErrorNone;

void HandleSrpClientCallback(otError                    aError,
                             const otSrpClientHostInfo *aHostInfo,
                             const otSrpClientService  *aServices,
                             const otSrpClientService  *aRemovedServices,
                             void                      *aContext)
{
    Log("HandleSrpClientCallback() called with error %s", ErrorToString(aError));

    VerifyOrQuit(aContext == sInstance);

    sProcessedClientCallback = true;
    sLastClientCallbackError = aError;

    OT_UNUSED_VARIABLE(aHostInfo);
    OT_UNUSED_VARIABLE(aServices);
    OT_UNUSED_VARIABLE(aRemovedServices);
}

static const char kHostName[] = "awesomehost";

void PrepareService1(Srp::Client::Service &aService)
{
    static const char          kServiceName[]   = "_srv._udp";
    static const char          kInstanceLabel[] = "awesome.srv";
    static const char          kSub1[]          = "_sub1";
    static const char          kSub2[]          = "_sub2";
    static const char          kSub3[]          = "_sub3";
    static const char         *kSubLabels[]     = {kSub1, kSub2, kSub3, nullptr};
    static const char          kTxtKey1[]       = "ABCD";
    static const uint8_t       kTxtValue1[]     = {'a', '0'};
    static const char          kTxtKey2[]       = "Z0";
    static const uint8_t       kTxtValue2[]     = {'1', '2', '3'};
    static const char          kTxtKey3[]       = "D";
    static const uint8_t       kTxtValue3[]     = {0};
    static const otDnsTxtEntry kTxtEntries[]    = {
           {kTxtKey1, kTxtValue1, sizeof(kTxtValue1)},
           {kTxtKey2, kTxtValue2, sizeof(kTxtValue2)},
           {kTxtKey3, kTxtValue3, sizeof(kTxtValue3)},
    };

    memset(&aService, 0, sizeof(aService));
    aService.mName          = kServiceName;
    aService.mInstanceName  = kInstanceLabel;
    aService.mSubTypeLabels = kSubLabels;
    aService.mTxtEntries    = kTxtEntries;
    aService.mNumTxtEntries = 3;
    aService.mPort          = 777;
    aService.mWeight        = 1;
    aService.mPriority      = 2;
}

void PrepareService2(Srp::Client::Service &aService)
{
    static const char  kService2Name[]   = "_00112233667882554._matter._udp";
    static const char  kInstance2Label[] = "ABCDEFGHI";
    static const char  kSub4[]           = "_44444444";
    static const char *kSubLabels2[]     = {kSub4, nullptr};

    memset(&aService, 0, sizeof(aService));
    aService.mName          = kService2Name;
    aService.mInstanceName  = kInstance2Label;
    aService.mSubTypeLabels = kSubLabels2;
    aService.mTxtEntries    = nullptr;
    aService.mNumTxtEntries = 0;
    aService.mPort          = 555;
    aService.mWeight        = 0;
    aService.mPriority      = 3;
}

//----------------------------------------------------------------------------------------------------------------------

typedef Dnssd::RequestId      RequestId;
typedef Dnssd::RequestIdRange RequestIdRange;

void ValidateRequestIdRange(const RequestIdRange &aIdRange, RequestId aStart, RequestId aEnd)
{
    RequestId maxId         = NumericLimits<RequestId>::kMax;
    bool      shouldContain = false;

    VerifyOrQuit(!aIdRange.IsEmpty());

    for (RequestId id = aStart - 5; id != aEnd + 6; id++)
    {
        // `idRange` should contain IDs within range `[aStart, aEnd]`

        if (id == aStart)
        {
            shouldContain = true;
        }

        if (id == aEnd + 1)
        {
            shouldContain = false;
        }

        VerifyOrQuit(aIdRange.Contains(id) == shouldContain);
    }

    // Test values that half the range apart

    for (RequestId id = aStart + maxId / 2 - 10; id != aEnd + maxId / 2 + 10; id++)
    {
        VerifyOrQuit(!aIdRange.Contains(id));
    }
}

void TestDnssdRequestIdRange(void)
{
    RequestId      maxId = NumericLimits<RequestId>::kMax;
    RequestIdRange idRange;

    Log("--------------------------------------------------------------------------------------------");
    Log("TestDnssdRequestIdRange");

    VerifyOrQuit(idRange.IsEmpty());

    idRange.Add(5);
    ValidateRequestIdRange(idRange, 5, 5);

    idRange.Remove(4);
    ValidateRequestIdRange(idRange, 5, 5);

    idRange.Remove(6);
    ValidateRequestIdRange(idRange, 5, 5);

    idRange.Remove(5);
    VerifyOrQuit(idRange.IsEmpty());
    VerifyOrQuit(!idRange.Contains(5));

    // Adding and removing multiple IDs

    idRange.Add(10);
    idRange.Add(15);
    ValidateRequestIdRange(idRange, 10, 15);

    idRange.Add(12);
    ValidateRequestIdRange(idRange, 10, 15);
    idRange.Add(15);
    ValidateRequestIdRange(idRange, 10, 15);
    idRange.Add(10);
    ValidateRequestIdRange(idRange, 10, 15);

    idRange.Add(9);
    ValidateRequestIdRange(idRange, 9, 15);
    idRange.Add(16);
    ValidateRequestIdRange(idRange, 9, 16);

    idRange.Remove(10);
    ValidateRequestIdRange(idRange, 9, 16);
    idRange.Remove(15);
    ValidateRequestIdRange(idRange, 9, 16);

    idRange.Remove(8);
    ValidateRequestIdRange(idRange, 9, 16);
    idRange.Remove(17);
    ValidateRequestIdRange(idRange, 9, 16);

    idRange.Remove(9);
    ValidateRequestIdRange(idRange, 10, 16);
    idRange.Remove(16);
    ValidateRequestIdRange(idRange, 10, 15);

    idRange.Clear();
    VerifyOrQuit(idRange.IsEmpty());
    VerifyOrQuit(!idRange.Contains(10));

    // Ranges close to roll-over max value

    idRange.Add(maxId);
    ValidateRequestIdRange(idRange, maxId, maxId);

    idRange.Remove(0);
    ValidateRequestIdRange(idRange, maxId, maxId);
    idRange.Remove(maxId - 1);
    ValidateRequestIdRange(idRange, maxId, maxId);

    idRange.Add(0);
    ValidateRequestIdRange(idRange, maxId, 0);

    idRange.Add(maxId - 2);
    ValidateRequestIdRange(idRange, maxId - 2, 0);

    idRange.Add(3);
    ValidateRequestIdRange(idRange, maxId - 2, 3);
    idRange.Add(3);
    ValidateRequestIdRange(idRange, maxId - 2, 3);

    idRange.Remove(4);
    ValidateRequestIdRange(idRange, maxId - 2, 3);
    idRange.Remove(maxId - 3);
    ValidateRequestIdRange(idRange, maxId - 2, 3);

    idRange.Remove(3);
    ValidateRequestIdRange(idRange, maxId - 2, 2);

    idRange.Remove(maxId - 2);
    ValidateRequestIdRange(idRange, maxId - 1, 2);

    Log("End of TestDnssdRequestIdRange");
}

void TestSrpAdvProxy(void)
{
    NetworkData::OnMeshPrefixConfig prefixConfig;
    Srp::Server                    *srpServer;
    Srp::Client                    *srpClient;
    Srp::AdvertisingProxy          *advProxy;
    Srp::Client::Service            service1;
    Srp::Client::Service            service2;
    uint16_t                        heapAllocations;

    Log("--------------------------------------------------------------------------------------------");
    Log("TestSrpAdvProxy");

    InitTest();

    srpServer = &sInstance->Get<Srp::Server>();
    srpClient = &sInstance->Get<Srp::Client>();
    advProxy  = &sInstance->Get<Srp::AdvertisingProxy>();

    heapAllocations = sHeapAllocatedPtrs.GetLength();

    PrepareService1(service1);
    PrepareService2(service2);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Add an on-mesh prefix (with SLAAC) to network data");

    prefixConfig.Clear();
    SuccessOrQuit(AsCoreType(&prefixConfig.mPrefix.mPrefix).FromString("fd00:cafe:beef::"));
    prefixConfig.mPrefix.mLength = 64;
    prefixConfig.mStable         = true;
    prefixConfig.mSlaac          = true;
    prefixConfig.mPreferred      = true;
    prefixConfig.mOnMesh         = true;
    prefixConfig.mDefaultRoute   = false;
    prefixConfig.mPreference     = NetworkData::kRoutePreferenceMedium;

    SuccessOrQuit(otBorderRouterAddOnMeshPrefix(sInstance, &prefixConfig));
    SuccessOrQuit(otBorderRouterRegister(sInstance));

    // Configured Dnssd platform API behavior

    sDnssdRegHostRequests.Clear();
    sDnssdRegServiceRequests.Clear();
    sDnssdUnregHostRequests.Clear();
    sDnssdUnregServiceRequests.Clear();
    sDnssdState                 = OT_PLAT_DNSSD_READY;
    sDnssdShouldCheckWithClient = true;
    sDnssdCallbackError         = kErrorNone; // Invoke callback directly from dnssd APIs

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Start SRP server");

    SuccessOrQuit(srpServer->SetAddressMode(Srp::Server::kAddressModeUnicast));
    VerifyOrQuit(srpServer->GetAddressMode() == Srp::Server::kAddressModeUnicast);

    VerifyOrQuit(srpServer->GetState() == Srp::Server::kStateDisabled);

    srpServer->SetServiceHandler(nullptr, sInstance);

    srpServer->SetEnabled(true);
    VerifyOrQuit(srpServer->GetState() != Srp::Server::kStateDisabled);

    AdvanceTime(10000);
    VerifyOrQuit(srpServer->GetState() == Srp::Server::kStateRunning);
    VerifyOrQuit(advProxy->IsRunning());

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Start SRP client");

    srpClient->SetCallback(HandleSrpClientCallback, sInstance);
    srpClient->SetLeaseInterval(180);

    srpClient->EnableAutoStartMode(nullptr, nullptr);
    VerifyOrQuit(srpClient->IsAutoStartModeEnabled());

    AdvanceTime(2000);
    VerifyOrQuit(srpClient->IsRunning());

    SuccessOrQuit(srpClient->SetHostName(kHostName));
    SuccessOrQuit(srpClient->EnableAutoHostAddress());

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Register a service");

    SuccessOrQuit(srpClient->AddService(service1));

    sProcessedClientCallback = false;

    AdvanceTime(2 * 1000);

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorNone);

    VerifyOrQuit(service1.GetState() == Srp::Client::kRegistered);

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 1);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 1);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Register a second service");

    SuccessOrQuit(srpClient->AddService(service2));

    sProcessedClientCallback = false;

    AdvanceTime(2 * 1000);

    // This time we should only see the new service being
    // registered as the host is same as before and already registered

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorNone);

    VerifyOrQuit(service1.GetState() == Srp::Client::kRegistered);
    VerifyOrQuit(service2.GetState() == Srp::Client::kRegistered);

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 2);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 2);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Wait for longer than lease interval for client to refresh");

    sProcessedClientCallback = false;

    AdvanceTime(181 * 1000);

    VerifyOrQuit(sProcessedClientCallback);

    // Validate that adv-proxy does not update any of registration on
    // DNS-SD platform since there is no change.

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal > 3);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == advProxy->GetCounters().mAdvTotal);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Add a new on-mesh prefix so to get a new host address");

    prefixConfig.Clear();
    SuccessOrQuit(AsCoreType(&prefixConfig.mPrefix.mPrefix).FromString("fd00:abba::"));
    prefixConfig.mPrefix.mLength = 64;
    prefixConfig.mStable         = true;
    prefixConfig.mSlaac          = true;
    prefixConfig.mPreferred      = true;
    prefixConfig.mOnMesh         = true;
    prefixConfig.mDefaultRoute   = false;
    prefixConfig.mPreference     = NetworkData::kRoutePreferenceMedium;

    SuccessOrQuit(otBorderRouterAddOnMeshPrefix(sInstance, &prefixConfig));
    SuccessOrQuit(otBorderRouterRegister(sInstance));

    sProcessedClientCallback = false;

    AdvanceTime(5 * 1000);

    // This time we should only see new host registration
    // since that's the only thing that changes

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorNone);

    VerifyOrQuit(service1.GetState() == Srp::Client::kRegistered);
    VerifyOrQuit(service2.GetState() == Srp::Client::kRegistered);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Remove the first service on client");

    SuccessOrQuit(srpClient->RemoveService(service1));

    sProcessedClientCallback = false;

    AdvanceTime(2 * 1000);

    // We should see the service being unregistered
    // by advertising proxy on DNS-SD platform.

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 1);

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorNone);

    VerifyOrQuit(service1.GetState() == Srp::Client::kRemoved);
    VerifyOrQuit(service2.GetState() == Srp::Client::kRegistered);

    // Wait for more than lease interval again and make sure
    // there is no change in DNS-SD platform API calls.

    sProcessedClientCallback = false;

    AdvanceTime(181 * 1000);

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorNone);

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 1);

    VerifyOrQuit(service1.GetState() == Srp::Client::kRemoved);
    VerifyOrQuit(service2.GetState() == Srp::Client::kRegistered);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Change service 2 on client, remove its sub-type");

    SuccessOrQuit(srpClient->ClearService(service2));
    PrepareService2(service2);
    service2.mSubTypeLabels = nullptr;

    SuccessOrQuit(srpClient->AddService(service2));

    sProcessedClientCallback = false;

    AdvanceTime(2 * 1000);

    // Since the service is now changed, advertising proxy
    // should update it (re-register it) on DNS-SD APIs.

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 3);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 1);

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorNone);

    VerifyOrQuit(service1.GetState() == Srp::Client::kRemoved);
    VerifyOrQuit(service2.GetState() == Srp::Client::kRegistered);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Remove the host on client");

    SuccessOrQuit(srpClient->RemoveHostAndServices(/* aShouldRemoveKeyLease */ false));

    sProcessedClientCallback = false;

    AdvanceTime(2 * 1000);

    // We should see the host and service being unregistered
    // on DNS-SD APIs.

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 3);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 2);

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorNone);

    VerifyOrQuit(service1.GetState() == Srp::Client::kRemoved);
    VerifyOrQuit(service2.GetState() == Srp::Client::kRemoved);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Remove the host on client again and force an update to be sent to server");

    SuccessOrQuit(srpClient->SetHostName(kHostName));
    SuccessOrQuit(srpClient->RemoveHostAndServices(/* aShouldRemoveKeyLease */ false, /* aSendUnregToServer */ true));

    sProcessedClientCallback = false;

    AdvanceTime(2 * 1000);

    // We should see no changes (no calls) to DNS-SD APIs.

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 3);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 2);

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorNone);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Re-add service 1 on client and register with server");

    SuccessOrQuit(srpClient->SetHostName(kHostName));
    SuccessOrQuit(srpClient->EnableAutoHostAddress());
    PrepareService1(service1);
    SuccessOrQuit(srpClient->AddService(service1));

    sProcessedClientCallback = false;

    AdvanceTime(2 * 1000);

    // We should see one host register and one service register
    // on DNS-SD APIs.

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 3);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 4);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 2);

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorNone);

    VerifyOrQuit(service1.GetState() == Srp::Client::kRegistered);

    // Wait for more than lease interval again and make sure
    // there is no change in DNS-SD platform API calls.

    sProcessedClientCallback = false;

    AdvanceTime(181 * 1000);

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorNone);

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 3);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 4);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 2);

    VerifyOrQuit(service1.GetState() == Srp::Client::kRegistered);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Disable SRP client and wait for lease time to expire");

    srpClient->ClearHostAndServices(); // does not signal removal to server

    // Since we clear everything on SRP client, we disable
    // matching the services with client from `otPlatDnssd`
    // APIs.
    sDnssdShouldCheckWithClient = false;

    AdvanceTime(181 * 1000);

    // Make sure host and service are unregistered.

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 3);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 4);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 3);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Disable SRP server");

    // Verify that all heap allocations by SRP server
    // and Advertising Proxy are freed.

    srpServer->SetEnabled(false);
    AdvanceTime(100);
    VerifyOrQuit(!advProxy->IsRunning());

    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == advProxy->GetCounters().mAdvTotal);
    VerifyOrQuit(advProxy->GetCounters().mAdvTimeout == 0);
    VerifyOrQuit(advProxy->GetCounters().mAdvRejected == 0);
    VerifyOrQuit(advProxy->GetCounters().mAdvSkipped == 0);
    VerifyOrQuit(advProxy->GetCounters().mAdvReplaced == 0);

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 3);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 4);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 3);

    VerifyOrQuit(heapAllocations == sHeapAllocatedPtrs.GetLength());

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Finalize OT instance and validate all heap allocations are freed");

    FinalizeTest();

    VerifyOrQuit(sHeapAllocatedPtrs.IsEmpty());

    Log("End of TestSrpAdvProxy");
}

void TestSrpAdvProxyDnssdStateChange(void)
{
    NetworkData::OnMeshPrefixConfig prefixConfig;
    Srp::Server                    *srpServer;
    Srp::Client                    *srpClient;
    Srp::AdvertisingProxy          *advProxy;
    Srp::Client::Service            service1;
    Srp::Client::Service            service2;
    uint16_t                        heapAllocations;

    Log("--------------------------------------------------------------------------------------------");
    Log("TestSrpAdvProxyDnssdStateChange");

    InitTest();

    srpServer = &sInstance->Get<Srp::Server>();
    srpClient = &sInstance->Get<Srp::Client>();
    advProxy  = &sInstance->Get<Srp::AdvertisingProxy>();

    heapAllocations = sHeapAllocatedPtrs.GetLength();

    PrepareService1(service1);
    PrepareService2(service2);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Add an on-mesh prefix (with SLAAC) to network data");

    prefixConfig.Clear();
    SuccessOrQuit(AsCoreType(&prefixConfig.mPrefix.mPrefix).FromString("fd00:cafe:beef::"));
    prefixConfig.mPrefix.mLength = 64;
    prefixConfig.mStable         = true;
    prefixConfig.mSlaac          = true;
    prefixConfig.mPreferred      = true;
    prefixConfig.mOnMesh         = true;
    prefixConfig.mDefaultRoute   = false;
    prefixConfig.mPreference     = NetworkData::kRoutePreferenceMedium;

    SuccessOrQuit(otBorderRouterAddOnMeshPrefix(sInstance, &prefixConfig));
    SuccessOrQuit(otBorderRouterRegister(sInstance));

    // Configure Dnssd platform API behavior

    sDnssdRegHostRequests.Clear();
    sDnssdRegServiceRequests.Clear();
    sDnssdUnregHostRequests.Clear();
    sDnssdUnregServiceRequests.Clear();
    sDnssdState                 = OT_PLAT_DNSSD_STOPPED;
    sDnssdShouldCheckWithClient = true;
    sDnssdCallbackError         = kErrorNone; // Invoke callback directly

    VerifyOrQuit(!advProxy->IsRunning());

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Start SRP server");

    SuccessOrQuit(srpServer->SetAddressMode(Srp::Server::kAddressModeUnicast));
    VerifyOrQuit(srpServer->GetAddressMode() == Srp::Server::kAddressModeUnicast);

    VerifyOrQuit(srpServer->GetState() == Srp::Server::kStateDisabled);

    srpServer->SetServiceHandler(nullptr, sInstance);

    srpServer->SetEnabled(true);
    VerifyOrQuit(srpServer->GetState() != Srp::Server::kStateDisabled);

    AdvanceTime(10000);
    VerifyOrQuit(srpServer->GetState() == Srp::Server::kStateRunning);
    VerifyOrQuit(!advProxy->IsRunning());

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Start SRP client");

    srpClient->SetCallback(HandleSrpClientCallback, sInstance);
    srpClient->SetLeaseInterval(180);

    srpClient->EnableAutoStartMode(nullptr, nullptr);
    VerifyOrQuit(srpClient->IsAutoStartModeEnabled());

    AdvanceTime(2000);
    VerifyOrQuit(srpClient->IsRunning());

    SuccessOrQuit(srpClient->SetHostName(kHostName));
    SuccessOrQuit(srpClient->EnableAutoHostAddress());

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Register a services");

    SuccessOrQuit(srpClient->AddService(service1));

    sProcessedClientCallback = false;

    AdvanceTime(2 * 1000);

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorNone);

    VerifyOrQuit(service1.GetState() == Srp::Client::kRegistered);

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Register a second service");

    SuccessOrQuit(srpClient->AddService(service2));

    sProcessedClientCallback = false;

    AdvanceTime(2 * 1000);

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorNone);

    VerifyOrQuit(service1.GetState() == Srp::Client::kRegistered);
    VerifyOrQuit(service2.GetState() == Srp::Client::kRegistered);

    // None of the DNS-SD APIs should be called since its state
    // `OT_PLAT_DNSSD_STOPPED`
    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Update DNS-SD state and signal that state is changed");

    sDnssdState = OT_PLAT_DNSSD_READY;
    otPlatDnssdStateHandleStateChange(sInstance);

    AdvanceTime(5);

    VerifyOrQuit(advProxy->IsRunning());
    VerifyOrQuit(advProxy->GetCounters().mStateChanges == 1);

    // Now the host and two services should be registered on
    // DNS-SD platform

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    VerifyOrQuit(service1.GetState() == Srp::Client::kRegistered);
    VerifyOrQuit(service2.GetState() == Srp::Client::kRegistered);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Wait for longer than lease interval for client to refresh");

    sProcessedClientCallback = false;

    AdvanceTime(181 * 1000);

    VerifyOrQuit(sProcessedClientCallback);

    // Validate that adv-proxy does not update any of registration on
    // DNS-SD platform since there is no change.

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Update DNS-SD state to `STOPPED` and signal its change");

    sDnssdState = OT_PLAT_DNSSD_STOPPED;
    otPlatDnssdStateHandleStateChange(sInstance);

    AdvanceTime(5);

    VerifyOrQuit(!advProxy->IsRunning());
    VerifyOrQuit(advProxy->GetCounters().mStateChanges == 2);

    // Since DNS-SD platform signal that it is stopped,
    // there should be no calls to any of APIs.

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Wait for longer than lease interval for client to refresh");

    sProcessedClientCallback = false;

    AdvanceTime(181 * 1000);

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(service1.GetState() == Srp::Client::kRegistered);
    VerifyOrQuit(service2.GetState() == Srp::Client::kRegistered);

    // The DNS-SD API counters should remain unchanged

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Update DNS-SD state to `READY` and signal its change");

    sDnssdState = OT_PLAT_DNSSD_READY;
    otPlatDnssdStateHandleStateChange(sInstance);

    AdvanceTime(5);

    VerifyOrQuit(advProxy->IsRunning());
    VerifyOrQuit(advProxy->GetCounters().mStateChanges == 3);

    // Check that the host and two services are again registered
    // on DNS-SD platform by advertising proxy.

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 4);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Update DNS-SD state to `STOPPED` and signal its change");

    sDnssdState = OT_PLAT_DNSSD_STOPPED;
    otPlatDnssdStateHandleStateChange(sInstance);

    AdvanceTime(5);

    VerifyOrQuit(!advProxy->IsRunning());
    VerifyOrQuit(advProxy->GetCounters().mStateChanges == 4);

    // Since DNS-SD platform signal that it is stopped,
    // there should be no calls to any of APIs.

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 4);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Remove the first service on client");

    SuccessOrQuit(srpClient->RemoveService(service1));

    sProcessedClientCallback = false;

    AdvanceTime(2 * 1000);

    // We should see the service being unregistered
    // by advertising proxy on DNS-SD platform.

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorNone);
    VerifyOrQuit(service1.GetState() == Srp::Client::kRemoved);
    VerifyOrQuit(service2.GetState() == Srp::Client::kRegistered);

    // No changes to DNS-SD API counters (since it is stopped)

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 4);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Update DNS-SD state to `READY` and signal its change");

    // Since the already removed `service1` is no longer available
    // on SRP client, we disable checking the services with client
    // from `otPlatDnssd` APIs.
    sDnssdShouldCheckWithClient = false;

    sDnssdState = OT_PLAT_DNSSD_READY;
    otPlatDnssdStateHandleStateChange(sInstance);

    AdvanceTime(5);

    VerifyOrQuit(advProxy->IsRunning());
    VerifyOrQuit(advProxy->GetCounters().mStateChanges == 5);

    // We should see the host and `service2` registered again,
    // and removed `service1` unregistered.

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 3);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 5);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 1);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Disable SRP server");

    // Verify that all heap allocations by SRP server
    // and Advertising Proxy are freed.

    srpServer->SetEnabled(false);
    AdvanceTime(100);

    VerifyOrQuit(!advProxy->IsRunning());
    VerifyOrQuit(advProxy->GetCounters().mStateChanges == 6);
    VerifyOrQuit(advProxy->GetCounters().mAdvSkipped > 0);
    VerifyOrQuit(advProxy->GetCounters().mAdvTotal ==
                 (advProxy->GetCounters().mAdvSuccessful + advProxy->GetCounters().mAdvSkipped));
    VerifyOrQuit(advProxy->GetCounters().mAdvTimeout == 0);
    VerifyOrQuit(advProxy->GetCounters().mAdvRejected == 0);
    VerifyOrQuit(advProxy->GetCounters().mAdvReplaced == 0);

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 3);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 5);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 2);

    VerifyOrQuit(heapAllocations == sHeapAllocatedPtrs.GetLength());

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Finalize OT instance and validate all heap allocations are freed");

    FinalizeTest();

    VerifyOrQuit(sHeapAllocatedPtrs.IsEmpty());

    Log("End of TestSrpAdvProxyDnssdStateChange");
}

void TestSrpAdvProxyDelayedCallback(void)
{
    NetworkData::OnMeshPrefixConfig prefixConfig;
    Srp::Server                    *srpServer;
    Srp::Client                    *srpClient;
    Srp::AdvertisingProxy          *advProxy;
    Srp::Client::Service            service1;
    Srp::Client::Service            service2;
    uint16_t                        heapAllocations;
    const DnssdRequest             *request;

    Log("--------------------------------------------------------------------------------------------");
    Log("TestSrpAdvProxyDelayedCallback");

    InitTest();

    srpServer = &sInstance->Get<Srp::Server>();
    srpClient = &sInstance->Get<Srp::Client>();
    advProxy  = &sInstance->Get<Srp::AdvertisingProxy>();

    heapAllocations = sHeapAllocatedPtrs.GetLength();

    PrepareService1(service1);
    PrepareService2(service2);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Add an on-mesh prefix (with SLAAC) to network data");

    prefixConfig.Clear();
    SuccessOrQuit(AsCoreType(&prefixConfig.mPrefix.mPrefix).FromString("fd00:cafe:beef::"));
    prefixConfig.mPrefix.mLength = 64;
    prefixConfig.mStable         = true;
    prefixConfig.mSlaac          = true;
    prefixConfig.mPreferred      = true;
    prefixConfig.mOnMesh         = true;
    prefixConfig.mDefaultRoute   = false;
    prefixConfig.mPreference     = NetworkData::kRoutePreferenceMedium;

    SuccessOrQuit(otBorderRouterAddOnMeshPrefix(sInstance, &prefixConfig));
    SuccessOrQuit(otBorderRouterRegister(sInstance));

    // Configured Dnssd platform API behavior

    sDnssdRegHostRequests.Clear();
    sDnssdRegServiceRequests.Clear();
    sDnssdUnregHostRequests.Clear();
    sDnssdUnregServiceRequests.Clear();
    sDnssdState                 = OT_PLAT_DNSSD_READY;
    sDnssdShouldCheckWithClient = true;
    sDnssdCallbackError         = kErrorPending; // Do not call the callbacks directly

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Start SRP server");

    SuccessOrQuit(srpServer->SetAddressMode(Srp::Server::kAddressModeUnicast));
    VerifyOrQuit(srpServer->GetAddressMode() == Srp::Server::kAddressModeUnicast);

    VerifyOrQuit(srpServer->GetState() == Srp::Server::kStateDisabled);

    srpServer->SetServiceHandler(nullptr, sInstance);

    srpServer->SetEnabled(true);
    VerifyOrQuit(srpServer->GetState() != Srp::Server::kStateDisabled);

    AdvanceTime(10000);
    VerifyOrQuit(srpServer->GetState() == Srp::Server::kStateRunning);
    VerifyOrQuit(advProxy->IsRunning());

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Start SRP client");

    srpClient->SetCallback(HandleSrpClientCallback, sInstance);
    srpClient->SetLeaseInterval(180);

    srpClient->EnableAutoStartMode(nullptr, nullptr);
    VerifyOrQuit(srpClient->IsAutoStartModeEnabled());

    AdvanceTime(2000);
    VerifyOrQuit(srpClient->IsRunning());

    SuccessOrQuit(srpClient->SetHostName(kHostName));
    SuccessOrQuit(srpClient->EnableAutoHostAddress());

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Register a service, invoke the registration callback after some delay");

    SuccessOrQuit(srpClient->AddService(service1));

    sProcessedClientCallback = false;

    AdvanceTime(1000);

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 1);

    VerifyOrQuit(!sProcessedClientCallback);
    VerifyOrQuit(srpServer->GetNextHost(nullptr) == nullptr);

    // Invoke the service callback first
    request = &sDnssdRegServiceRequests[0];
    VerifyOrQuit(request->mCallback != nullptr);
    request->mCallback(sInstance, request->mId, kErrorNone);

    AdvanceTime(10);
    VerifyOrQuit(!sProcessedClientCallback);
    VerifyOrQuit(srpServer->GetNextHost(nullptr) == nullptr);

    // Invoke the host registration callback next
    request = &sDnssdRegHostRequests[0];
    VerifyOrQuit(request->mCallback != nullptr);
    request->mCallback(sInstance, request->mId, kErrorNone);

    AdvanceTime(10);
    VerifyOrQuit(srpServer->GetNextHost(nullptr) != nullptr);

    AdvanceTime(100);
    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorNone);
    VerifyOrQuit(service1.GetState() == Srp::Client::kRegistered);

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 1);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 1);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Register a second service, invoke registration callback with `kErrorDuplicated`");

    SuccessOrQuit(srpClient->AddService(service2));

    sProcessedClientCallback = false;

    AdvanceTime(1000);

    VerifyOrQuit(!sProcessedClientCallback);

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 2);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 1);

    // Invoke the service callback with kErrorDuplicated

    request = &sDnssdRegServiceRequests[1];
    VerifyOrQuit(request->mCallback != nullptr);
    request->mCallback(sInstance, request->mId, kErrorDuplicated);

    AdvanceTime(100);

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorDuplicated);

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 2);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 1);
    VerifyOrQuit(advProxy->GetCounters().mAdvRejected == 1);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Try registering service again from client, invoke callback with success");

    SuccessOrQuit(srpClient->ClearService(service2));
    PrepareService2(service2);
    SuccessOrQuit(srpClient->AddService(service2));

    sProcessedClientCallback = false;

    AdvanceTime(1000);

    VerifyOrQuit(!sProcessedClientCallback);

    // We should see a new service registration request.

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 3);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 3);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 1);
    VerifyOrQuit(advProxy->GetCounters().mAdvRejected == 1);

    // Invoked the service callback with success.

    request = &sDnssdRegServiceRequests[2];
    VerifyOrQuit(request->mCallback != nullptr);
    request->mCallback(sInstance, request->mId, kErrorNone);

    AdvanceTime(100);

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorNone);
    VerifyOrQuit(service1.GetState() == Srp::Client::kRegistered);
    VerifyOrQuit(service2.GetState() == Srp::Client::kRegistered);

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 3);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 2);
    VerifyOrQuit(advProxy->GetCounters().mAdvRejected == 1);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Change the service and register again, but ignore the registration callback");

    SuccessOrQuit(srpClient->ClearService(service2));
    PrepareService2(service2);
    service2.mSubTypeLabels = nullptr;
    SuccessOrQuit(srpClient->AddService(service2));

    sProcessedClientCallback = false;

    AdvanceTime(1000);

    VerifyOrQuit(!sProcessedClientCallback);

    // We should see a new service registration request.

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 4);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 4);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 2);
    VerifyOrQuit(advProxy->GetCounters().mAdvRejected == 1);
    VerifyOrQuit(advProxy->GetCounters().mAdvTimeout == 0);

    // Wait for advertising proxy timeout (there will be no callback from
    // platform) so validate that registration failure is reported to
    // the SRP client.

    AdvanceTime(2 * 1000);

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError != kErrorNone);

    VerifyOrQuit(advProxy->GetCounters().mAdvTimeout == 1);

    // Wait for longer than client retry time.

    AdvanceTime(3 * 1000);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Disable SRP server");

    // Verify that all heap allocations by SRP server
    // and Advertising Proxy are freed.

    srpServer->SetEnabled(false);
    AdvanceTime(100);

    // Make sure the host and two services are unregistered
    // (even though the second service was not successfully
    // registered yet).

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() >= 4);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 2);

    VerifyOrQuit(heapAllocations == sHeapAllocatedPtrs.GetLength());

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Finalize OT instance and validate all heap allocations are freed");

    FinalizeTest();

    VerifyOrQuit(sHeapAllocatedPtrs.IsEmpty());

    Log("End of TestSrpAdvProxyDelayedCallback");
}

void TestSrpAdvProxyReplacedEntries(void)
{
    NetworkData::OnMeshPrefixConfig prefixConfig;
    Srp::Server                    *srpServer;
    Srp::Client                    *srpClient;
    Srp::AdvertisingProxy          *advProxy;
    Srp::Client::Service            service1;
    Srp::Client::Service            service2;
    uint16_t                        heapAllocations;
    const DnssdRequest             *request;
    uint16_t                        numServices;

    Log("--------------------------------------------------------------------------------------------");
    Log("TestSrpAdvProxyReplacedEntries");

    InitTest();

    srpServer = &sInstance->Get<Srp::Server>();
    srpClient = &sInstance->Get<Srp::Client>();
    advProxy  = &sInstance->Get<Srp::AdvertisingProxy>();

    heapAllocations = sHeapAllocatedPtrs.GetLength();

    PrepareService1(service1);
    PrepareService2(service2);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Add an on-mesh prefix (with SLAAC) to network data");

    prefixConfig.Clear();
    SuccessOrQuit(AsCoreType(&prefixConfig.mPrefix.mPrefix).FromString("fd00:cafe:beef::"));
    prefixConfig.mPrefix.mLength = 64;
    prefixConfig.mStable         = true;
    prefixConfig.mSlaac          = true;
    prefixConfig.mPreferred      = true;
    prefixConfig.mOnMesh         = true;
    prefixConfig.mDefaultRoute   = false;
    prefixConfig.mPreference     = NetworkData::kRoutePreferenceMedium;

    SuccessOrQuit(otBorderRouterAddOnMeshPrefix(sInstance, &prefixConfig));
    SuccessOrQuit(otBorderRouterRegister(sInstance));

    // Configured Dnssd platform API behavior

    sDnssdRegHostRequests.Clear();
    sDnssdRegServiceRequests.Clear();
    sDnssdUnregHostRequests.Clear();
    sDnssdUnregServiceRequests.Clear();
    sDnssdState                 = OT_PLAT_DNSSD_READY;
    sDnssdShouldCheckWithClient = true;
    sDnssdCallbackError         = kErrorPending; // Do not call the callbacks directly

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Start SRP server");

    SuccessOrQuit(srpServer->SetAddressMode(Srp::Server::kAddressModeUnicast));
    VerifyOrQuit(srpServer->GetAddressMode() == Srp::Server::kAddressModeUnicast);

    VerifyOrQuit(srpServer->GetState() == Srp::Server::kStateDisabled);

    srpServer->SetServiceHandler(nullptr, sInstance);

    srpServer->SetEnabled(true);
    VerifyOrQuit(srpServer->GetState() != Srp::Server::kStateDisabled);

    AdvanceTime(10000);
    VerifyOrQuit(srpServer->GetState() == Srp::Server::kStateRunning);
    VerifyOrQuit(advProxy->IsRunning());

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Set AdvTimeout to 5 minutes on AdvProxy");

    // Change the timeout on AvdertisingProxy to 5 minutes
    // so that we can send multiple SRP updates and create
    // situations where previous advertisement are replaced.

    advProxy->SetAdvTimeout(5 * 60 * 1000);
    VerifyOrQuit(advProxy->GetAdvTimeout() == 5 * 60 * 1000);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Start SRP client");

    srpClient->SetCallback(HandleSrpClientCallback, sInstance);

    srpClient->EnableAutoStartMode(nullptr, nullptr);
    VerifyOrQuit(srpClient->IsAutoStartModeEnabled());

    AdvanceTime(2000);
    VerifyOrQuit(srpClient->IsRunning());

    SuccessOrQuit(srpClient->SetHostName(kHostName));
    SuccessOrQuit(srpClient->EnableAutoHostAddress());

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Register a service and do not invoke the registration request callbacks");

    SuccessOrQuit(srpClient->AddService(service1));

    sProcessedClientCallback = false;

    AdvanceTime(1200);

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 1);
    VerifyOrQuit(advProxy->GetCounters().mAdvReplaced == 0);

    VerifyOrQuit(!sProcessedClientCallback);
    VerifyOrQuit(srpServer->GetNextHost(nullptr) == nullptr);

    // SRP client min retry is 1800 msec, we wait for longer
    // to make sure client retries.

    AdvanceTime(1900);

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 2);
    VerifyOrQuit(advProxy->GetCounters().mAdvReplaced == 0);

    // We should see no new service or host registrations on
    // DNS-SD platform APIs as the requests should be same
    // and fully matching the outstanding ones.

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Invoke the DNS-SD API callbacks");

    request = &sDnssdRegServiceRequests[0];
    VerifyOrQuit(request->mCallback != nullptr);
    request->mCallback(sInstance, request->mId, kErrorNone);

    request = &sDnssdRegHostRequests[0];
    VerifyOrQuit(request->mCallback != nullptr);
    request->mCallback(sInstance, request->mId, kErrorNone);

    AdvanceTime(100);

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorNone);
    VerifyOrQuit(srpServer->GetNextHost(nullptr) != nullptr);

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 2);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 2);
    VerifyOrQuit(advProxy->GetCounters().mAdvReplaced == 0);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Check outstanding Adv being replaced");

    // Change service 1
    SuccessOrQuit(srpClient->ClearService(service1));
    PrepareService1(service1);
    service1.mSubTypeLabels = nullptr; // No sub-types
    SuccessOrQuit(srpClient->AddService(service1));

    sProcessedClientCallback = false;

    AdvanceTime(1200);

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 3);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 2);
    VerifyOrQuit(advProxy->GetCounters().mAdvReplaced == 0);

    // We should see the changed service registered on DNS-SD
    // platform APIs.

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 2);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    // Change service 1 again (add sub-types back).
    SuccessOrQuit(srpClient->ClearService(service1));
    PrepareService1(service1);
    SuccessOrQuit(srpClient->AddService(service1));

    AdvanceTime(1200);

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 4);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 2);
    VerifyOrQuit(advProxy->GetCounters().mAdvReplaced == 1);

    // We should see the changed service registered on DNS-SD
    // platform APIs again.

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 3);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Invoke the replaced entry DNS-SD API callback");

    request = &sDnssdRegServiceRequests[1];
    VerifyOrQuit(request->mCallback != nullptr);
    request->mCallback(sInstance, request->mId, kErrorNone);

    AdvanceTime(100);

    // Since adv is replaced invoking the old registration callback
    // should not complete it.

    VerifyOrQuit(!sProcessedClientCallback);
    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 4);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 2);
    VerifyOrQuit(advProxy->GetCounters().mAdvReplaced == 1);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Invoke the new entry DNS-SD API callback");

    request = &sDnssdRegServiceRequests[2];
    VerifyOrQuit(request->mCallback != nullptr);
    request->mCallback(sInstance, request->mId, kErrorNone);

    AdvanceTime(100);

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorNone);

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 4);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 4);
    VerifyOrQuit(advProxy->GetCounters().mAdvReplaced == 1);

    // Make sure the service entry on the SRP server is the
    // last (most recent) request with three sub-types

    VerifyOrQuit(srpServer->GetNextHost(nullptr)->GetServices().GetHead() != nullptr);
    VerifyOrQuit(srpServer->GetNextHost(nullptr)->GetServices().GetHead()->GetNumberOfSubTypes() == 3);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Check replacing Adv being blocked till old Adv is completed");

    // Change service 1 and add service 2
    SuccessOrQuit(srpClient->ClearService(service1));
    PrepareService1(service1);
    service1.mSubTypeLabels = nullptr; // No sub-types
    SuccessOrQuit(srpClient->AddService(service1));
    SuccessOrQuit(srpClient->AddService(service2));

    sProcessedClientCallback = false;

    AdvanceTime(1200);

    // We should see a new Adv with two new service registrations
    // on DNS-SD APIs.

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 5);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 4);
    VerifyOrQuit(advProxy->GetCounters().mAdvReplaced == 1);

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 5);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    // Now have SRP client send a new SRP update message
    // just changing `service2`. We clear `servcie1` on client
    // so it is not included in new SRP update message.

    SuccessOrQuit(srpClient->ClearService(service1));
    SuccessOrQuit(srpClient->ClearService(service2));
    PrepareService2(service2);
    service2.mPort = 2222; // Use a different port number
    SuccessOrQuit(srpClient->AddService(service2));

    AdvanceTime(1200);

    // We should see the new Adv (total increasing) and
    // also replacing the outstanding one

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 6);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 4);
    VerifyOrQuit(advProxy->GetCounters().mAdvReplaced == 2);

    // We should new registration for the changed `service2`

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 6);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Invoke the callback for new registration replacing old one first");

    request = &sDnssdRegServiceRequests[5];
    VerifyOrQuit(request->mCallback != nullptr);
    request->mCallback(sInstance, request->mId, kErrorNone);

    AdvanceTime(100);

    // This should not change anything, since the new Avd should
    // be still blocked by the earlier Adv that it replaced.

    VerifyOrQuit(!sProcessedClientCallback);

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 6);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 4);
    VerifyOrQuit(advProxy->GetCounters().mAdvReplaced == 2);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Invoke the callback for replaced Adv services");

    request = &sDnssdRegServiceRequests[4];
    VerifyOrQuit(request->mCallback != nullptr);
    request->mCallback(sInstance, request->mId, kErrorNone);

    request = &sDnssdRegServiceRequests[3];
    VerifyOrQuit(request->mCallback != nullptr);
    request->mCallback(sInstance, request->mId, kErrorNone);

    AdvanceTime(100);

    // This should trigger both Adv to complete.

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorNone);

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 6);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 6);
    VerifyOrQuit(advProxy->GetCounters().mAdvReplaced == 2);

    VerifyOrQuit(service2.GetState() == Srp::Client::kRegistered);

    // Make sure the `service2` entry on the SRP server is the
    // last (most recent) request with new port number.

    VerifyOrQuit(srpServer->GetNextHost(nullptr)->GetServices().GetHead() != nullptr);

    numServices = 0;

    for (const Srp::Server::Service &service : srpServer->GetNextHost(nullptr)->GetServices())
    {
        numServices++;

        if (StringMatch(service.GetInstanceLabel(), service2.GetInstanceName(), kStringCaseInsensitiveMatch))
        {
            VerifyOrQuit(service.GetPort() == service2.GetPort());
        }
        else if (StringMatch(service.GetInstanceLabel(), service1.GetInstanceName(), kStringCaseInsensitiveMatch))
        {
            // Service 1 was changed to have no sub-types
            VerifyOrQuit(service.GetPort() == service1.GetPort());
            VerifyOrQuit(service.GetNumberOfSubTypes() == 0);
        }
        else
        {
            VerifyOrQuit(false); // Unexpected extra service on SRP server.
        }
    }

    VerifyOrQuit(numServices == 2);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Check replacing Adv being blocked till old Adv is completed when removing services");

    // Change and re-add both services so they are both
    // included in a new SRP update message from client.

    SuccessOrQuit(srpClient->ClearService(service2));
    PrepareService1(service1);
    PrepareService2(service2);
    SuccessOrQuit(srpClient->AddService(service1));
    SuccessOrQuit(srpClient->AddService(service2));

    sProcessedClientCallback = false;

    AdvanceTime(1200);

    // We should see a new Adv with two new service registrations
    // on DNS-SD APIs.

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 7);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 6);
    VerifyOrQuit(advProxy->GetCounters().mAdvReplaced == 2);

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 8);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 0);

    // Now have SRP client send a new SRP update message
    // just removing `service1`. We clear `servcie2` on client
    // so it is not included in new SRP update message.

    SuccessOrQuit(srpClient->RemoveService(service1));
    SuccessOrQuit(srpClient->ClearService(service2));

    AdvanceTime(1200);

    // We should see a new Adv added replacing the outstanding
    // one.

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 8);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 6);
    VerifyOrQuit(advProxy->GetCounters().mAdvReplaced == 3);

    VerifyOrQuit(sDnssdRegHostRequests.GetLength() == 1);
    VerifyOrQuit(sDnssdRegServiceRequests.GetLength() == 8);
    VerifyOrQuit(sDnssdUnregHostRequests.GetLength() == 0);
    VerifyOrQuit(sDnssdUnregServiceRequests.GetLength() == 1);

    // Even though the new SRP update which removed `servcie2`
    // is already unregistered, it should be blocked by the
    // earlier Adv.

    VerifyOrQuit(!sProcessedClientCallback);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Invoke the callback for replaced Adv services");

    request = &sDnssdRegServiceRequests[6];
    VerifyOrQuit(request->mCallback != nullptr);
    request->mCallback(sInstance, request->mId, kErrorNone);

    request = &sDnssdRegServiceRequests[7];
    VerifyOrQuit(request->mCallback != nullptr);
    request->mCallback(sInstance, request->mId, kErrorNone);

    AdvanceTime(100);

    // This should trigger both Adv to complete, and first one
    // should be committed before the second one removing the
    // `service2`.

    VerifyOrQuit(sProcessedClientCallback);
    VerifyOrQuit(sLastClientCallbackError == kErrorNone);

    VerifyOrQuit(advProxy->GetCounters().mAdvTotal == 8);
    VerifyOrQuit(advProxy->GetCounters().mAdvSuccessful == 8);
    VerifyOrQuit(advProxy->GetCounters().mAdvReplaced == 3);

    VerifyOrQuit(service1.GetState() == Srp::Client::kRemoved);

    // Check services on server and make sure `service2`
    // is marked as deleted.

    VerifyOrQuit(srpServer->GetNextHost(nullptr)->GetServices().GetHead() != nullptr);

    numServices = 0;

    for (const Srp::Server::Service &service : srpServer->GetNextHost(nullptr)->GetServices())
    {
        numServices++;

        if (StringMatch(service.GetInstanceLabel(), service1.GetInstanceName(), kStringCaseInsensitiveMatch))
        {
            VerifyOrQuit(service.IsDeleted());
        }
        else if (StringMatch(service.GetInstanceLabel(), service2.GetInstanceName(), kStringCaseInsensitiveMatch))
        {
            VerifyOrQuit(!service.IsDeleted());
        }
        else
        {
            VerifyOrQuit(false); // Unexpected extra service on SRP server.
        }
    }

    VerifyOrQuit(numServices == 2);

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Disable SRP server");

    sDnssdShouldCheckWithClient = false;

    // Verify that all heap allocations by SRP server
    // and Advertising Proxy are freed.

    srpServer->SetEnabled(false);
    AdvanceTime(100);

    VerifyOrQuit(heapAllocations == sHeapAllocatedPtrs.GetLength());

    Log("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ");
    Log("Finalize OT instance and validate all heap allocations are freed");

    FinalizeTest();

    VerifyOrQuit(sHeapAllocatedPtrs.IsEmpty());

    Log("End of TestSrpAdvProxyReplacedEntries");
}

#endif // ENABLE_ADV_PROXY_TEST

int main(void)
{
#if ENABLE_ADV_PROXY_TEST
    TestDnssdRequestIdRange();
    TestSrpAdvProxy();
    TestSrpAdvProxyDnssdStateChange();
    TestSrpAdvProxyDelayedCallback();
    TestSrpAdvProxyReplacedEntries();
    printf("All tests passed\n");
#else
    printf("SRP_ADV_PROXY feature is not enabled\n");
#endif

    return 0;
}
