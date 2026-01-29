/*
 *  Copyright (c) 2026, The OpenThread Authors.
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
 *   This file implements the Seeker functionality.
 */

#include "seeker.hpp"

#if OPENTHREAD_CONFIG_JOINER_ENABLE

#include "instance/instance.hpp"

namespace ot {
namespace MeshCoP {

RegisterLogModule("Seeker");

Seeker::Seeker(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mState(kStateStopped)
    , mCandidates(aInstance)
{
}

Error Seeker::Start(ScanEvaluator aScanEvaluator, void *aContext)
{
    Error           error = kErrorNone;
    Mac::ExtAddress randomAddress;

    VerifyOrExit(aScanEvaluator != nullptr, error = kErrorInvalidArgs);

    VerifyOrExit(GetState() == kStateStopped, error = kErrorBusy);
    VerifyOrExit(Get<ThreadNetif>().IsUp() && Get<Mle::Mle>().IsDisabled(), error = kErrorInvalidState);

    randomAddress.GenerateRandom();
    Get<Mac::Mac>().SetExtAddress(randomAddress);
    Get<Mle::Mle>().UpdateLinkLocalAddress();

    mScanEvaluator.Set(aScanEvaluator, aContext);

    SuccessOrExit(error =
                      Get<Mle::DiscoverScanner>().Discover(Mac::ChannelMask(0), Get<Mac::Mac>().GetPanId(),
                                                           /* aJoiner */ true, /* aEnableFiltering */ false,
                                                           /* aFilterIndexes */ nullptr, HandleDiscoverResult, this));
    SetState(kStateDiscovering);

exit:
    return error;
}

void Seeker::Stop(void)
{
    switch (GetState())
    {
    case kStateStopped:
    case kStateDiscovering:
    case kStateDiscoverDone:
        break;
    case kStateConnectingNetworks:
    case kStateConnectingAny:
        IgnoreError(Get<Ip6::Filter>().RemoveUnsecurePort(kUdpPort));
        break;
    }

    mCandidates.Clear();

    SetState(kStateStopped);
}

void Seeker::HandleDiscoverResult(ScanResult *aResult, void *aContext)
{
    static_cast<Seeker *>(aContext)->HandleDiscoverResult(aResult);
}

void Seeker::HandleDiscoverResult(ScanResult *aResult)
{
    bool preferred = false;

    VerifyOrExit(GetState() == kStateDiscovering);

    if (aResult == nullptr)
    {
        SetState(kStateDiscoverDone);
        IgnoreReturnValue(mScanEvaluator.Invoke(aResult));
        ExitNow();
    }

    VerifyOrExit(aResult->mJoinerUdpPort > 0);
    VerifyOrExit(AsCoreType(&aResult->mSteeringData).IsValid());

    switch (mScanEvaluator.Invoke(aResult))
    {
    case kAccept:
        break;
    case kAcceptPreferred:
        preferred = true;
        break;

    case kIgnore:
    default:
        ExitNow();
    }

    SaveCandidate(*aResult, preferred);

exit:
    return;
}

void Seeker::SaveCandidate(const ScanResult &aResult, bool aPreferred)
{
    Error                         error           = kErrorNone;
    const MeshCoP::ExtendedPanId &extPanId        = AsCoreType(&aResult.mExtendedPanId);
    bool                          shouldPushAsNew = false;
    CandidateEntry                entry;

    if (mCandidates.FindMatching(entry, extPanId, AsCoreType(&aResult.mExtAddress)) == kErrorNone)
    {
        entry.Log(Candidate::kReplace);
    }
    else
    {
        uint16_t count = CountAndSelectLeastFavoredCandidateFor(extPanId, entry);

        if (count == kMaxCandidatesPerNetwork)
        {
            entry.Log(Candidate::kReplace);
        }
        else if (mCandidates.IsFull())
        {
            error = (count == 0) ? EvictCandidate(entry) : kErrorNoBufs;
        }
        else
        {
            shouldPushAsNew = true;
        }
    }

    entry.SetFrom(aResult, aPreferred);

    if (error != kErrorNone)
    {
        entry.Log(Candidate::kDrop);
        ExitNow();
    }

    if (shouldPushAsNew)
    {
        IgnoreError(mCandidates.Push(entry));
    }
    else
    {
        IgnoreError(mCandidates.Write(entry));
    }

    entry.Log(Candidate::kSave);

exit:
    return;
}

Error Seeker::EvictCandidate(CandidateEntry &aEntry)
{
    Error          error = kErrorNoBufs;
    CandidateEntry entry;

    for (entry.InitForIteration(); mCandidates.ReadNext(entry) == kErrorNone;)
    {
        uint16_t count = CountAndSelectLeastFavoredCandidateFor(entry.mExtPanId, aEntry);

        if (count > 1)
        {
            aEntry.Log(Candidate::kEvict);
            error = kErrorNone;
            break;
        }
    }

    return error;
}

Error Seeker::SetUpNextConnection(Ip6::SockAddr &aSockAddr)
{
    Error          error = kErrorNone;
    CandidateEntry entry;

    switch (GetState())
    {
    case kStateDiscoverDone:
        SetState(kStateConnectingNetworks);
        break;

    case kStateConnectingNetworks:
    case kStateConnectingAny:
        break;

    case kStateStopped:
    case kStateDiscovering:
        ExitNow(error = kErrorInvalidState);
    }

    error = SelectNextCandidate(entry);

    if (error != kErrorNone)
    {
        Stop();
        ExitNow();
    }

    entry.Log(Candidate::kConnect);

    entry.mConnAttempted = true;
    IgnoreError(mCandidates.Write(entry));

    Get<Mac::Mac>().SetPanId(entry.mPanId);
    SuccessOrExit(error = Get<Mac::Mac>().SetPanChannel(entry.mChannel));

    if (!Get<Ip6::Filter>().IsUnsecurePort(kUdpPort))
    {
        SuccessOrExit(error = Get<Ip6::Filter>().AddUnsecurePort(kUdpPort));
    }

    aSockAddr.Clear();
    aSockAddr.SetPort(entry.mJoinerUdpPort);
    aSockAddr.GetAddress().SetToLinkLocalAddress(entry.mExtAddr);

exit:
    return error;
}

Error Seeker::SelectNextCandidate(CandidateEntry &aEntry)
{
    CandidateEntry entry;

    if (mState == kStateConnectingNetworks)
    {
        // While in `kStateConnectingNetworks` we try to first cover all
        // discovered networks (Extended PAN IDs). We determine the most
        // favored candidate among all discovered networks which is not
        // yet been attempted.

        aEntry.MarkAsEmpty();

        for (entry.InitForIteration(); mCandidates.ReadNext(entry) == kErrorNone;)
        {
            CandidateEntry mathcingPanEntry;

            if (SelectMostFavoredCandidateFor(entry.mExtPanId, mathcingPanEntry) == kErrorNone)
            {
                aEntry.ReplaceWithIfFavored(mathcingPanEntry);
            }
        }

        if (!aEntry.IsEmpty())
        {
            ExitNow();
        }

        // If we have already covered the most favored candidate per Network
        // (Extended PAN ID), we switch to `kStateConnectingAny` where we
        // try any remaining discovered candidates (e.g. backup candidates
        // associated with same networks).

        mState = kStateConnectingAny;
    }

    for (entry.InitForIteration(); mCandidates.ReadNext(entry) == kErrorNone;)
    {
        if (entry.mConnAttempted)
        {
            continue;
        }

        aEntry.ReplaceWithIfFavored(entry);
    }

exit:
    return aEntry.IsEmpty() ? kErrorNotFound : kErrorNone;
}

uint16_t Seeker::CountAndSelectLeastFavoredCandidateFor(const MeshCoP::ExtendedPanId &aExtPanId,
                                                        CandidateEntry               &aEntry) const
{
    // Goes through all candidates for a given network (matching a
    // given Extended PAN ID). Returns the number of such entries,
    // also determines the the lease favored matching entry and
    // return it is `aEntry`. This is then used to decide whether
    // to replace an existing candidate entry with a new one.

    uint16_t       count = 0;
    CandidateEntry entry;

    for (entry.InitForIteration(); mCandidates.ReadNext(entry) == kErrorNone;)
    {
        if (!entry.Matches(aExtPanId))
        {
            continue;
        }

        count++;

        if ((count == 1) || aEntry.IsFavoredOver(entry))
        {
            aEntry = entry;
        }
    }

    return count;
}

Error Seeker::SelectMostFavoredCandidateFor(MeshCoP::ExtendedPanId &aExtPanId, CandidateEntry &aFavoredEntry) const
{
    // Goes through all candidates associated with a given network
    // (matching `aExtP). If connection has been already attempted
    // with any such candidate, `kErrorAlready` is returned.
    // Otherwise, the most favored such candidate is determined and
    // returned in `aFavoredEntry`.

    Error          error = kErrorNone;
    CandidateEntry entry;

    aFavoredEntry.MarkAsEmpty();

    for (entry.InitForIteration(); mCandidates.ReadNext(entry) == kErrorNone;)
    {
        if (!entry.Matches(aExtPanId))
        {
            continue;
        }

        if (entry.mConnAttempted)
        {
            error = kErrorAlready;
            ExitNow();
        }

        aFavoredEntry.ReplaceWithIfFavored(entry);
    }

exit:
    return error;
}

//---------------------------------------------------------------------------------------------------------------------
// Seeker::Candidate

void Seeker::Candidate::SetFrom(const ScanResult &aResult, bool aPreferred)
{
    mExtPanId      = AsCoreType(&aResult.mExtendedPanId);
    mExtAddr       = AsCoreType(&aResult.mExtAddress);
    mPanId         = aResult.mPanId;
    mJoinerUdpPort = aResult.mJoinerUdpPort;
    mChannel       = aResult.mChannel;
    mRssi          = aResult.mRssi;
    mPreferred     = aPreferred;
    mConnAttempted = false;
}

bool Seeker::Candidate::IsFavoredOver(const Candidate &aOther) const
{
    int compare;

    compare = ThreeWayCompare(mPreferred, aOther.mPreferred);
    VerifyOrExit(compare == 0);
    compare = ThreeWayCompare(mRssi, aOther.mRssi);

exit:
    return (compare > 0);
}

bool Seeker::Candidate::Matches(const MeshCoP::ExtendedPanId &aExtPanId, const Mac::ExtAddress &aExtAddr) const
{
    return (mExtPanId == aExtPanId) && (mExtAddr == aExtAddr);
}

#if OT_SHOULD_LOG_AT(OT_LOG_LEVEL_INFO)

const char *Seeker::Candidate::ActionToString(Action aAction)
{
#define ActionMapList(_)     \
    _(kSave, "Saving")       \
    _(kReplace, "Replacing") \
    _(kEvict, "Evicting")    \
    _(kDrop, "Dropping")     \
    _(kConnect, "Connecting to")

    DefineEnumStringArray(ActionMapList);

    return kStrings[aAction];
}

void Seeker::Candidate::Log(Action aAction) const
{
    LogInfo("%s candidate:", ActionToString(aAction));
    LogInfo("   ext-panid: %s", mExtPanId.ToString().AsCString());
    LogInfo("   ext-addr: %s", mExtAddr.ToString().AsCString());
    LogInfo("   panid: 0x%04x", mPanId);
    LogInfo("   channel: %u", mChannel);
    LogInfo("   rssi: %d", mRssi);
    LogInfo("   preferred: %s", ToYesNo(mPreferred));
    LogInfo("   joiner-port: %u", mJoinerUdpPort);
}

#else
void Seeker::Candidate::Log(Action) const {}
#endif

//----------------------------------------------------------------------------------------------------------------------
// Seeker::CanidateEntry

void Seeker::CandidateEntry::ReplaceWithIfFavored(const CandidateEntry &aEntry)
{
    // Replaces this entry with `aEntry` if this entry itself is
    // empty (not yet set) or if the new given `aEntry` is favored
    // over the current one.

    if (IsEmpty() || aEntry.IsFavoredOver(*this))
    {
        *this = aEntry;
    }
}

} // namespace MeshCoP
} // namespace ot

#endif // OPENTHREAD_CONFIG_JOINER_ENABLE
