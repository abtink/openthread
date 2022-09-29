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
 *   This file includes definitions for Thread URIs.
 */

#ifndef URI_PATHS_HPP_
#define URI_PATHS_HPP_

#include "openthread-core-config.h"

#include "common/error.hpp"

namespace ot {

/**
 * This enumeration represents Thread URIs.
 *
 */
enum Uri : uint8_t
{
    kUriAddressError,           // "a/ae"
    kUriAddressNotify,          // "a/an"
    kUriAddressQuery,           // "a/aq"
    kUriAddressRelease,         // "a/ar"
    kUriAddressSolicit,         // "a/as"
    kUriServerData,             // "a/sd"
    kUriAnycastLocate,          // "a/yl"
    kUriBackboneAnswer,         // "b/ba"
    kUriBackboneMlr,            // "b/bmr"
    kUriBackboneQuery,          // "b/bq"
    kUriAnnounceBegin,          // "c/ab"
    kUriActiveGet,              // "c/ag"
    kUriActiveSet,              // "c/as"
    kUriCommissionerKeepAlive,  // "c/ca"
    kUriCommissionerGet,        // "c/cg"
    kUriCommissionerPetition,   // "c/cp"
    kUriCommissionerSet,        // "c/cs"
    kUriDatasetChanged,         // "c/dc"
    kUriEnergyReport,           // "c/er"
    kUriEnergyScan,             // "c/es"
    kUriJoinerEntrust,          // "c/je"
    kUriJoinerFinalize,         // "c/jf"
    kUriLeaderKeepAlive,        // "c/la"
    kUriLeaderPetition,         // "c/lp"
    kUriPanIdConflict,          // "c/pc"
    kUriPendingGet,             // "c/pg"
    kUriPanIdQuery,             // "c/pq"
    kUriPendingSet,             // "c/ps"
    kUriRelayRx,                // "c/rx"
    kUriRelayTx,                // "c/tx"
    kUriProxyRx,                // "c/ur"
    kUriProxyTx,                // "c/ut"
    kUriDiagnosticGetAnswer,    // "d/da"
    kUriDiagnosticGetRequest,   // "d/dg"
    kUriDiagnosticGetQuery,     // "d/dq"
    kUriDiagnosticReset,        // "d/dr"
    kUriDuaRegistrationNotify,  // "n/dn"
    kUriDuaRegistrationRequest, // "n/dr"
    kUriMlr,                    // "n/mr"
    kUriUnknown,                // Unknown URI
};

/**
 * This function returns URI path string for a given URI.
 *
 * @param[in] aUri   A URI.
 *
 * @returns The path string for @p aUri.
 *
 */
const char *PathForUri(Uri aUri);

/**
 * This function looks up the URI from a given path string.
 *
 * @param[in] aPath    A path string.
 *
 * @returns The URI associated with @p aPath or `kUriUnknown` if no match was found.
 *
 */
Uri UriFromPath(const char *aPath);

} // namespace ot

#endif // URI_PATHS_HPP_
