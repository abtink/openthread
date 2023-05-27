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

/**
 * @file
 *   This file includes definitions for Backbone Router config.
 */

#ifndef BACKBONE_ROUTER_CONFIG_HPP_
#define BACKBONE_ROUTER_CONFIG_HPP_

#include "openthread-core-config.h"

#if (OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2)

#include <openthread/backbone_router.h>

#include "common/error.hpp"
#include "common/equatable.hpp"
#include "common/as_core_type.hpp"
#include "mac/mac_types.hpp"

namespace ot {
namespace BackboneRouter {

/**
 * Represents Backbone Router configuration.
 *
 */
class Config : public otBackboneRouterConfig, public Unequatable<Config>
{
public:
    /**
     * Sets Primary Backbone Router `mServer16` field to invalid `Mac::kShortAddrInvalid`.
     *
     */
    void SetServer16ToInvalid(void) { mServer16 = Mac::kShortAddrInvalid; }

    /**
     * Indicates whether or not Primary Backbone Router `mServer16` is valid.
     *
     * @retval TRUE   If the Primary Backbone Router `mServer16` is valid.
     * @retval FALSE  If the Primary Backbone Router `mServer16` is not valid.
     *
     */
    bool IsServer16Valid(void) const { return (mServer16 != Mac::kShortAddrInvalid); }

    /**
     * Overloads operator `==` to evaluate whether or not two `Config` instances are equal.
     *
     * @param[in]  aOther  The other `Config` to compare with.
     *
     * @retval TRUE   If the two `Config` instances are equal.
     * @retval FALSE  If the two `Config` instances are not equal.
     *
     */
    bool operator==(const Config &aOther);
};

} // namespace BackboneRouter

DefineCoreType(otBackboneRouterConfig, BackboneRouter::Config);

} // namespace ot

#endif // (OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2)

#endif // BACKBONE_ROUTER_CONFIG_HPP_
