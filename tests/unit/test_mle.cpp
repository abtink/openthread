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


#include <functional>
#include <type_traits>

#include "test_util.h"


/*
#include "test_platform.h"
#include "test_util.hpp"


#include "common/num_utils.hpp"
#include "thread/mle_types.hpp"
*/

namespace ot {

#if 0 // OPENTHREAD_FTD && (OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_3_1)

void TestDefaultDeviceProperties(void)
{
    Instance                 *instance;
    const otDeviceProperties *props;
    uint8_t                   weight;

    instance = static_cast<Instance *>(testInitInstance());
    VerifyOrQuit(instance != nullptr);

    props = otThreadGetDeviceProperties(instance);

    VerifyOrQuit(props->mPowerSupply == OPENTHREAD_CONFIG_DEVICE_POWER_SUPPLY);
    VerifyOrQuit(!props->mSupportsCcm);
    VerifyOrQuit(!props->mIsUnstable);
    VerifyOrQuit(props->mLeaderWeightAdjustment == OPENTHREAD_CONFIG_MLE_DEFAULT_LEADER_WEIGHT_ADJUSTMENT);
#if OPENTHREAD_CONFIG_BORDER_ROUTING_ENABLE
    VerifyOrQuit(props->mIsBorderRouter);
#else
    VerifyOrQuit(!props->mIsBorderRouter);
#endif

    weight = 64;

    switch (props->mPowerSupply)
    {
    case OT_POWER_SUPPLY_BATTERY:
        weight -= 8;
        break;
    case OT_POWER_SUPPLY_EXTERNAL:
        break;
    case OT_POWER_SUPPLY_EXTERNAL_STABLE:
        weight += 4;
        break;
    case OT_POWER_SUPPLY_EXTERNAL_UNSTABLE:
        weight -= 4;
        break;
    }

    weight += props->mIsBorderRouter ? 1 : 0;

    VerifyOrQuit(otThreadGetLocalLeaderWeight(instance) == weight);

    printf("TestDefaultDeviceProperties passed\n");
}

void CompareDevicePropertiess(const otDeviceProperties &aFirst, const otDeviceProperties &aSecond)
{
    static constexpr int8_t kMinAdjustment = -16;
    static constexpr int8_t kMaxAdjustment = +16;

    VerifyOrQuit(aFirst.mPowerSupply == aSecond.mPowerSupply);
    VerifyOrQuit(aFirst.mIsBorderRouter == aSecond.mIsBorderRouter);
    VerifyOrQuit(aFirst.mSupportsCcm == aSecond.mSupportsCcm);
    VerifyOrQuit(aFirst.mIsUnstable == aSecond.mIsUnstable);
    VerifyOrQuit(Clamp(aFirst.mLeaderWeightAdjustment, kMinAdjustment, kMaxAdjustment) ==
                 Clamp(aSecond.mLeaderWeightAdjustment, kMinAdjustment, kMaxAdjustment));
}

void TestLeaderWeightCalculation(void)
{
    struct TestCase
    {
        otDeviceProperties mDeviceProperties;
        uint8_t            mExpectedLeaderWeight;
    };

    static const TestCase kTestCases[] = {
        {{OT_POWER_SUPPLY_BATTERY, false, false, false, 0}, 56},
        {{OT_POWER_SUPPLY_EXTERNAL, false, false, false, 0}, 64},
        {{OT_POWER_SUPPLY_EXTERNAL_STABLE, false, false, false, 0}, 68},
        {{OT_POWER_SUPPLY_EXTERNAL_UNSTABLE, false, false, false, 0}, 60},

        {{OT_POWER_SUPPLY_BATTERY, true, false, false, 0}, 57},
        {{OT_POWER_SUPPLY_EXTERNAL, true, false, false, 0}, 65},
        {{OT_POWER_SUPPLY_EXTERNAL_STABLE, true, false, false, 0}, 69},
        {{OT_POWER_SUPPLY_EXTERNAL_UNSTABLE, true, false, false, 0}, 61},

        {{OT_POWER_SUPPLY_BATTERY, true, true, false, 0}, 64},
        {{OT_POWER_SUPPLY_EXTERNAL, true, true, false, 0}, 72},
        {{OT_POWER_SUPPLY_EXTERNAL_STABLE, true, true, false, 0}, 76},
        {{OT_POWER_SUPPLY_EXTERNAL_UNSTABLE, true, true, false, 0}, 68},

        // Check when `mIsUnstable` is set.
        {{OT_POWER_SUPPLY_BATTERY, false, false, true, 0}, 56},
        {{OT_POWER_SUPPLY_EXTERNAL, false, false, true, 0}, 60},
        {{OT_POWER_SUPPLY_EXTERNAL_STABLE, false, false, true, 0}, 64},
        {{OT_POWER_SUPPLY_EXTERNAL_UNSTABLE, false, false, true, 0}, 60},

        {{OT_POWER_SUPPLY_BATTERY, true, false, true, 0}, 57},
        {{OT_POWER_SUPPLY_EXTERNAL, true, false, true, 0}, 61},
        {{OT_POWER_SUPPLY_EXTERNAL_STABLE, true, false, true, 0}, 65},
        {{OT_POWER_SUPPLY_EXTERNAL_UNSTABLE, true, false, true, 0}, 61},

        // Include non-zero `mLeaderWeightAdjustment`.
        {{OT_POWER_SUPPLY_BATTERY, true, false, false, 10}, 67},
        {{OT_POWER_SUPPLY_EXTERNAL, true, false, false, 10}, 75},
        {{OT_POWER_SUPPLY_EXTERNAL_STABLE, true, false, false, 10}, 79},
        {{OT_POWER_SUPPLY_EXTERNAL_UNSTABLE, true, false, false, 10}, 71},

        {{OT_POWER_SUPPLY_BATTERY, false, false, false, -10}, 46},
        {{OT_POWER_SUPPLY_EXTERNAL, false, false, false, -10}, 54},
        {{OT_POWER_SUPPLY_EXTERNAL_STABLE, false, false, false, -10}, 58},
        {{OT_POWER_SUPPLY_EXTERNAL_UNSTABLE, false, false, false, -10}, 50},

        // Use `mLeaderWeightAdjustment` larger than valid range
        // Make sure it clamps to -16 and +16.
        {{OT_POWER_SUPPLY_BATTERY, false, false, false, 20}, 72},
        {{OT_POWER_SUPPLY_EXTERNAL, false, false, false, 20}, 80},
        {{OT_POWER_SUPPLY_EXTERNAL_STABLE, false, false, false, 20}, 84},
        {{OT_POWER_SUPPLY_EXTERNAL_UNSTABLE, false, false, false, 20}, 76},

        {{OT_POWER_SUPPLY_BATTERY, true, false, false, -20}, 41},
        {{OT_POWER_SUPPLY_EXTERNAL, true, false, false, -20}, 49},
        {{OT_POWER_SUPPLY_EXTERNAL_STABLE, true, false, false, -20}, 53},
        {{OT_POWER_SUPPLY_EXTERNAL_UNSTABLE, true, false, false, -20}, 45},
    };

    Instance *instance;

    instance = static_cast<Instance *>(testInitInstance());
    VerifyOrQuit(instance != nullptr);

    for (const TestCase &testCase : kTestCases)
    {
        otThreadSetDeviceProperties(instance, &testCase.mDeviceProperties);
        CompareDevicePropertiess(testCase.mDeviceProperties, *otThreadGetDeviceProperties(instance));
        VerifyOrQuit(otThreadGetLocalLeaderWeight(instance) == testCase.mExpectedLeaderWeight);
    }

    printf("TestLeaderWeightCalculation passed\n");
}

#endif // #if OPENTHREAD_FTD && (OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_3_1)


} // namespace ot

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

template <class T> class OnceCallback;


/**
 * A callback which can be invoked at most once.
 *
 * IsNull is guaranteed to return true once the callback has been invoked.
 *
 * Example usage:
 *  OnceCallback<int(int)> square([](int x) { return x * x; });
 *  std::move(square)(5); // Returns 25.
 *  std::move(square)(6); // Crashes since `square` has already run.
 *  square(7); // Compiling error.
 *
 * Inspired by Chromium base::OnceCallback
 * (https://chromium.googlesource.com/chromium/src.git/+/refs/heads/main/base/callback.h).
 *
 */
template <typename R, typename... Args> class OnceCallback<R(Args...)>
{
public:
    // Constructs a new `OnceCallback` instance with a callable.
    //
    // This constructor is for matching std::function<> and lambda and the
    // `std::enable_if_t` check is only required for working around gcc 4.x
    // compiling issue which trying to instantiate this template constructor
    // for use cases like `::mOnceCallback(aOnceCallback)`.
    template <typename T, typename = typename std::enable_if<!std::is_same<OnceCallback, T>::value>::type>
    OnceCallback(T &&func)
        : mFunc(std::forward<T>(func))
    {
    }

    OnceCallback(const OnceCallback &)            = delete;
    OnceCallback &operator=(const OnceCallback &) = delete;
    OnceCallback(OnceCallback &&)                 = default;
    OnceCallback &operator=(OnceCallback &&)      = default;

    R operator()(Args...) const &
    {
        static_assert(!sizeof(*this), "OnceCallback::() can only be invoked on a non-const "
                                      "rvalue, i.e. std::move(callback)().");
    }

    R operator()(Args... args) &&
    {
        // Move `this` to a local variable to clear internal state
        // before invoking the callback function.
        OnceCallback cb = std::move(*this);

        return cb.mFunc(std::forward<Args>(args)...);
    }

    bool IsNull() const { return mFunc == nullptr; }

private:
    std::function<R(Args...)> mFunc;
};

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

typedef OnceCallback<void(void)> SimpleOnceCallback;

static uint16_t gCallCaounter = 0;

void TestFunc(void)
{
    gCallCaounter++;
    printf("TestFunc() is called - gCallCaounter=%u\n", gCallCaounter);
}

void InvokeCallbackTwice(SimpleOnceCallback &&aCallback)
{
    printf("In InvokeCallbackTwice()\n");

    printf("  aCallback.IsNull() = %d\n", aCallback.IsNull());

    std::move(aCallback)();

    printf("  aCallback.IsNull() = %d\n", aCallback.IsNull());

    std::move(aCallback)();
}


int main(void)
{
    SimpleOnceCallback callback(TestFunc);


    printf("callback.IsNull() = %d\n", callback.IsNull());

    InvokeCallbackTwice(std::move(callback));

    printf("callback.IsNull() = %d - After InvokeCallbackTwice() \n", callback.IsNull());

    InvokeCallbackTwice(std::move(callback));

    VerifyOrQuit(gCallCaounter == 1);
}
