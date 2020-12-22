/*
 *  Copyright (c) 2019, The OpenThread Authors.
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
 *   This file implements a simple CLI for the SRP server.
 */

#include "cli_srp_server.hpp"

#include <inttypes.h>

#include "cli/cli.hpp"
#include "common/string.hpp"
#include "utils/parse_cmdline.hpp"

#if OPENTHREAD_CONFIG_SRP_SERVER_ENABLE

namespace ot {
namespace Cli {

constexpr SrpServer::Command SrpServer::sCommands[];

otError SrpServer::Process(uint8_t aArgsLength, char *aArgs[])
{
    otError        error = OT_ERROR_INVALID_COMMAND;
    const Command *command;

    VerifyOrExit(aArgsLength != 0, IgnoreError(ProcessHelp(0, nullptr)));

    command = Utils::LookupTable::Find(aArgs[0], sCommands);
    VerifyOrExit(command != nullptr);

    error = (this->*command->mHandler)(aArgsLength, aArgs);

exit:
    return error;
}

otError SrpServer::ProcessEnable(uint8_t aArgsLength, char *aArgs[])
{
    OT_UNUSED_VARIABLE(aArgsLength);
    OT_UNUSED_VARIABLE(aArgs);

    otSrpServerSetEnabled(mInterpreter.mInstance, /* aEnabled */ true);

    return OT_ERROR_NONE;
}

otError SrpServer::ProcessDisable(uint8_t aArgsLength, char *aArgs[])
{
    OT_UNUSED_VARIABLE(aArgsLength);
    OT_UNUSED_VARIABLE(aArgs);

    otSrpServerSetEnabled(mInterpreter.mInstance, /* aEnabled */ false);

    return OT_ERROR_NONE;
}

otError SrpServer::ProcessLease(uint8_t aArgsLength, char *aArgs[])
{
    otError  error = OT_ERROR_NONE;
    uint32_t minLease;
    uint32_t maxLease;
    uint32_t minKeyLease;
    uint32_t maxKeyLease;

    VerifyOrExit(aArgsLength == 5, error = OT_ERROR_INVALID_ARGS);
    SuccessOrExit(error = Utils::CmdLineParser::ParseAsUint32(aArgs[1], minLease));
    SuccessOrExit(error = Utils::CmdLineParser::ParseAsUint32(aArgs[2], maxLease));
    SuccessOrExit(error = Utils::CmdLineParser::ParseAsUint32(aArgs[3], minKeyLease));
    SuccessOrExit(error = Utils::CmdLineParser::ParseAsUint32(aArgs[4], maxKeyLease));

    error = otSrpServerSetLeaseRange(mInterpreter.mInstance, minLease, maxLease, minKeyLease, maxKeyLease);

exit:
    return error;
}

otError SrpServer::ProcessHost(uint8_t aArgsLength, char *aArgs[])
{
    OT_UNUSED_VARIABLE(aArgs);

    otError                error = OT_ERROR_NONE;
    const otSrpServerHost *host;

    VerifyOrExit(aArgsLength <= 1, error = OT_ERROR_INVALID_ARGS);

    host = nullptr;
    while ((host = otSrpServerGetNextHost(mInterpreter.mInstance, host)) != nullptr)
    {
        const otIp6Address *addresses;
        uint8_t             addressesNum;

        mInterpreter.OutputLine(otSrpServerHostGetFullName(host));

        mInterpreter.OutputSpaces(Interpreter::kIndentSize);
        mInterpreter.OutputFormat("addresses: ");

        addresses = otSrpServerHostGetAddresses(host, &addressesNum);

        for (uint8_t i = 0; i < addressesNum; ++i)
        {
            mInterpreter.OutputIp6Address(addresses[i]);
            mInterpreter.OutputSpaces(2);
        }

        mInterpreter.OutputFormat("\r\n");
    }

exit:
    return error;
}

otError SrpServer::ProcessService(uint8_t aArgsLength, char *aArgs[])
{
    OT_UNUSED_VARIABLE(aArgs);

    otError                error = OT_ERROR_NONE;
    const otSrpServerHost *host;

    VerifyOrExit(aArgsLength <= 1, error = OT_ERROR_INVALID_ARGS);

    host = nullptr;
    while ((host = otSrpServerGetNextHost(mInterpreter.mInstance, host)) != nullptr)
    {
        for (const otSrpServerService *service = otSrpServerHostGetServices(host); service != nullptr;
             service                           = service->mNext)
        {
            const otIp6Address *addresses;
            uint8_t             addressesNum;

            mInterpreter.OutputLine(service->mFullName);
            mInterpreter.OutputLine(Interpreter::kIndentSize, "host: %s", otSrpServerHostGetFullName(host));
            mInterpreter.OutputLine(Interpreter::kIndentSize, "priority: %hu", service->mPriority);
            mInterpreter.OutputLine(Interpreter::kIndentSize, "weight: %hu", service->mWeight);
            mInterpreter.OutputLine(Interpreter::kIndentSize, "port: %hu", service->mPort);

            mInterpreter.OutputSpaces(Interpreter::kIndentSize);
            mInterpreter.OutputFormat("addresses: ");

            addresses = otSrpServerHostGetAddresses(host, &addressesNum);
            for (uint8_t i = 0; i < addressesNum; ++i)
            {
                mInterpreter.OutputIp6Address(addresses[i]);
                mInterpreter.OutputSpaces(2);
            }
            mInterpreter.OutputFormat("\r\n");

            if (service->mTxtData != nullptr)
            {
                mInterpreter.OutputSpaces(Interpreter::kIndentSize);
                mInterpreter.OutputFormat("txt: ");
                mInterpreter.OutputBytes(service->mTxtData, service->mTxtLength);
                mInterpreter.OutputFormat("\r\n");
            }
        }
    }

exit:
    return error;
}

otError SrpServer::ProcessHelp(uint8_t aArgsLength, char *aArgs[])
{
    OT_UNUSED_VARIABLE(aArgsLength);
    OT_UNUSED_VARIABLE(aArgs);

    for (const Command &command : sCommands)
    {
        mInterpreter.OutputLine(command.mName);
    }

    return OT_ERROR_NONE;
}

} // namespace Cli
} // namespace ot

#endif // OPENTHREAD_CONFIG_SRP_SERVER_ENABLE
