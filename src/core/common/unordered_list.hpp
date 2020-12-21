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
 *   This file includes definitions for a generic unordered list.
 */

#ifndef UNORDERED_LIST_HPP_
#define UNORDERED_LIST_HPP_

#include "openthread-core-config.h"

#include <openthread/error.h>

namespace ot {

/**
 * @addtogroup core-unordered-list
 *
 * @brief
 *   This module includes definitions for OpenThread Unordered List.
 *
 * @{
 *
 */

/**
 * This template class represents an unordered list.
 *
 * TODO:
 * The template type `Type` should provide `GetNext()` and `SetNext()` methods (which can be realized by `Type`
 * inheriting from `LinkedListEntry<Type>` class).
 *
 */
template <typename Type, uint16_t kSize> class UnorderedList
{
public:
    /**
     * This constructor initializes the list.
     *
     */
    UnorderedList(void) { Clear(); }

    /**
     * This method clears the list and all entries in it.
     *
     */
    void Clear(void)
    {
        for (Type &entry : mEntries)
        {
            entry.Clear();
        }
    }

    /**
     * This method indicates whether the list is empty or not.
     *
     * @retval TRUE   If the linked list is empty.
     * @retval FALSE  If the linked list is not empty.
     *
     */
    bool IsEmpty(void) const { return !mEntries[0].IsInUse(); }

    /**
     * This method indicates whether the list is full or not.
     *
     * @retval TRUE   If the linked list is full.
     * @retval FALSE  If the linked list is not full.
     *
     */
    bool IsFull(void) const { return mEntries[kSize - 1].IsInUse(); }

    /**
     * This template method searches within the list to find an entry matching a given indicator.
     *
     * The template type `Indicator` specifies the type of @p aIndicator object which is used to match against entries
     * in the list. To check that an entry matches the given indicator, the `Matches()` method is invoked on each
     * `Type` entry in the list. The `Matches()` method should be provided by `Type` class accordingly:
     *
     *     bool Type::Matches(const Indicator &aIndicator) const
     *
     * @param[in]  aIndicator  An indicator to match with entries in the list.
     *
     * @returns A pointer to the matching entry if one is found, or nullptr if no matching entry was found in the list.
     *
     */
    template <typename Indicator> const Type *FindMatching(const Indicator &aIndicator) const
    {
        uint16_t index;

        return (Find(aIndicator, &index) == OT_ERROR_NONE) ? mEntries[index] : nullptr;
    }

    // Adds a new entry if no matching entry is already present in the list matching
    template <typename Indicator> otError AddMatching(const Indicator &aIndicator, Type *&aEntry)
    {
        otError  error = OT_ERROR_NONE;
        uint16_t index;
        uint16_t endIndex;

        if (Find(aIndicator, index, &endIndex) == OT_ERROR_NONE)
        {
            error  = OT_ERROR_ALREADY;
            aEntry = mEntries[index];
        }
        else if (endIndex < kSize)
        {
            aEntry = mEntries[endIndex];
        }
        else
        {
            error  = OT_ERROR_NO_BUFS;
            aEntry = nullptr;
        }

        return error;
    }

    /**
     * This template method removes an entry matching a given entry indicator from the linked list.
     *
     * The template type `Indicator` specifies the type of @p aIndicator object which is used to match against entries
     * in the list. To check that an entry matches the given indicator, the `Matches()` method is invoked on each
     * `Type` entry in the list. The `Matches()` method should be provided by `Type` class accordingly:
     *
     *     bool Type::Matches(const Indicator &aIndicator) const
     *
     * @note This method does not change the removed entry itself (which is returned in case of success), i.e., the
     * entry next pointer stays as before.
     *
     *
     * @param[in] aIndicator   An entry indicator to match against entries in the list.
     *
     * @returns A pointer to the removed matching entry if one could be found, or nullptr if no matching entry is found.
     *
     */
    template <typename Indicator> otError RemoveMatching(const Indicator &aIndicator)
    {
        otError  error = OT_ERROR_NONE;
        uint16_t index;
        uint16_t endIndex;

        error = Find(aIndicator, index, &endIndex);

        if (error == OT_ERROR_NONE)
        {
            // Replace the entry with the one at the endIndex...
            if (index != endIndex - 1)
            {
                mEntries[index] = mEntries[endIndex - 1];
            }

            mEntries[endIndex - 1].Clear();
        }

        return error;
    }

private:
    template <typename Indicator>
    otError Find(const Indicator &aIndicator, uint16_t &aIndex, uint16_t *aEndIndex = nullptr) const
    {
        otError  error = OT_ERROR_NOT_FOUND;
        uint16_t index;

        for (index = 0; index < kSize; index++)
        {
            const Type &entry = mEntries[index];

            if (!entry.IsInUse())
            {
                break;
            }

            if (mEntries[index].Matches(aIndicator))
            {
                error  = OT_ERROR_NONE;
                aIndex = index;

                if (aEndIndex == nullptr)
                {
                    break;
                }
            }
        }

        if (aEndIndex != nullptr)
        {
            *aEndIndex = index;
        }

        return error;
    }

    Type mEntries[kSize];
};

/**
 * @}
 *
 */

} // namespace ot

#endif // UNORDERED_LIST_HPP_
