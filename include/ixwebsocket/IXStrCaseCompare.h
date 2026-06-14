/*
 *  IXStrCaseCompare.h
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2020 Machine Zone. All rights reserved.
 */

#pragma once

#include <string>
#include <string_view>

namespace ix
{
    struct CaseInsensitiveLess
    {
        // Case Insensitive compare_less binary function
        struct NocaseCompare
        {
            bool operator()(const unsigned char& c1, const unsigned char& c2) const;
        };

        static bool cmp(const std::string& s1, const std::string& s2);

        bool operator()(const std::string& s1, const std::string& s2) const;
    };

    bool caseInsensitiveEquals(const std::string& a, const std::string& b);

    bool caseInsensitiveEquals(std::string_view a, std::string_view b);

    bool caseInsensitiveStartsWith(std::string_view value, std::string_view prefix);
} // namespace ix
