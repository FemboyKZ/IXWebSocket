/*
 *  IXStrCaseCompare.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2020 Machine Zone. All rights reserved.
 */

#include "IXStrCaseCompare.h"

#include <algorithm>
#include <locale>
#include <string_view>

namespace ix
{
    bool CaseInsensitiveLess::NocaseCompare::operator()(const unsigned char& c1,
                                                        const unsigned char& c2) const
    {
#if defined(_WIN32) && !defined(__GNUC__)
        return std::tolower(c1, std::locale()) < std::tolower(c2, std::locale());
#else
        return std::tolower(c1) < std::tolower(c2);
#endif
    }

    bool CaseInsensitiveLess::cmp(const std::string& s1, const std::string& s2)
    {
        return std::lexicographical_compare(s1.begin(),
                                            s1.end(), // source range
                                            s2.begin(),
                                            s2.end(),         // dest range
                                            NocaseCompare()); // comparison
    }

    bool CaseInsensitiveLess::operator()(const std::string& s1, const std::string& s2) const
    {
        return CaseInsensitiveLess::cmp(s1, s2);
    }

    bool caseInsensitiveEquals(std::string_view a, std::string_view b)
    {
        if (a.size() != b.size()) return false;
        return std::equal(a.begin(), a.end(), b.begin(), [](unsigned char c1, unsigned char c2) {
#if defined(_WIN32) && !defined(__GNUC__)
            return std::tolower(c1, std::locale()) == std::tolower(c2, std::locale());
#else
            return std::tolower(c1) == std::tolower(c2);
#endif
        });
    }

    bool caseInsensitiveEquals(const std::string& a, const std::string& b)
    {
        return caseInsensitiveEquals(std::string_view(a), std::string_view(b));
    }

    bool caseInsensitiveStartsWith(std::string_view value, std::string_view prefix)
    {
        if (value.size() < prefix.size())
        {
            return false;
        }

        return caseInsensitiveEquals(value.substr(0, prefix.size()), prefix);
    }
} // namespace ix
