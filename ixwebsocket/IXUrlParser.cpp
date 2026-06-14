/*
 * Lightweight URL & URI parser (RFC 1738, RFC 3986)
 * https://github.com/corporateshark/LUrlParser
 *
 * The MIT License (MIT)
 *
 * Copyright (C) 2015 Sergey Kosarevsky (sk@linderdaum.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 *  IXUrlParser.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2019 Machine Zone, Inc. All rights reserved.
 */

#include "IXUrlParser.h"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstring>

namespace
{
    bool containsInvalidUrlCharacter(const std::string& url)
    {
        for (unsigned char c : url)
        {
            if (c <= 0x20 || c == 0x7f)
            {
                return true;
            }
        }

        return false;
    }

    enum LUrlParserError
    {
        LUrlParserError_Ok = 0,
        LUrlParserError_Uninitialized = 1,
        LUrlParserError_NoUrlCharacter = 2,
        LUrlParserError_InvalidSchemeName = 3,
        LUrlParserError_NoDoubleSlash = 4,
        LUrlParserError_NoAtSign = 5,
        LUrlParserError_UnexpectedEndOfLine = 6,
        LUrlParserError_NoSlash = 7,
    };

    class clParseURL
    {
    public:
        LUrlParserError m_ErrorCode;
        std::string m_Scheme;
        std::string m_Host;
        std::string m_Port;
        std::string m_Path;
        std::string m_Query;
        std::string m_Fragment;
        std::string m_UserName;
        std::string m_Password;
        bool m_HasPort;

        clParseURL()
            : m_ErrorCode(LUrlParserError_Uninitialized)
            , m_HasPort(false)
        {
        }

        /// return 'true' if the parsing was successful
        bool IsValid() const
        {
            return m_ErrorCode == LUrlParserError_Ok;
        }

        /// helper to convert the port number to int, return 'true' if the port is valid (within the
        /// 0..65535 range)
        bool GetPort(int* OutPort) const;

        /// parse the URL
        static clParseURL ParseURL(const std::string& URL);

    private:
        explicit clParseURL(LUrlParserError ErrorCode)
            : m_ErrorCode(ErrorCode)
            , m_HasPort(false)
        {
        }
    };

    static bool IsSchemeValid(const std::string& SchemeName)
    {
        if (SchemeName.empty())
        {
            return false;
        }

        if (!std::isalpha(static_cast<unsigned char>(SchemeName[0])))
        {
            return false;
        }

        for (auto c : SchemeName)
        {
            if (!std::isalnum(static_cast<unsigned char>(c)) && c != '+' && c != '-' &&
                c != '.')
            {
                return false;
            }
        }

        return true;
    }

    bool clParseURL::GetPort(int* OutPort) const
    {
        if (!IsValid())
        {
            return false;
        }

        int Port = 0;
        auto [ptr, ec] = std::from_chars(m_Port.data(), m_Port.data() + m_Port.size(), Port);
        if (ec != std::errc() || ptr != m_Port.data() + m_Port.size() || Port <= 0 ||
            Port > 65535)
        {
            return false;
        }

        if (OutPort)
        {
            *OutPort = Port;
        }

        return true;
    }

    // based on RFC 1738 and RFC 3986
    clParseURL clParseURL::ParseURL(const std::string& URL)
    {
        clParseURL Result;

        if (containsInvalidUrlCharacter(URL))
        {
            return clParseURL(LUrlParserError_UnexpectedEndOfLine);
        }

        const char* CurrentString = URL.c_str();

        /*
         *	<scheme>:<scheme-specific-part>
         *	<scheme> := [a-z\+\-\.]+
         *	For resiliency, programs interpreting URLs should treat upper case letters as
         *equivalent to lower case in scheme names
         */

        // try to read scheme
        {
            const char* LocalString = strchr(CurrentString, ':');

            if (!LocalString)
            {
                return clParseURL(LUrlParserError_NoUrlCharacter);
            }

            // save the scheme name
            Result.m_Scheme = std::string(CurrentString, LocalString - CurrentString);

            if (!IsSchemeValid(Result.m_Scheme))
            {
                return clParseURL(LUrlParserError_InvalidSchemeName);
            }

            // scheme should be lowercase
            std::transform(Result.m_Scheme.begin(),
                           Result.m_Scheme.end(),
                           Result.m_Scheme.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            // skip ':'
            CurrentString = LocalString + 1;
        }

        /*
         *	//<user>:<password>@<host>:<port>/<url-path>
         *	any ":", "@" and "/" must be normalized
         */

        // skip "//"
        if (*CurrentString++ != '/') return clParseURL(LUrlParserError_NoDoubleSlash);
        if (*CurrentString++ != '/') return clParseURL(LUrlParserError_NoDoubleSlash);

        // check if the user name and password are specified
        bool bHasUserName = false;

        const char* LocalString = CurrentString;

        while (*LocalString)
        {
            if (*LocalString == '@')
            {
                // user name and password are specified
                bHasUserName = true;
                break;
            }
            else if (*LocalString == '/' || *LocalString == '?' || *LocalString == '#')
            {
                // end of <host>:<port> specification
                bHasUserName = false;
                break;
            }

            LocalString++;
        }

        // user name and password
        LocalString = CurrentString;

        if (bHasUserName)
        {
            // read user name
            while (*LocalString && *LocalString != ':' && *LocalString != '@')
                LocalString++;

            Result.m_UserName = std::string(CurrentString, LocalString - CurrentString);

            // proceed with the current pointer
            CurrentString = LocalString;

            if (*CurrentString == ':')
            {
                // skip ':'
                CurrentString++;

                // read password
                LocalString = CurrentString;

                while (*LocalString && *LocalString != '@')
                    LocalString++;

                Result.m_Password = std::string(CurrentString, LocalString - CurrentString);

                CurrentString = LocalString;
            }

            // skip '@'
            if (*CurrentString != '@')
            {
                return clParseURL(LUrlParserError_NoAtSign);
            }

            CurrentString++;
        }

        bool bHasBracket = (*CurrentString == '[');

        // go ahead, read the host name
        LocalString = CurrentString;

        while (*LocalString)
        {
            if (bHasBracket && *LocalString == ']')
            {
                // end of IPv6 address
                LocalString++;
                break;
            }
            else if (!bHasBracket &&
                     (*LocalString == ':' || *LocalString == '/' || *LocalString == '?' ||
                      *LocalString == '#'))
            {
                // port number is specified
                break;
            }

            LocalString++;
        }

        if (bHasBracket)
        {
            if (LocalString == CurrentString || *(LocalString - 1) != ']' ||
                LocalString - CurrentString <= 2)
            {
                return clParseURL(LUrlParserError_UnexpectedEndOfLine);
            }

            Result.m_Host = std::string(CurrentString + 1, LocalString - CurrentString - 2);
        }
        else
        {
            Result.m_Host = std::string(CurrentString, LocalString - CurrentString);
        }

        if (Result.m_Host.empty())
        {
            return clParseURL(LUrlParserError_UnexpectedEndOfLine);
        }

        CurrentString = LocalString;

        // is port number specified?
        if (*CurrentString == ':')
        {
            Result.m_HasPort = true;
            CurrentString++;

            // read port number
            LocalString = CurrentString;

            while (*LocalString && *LocalString != '/' && *LocalString != '?' &&
                   *LocalString != '#')
                LocalString++;

            Result.m_Port = std::string(CurrentString, LocalString - CurrentString);

            CurrentString = LocalString;
        }

        // end of string
        if (!*CurrentString)
        {
            Result.m_ErrorCode = LUrlParserError_Ok;

            return Result;
        }

        // skip '/'
        if (*CurrentString != '/' && *CurrentString != '?' && *CurrentString != '#')
        {
            return clParseURL(LUrlParserError_NoSlash);
        }

        if (*CurrentString == '/')
        {
            CurrentString++;
        }

        // parse the path
        LocalString = CurrentString;

        while (*LocalString && *LocalString != '#' && *LocalString != '?')
            LocalString++;

        Result.m_Path = std::string(CurrentString, LocalString - CurrentString);

        CurrentString = LocalString;

        // check for query
        if (*CurrentString == '?')
        {
            // skip '?'
            CurrentString++;

            // read query
            LocalString = CurrentString;

            while (*LocalString && *LocalString != '#')
                LocalString++;

            Result.m_Query = std::string(CurrentString, LocalString - CurrentString);

            CurrentString = LocalString;
        }

        // check for fragment
        if (*CurrentString == '#')
        {
            // skip '#'
            CurrentString++;

            // read fragment
            LocalString = CurrentString;

            while (*LocalString)
                LocalString++;

            Result.m_Fragment = std::string(CurrentString, LocalString - CurrentString);
        }

        Result.m_ErrorCode = LUrlParserError_Ok;

        return Result;
    }

    int getProtocolPort(const std::string& protocol)
    {
        if (protocol == "ws" || protocol == "http")
        {
            return 80;
        }
        else if (protocol == "wss" || protocol == "https")
        {
            return 443;
        }
        return -1;
    }
} // namespace

namespace ix
{
    bool UrlParser::parse(const std::string& url,
                          std::string& protocol,
                          std::string& host,
                          std::string& path,
                          std::string& query,
                          int& port)
    {
        bool isProtocolDefaultPort;
        return parse(url, protocol, host, path, query, port, isProtocolDefaultPort);
    }

    bool UrlParser::parse(const std::string& url,
                              std::string& protocol,
                              std::string& host,
                              std::string& path,
                              std::string& query,
                              int& port,
                              bool& isProtocolDefaultPort)
    {
        clParseURL res = clParseURL::ParseURL(url);

        if (!res.IsValid())
        {
            return false;
        }

        protocol = res.m_Scheme;
        host = res.m_Host;
        path = res.m_Path;
        query = res.m_Query;

        const auto protocolPort = getProtocolPort(protocol);
        if (res.m_HasPort)
        {
            if (!res.GetPort(&port))
            {
                return false;
            }
        }
        else
        {
            port = protocolPort;
        }
        isProtocolDefaultPort = port == protocolPort;

        if (path.empty())
        {
            path = "/";
        }
        else if (path[0] != '/')
        {
            path = '/' + path;
        }

        if (!query.empty())
        {
            path += "?";
            path += query;
        }

        return true;
    }

    bool UrlParser::parse(const std::string& url,
                          std::string& protocol,
                          std::string& host,
                          std::string& path,
                          std::string& query,
                          int& port,
                          std::string& username,
                          std::string& password)
    {
        clParseURL res = clParseURL::ParseURL(url);
        if (!res.IsValid()) return false;

        protocol = res.m_Scheme;
        host = res.m_Host;
        path = res.m_Path;
        query = res.m_Query;
        username = res.m_UserName;
        password = res.m_Password;

        if (res.m_HasPort)
        {
            if (!res.GetPort(&port))
            {
                return false;
            }
        }
        else
        {
            port = getProtocolPort(protocol);
        }

        return true;
    }

} // namespace ix
