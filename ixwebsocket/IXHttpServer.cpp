/*
 *  IXHttpServer.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2019 Machine Zone, Inc. All rights reserved.
 */

#include "IXHttpServer.h"

#include "IXGzipCodec.h"
#include "IXNetSystem.h"
#include "IXSocketConnect.h"
#include "IXStrCaseCompare.h"
#include "IXUserAgent.h"
#include <algorithm>
#include <charconv>
#include <cctype>
#include <ctime>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <unordered_map>
#include <vector>

namespace
{
    constexpr std::streamoff kMaxStaticFileSize = 64LL * 1024LL * 1024LL;
    constexpr size_t kMaxStaticFileGzipSize = 4 * 1024 * 1024;
    constexpr size_t kMaxStaticFileCacheEntries = 256;
    constexpr size_t kMaxStaticFileCacheBytes = 128ULL * 1024ULL * 1024ULL;

    struct StaticFileMetadata
    {
        uint64_t size = 0;
        std::time_t mtime = 0;
    };

    struct StaticFileCacheEntry
    {
        StaticFileMetadata metadata;
        std::string content;
        std::string gzipContent;
        std::string etag;
        bool gzipReady = false;
    };

    struct StaticFileRange
    {
        uint64_t start = 0;
        uint64_t end = 0;
        bool malformed = false;
        bool satisfiable = true;
        bool parsed = false;
    };

#ifdef _WIN32
    using FileStat = struct __stat64;

    int statFile(const std::string& path, FileStat& fileStat)
    {
        return _stat64(path.c_str(), &fileStat);
    }

    bool isRegularFile(const FileStat& fileStat)
    {
        return (fileStat.st_mode & _S_IFREG) != 0;
    }
#else
    using FileStat = struct stat;

    int statFile(const std::string& path, FileStat& fileStat)
    {
        return stat(path.c_str(), &fileStat);
    }

    bool isRegularFile(const FileStat& fileStat)
    {
        return S_ISREG(fileStat.st_mode);
    }
#endif

    bool readStaticFileMetadata(const std::string& path,
                                StaticFileMetadata& metadata,
                                bool& tooLarge)
    {
        tooLarge = false;

        FileStat fileStat{};
        if (statFile(path, fileStat) != 0 || fileStat.st_size < 0)
        {
            return false;
        }

        if (!isRegularFile(fileStat))
        {
            return false;
        }

        if (fileStat.st_size > kMaxStaticFileSize)
        {
            tooLarge = true;
            return false;
        }

        metadata.size = static_cast<uint64_t>(fileStat.st_size);
        metadata.mtime = fileStat.st_mtime;
        return true;
    }

    std::optional<std::string> readFileRange(const std::string& path, uint64_t start, uint64_t size)
    {
        if (start > static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()) ||
            size > static_cast<uint64_t>(std::numeric_limits<size_t>::max()) ||
            size > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max()))
        {
            return std::nullopt;
        }

        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) return std::nullopt;

        if (start > 0)
        {
            file.seekg(static_cast<std::streamoff>(start));
            if (!file)
            {
                return std::nullopt;
            }
        }

        std::string content(static_cast<size_t>(size), '\0');
        if (!content.empty())
        {
            file.read(&content[0], static_cast<std::streamsize>(content.size()));
            if (!file)
            {
                return std::nullopt;
            }
        }

        return content;
    }

    std::optional<std::string> readFileContent(const std::string& path, uint64_t size)
    {
        return readFileRange(path, 0, size);
    }

    std::string makeEtag(const StaticFileMetadata& metadata)
    {
        std::stringstream etagStream;
        etagStream << "W/\"" << std::hex << metadata.size << "-"
                   << static_cast<int64_t>(metadata.mtime) << "\"";
        return etagStream.str();
    }

    StaticFileRange parseStaticFileRange(std::string_view rangeHeader, uint64_t contentSize)
    {
        StaticFileRange range;
        constexpr std::string_view kBytesPrefix = "bytes=";
        if (rangeHeader.rfind(kBytesPrefix, 0) != 0)
        {
            return range;
        }

        rangeHeader.remove_prefix(kBytesPrefix.size());
        if (rangeHeader.find(',') != std::string_view::npos)
        {
            return range;
        }

        const size_t dashPos = rangeHeader.find('-');
        if (dashPos == std::string_view::npos)
        {
            return range;
        }

        range.parsed = true;
        std::string_view startToken = rangeHeader.substr(0, dashPos);
        std::string_view endToken = rangeHeader.substr(dashPos + 1);

        auto parseSizeToken = [&range](std::string_view token, uint64_t& out) {
            if (token.empty())
            {
                range.malformed = true;
                return;
            }

            auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), out);
            if (ec != std::errc() || ptr != token.data() + token.size())
            {
                range.malformed = true;
            }
        };

        if (startToken.empty() && endToken.empty())
        {
            range.malformed = true;
        }
        else if (!startToken.empty() && !endToken.empty())
        {
            parseSizeToken(startToken, range.start);
            parseSizeToken(endToken, range.end);
            if (!range.malformed)
            {
                if (range.start > range.end)
                {
                    range.malformed = true;
                }
                else if (range.start >= contentSize)
                {
                    range.satisfiable = false;
                }
                else
                {
                    range.end = std::min(range.end, contentSize - 1);
                }
            }
        }
        else if (!startToken.empty())
        {
            parseSizeToken(startToken, range.start);
            if (!range.malformed)
            {
                if (range.start >= contentSize)
                {
                    range.satisfiable = false;
                }
                else
                {
                    range.end = contentSize - 1;
                }
            }
        }
        else
        {
            uint64_t suffixLength = 0;
            parseSizeToken(endToken, suffixLength);
            if (!range.malformed)
            {
                if (suffixLength == 0)
                {
                    range.malformed = true;
                }
                else if (contentSize == 0)
                {
                    range.satisfiable = false;
                }
                else
                {
                    suffixLength = std::min(suffixLength, contentSize);
                    range.start = contentSize - suffixLength;
                    range.end = contentSize - 1;
                }
            }
        }

        return range;
    }

    class StaticFileCache
    {
    public:
        std::shared_ptr<StaticFileCacheEntry> get(const std::string& path, bool& tooLarge)
        {
            StaticFileMetadata metadata;
            if (!readStaticFileMetadata(path, metadata, tooLarge))
            {
                return nullptr;
            }

            {
                std::lock_guard<std::mutex> lock(_mutex);
                auto it = _entries.find(path);
                if (it != _entries.end() && it->second->metadata.size == metadata.size &&
                    it->second->metadata.mtime == metadata.mtime)
                {
                    touchEntry(path);
                    return it->second;
                }
            }

            auto content = readFileContent(path, metadata.size);
            if (!content)
            {
                return nullptr;
            }

            StaticFileMetadata metadataAfterRead;
            bool tooLargeAfterRead = false;
            if (!readStaticFileMetadata(path, metadataAfterRead, tooLargeAfterRead) ||
                metadataAfterRead.size != metadata.size ||
                metadataAfterRead.mtime != metadata.mtime)
            {
                tooLarge = tooLargeAfterRead;
                return nullptr;
            }

            auto entry = std::make_shared<StaticFileCacheEntry>();
            entry->metadata = metadata;
            entry->content = std::move(*content);
            entry->etag = makeEtag(entry->metadata);

            {
                std::lock_guard<std::mutex> lock(_mutex);
                if (entry->content.size() <= kMaxStaticFileCacheBytes)
                {
                    auto existing = _entries.find(path);
                    if (existing != _entries.end())
                    {
                        removeEntry(path);
                    }

                    evictUntilCanAdd(entrySize(*entry));

                    _entries[path] = entry;
                    _lru.push_back(path);
                    _cachedBytes += entrySize(*entry);
                }
            }

            return entry;
        }

#ifdef IXWEBSOCKET_USE_ZLIB
        std::shared_ptr<const std::string> getGzipContent(
            const std::string& path,
            const std::shared_ptr<StaticFileCacheEntry>& entry)
        {
            {
                std::lock_guard<std::mutex> lock(_mutex);
                auto it = _entries.find(path);
                if (it != _entries.end() && it->second == entry && entry->gzipReady)
                {
                    touchEntry(path);
                    return std::shared_ptr<const std::string>(entry, &entry->gzipContent);
                }
            }

            std::string gzipContent = ix::gzipCompress(entry->content);

            {
                std::lock_guard<std::mutex> lock(_mutex);
                auto it = _entries.find(path);
                if (it != _entries.end() && it->second == entry)
                {
                    if (entry->gzipReady)
                    {
                        touchEntry(path);
                        return std::shared_ptr<const std::string>(entry, &entry->gzipContent);
                    }

                    if (gzipContent.size() > kMaxStaticFileCacheBytes)
                    {
                        return std::make_shared<const std::string>(std::move(gzipContent));
                    }

                    evictUntilCanAdd(gzipContent.size(), &path);
                    if (_cachedBytes + gzipContent.size() > kMaxStaticFileCacheBytes)
                    {
                        return std::make_shared<const std::string>(std::move(gzipContent));
                    }

                    entry->gzipContent = std::move(gzipContent);
                    entry->gzipReady = true;
                    _cachedBytes += entry->gzipContent.size();
                    touchEntry(path);
                    return std::shared_ptr<const std::string>(entry, &entry->gzipContent);
                }
            }

            return std::make_shared<const std::string>(std::move(gzipContent));
        }
#endif

    private:
        static size_t entrySize(const StaticFileCacheEntry& entry)
        {
            return entry.content.size() + entry.gzipContent.size();
        }

        void touchEntry(const std::string& path)
        {
            _lru.remove(path);
            _lru.push_back(path);
        }

        void removeEntry(const std::string& path)
        {
            auto it = _entries.find(path);
            if (it == _entries.end())
            {
                return;
            }

            _cachedBytes -= entrySize(*it->second);
            _entries.erase(it);
            _lru.remove(path);
        }

        void evictUntilCanAdd(size_t bytesToAdd, const std::string* protectedPath = nullptr)
        {
            if (bytesToAdd > kMaxStaticFileCacheBytes)
            {
                return;
            }

            while (!_entries.empty() &&
                   (_entries.size() >= kMaxStaticFileCacheEntries ||
                    _cachedBytes > kMaxStaticFileCacheBytes - bytesToAdd))
            {
                auto victimIt = _lru.begin();
                if (protectedPath)
                {
                    victimIt = std::find_if(_lru.begin(), _lru.end(), [protectedPath](const auto& path) {
                        return path != *protectedPath;
                    });
                    if (victimIt == _lru.end())
                    {
                        return;
                    }
                }

                removeEntry(*victimIt);
            }
        }

        std::mutex _mutex;
        std::unordered_map<std::string, std::shared_ptr<StaticFileCacheEntry>> _entries;
        std::list<std::string> _lru;
        size_t _cachedBytes = 0;
    };

    std::string response_head_file(const std::string& file_name){
        auto endsWith = [](const std::string& str, const std::string& suffix) {
            return str.size() >= suffix.size() &&
                   str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
        };

        if (endsWith(file_name, ".html") || endsWith(file_name, ".htm"))
            return "text/html";
        else if (endsWith(file_name, ".css"))
            return "text/css";
        else if (endsWith(file_name, ".js") || endsWith(file_name, ".mjs"))
            return "application/x-javascript";
        else if (endsWith(file_name, ".ico"))
            return "image/x-icon";
        else if (endsWith(file_name, ".png"))
            return "image/png";
        else if (endsWith(file_name, ".jpg") || endsWith(file_name, ".jpeg"))
            return "image/jpeg";
        else if (endsWith(file_name, ".gif"))
            return "image/gif";
        else if (endsWith(file_name, ".svg"))
            return "image/svg+xml";
        else
            return "application/octet-stream";
    }

    std::string extractRequestPath(const std::string& uri)
    {
        std::string path = uri;

        auto queryPos = path.find('?');
        if (queryPos != std::string::npos)
        {
            path.resize(queryPos);
        }

        auto fragmentPos = path.find('#');
        if (fragmentPos != std::string::npos)
        {
            path.resize(fragmentPos);
        }

        if (path.empty())
        {
            path = "/";
        }

        return path;
    }

    std::optional<std::string> normalizePath(const std::string& rawPath)
    {
        if (rawPath.empty() || rawPath[0] != '/')
        {
            return std::nullopt;
        }

        std::vector<std::string> segments;
        size_t cursor = 1;

        while (cursor <= rawPath.size())
        {
            size_t slashPos = rawPath.find('/', cursor);
            if (slashPos == std::string::npos)
            {
                slashPos = rawPath.size();
            }

            std::string segment = rawPath.substr(cursor, slashPos - cursor);
            if (!segment.empty())
            {
                if (segment == ".")
                {
                    // No-op segment.
                }
                else if (segment == "..")
                {
                    if (segments.empty())
                    {
                        return std::nullopt;
                    }

                    segments.pop_back();
                }
                else
                {
                    if (segment.find('\\') != std::string::npos)
                    {
                        return std::nullopt;
                    }

                    segments.push_back(std::move(segment));
                }
            }

            cursor = slashPos + 1;
        }

        std::string normalizedPath = "/";
        for (size_t i = 0; i < segments.size(); ++i)
        {
            normalizedPath += segments[i];
            if (i + 1 < segments.size())
            {
                normalizedPath += '/';
            }
        }

        return normalizedPath;
    }

    std::string normalizeForPrefixCompare(std::filesystem::path path)
    {
        std::string value = path.lexically_normal().generic_string();
#ifdef _WIN32
        std::transform(value.begin(), value.end(), value.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
#endif
        return value;
    }

    bool pathIsInsideRoot(const std::filesystem::path& root,
                          const std::filesystem::path& candidate)
    {
        std::string rootPath = normalizeForPrefixCompare(root);
        std::string candidatePath = normalizeForPrefixCompare(candidate);

        if (candidatePath == rootPath)
        {
            return true;
        }

        if (!rootPath.empty() && rootPath.back() != '/')
        {
            rootPath += '/';
        }

        return candidatePath.compare(0, rootPath.size(), rootPath) == 0;
    }

    std::optional<std::string> resolveStaticFilePath(const std::string& normalizedPath)
    {
        if (normalizedPath.empty() || normalizedPath[0] != '/')
        {
            return std::nullopt;
        }

        std::error_code ec;
        std::filesystem::path root = std::filesystem::weakly_canonical(
            std::filesystem::current_path(ec), ec);
        if (ec)
        {
            return std::nullopt;
        }

        std::filesystem::path relative = normalizedPath.substr(1);
        std::filesystem::path candidate = std::filesystem::weakly_canonical(root / relative, ec);
        if (ec || !pathIsInsideRoot(root, candidate))
        {
            return std::nullopt;
        }

        return candidate.string();
    }

    std::string_view getHeaderValue(const ix::WebSocketHttpHeaders& headers,
                                    const std::string& name)
    {
        auto it = headers.find(name);
        if (it == headers.end())
        {
            return std::string_view();
        }

        return it->second;
    }

    bool isSensitiveHttpHeaderForLogging(std::string_view name)
    {
        return ix::caseInsensitiveEquals(name, "authorization") ||
               ix::caseInsensitiveEquals(name, "proxy-authorization") ||
               ix::caseInsensitiveEquals(name, "cookie") ||
               ix::caseInsensitiveEquals(name, "cookie2");
    }

    std::string redactHttpHeaderForLogging(const std::string& name, const std::string& value)
    {
        if (isSensitiveHttpHeaderForLogging(name))
        {
            return "[redacted]";
        }

        return value;
    }

    std::string redactHttpBodyForLogging(size_t bodySize)
    {
        std::stringstream ss;
        ss << "[request body redacted, " << bodySize << " bytes]";
        return ss.str();
    }

    std::string redactHttpRequestTargetForLogging(const std::string& uri)
    {
        return extractRequestPath(uri);
    }

} // namespace

namespace ix
{
    const int HttpServer::kDefaultTimeoutSecs(30);

    HttpServer::HttpServer(int port,
                           const std::string& host,
                           int backlog,
                           size_t maxConnections,
                           int addressFamily,
                           int timeoutSecs,
                           int handshakeTimeoutSecs)
        : WebSocketServer(port, host, backlog, maxConnections, handshakeTimeoutSecs, addressFamily)
        , _timeoutSecs(timeoutSecs)
    {
        setDefaultConnectionCallback();
    }

    void HttpServer::setOnConnectionCallback(const OnConnectionCallback& callback)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _onConnectionCallback = callback;
    }

    void HttpServer::handleConnection(std::unique_ptr<Socket> socket,
                                      std::shared_ptr<ConnectionState> connectionState)
    {
        int timeoutSecs = 0;
        OnConnectionCallback onConnectionCallback;
        {
            std::lock_guard<std::mutex> lock(_configMutex);
            timeoutSecs = _timeoutSecs;
            onConnectionCallback = _onConnectionCallback;
        }

        auto [success, errorMsg, request] = Http::parseRequest(socket, timeoutSecs);

        if (!success)
        {
            logError("HTTP request parsing failed: " + errorMsg);
            auto errorResponse = std::make_shared<HttpResponse>(
                400, "Bad Request", HttpErrorCode::HeaderParsingError,
                WebSocketHttpHeaders(), errorMsg);
            Http::sendResponse(errorResponse, socket, timeoutSecs);
            connectionState->setTerminated();
            return;
        }
        auto upgradeHeaderIt = request->headers.find("Upgrade");
        auto connectionHeaderIt = request->headers.find("Connection");
        bool isWebSocketUpgrade =
            upgradeHeaderIt != request->headers.end() &&
            connectionHeaderIt != request->headers.end() &&
            headerContainsTokenCaseInsensitive(upgradeHeaderIt->second, "websocket") &&
            headerContainsTokenCaseInsensitive(connectionHeaderIt->second, "upgrade");

        if (isWebSocketUpgrade)
        {
            WebSocketServer::handleUpgrade(std::move(socket), connectionState, request);
        }
        else
        {
            HttpResponsePtr response;
            try
            {
                response = onConnectionCallback(request, connectionState);
            }
            catch (const std::exception& e)
            {
                logError(std::string("HttpServer connection callback threw: ") + e.what());
                response = std::make_shared<HttpResponse>(500,
                                                          "Internal Server Error",
                                                          HttpErrorCode::Ok,
                                                          WebSocketHttpHeaders(),
                                                          std::string());
            }
            catch (...)
            {
                logError("HttpServer connection callback threw");
                response = std::make_shared<HttpResponse>(500,
                                                          "Internal Server Error",
                                                          HttpErrorCode::Ok,
                                                          WebSocketHttpHeaders(),
                                                          std::string());
            }

            if (!Http::sendResponse(response, socket, timeoutSecs))
            {
                logError("Cannot send response");
            }
        }
        connectionState->setTerminated();
    }

    void HttpServer::setDefaultConnectionCallback()
    {
        auto staticFileCache = std::make_shared<StaticFileCache>();
        setOnConnectionCallback(
            [this, staticFileCache](HttpRequestPtr request,
                                    std::shared_ptr<ConnectionState> connectionState) -> HttpResponsePtr
            {
                WebSocketHttpHeaders headers;
                std::string customServer = getCustomServerHeader();
                headers["Server"] = customServer.empty() ? userAgent() : customServer;

                std::string requestPath = extractRequestPath(request->uri);
                auto normalizedPath = normalizePath(requestPath);
                if (!normalizedPath)
                {
                    return std::make_shared<HttpResponse>(
                        403, "Forbidden", HttpErrorCode::Ok, headers, std::string());
                }

                std::string uri(*normalizedPath);
                if (uri == "/")
                {
                    uri = "/index.html";
                }

                headers["Content-Type"] = response_head_file(uri);

                // Handle OPTIONS preflight
                if (request->method == "OPTIONS")
                {
                    headers["Allow"] = "GET, HEAD, OPTIONS";
                    return std::make_shared<HttpResponse>(
                        204, "No Content", HttpErrorCode::Ok, headers, std::string());
                }

                const bool headRequest = request->method == "HEAD";
                if (request->method != "GET" && !headRequest)
                {
                    headers["Allow"] = "GET, HEAD, OPTIONS";
                    return std::make_shared<HttpResponse>(
                        405, "Method Not Allowed", HttpErrorCode::Ok, headers, std::string());
                }

                auto resolvedPath = resolveStaticFilePath(uri);
                if (!resolvedPath)
                {
                    return std::make_shared<HttpResponse>(
                        403, "Forbidden", HttpErrorCode::Ok, headers, std::string());
                }

                std::string path(*resolvedPath);

                StaticFileMetadata metadata;
                bool fileTooLarge = false;
                if (!readStaticFileMetadata(path, metadata, fileTooLarge))
                {
                    if (fileTooLarge)
                    {
                        return std::make_shared<HttpResponse>(
                            413, "Payload Too Large", HttpErrorCode::Ok, headers, std::string());
                    }

                    return std::make_shared<HttpResponse>(
                        404, "Not Found", HttpErrorCode::Ok, WebSocketHttpHeaders(), std::string());
                }

                const std::string etag = makeEtag(metadata);
                headers["ETag"] = etag;

                // Check If-None-Match for ETag validation
                auto ifNoneMatch = request->headers.find("If-None-Match");
                if (ifNoneMatch != request->headers.end() && ifNoneMatch->second == etag)
                {
                    return std::make_shared<HttpResponse>(
                        304, "Not Modified", HttpErrorCode::Ok, headers, std::string());
                }

                // Handle Range requests before filling the full-file cache.
                auto rangeHeader = request->headers.find("Range");
                if (rangeHeader != request->headers.end())
                {
                    StaticFileRange range =
                        parseStaticFileRange(rangeHeader->second, metadata.size);
                    if (range.parsed)
                    {
                        headers["Accept-Ranges"] = "bytes";
                        if (!range.malformed && range.satisfiable)
                        {
                            const uint64_t rangeSize = range.end - range.start + 1;

                            std::stringstream rangeStream;
                            rangeStream << "bytes " << range.start << "-" << range.end << "/"
                                        << metadata.size;
                            headers["Content-Range"] = rangeStream.str();

                            if (headRequest)
                            {
                                headers["Content-Length"] = std::to_string(rangeSize);
                                return std::make_shared<HttpResponse>(
                                    206,
                                    "Partial Content",
                                    HttpErrorCode::Ok,
                                    headers,
                                    std::string(),
                                    std::string(),
                                    0,
                                    0,
                                    false);
                            }

                            auto rangeContent = readFileRange(path, range.start, rangeSize);
                            if (!rangeContent)
                            {
                                return std::make_shared<HttpResponse>(
                                    404,
                                    "Not Found",
                                    HttpErrorCode::Ok,
                                    WebSocketHttpHeaders(),
                                    std::string());
                            }

                            StaticFileMetadata metadataAfterRead;
                            bool tooLargeAfterRead = false;
                            if (!readStaticFileMetadata(path, metadataAfterRead, tooLargeAfterRead) ||
                                metadataAfterRead.size != metadata.size ||
                                metadataAfterRead.mtime != metadata.mtime)
                            {
                                return std::make_shared<HttpResponse>(
                                    404,
                                    "Not Found",
                                    HttpErrorCode::Ok,
                                    WebSocketHttpHeaders(),
                                    std::string());
                            }

                            return std::make_shared<HttpResponse>(
                                206,
                                "Partial Content",
                                HttpErrorCode::Ok,
                                headers,
                                std::move(*rangeContent));
                        }

                        if (!range.malformed && !range.satisfiable)
                        {
                            headers["Content-Range"] = "bytes */" + std::to_string(metadata.size);
                            return std::make_shared<HttpResponse>(
                                416,
                                "Range Not Satisfiable",
                                HttpErrorCode::Ok,
                                headers,
                                std::string());
                        }
                    }
                }

                auto fileEntry = staticFileCache->get(path, fileTooLarge);
                if (!fileEntry)
                {
                    if (fileTooLarge)
                    {
                        return std::make_shared<HttpResponse>(
                            413, "Payload Too Large", HttpErrorCode::Ok, headers, std::string());
                    }

                    return std::make_shared<HttpResponse>(
                        404, "Not Found", HttpErrorCode::Ok, WebSocketHttpHeaders(), std::string());
                }

                const std::string& content = fileEntry->content;

                headers["Accept-Ranges"] = "bytes";

#ifdef IXWEBSOCKET_USE_ZLIB
                std::string_view acceptEncoding =
                    getHeaderValue(request->headers, "Accept-Encoding");
                std::shared_ptr<const std::string> gzipContent;
                const std::string* responseContent = &content;
                if (content.size() <= kMaxStaticFileGzipSize)
                {
                    headers["Vary"] = "Accept-Encoding";
                }
                if ((acceptEncoding == "*" ||
                     headerContainsTokenCaseInsensitive(acceptEncoding, "gzip")) &&
                    content.size() <= kMaxStaticFileGzipSize)
                {
                    gzipContent = staticFileCache->getGzipContent(path, fileEntry);
                    responseContent = gzipContent.get();
                    headers["Content-Encoding"] = "gzip";
                }
#else
                const std::string* responseContent = &content;
#endif

                // Log request
                std::stringstream ss;
                ss << connectionState->getRemoteIp() << ":" << connectionState->getRemotePort()
                   << " " << request->method << " " << request->headers["User-Agent"] << " "
                   << redactHttpRequestTargetForLogging(request->uri) << " "
                   << responseContent->size();
                logInfo(ss.str());


                if (headRequest)
                {
                    headers["Content-Length"] = std::to_string(responseContent->size());
                    return std::make_shared<HttpResponse>(200,
                                                          "OK",
                                                          HttpErrorCode::Ok,
                                                          headers,
                                                          std::string(),
                                                          std::string(),
                                                          0,
                                                          0,
                                                          false);
                }

                return std::make_shared<HttpResponse>(
                    200, "OK", HttpErrorCode::Ok, headers, *responseContent);
            });
    }

    void HttpServer::makeRedirectServer(const std::string& redirectUrl)
    {
        //
        // See https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections
        //
        setOnConnectionCallback(
            [this, redirectUrl](HttpRequestPtr request,
                                std::shared_ptr<ConnectionState> connectionState) -> HttpResponsePtr
            {
                WebSocketHttpHeaders headers;
                std::string customServer = getCustomServerHeader();
                headers["Server"] = customServer.empty() ? userAgent() : customServer;

                // Log request
                std::stringstream ss;
                ss << connectionState->getRemoteIp() << ":" << connectionState->getRemotePort()
                   << " " << request->method << " " << request->headers["User-Agent"] << " "
                   << redactHttpRequestTargetForLogging(request->uri);
                logInfo(ss.str());

                if (request->method == "POST")
                {
                    return std::make_shared<HttpResponse>(
                        200, "OK", HttpErrorCode::Ok, headers, std::string());
                }

                headers["Location"] = redirectUrl;

                return std::make_shared<HttpResponse>(
                    301, "OK", HttpErrorCode::Ok, headers, std::string());
            });
    }

    //
    // Display the client parameter and body on the console
    //
    void HttpServer::makeDebugServer()
    {
        setOnConnectionCallback(
            [this](HttpRequestPtr request,
                   std::shared_ptr<ConnectionState> connectionState) -> HttpResponsePtr
            {
                WebSocketHttpHeaders headers;
                std::string customServer = getCustomServerHeader();
                headers["Server"] = customServer.empty() ? userAgent() : customServer;

                // Log request
                std::stringstream ss;
                ss << connectionState->getRemoteIp() << ":" << connectionState->getRemotePort()
                   << " " << request->method << " " << request->headers["User-Agent"] << " "
                   << redactHttpRequestTargetForLogging(request->uri);
                logInfo(ss.str());

                logInfo("== Headers == ");
                for (const auto& [name, value] : request->headers)
                {
                    std::ostringstream oss;
                    oss << name << ": " << redactHttpHeaderForLogging(name, value);
                    logInfo(oss.str());
                }
                logInfo("");

                logInfo("== Body == ");
                logInfo(redactHttpBodyForLogging(request->body.size()));
                logInfo("");

                return std::make_shared<HttpResponse>(
                    200, "OK", HttpErrorCode::Ok, headers, std::string("OK"));
            });
    }

    int HttpServer::getTimeoutSecs()
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        return _timeoutSecs;
    }

    void HttpServer::setTimeoutSecs(int secs)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _timeoutSecs = secs;
    }

} // namespace ix
