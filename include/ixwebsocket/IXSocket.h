/*
 *  IXSocket.h
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2017-2018 Machine Zone, Inc. All rights reserved.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

#ifdef __APPLE__
#include <sys/types.h>
#endif

#include "IXCancellationRequest.h"
#include "IXIoResult.h"
#include "IXProgressCallback.h"
#include "IXProxyConfig.h"
#include "IXSelectInterrupt.h"

namespace ix
{
    enum class PollResultType
    {
        ReadyForRead = 0,
        ReadyForWrite = 1,
        Timeout = 2,
        Error = 3,
        SendRequest = 4,
        CloseRequest = 5
    };

    class Socket
    {
    public:
        Socket(int fd = -1);
        virtual ~Socket();
        bool init(std::string& errorMsg);

        // Functions to check whether there is activity on the socket
        PollResultType poll(int timeoutMs = kDefaultPollTimeout);
        bool wakeUpFromPoll(uint64_t wakeUpCode);
        bool isWakeUpFromPollSupported();

        PollResultType isReadyToWrite(int timeoutMs);
        PollResultType isReadyToRead(int timeoutMs);

        // Virtual methods
        virtual bool accept(std::string& errMsg);
        virtual bool accept(std::string& errMsg,
                            const CancellationRequest& isCancellationRequested);

        virtual bool connect(const std::string& host,
                             int port,
                             std::string& errMsg,
                             const CancellationRequest& isCancellationRequested);
        virtual void close();
        bool isOpen() const;
        int getFd() const;

        virtual IoResult send(const char* buffer, size_t length);
        IoResult send(const std::string& buffer);
        virtual IoResult recv(void* buffer, size_t length);

        // Blocking and cancellable versions, working with socket that can be set
        // to non blocking mode. Used during HTTP upgrade.
        bool readByte(void* buffer, const CancellationRequest& isCancellationRequested);
        bool writeBytes(const std::string& str, const CancellationRequest& isCancellationRequested);
        bool writeBytes(const std::string& str,
                        const CancellationRequest& isCancellationRequested,
                        int timeoutSecs);

        std::optional<std::string> readLine(const CancellationRequest& isCancellationRequested);
        std::optional<std::string> readLine(const CancellationRequest& isCancellationRequested,
                                            int timeoutSecs);
        std::optional<std::string> readBytes(size_t length,
                                             const OnProgressCallback& onProgressCallback,
                                             const OnChunkCallback& onChunkCallback,
                                             const CancellationRequest& isCancellationRequested);
        std::optional<std::string> readBytes(size_t length,
                                             const OnProgressCallback& onProgressCallback,
                                             const OnChunkCallback& onChunkCallback,
                                             const CancellationRequest& isCancellationRequested,
                                             int timeoutSecs);

        static int getErrno();
        static bool isWaitNeeded();
        static void closeSocket(int fd);

        static PollResultType poll(bool readyToRead,
                                   int timeoutMs,
                                   int sockfd,
                                   const SelectInterruptPtr& selectInterrupt);

        void setProxyConfig(const ProxyConfig& proxyConfig);
        const ProxyConfig& getProxyConfig() const;

    protected:
        std::atomic<int> _sockfd;
        mutable std::mutex _socketMutex;
        ProxyConfig _proxyConfig;

        static bool readSelectInterruptRequest(const SelectInterruptPtr& selectInterrupt,
                                               PollResultType* pollResult);

        bool connectThroughProxy(const std::string& host,
                                 int port,
                                 std::string& errMsg,
                                 const CancellationRequest& isCancellationRequested);
        bool connectThroughSecureProxy(const std::string& host,
                                       int port,
                                       std::string& errMsg,
                                       const CancellationRequest& isCancellationRequested);
        Socket* getProxySocket() const;

    private:
        static const int kDefaultPollTimeout;
        static const int kDefaultPollNoTimeout;

        SelectInterruptPtr _selectInterrupt;
        std::unique_ptr<Socket> _proxySocket;
    };
} // namespace ix
