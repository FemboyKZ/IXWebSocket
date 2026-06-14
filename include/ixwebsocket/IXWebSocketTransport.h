/*
 *  IXWebSocketTransport.h
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2017-2018 Machine Zone, Inc. All rights reserved.
 */

#pragma once

//
// Adapted from https://github.com/dhbaird/easywsclient
//

#include "IXCancellationRequest.h"
#include "IXIoResult.h"
#include "IXProgressCallback.h"
#include "IXProxyConfig.h"
#include "IXSocketTLSOptions.h"
#include "IXWebSocketCloseConstants.h"
#include "IXWebSocketHandshake.h"
#include "IXWebSocketHttpHeaders.h"
#include "IXWebSocketPerMessageDeflate.h"
#include "IXWebSocketPerMessageDeflateOptions.h"
#include "IXWebSocketSendData.h"
#include "IXWebSocketSendInfo.h"
#include <atomic>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace ix
{
    class Socket;

    enum class SendMessageKind
    {
        Text,
        Binary,
        Ping
    };

    class WebSocketTransport
    {
    public:
        enum class ReadyState
        {
            CLOSING,
            CLOSED,
            CONNECTING,
            OPEN
        };

        enum class MessageKind
        {
            MSG_TEXT,
            MSG_BINARY,
            PING,
            PONG,
            FRAGMENT
        };

        enum class PollResult
        {
            Succeeded,
            AbnormalClose,
            CannotFlushSendBuffer
        };

        using OnMessageCallback =
            std::function<void(const std::string&, size_t, bool, MessageKind)>;
        using OnCloseCallback = std::function<void(uint16_t, const std::string&, size_t, bool)>;

        WebSocketTransport();
        ~WebSocketTransport();

        void configure(const WebSocketPerMessageDeflateOptions& perMessageDeflateOptions,
                       const SocketTLSOptions& socketTLSOptions,
                       const ProxyConfig& proxyConfig,
                       bool enablePong,
                       int pingIntervalSecs,
                       int pingTimeoutSecs = -1,
                       int idleTimeoutSecs = -1,
                       int sendTimeoutSecs = 300,
                       int closeTimeoutSecs = 5);

        // Client
        WebSocketInitResult connectToUrl(const std::string& url,
                                         const WebSocketHttpHeaders& headers,
                                         int timeoutSecs);

        // Server
        WebSocketInitResult connectToSocket(std::unique_ptr<Socket> socket,
                                            int timeoutSecs,
                                            bool enablePerMessageDeflate,
                                            HttpRequestPtr request = nullptr,
                                            const std::vector<std::string>& subProtocols = {});

        PollResult poll();
        WebSocketSendInfo sendBinary(const IXWebSocketSendData& message,
                                     const OnProgressCallback& onProgressCallback);
        WebSocketSendInfo sendText(const IXWebSocketSendData& message,
                                   const OnProgressCallback& onProgressCallback);
        WebSocketSendInfo sendPing(const IXWebSocketSendData& message);

        void close(uint16_t code = WebSocketCloseConstants::kNormalClosureCode,
                   const std::string& reason = WebSocketCloseConstants::kNormalClosureMessage,
                   size_t closeWireSize = 0,
                   bool remote = false);

        void closeSocket();

        ReadyState getReadyState() const;
        void setReadyState(ReadyState readyState);
        void setOnCloseCallback(const OnCloseCallback& onCloseCallback);
        void dispatch(PollResult pollResult, const OnMessageCallback& onMessageCallback);
        size_t bufferedAmount() const;

        // set ping heartbeat message
        void setPingMessage(const std::string& message, SendMessageKind pingType);

        // internal
        // send any type of ping packet, not only 'ping' type
        WebSocketSendInfo sendHeartBeat(SendMessageKind pingType);

    private:
        std::string _url;

        struct wsheader_type
        {
            unsigned header_size;
            bool fin;
            bool rsv1;
            bool rsv2;
            bool rsv3;
            bool mask;
            enum opcode_type
            {
                CONTINUATION = 0x0,
                TEXT_FRAME = 0x1,
                BINARY_FRAME = 0x2,
                CLOSE = 8,
                PING = 9,
                PONG = 0xa,
            } opcode;
            int N0;
            uint64_t N;
            uint8_t masking_key[4];
        };

        // Tells whether we should mask the data we send.
        // client should mask but server should not
        std::atomic<bool> _useMask;

        // Tells whether we should flush the send buffer before
        // saying that a send is complete. This is the mode for server code.
        std::atomic<bool> _blockingSend;

        // Buffer for reading from our socket. That buffer is never resized.
        std::vector<uint8_t> _readbuf;

        // Contains all messages that were fetched in the last socket read.
        // This could be a mix of control messages (Close, Ping, etc...) and
        // data messages. That buffer is resized
        std::vector<uint8_t> _rxbuf;
        size_t _rxbufOffset = 0;  // Offset of unconsumed data
        void compactRxBuf();  // Compact buffer when offset exceeds threshold
        void resetConnectionState();

        // If set to a positive value, only read bytes from the socket until
        // _rxbuf has reached this size to avoid unnecessary erase churn.
        uint64_t _rxbufWanted = 0;

        // Contains all messages that are waiting to be sent
        std::vector<uint8_t> _txbuf;
        size_t _txbufOffset = 0;  // Offset of unconsumed data
        mutable std::mutex _txbufMutex;
        std::recursive_mutex _sendDataMutex;
        void compactTxBuf();  // Compact buffer when offset exceeds threshold

        // Hold fragments for multi-fragment messages in a list. This avoids repeated
        // large-buffer growth while still enforcing a bounded per-message memory budget.
        std::list<std::string> _chunks;
        size_t _chunksSize = 0;
        static constexpr uint64_t kMaxFramePayloadSize = 64ULL * 1024ULL * 1024ULL;
        static constexpr size_t kMaxFragmentedMessageSize =
            static_cast<size_t>(kMaxFramePayloadSize);

        // Record the message kind (will be TEXT or BINARY) for a fragmented
        // message, present in the first chunk, since the final chunk will be a
        // CONTINUATION opcode and doesn't tell the full message kind
        MessageKind _fragmentedMessageKind;

        // Ditto for whether a message is compressed
        bool _receivedMessageCompressed;

        // Fragments are 32K long
        static constexpr size_t kChunkSize = 1 << 15;

        // Underlying TCP socket
        std::unique_ptr<Socket> _socket;
        std::mutex _socketMutex;

        // Hold the state of the connection (OPEN, CLOSED, etc...)
        std::atomic<ReadyState> _readyState;
        // Mutex to serialize setReadyState() execution.
        std::mutex _setReadyStateMutex;

        OnCloseCallback _onCloseCallback;
        std::string _closeReason;
        std::mutex _closeMutex;
        mutable std::mutex _closeReasonMutex;
        std::atomic<uint16_t> _closeCode;
        std::atomic<size_t> _closeWireSize;
        std::atomic<bool> _closeRemote;

        // Data used for Per Message Deflate compression (with zlib)
        WebSocketPerMessageDeflatePtr _perMessageDeflate;
        WebSocketPerMessageDeflateOptions _perMessageDeflateOptions;
        std::atomic<bool> _enablePerMessageDeflate;

        std::string _decompressedMessage;
        std::string _compressedMessage;

        // Used to control TLS connection behavior
        SocketTLSOptions _socketTLSOptions;

        // Proxy configuration
        ProxyConfig _proxyConfig;

        // Used to cancel dns lookup + socket connect + http upgrade
        std::atomic<bool> _requestInitCancellation;

        mutable std::mutex _closingTimePointMutex;
        std::chrono::time_point<std::chrono::steady_clock> _closingTimePoint;
        static const int kClosingMaximumWaitingDelayInMs;

        // enable auto response to ping
        std::atomic<bool> _enablePong;
        static const bool kDefaultEnablePong;

        // Optional ping and pong timeout
        std::atomic<int> _pingIntervalSecs;
        std::atomic<int> _pingTimeoutSecs;
        std::atomic<int> _idleTimeoutSecs;
        std::atomic<int> _sendTimeoutSecs;
        std::atomic<int> _closeTimeoutMs;
        std::atomic<bool> _pongReceived;
        std::chrono::time_point<std::chrono::steady_clock> _lastPongTimePoint;
        std::chrono::time_point<std::chrono::steady_clock> _lastActivityTimePoint;

        static const int kDefaultPingIntervalSecs;

        bool _setCustomMessage;
        std::string _kPingMessage;
        SendMessageKind _pingType;
        mutable std::mutex _pingConfigMutex;
        std::atomic<uint64_t> _pingCount;

        // We record when ping are being sent so that we can know when to send the next one
        mutable std::mutex _timePointsMutex;  // protects all time points
        std::chrono::time_point<std::chrono::steady_clock> _lastSendPingTimePoint;

        // If this function returns true, it is time to send a new ping
        bool pingIntervalExceeded(int pingIntervalSecs);
        SendMessageKind getPingType() const;
        void initTimePointsAfterConnect();

        // after calling close(), if no CLOSE frame answer is received back from the remote, we
        // should close the connexion
        bool closingDelayExceeded(int closeTimeoutMs);

        void sendCloseFrame(uint16_t code, const std::string& reason);

        void closeSocketAndSwitchToClosedState(uint16_t code,
                                               const std::string& reason,
                                               size_t closeWireSize,
                                               bool remote);

        bool wakeUpFromPoll(uint64_t wakeUpCode);

        bool flushSendBuffer();
        bool sendOnSocket();
        bool receiveFromSocket();

        WebSocketSendInfo sendData(wsheader_type::opcode_type type,
                                   const IXWebSocketSendData& message,
                                   bool compress,
                                   const OnProgressCallback& onProgressCallback = nullptr);

        template<class Iterator>
        bool sendFragment(
            wsheader_type::opcode_type type,
            bool fin,
            Iterator begin,
            Iterator end,
            uint64_t messageSize,
            bool compress);

        bool emitMessage(MessageKind messageKind,
                         const std::string& message,
                         bool compressedMessage,
                         const OnMessageCallback& onMessageCallback);

        bool isSendBufferEmpty() const;

        template<class Iterator>
        bool appendToSendBuffer(const uint8_t* header,
                                size_t headerSize,
                                Iterator begin,
                                Iterator end,
                                uint64_t message_size,
                                uint8_t masking_key[4]);

        void unmaskReceiveBuffer(const wsheader_type& ws);

        void getMergedChunks(std::string& message) const;

        void setCloseReason(const std::string& reason);
        std::string getCloseReason() const;
    };
} // namespace ix
