/*
 *  IXUnityBuildsTest.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2019 Machine Zone. All rights reserved.
 */

#include "catch.hpp"
#include <cstring>
#include <ixwebsocket/IXCancellationRequest.h>
#include <ixwebsocket/IXConnectionState.h>
#include <ixwebsocket/IXDNSLookup.h>
#include <ixwebsocket/IXHttp.h>
#include <ixwebsocket/IXHttpClient.h>
#include <ixwebsocket/IXHttpServer.h>
#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXProgressCallback.h>
#include <ixwebsocket/IXSelectInterrupt.h>
#include <ixwebsocket/IXSelectInterruptFactory.h>
#include <ixwebsocket/IXSetThreadName.h>
#include <ixwebsocket/IXSocket.h>
#include <ixwebsocket/IXSocketConnect.h>
#include <ixwebsocket/IXSocketFactory.h>
#include <ixwebsocket/IXSocketMbedTLS.h>
#include <ixwebsocket/IXSocketOpenSSL.h>
#include <ixwebsocket/IXSocketServer.h>
#include <ixwebsocket/IXUrlParser.h>
#include <ixwebsocket/IXWebSocket.h>
#include <ixwebsocket/IXWebSocketCloseConstants.h>
#include <ixwebsocket/IXWebSocketCloseInfo.h>
#include <ixwebsocket/IXWebSocketErrorInfo.h>
#include <ixwebsocket/IXWebSocketHandshake.h>
#include <ixwebsocket/IXWebSocketHandshakeKeyGen.h>
#include <ixwebsocket/IXWebSocketHttpHeaders.h>
#include <ixwebsocket/IXWebSocketMessage.h>
#include <ixwebsocket/IXWebSocketMessageType.h>
#include <ixwebsocket/IXWebSocketOpenInfo.h>
#include <ixwebsocket/IXWebSocketPerMessageDeflate.h>
#include <ixwebsocket/IXWebSocketPerMessageDeflateCodec.h>
#include <ixwebsocket/IXWebSocketPerMessageDeflateOptions.h>
#include <ixwebsocket/IXWebSocketSendInfo.h>
#include <ixwebsocket/IXWebSocketServer.h>
#include <ixwebsocket/IXWebSocketTransport.h>

using namespace ix;

TEST_CASE("unity build", "[unity_build]")
{
    SECTION("dummy test")
    {
        REQUIRE(true);
    }

    SECTION("websocket handshake accept key is nul terminated")
    {
        char output[29];
        std::memset(output, 'x', sizeof(output));

        WebSocketHandshakeKeyGen::generate("dGhlIHNhbXBsZSBub25jZQ==", output);

        REQUIRE(std::string(output) == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        REQUIRE(output[28] == '\0');
    }
}
