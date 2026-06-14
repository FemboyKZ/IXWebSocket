/*
 *  IXSocketMbedTLS.cpp
 *  Author: Benjamin Sergeant, Max Weisel
 *  Copyright (c) 2019-2020 Machine Zone, Inc. All rights reserved.
 *
 *  Some code taken from
 *  https://github.com/rottor12/WsClientLib/blob/master/lib/src/WsClientLib.cpp
 *  and mini_client.c example from mbedtls
 */
#ifdef IXWEBSOCKET_USE_MBED_TLS

#include "IXSocketMbedTLS.h"

#include "IXNetSystem.h"
#include "IXSocket.h"
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <limits>
#include <string.h>
#ifdef IXWEBSOCKET_USE_MBED_TLS_MIN_VERSION_3
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#endif

#ifdef _WIN32
// For manipulating the certificate store
#include <wincrypt.h>
#endif

namespace ix
{
    namespace
    {
#ifndef _WIN32
        bool loadCertificateBundleFromFiles(mbedtls_x509_crt* cert,
                                            const char* const* paths,
                                            size_t pathCount,
                                            std::string& errorMsg)
        {
            bool foundBundle = false;
            std::string parseErrors;

            for (size_t i = 0; i < pathCount; ++i)
            {
                const char* path = paths[i];
                std::ifstream file(path);
                if (!file.good())
                {
                    continue;
                }

                foundBundle = true;
                int ret = mbedtls_x509_crt_parse_file(cert, path);
                if (ret == 0)
                {
                    return true;
                }

                char buf[256];
                mbedtls_strerror(ret, buf, sizeof(buf));
                parseErrors += path;
                parseErrors += ": ";
                parseErrors += buf;
                parseErrors += "; ";
            }

            errorMsg = foundBundle ? "Cannot parse system CA bundle: " + parseErrors
                                   : "No supported system CA bundle found";
            return false;
        }
#endif

        constexpr int kTlsHandshakePollTimeoutMs = 100;

        bool waitForMbedTlsIo(Socket& socket,
                              int result,
                              const CancellationRequest& isCancellationRequested,
                              std::string& errMsg)
        {
            if (isCancellationRequested && isCancellationRequested())
            {
                errMsg = "Cancellation requested";
                return false;
            }

            PollResultType pollResult = result == MBEDTLS_ERR_SSL_WANT_READ
                                            ? socket.isReadyToRead(kTlsHandshakePollTimeoutMs)
                                            : socket.isReadyToWrite(kTlsHandshakePollTimeoutMs);
            if (pollResult == PollResultType::Error)
            {
                errMsg = "TLS handshake socket wait failed";
                return false;
            }

            if (isCancellationRequested && isCancellationRequested())
            {
                errMsg = "Cancellation requested";
                return false;
            }

            return true;
        }
    }

    SocketMbedTLS::SocketMbedTLS(const SocketTLSOptions& tlsOptions, int fd)
        : Socket(fd)
        , _tlsOptions(tlsOptions)
    {
        initMBedTLS();
    }

    SocketMbedTLS::~SocketMbedTLS()
    {
        SocketMbedTLS::close();
    }

    void SocketMbedTLS::initMBedTLS()
    {
        std::lock_guard<std::mutex> lock(_mutex);

        _tlsReady = false;
        mbedtls_ssl_init(&_ssl);
        mbedtls_ssl_config_init(&_conf);
        mbedtls_ctr_drbg_init(&_ctr_drbg);
        mbedtls_entropy_init(&_entropy);
        mbedtls_x509_crt_init(&_cacert);
        mbedtls_x509_crt_init(&_cert);
        mbedtls_pk_init(&_pkey);
        // Initialize PSA when building with Mbed TLS v3.
        // See: https://github.com/Mbed-TLS/mbedtls/blob/development/docs/use-psa-crypto.md
#ifdef IXWEBSOCKET_USE_MBED_TLS_MIN_VERSION_3
        (void) psa_crypto_init();
#endif
    }

    bool SocketMbedTLS::loadSystemCertificates(std::string& errorMsg)
    {
#ifdef _WIN32
        DWORD flags = CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG |
                      CERT_SYSTEM_STORE_CURRENT_USER;
        HCERTSTORE systemStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, flags, L"Root");

        if (!systemStore)
        {
            errorMsg = "CertOpenStore failed with ";
            errorMsg += std::to_string(GetLastError());
            return false;
        }

        PCCERT_CONTEXT certificateIterator = NULL;

        int certificateCount = 0;
        while (certificateIterator = CertEnumCertificatesInStore(systemStore, certificateIterator))
        {
            if (certificateIterator->dwCertEncodingType & X509_ASN_ENCODING)
            {
                int ret = mbedtls_x509_crt_parse(&_cacert,
                                                 certificateIterator->pbCertEncoded,
                                                 certificateIterator->cbCertEncoded);
                if (ret == 0)
                {
                    ++certificateCount;
                }
            }
        }

        CertFreeCertificateContext(certificateIterator);
        CertCloseStore(systemStore, 0);

        if (certificateCount == 0)
        {
            errorMsg = "No certificates found";
            return false;
        }

        return true;
#else
    #if defined(__APPLE__)
        const char* const caFiles[] = {
            "/etc/ssl/cert.pem",
            "/usr/local/etc/openssl/cert.pem",
            "/opt/homebrew/etc/openssl/cert.pem",
            "/opt/homebrew/etc/openssl@3/cert.pem",
        };
    #else
        const char* const caFiles[] = {
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
            "/etc/pki/tls/cacert.pem",
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
            "/etc/ssl/cert.pem",
        };
    #endif
        return loadCertificateBundleFromFiles(
            &_cacert, caFiles, sizeof(caFiles) / sizeof(caFiles[0]), errorMsg);
#endif
    }

    int SocketMbedTLS::sendFromSocket(void* ctx, const unsigned char* buf, size_t len)
    {
        auto* socket = static_cast<Socket*>(ctx);
        if (socket == nullptr)
        {
            return MBEDTLS_ERR_NET_INVALID_CONTEXT;
        }

        auto result = socket->send(reinterpret_cast<const char*>(buf), len);
        if (result)
        {
            return static_cast<int>(result.bytes);
        }

        if (result.wouldBlock())
        {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }

        if (result.closed())
        {
            return MBEDTLS_ERR_NET_CONN_RESET;
        }

        return MBEDTLS_ERR_NET_SEND_FAILED;
    }

    int SocketMbedTLS::recvFromSocket(void* ctx, unsigned char* buf, size_t len)
    {
        auto* socket = static_cast<Socket*>(ctx);
        if (socket == nullptr)
        {
            return MBEDTLS_ERR_NET_INVALID_CONTEXT;
        }

        auto result = socket->recv(reinterpret_cast<char*>(buf), len);
        if (result)
        {
            return static_cast<int>(result.bytes);
        }

        if (result.wouldBlock())
        {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }

        if (result.closed())
        {
            return 0;
        }

        return MBEDTLS_ERR_NET_RECV_FAILED;
    }

    int SocketMbedTLS::sendFromRawSocket(void* ctx, const unsigned char* buf, size_t len)
    {
        auto* socket = static_cast<SocketMbedTLS*>(ctx);
        if (socket == nullptr)
        {
            return MBEDTLS_ERR_NET_INVALID_CONTEXT;
        }

        auto result = socket->Socket::send(reinterpret_cast<const char*>(buf), len);
        if (result)
        {
            return static_cast<int>(result.bytes);
        }

        if (result.wouldBlock())
        {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }

        if (result.closed())
        {
            return MBEDTLS_ERR_NET_CONN_RESET;
        }

        return MBEDTLS_ERR_NET_SEND_FAILED;
    }

    int SocketMbedTLS::recvFromRawSocket(void* ctx, unsigned char* buf, size_t len)
    {
        auto* socket = static_cast<SocketMbedTLS*>(ctx);
        if (socket == nullptr)
        {
            return MBEDTLS_ERR_NET_INVALID_CONTEXT;
        }

        auto result = socket->Socket::recv(reinterpret_cast<char*>(buf), len);
        if (result)
        {
            return static_cast<int>(result.bytes);
        }

        if (result.wouldBlock())
        {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }

        if (result.closed())
        {
            return 0;
        }

        return MBEDTLS_ERR_NET_RECV_FAILED;
    }

    bool SocketMbedTLS::init(const std::string& host, bool isClient, std::string& errMsg)
    {
        initMBedTLS();
        std::lock_guard<std::mutex> lock(_mutex);

        const char* pers = "IXSocketMbedTLS";

        if (mbedtls_ctr_drbg_seed(&_ctr_drbg,
                                  mbedtls_entropy_func,
                                  &_entropy,
                                  (const unsigned char*) pers,
                                  strlen(pers)) != 0)
        {
            errMsg = "Setting entropy seed failed";
            return false;
        }

        if (mbedtls_ssl_config_defaults(&_conf,
                                        (isClient) ? MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER,
                                        MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT) != 0)
        {
            errMsg = "Setting config default failed";
            return false;
        }

        mbedtls_ssl_conf_rng(&_conf, mbedtls_ctr_drbg_random, &_ctr_drbg);

        if (_tlsOptions.hasCertAndKey())
        {
            if (mbedtls_x509_crt_parse_file(&_cert, _tlsOptions.certFile.c_str()) < 0)
            {
                errMsg = "Cannot parse cert file '" + _tlsOptions.certFile + "'";
                return false;
            }
#ifdef IXWEBSOCKET_USE_MBED_TLS_MIN_VERSION_3
            if (mbedtls_pk_parse_keyfile(&_pkey, _tlsOptions.keyFile.c_str(), "", mbedtls_ctr_drbg_random, &_ctr_drbg) < 0)
#else
            if (mbedtls_pk_parse_keyfile(&_pkey, _tlsOptions.keyFile.c_str(), "") < 0)
#endif
            {
                errMsg = "Cannot parse key file '" + _tlsOptions.keyFile + "'";
                return false;
            }
            if (mbedtls_ssl_conf_own_cert(&_conf, &_cert, &_pkey) < 0)
            {
                errMsg = "Problem configuring cert '" + _tlsOptions.certFile + "'";
                return false;
            }
        }

        if (_tlsOptions.isPeerVerifyDisabled())
        {
            mbedtls_ssl_conf_authmode(&_conf, MBEDTLS_SSL_VERIFY_NONE);
        }
        else
        {
            mbedtls_ssl_conf_authmode(&_conf, MBEDTLS_SSL_VERIFY_REQUIRED);

            if (_tlsOptions.isUsingSystemDefaults())
            {
                if (!loadSystemCertificates(errMsg))
                {
                    return false;
                }
            }
            else
            {
                if (_tlsOptions.isUsingInMemoryCAs())
                {
                    const char* buffer = _tlsOptions.caFile.c_str();
                    size_t bufferSize =
                        _tlsOptions.caFile.size() + 1; // Needs to include null terminating
                                                       // character otherwise mbedtls will fail.
                    if (mbedtls_x509_crt_parse(
                            &_cacert, (const unsigned char*) buffer, bufferSize) < 0)
                    {
                        errMsg = "Cannot parse CA from memory.";
                        return false;
                    }
                }
                else if (mbedtls_x509_crt_parse_file(&_cacert, _tlsOptions.caFile.c_str()) < 0)
                {
                    errMsg = "Cannot parse CA file '" + _tlsOptions.caFile + "'";
                    return false;
                }
            }

            mbedtls_ssl_conf_ca_chain(&_conf, &_cacert, NULL);
        }

        if (mbedtls_ssl_setup(&_ssl, &_conf) != 0)
        {
            errMsg = "SSL setup failed";
            return false;
        }

        if (!_tlsOptions.disable_hostname_validation)
        {
            if (!host.empty() && mbedtls_ssl_set_hostname(&_ssl, host.c_str()) != 0)
            {
                errMsg = "SNI setup failed";
                return false;
            }
        }

        _tlsReady = true;
        return true;
    }

    bool SocketMbedTLS::accept(std::string& errMsg)
    {
        return accept(errMsg, nullptr);
    }

    bool SocketMbedTLS::accept(std::string& errMsg,
                               const CancellationRequest& isCancellationRequested)
    {
        bool isClient = false;
        bool initialized = init(std::string(), isClient, errMsg);
        if (!initialized)
        {
            close();
            return false;
        }

        mbedtls_ssl_set_bio(
            &_ssl, this, &SocketMbedTLS::sendFromRawSocket, &SocketMbedTLS::recvFromRawSocket, NULL);

        int res;
        do
        {
            {
                std::lock_guard<std::mutex> lock(_mutex);
                res = mbedtls_ssl_handshake(&_ssl);
            }

            if (isCancellationRequested && isCancellationRequested())
            {
                errMsg = "Cancellation requested";
                close();
                return false;
            }

            if ((res == MBEDTLS_ERR_SSL_WANT_READ || res == MBEDTLS_ERR_SSL_WANT_WRITE) &&
                !waitForMbedTlsIo(*this, res, isCancellationRequested, errMsg))
            {
                close();
                return false;
            }
        } while (res == MBEDTLS_ERR_SSL_WANT_READ || res == MBEDTLS_ERR_SSL_WANT_WRITE);

        if (res != 0)
        {
            char buf[256];
            mbedtls_strerror(res, buf, sizeof(buf));

            errMsg = "error in handshake : ";
            errMsg += buf;

            if (res == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)
            {
                char verifyBuf[512];
                uint32_t flags = mbedtls_ssl_get_verify_result(&_ssl);

                mbedtls_x509_crt_verify_info(verifyBuf, sizeof(verifyBuf), "  ! ", flags);
                errMsg += " : ";
                errMsg += verifyBuf;
            }

            close();
            return false;
        }

        return true;
    }

    bool SocketMbedTLS::connect(const std::string& host,
                                int port,
                                std::string& errMsg,
                                const CancellationRequest& isCancellationRequested)
    {
        if (!Socket::connect(host, port, errMsg, isCancellationRequested)) return false;

        bool isClient = true;
        bool initialized = init(host, isClient, errMsg);
        if (!initialized)
        {
            close();
            return false;
        }

        if (getProxySocket())
        {
            mbedtls_ssl_set_bio(
                &_ssl, getProxySocket(), &SocketMbedTLS::sendFromSocket, &SocketMbedTLS::recvFromSocket, NULL);
        }
        else
        {
            mbedtls_ssl_set_bio(
                &_ssl, this, &SocketMbedTLS::sendFromRawSocket, &SocketMbedTLS::recvFromRawSocket, NULL);
        }

        int res;
        do
        {
            {
                std::lock_guard<std::mutex> lock(_mutex);
                res = mbedtls_ssl_handshake(&_ssl);
            }

            if (isCancellationRequested && isCancellationRequested())
            {
                errMsg = "Cancellation requested";
                close();
                return false;
            }

            if ((res == MBEDTLS_ERR_SSL_WANT_READ || res == MBEDTLS_ERR_SSL_WANT_WRITE) &&
                !waitForMbedTlsIo(*this, res, isCancellationRequested, errMsg))
            {
                close();
                return false;
            }
        } while (res == MBEDTLS_ERR_SSL_WANT_READ || res == MBEDTLS_ERR_SSL_WANT_WRITE);

        if (res != 0)
        {
            char buf[256];
            mbedtls_strerror(res, buf, sizeof(buf));

            errMsg = "error in handshake : ";
            errMsg += buf;

            close();
            return false;
        }

        return true;
    }

    void SocketMbedTLS::close()
    {
        std::lock_guard<std::mutex> lock(_mutex);

        _tlsReady = false;
        mbedtls_ssl_free(&_ssl);
        mbedtls_ssl_config_free(&_conf);
        mbedtls_ctr_drbg_free(&_ctr_drbg);
        mbedtls_entropy_free(&_entropy);
        mbedtls_x509_crt_free(&_cacert);
        mbedtls_x509_crt_free(&_cert);
        mbedtls_pk_free(&_pkey);
#ifdef IXWEBSOCKET_USE_MBED_TLS_MIN_VERSION_3
        mbedtls_psa_crypto_free();
#endif

        Socket::close();
    }

    IoResult SocketMbedTLS::send(const char* buf, size_t nbyte)
    {
        std::lock_guard<std::mutex> lock(_mutex);

        if (!_tlsReady)
        {
            return {0, IoError::ConnectionClosed};
        }

        const size_t writeSize =
            std::min(nbyte, static_cast<size_t>(std::numeric_limits<int>::max()));
        int res = mbedtls_ssl_write(&_ssl, (const unsigned char*) buf, writeSize);

        if (res > 0) return {static_cast<size_t>(res), IoError::Success};
        if (res == MBEDTLS_ERR_SSL_WANT_READ || res == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            return {0, IoError::WouldBlock};
        }
        return {0, IoError::Error};
    }

    IoResult SocketMbedTLS::recv(void* buf, size_t nbyte)
    {
        while (true)
        {
            std::lock_guard<std::mutex> lock(_mutex);

            if (!_tlsReady)
            {
                return {0, IoError::ConnectionClosed};
            }

            const int readSize = static_cast<int>(
                std::min(nbyte, static_cast<size_t>(std::numeric_limits<int>::max())));
            int res = mbedtls_ssl_read(&_ssl, (unsigned char*) buf, readSize);

            if (res > 0) return {static_cast<size_t>(res), IoError::Success};
            if (res == 0) return {0, IoError::ConnectionClosed};
            if (res == MBEDTLS_ERR_SSL_WANT_READ || res == MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                return {0, IoError::WouldBlock};
            }
            return {0, IoError::Error};
        }
    }

} // namespace ix

#endif // IXWEBSOCKET_USE_MBED_TLS
