#include "prx/libSceSsl/SslTypes.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"
#include "SslCertificateFixture.hpp"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <string>
#include <thread>

extern "C" {
int APS5_VABI sceSslInit_nid_postfix(std::uint64_t);
int APS5_VABI sceSslTerm_nid_postfix(int);
int APS5_VABI sceSslLoadCert(int, int, SceSsl::Data**, SceSsl::Data*, SceSsl::Data*);
int APS5_VABI sceSslGetCaList(int, SceSsl::CaList*);
int APS5_VABI sceSslFreeCaList(int, SceSsl::CaList*);
int APS5_VABI sceSslCreateConnection(int, int, const char*);
int APS5_VABI sceSslDeleteConnection(int);
int APS5_VABI sceSslConnect(int);
int APS5_VABI sceSslClose(int);
int APS5_VABI sceSslRead(int, void*, std::size_t, int);
int APS5_VABI sceSslWrite(int, void*, std::size_t, int);
int APS5_VABI sceSslEnableVerifyOption(int, std::uint32_t);
int APS5_VABI sceSslDisableVerifyOption(int, std::uint32_t);
int APS5_VABI sceSslSetMinSslVersion(int, int);
int APS5_VABI sceSslSetAlpn(int, const char*);
const char* APS5_VABI sceSslGetAlpnSelected(int);
void* APS5_VABI sceSslGetSubjectName(int, void*);
void* APS5_VABI sceSslGetIssuerName(int, void*);
int APS5_VABI sceSslGetNameEntryCount(int, void*);
int APS5_VABI sceSslGetNameEntryInfo(int, void*, int, char*, std::size_t, std::uint8_t*, std::size_t, std::size_t*);
int APS5_VABI sceSslFreeSslCertName(int, void*);
int APS5_VABI sceSslGetSerialNumber(int, void*, std::uint8_t*, std::size_t*);
int APS5_VABI socketpair_nid_postfix(int, int, int, int*);
std::int64_t APS5_VABI send_nid_postfix(int, const void*, std::uint64_t, int);
std::int64_t APS5_VABI recv_nid_postfix(int, void*, std::uint64_t, int);
int APS5_VABI close_nid_postfix(int);
}

namespace {

constexpr char ServerName[] = "AnyPS5 fixture client";
constexpr std::uint32_t CommonNameCheck = 0x04;
constexpr std::uint32_t KnownCaCheck = 0x20;

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template <typename TAction>
void Throws(TAction action, const char* message) {
    bool caught = false;
    try { action(); } catch (const std::exception&) { caught = true; }
    Check(caught, message);
}

SceSsl::Data Data(const char* text) {
    return {reinterpret_cast<std::uint8_t*>(const_cast<char*>(text)), std::strlen(text)};
}

int ServerSend(void* parameter, const unsigned char* buffer, std::size_t length) {
    const auto result = send_nid_postfix(*static_cast<int*>(parameter), buffer, length, 0x20000);
    return result < 0 ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : static_cast<int>(result);
}

int ServerReceive(void* parameter, unsigned char* buffer, std::size_t length) {
    const auto result = recv_nid_postfix(*static_cast<int*>(parameter), buffer, length, 0);
    return result < 0 ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : static_cast<int>(result);
}

struct Server {
    int socket;
    bool exchange;
    bool finished = false;

    void Run() {
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context drbg;
        mbedtls_x509_crt certificate;
        mbedtls_pk_context key;
        mbedtls_ssl_config config;
        mbedtls_ssl_context ssl;
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&drbg);
        mbedtls_x509_crt_init(&certificate);
        mbedtls_pk_init(&key);
        mbedtls_ssl_config_init(&config);
        mbedtls_ssl_init(&ssl);
        static const char* protocols[] = {"h2", nullptr};
        bool ready = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, nullptr, 0) == 0 &&
            mbedtls_x509_crt_parse(&certificate, reinterpret_cast<const unsigned char*>(ClientPem), sizeof(ClientPem)) == 0 &&
            mbedtls_x509_crt_parse(&certificate, reinterpret_cast<const unsigned char*>(RootPem), sizeof(RootPem)) == 0 &&
            mbedtls_pk_parse_key(&key, reinterpret_cast<const unsigned char*>(ClientKey), sizeof(ClientKey), nullptr, 0,
                mbedtls_ctr_drbg_random, &drbg) == 0 &&
            mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) == 0;
        if (ready) {
            mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &drbg);
            ready = mbedtls_ssl_conf_own_cert(&config, &certificate, &key) == 0 && mbedtls_ssl_conf_alpn_protocols(&config, protocols) == 0 &&
                mbedtls_ssl_setup(&ssl, &config) == 0;
        }
        if (ready) {
            mbedtls_ssl_set_bio(&ssl, &socket, ServerSend, ServerReceive, nullptr);
            ready = mbedtls_ssl_handshake(&ssl) == 0;
        }
        if (ready && exchange) {
            unsigned char request[5]{};
            std::size_t received = 0;
            while (ready && received < sizeof(request)) {
                const int count = mbedtls_ssl_read(&ssl, request + received, sizeof(request) - received);
                ready = count > 0;
                if (ready) received += static_cast<std::size_t>(count);
            }
            ready = ready && std::memcmp(request, "hello", sizeof(request)) == 0 &&
                mbedtls_ssl_write(&ssl, reinterpret_cast<const unsigned char*>("wor"), 3) == 3 &&
                mbedtls_ssl_write(&ssl, reinterpret_cast<const unsigned char*>("ld!"), 3) == 3 && mbedtls_ssl_close_notify(&ssl) == 0;
            unsigned char rest[1];
            while (ready && mbedtls_ssl_read(&ssl, rest, sizeof(rest)) > 0) {}
        }
        finished = ready;
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&config);
        mbedtls_pk_free(&key);
        mbedtls_x509_crt_free(&certificate);
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&entropy);
        close_nid_postfix(socket);
    }
};

struct Pair {
    int client;
    Server server;
    std::thread thread;

    explicit Pair(bool exchange) : client(-1), server{-1, exchange} {
        int descriptors[2]{};
        Check(socketpair_nid_postfix(1, 1, 0, descriptors) == 0, "socketpair failed");
        client = descriptors[0];
        server.socket = descriptors[1];
        thread = std::thread([this] { server.Run(); });
    }

    ~Pair() {
        close_nid_postfix(client);
        thread.join();
    }
};

int Context(bool trustRoot) {
    const int context = sceSslInit_nid_postfix(0x100000);
    Check(context > 0, "sceSslInit failed");
    if (trustRoot) {
        auto root = Data(RootPem);
        SceSsl::Data* list[] = {&root};
        Check(sceSslLoadCert(context, 1, list, nullptr, nullptr) == 0, "sceSslLoadCert failed");
    }
    return context;
}

void Exchange() {
    const int context = Context(true);
    {
        Pair pair(true);
        const int connection = sceSslCreateConnection(context, pair.client, ServerName);
        Check(connection > 0, "sceSslCreateConnection failed");
        Check(sceSslGetAlpnSelected(connection) == nullptr, "ALPN selected before the handshake");
        Throws([&] { sceSslSetAlpn(connection, "\x05h2"); }, "malformed ALPN list was accepted");
        Check(sceSslSetAlpn(connection, "\x02h2\x08http/1.1") == 0, "sceSslSetAlpn failed");
        Check(sceSslSetMinSslVersion(connection, 5) == 0, "sceSslSetMinSslVersion failed");
        Throws([&] { sceSslSetMinSslVersion(connection, 6); }, "unknown version was accepted");
        Check(sceSslEnableVerifyOption(connection, 0x18) == 0, "sceSslEnableVerifyOption failed");
        Throws([&] { sceSslEnableVerifyOption(connection, 0x40000); }, "unknown option was accepted");
        char early[1]{};
        Throws([&] { sceSslRead(connection, early, sizeof(early), 0); }, "read before the handshake was accepted");
        Check(sceSslConnect(connection) == 0, "sceSslConnect failed");
        Throws([&] { sceSslConnect(connection); }, "second handshake was accepted");
        Throws([&] { sceSslSetAlpn(connection, nullptr); }, "ALPN changed after the handshake");
        const char* selected = sceSslGetAlpnSelected(connection);
        Check(selected && std::strcmp(selected, "h2") == 0, "ALPN protocol differs");
        char request[] = "hello";
        Check(sceSslWrite(connection, request, 5, 0) == 5, "sceSslWrite failed");
        char reply[8]{};
        Check(sceSslRead(connection, reply, 2, 3) == 2 && std::memcmp(reply, "wo", 2) == 0, "peek failed");
        Check(sceSslRead(connection, reply, 6, 0) == 6 && std::memcmp(reply, "world!", 6) == 0, "full read failed");
        Check(sceSslRead(connection, reply, sizeof(reply), 1) == 0, "close notification was not reported as the end");
        Check(sceSslClose(connection) == 0, "sceSslClose failed");
        Throws([&] { sceSslWrite(connection, request, 5, 0); }, "write after close was accepted");
        Check(sceSslDeleteConnection(connection) == 0, "sceSslDeleteConnection failed");
    }
    Check(sceSslTerm_nid_postfix(context) == 0, "sceSslTerm failed");
}

void Handshake(bool trustRoot, const char* host, std::uint32_t disabled, bool accepted) {
    const int context = Context(trustRoot);
    {
        Pair pair(false);
        const int connection = sceSslCreateConnection(context, pair.client, host);
        if (disabled) Check(sceSslDisableVerifyOption(connection, disabled) == 0, "sceSslDisableVerifyOption failed");
        if (accepted) {
            Check(sceSslConnect(connection) == 0, "accepted handshake failed");
        } else {
            Throws([&] { sceSslConnect(connection); }, "rejected certificate was accepted");
        }
        Check(sceSslDeleteConnection(connection) == 0, "sceSslDeleteConnection failed");
    }
    sceSslTerm_nid_postfix(context);
}

void Names() {
    const int context = Context(true);
    SceSsl::CaList list{};
    Check(sceSslGetCaList(context, &list) == 0 && list.num == 1, "sceSslGetCaList failed");
    void* certificate = list.certs[0];
    std::uint8_t serial[8]{};
    std::size_t serialLength = sizeof(serial);
    Check(sceSslGetSerialNumber(context, certificate, serial, &serialLength) == 0, "sceSslGetSerialNumber failed");
    Check(serialLength == 3 && serial[0] == 0x00 && serial[1] == 0x80 && serial[2] == 0xa1, "serial number differs");
    serialLength = 2;
    Throws([&] { sceSslGetSerialNumber(context, certificate, serial, &serialLength); }, "short serial buffer was accepted");
    for (const bool subject : {true, false}) {
        void* name = subject ? sceSslGetSubjectName(context, certificate) : sceSslGetIssuerName(context, certificate);
        Check(name != nullptr, "name handle missing");
        Check(sceSslGetNameEntryCount(context, name) == 3, "name entry count differs");
        char oid[32]{};
        std::uint8_t value[64]{};
        std::size_t valueLength = 0;
        Check(sceSslGetNameEntryInfo(context, name, 2, oid, sizeof(oid), value, sizeof(value), &valueLength) == 0, "entry read failed");
        Check(std::strcmp(oid, "2.5.4.3") == 0, "entry OID differs");
        Check(valueLength == 19 && std::memcmp(value, "AnyPS5 fixture root", 19) == 0, "entry value differs");
        Throws([&] { sceSslGetNameEntryInfo(context, name, 3, oid, sizeof(oid), value, sizeof(value), &valueLength); },
            "entry out of range was accepted");
        Throws([&] { sceSslGetNameEntryInfo(context, name, 2, oid, sizeof(oid), value, 4, &valueLength); }, "short value buffer was accepted");
        Check(sceSslFreeSslCertName(context, name) == 0, "sceSslFreeSslCertName failed");
        Throws([&] { sceSslFreeSslCertName(context, name); }, "name was freed twice");
    }
    int marker = 0;
    Throws([&] { sceSslGetSubjectName(context, &marker); }, "unknown certificate was accepted");
    Check(sceSslFreeCaList(context, &list) == 0, "sceSslFreeCaList failed");
    sceSslTerm_nid_postfix(context);
}

}

int main() {
    try {
        Exchange();
        Handshake(true, ServerName, 0, true);
        Handshake(true, "other.example", 0, false);
        Handshake(true, "other.example", CommonNameCheck, true);
        Handshake(false, ServerName, 0, false);
        Handshake(false, ServerName, KnownCaCheck, true);
        Names();
    } catch (const std::exception& error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
    return 0;
}
