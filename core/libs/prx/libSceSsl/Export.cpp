#include "SslTypes.hpp"
#include "prx/libc/include/General.hpp"
#include "prx/libc/include/GuestArena.hpp"

#include <mbedtls/asn1.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

extern "C" {
std::int64_t APS5_VABI sceNetSend(int s, const void* buf, std::size_t len, int flags);
std::int64_t APS5_VABI sceNetRecv(int s, void* buf, std::size_t len, int flags);
std::int64_t APS5_VABI send_nid_postfix(int descriptor, const void* buffer, std::uint64_t length, int flags);
std::int64_t APS5_VABI recv_nid_postfix(int descriptor, void* buffer, std::uint64_t length, int flags);
int* APS5_VABI __error_nid_postfix();
}

namespace {

constexpr int ErrorNotFound = static_cast<int>(0x8095f004);
constexpr int ErrorInvalidArg = static_cast<int>(0x8095177a);
constexpr int ErrorInvalidId = static_cast<int>(0x8095f006);
constexpr std::int64_t NetErrorBadDescriptor = static_cast<std::int32_t>(0x80410109u);
constexpr std::int64_t NetErrorAgain = static_cast<std::int32_t>(0x80410123u);
constexpr int GuestEagain = 35;
constexpr int GuestNoSignal = 0x20000;

constexpr std::uint32_t VerifyServer = 0x01;
constexpr std::uint32_t VerifyCommonName = 0x04;
constexpr std::uint32_t VerifyNotAfter = 0x08;
constexpr std::uint32_t VerifyNotBefore = 0x10;
constexpr std::uint32_t VerifyKnownCa = 0x20;
constexpr std::uint32_t VerifyNotSha1 = 0x2000;
constexpr std::uint32_t VerifyOptions = VerifyServer | VerifyCommonName | VerifyNotAfter | VerifyNotBefore | VerifyKnownCa | VerifyNotSha1;
constexpr std::uint32_t DefaultVerifyOptions = VerifyServer | VerifyCommonName | VerifyKnownCa;

constexpr int ReadPartial = 0x01;
constexpr int ReadPeek = 0x03;

constexpr int VersionNone = 0;
constexpr int VersionTls12 = 5;

struct Pool {
    std::size_t size, current = 0, peak = 0;
    bool exhausted = false;
    std::mutex mutex;
    explicit Pool(std::size_t size) : size(size) {}
};

struct alignas(std::max_align_t) Allocation {
    Pool* pool;
    std::size_t size;
};

thread_local Pool* currentPool = nullptr;

void* PoolCalloc(std::size_t count, std::size_t size) noexcept {
    if (!currentPool) return nullptr;
    std::lock_guard lock(currentPool->mutex);
    if (size && count > std::numeric_limits<std::size_t>::max() / size) {
        currentPool->exhausted = true;
        return nullptr;
    }
    const auto bytes = count * size;
    if (bytes > currentPool->size - currentPool->current || bytes > std::numeric_limits<std::size_t>::max() - sizeof(Allocation)) {
        currentPool->exhausted = true;
        return nullptr;
    }
    auto* allocation = static_cast<Allocation*>(std::calloc(1, sizeof(Allocation) + bytes));
    if (!allocation) {
        currentPool->exhausted = true;
        return nullptr;
    }
    allocation->pool = currentPool;
    allocation->size = bytes;
    currentPool->current += bytes;
    currentPool->peak = std::max(currentPool->peak, currentPool->current);
    return allocation + 1;
}

void PoolFree(void* pointer) noexcept {
    if (!pointer) return;
    auto* allocation = static_cast<Allocation*>(pointer) - 1;
    {
        std::lock_guard lock(allocation->pool->mutex);
        allocation->pool->current -= allocation->size;
    }
    mbedtls_platform_zeroize(pointer, allocation->size);
    std::free(allocation);
}

struct PoolScope {
    Pool* previous;
    explicit PoolScope(Pool& pool) : previous(std::exchange(currentPool, &pool)) { pool.exhausted = false; }
    ~PoolScope() { currentPool = previous; }
};

struct PoolDeleter {
    void operator()(std::uint8_t* bytes) const { PoolFree(bytes); }
};

using Block = std::unique_ptr<std::uint8_t, PoolDeleter>;

Block Allocate(std::size_t size) {
    Block block(static_cast<std::uint8_t*>(PoolCalloc(1, std::max<std::size_t>(1, size))));
    if (!block) throw std::bad_alloc();
    return block;
}

std::size_t Add(std::size_t left, std::size_t right) {
    if (right > std::numeric_limits<std::size_t>::max() - left) throw std::length_error("SSL allocation size overflow");
    return left + right;
}

void CheckBackend(int error, const char* message) {
    if (error == 0) return;
    if (currentPool && currentPool->exhausted) throw std::bad_alloc();
    throw std::invalid_argument(message);
}

struct CertificateChain;

struct CertificateHandle {
    std::weak_ptr<CertificateChain> owner;
    const mbedtls_x509_crt* certificate;
};

struct CertificateChain {
    mbedtls_x509_crt root;
    std::vector<CertificateHandle*> handles;
    CertificateChain() { mbedtls_x509_crt_init(&root); }
    ~CertificateChain() { mbedtls_x509_crt_free(&root); }
};

struct PrivateKey {
    mbedtls_pk_context key;
    PrivateKey() { mbedtls_pk_init(&key); }
    ~PrivateKey() { mbedtls_pk_free(&key); }
};

struct Random {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    Random() {
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&drbg);
    }
    ~Random() {
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&entropy);
    }
    void Seed() {
        CheckBackend(mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, nullptr, 0), "SSL random generator initialization failed");
    }
};

struct Identity {
    std::shared_ptr<CertificateChain> chain;
    PrivateKey key;
};

struct Snapshot {
    Block data;
    std::vector<std::shared_ptr<CertificateChain>> certificates;
    std::size_t count;
};

struct NameEntry {
    std::string oid;
    std::vector<std::uint8_t> value;
};

struct CertificateName {
    std::vector<NameEntry> entries;
};

struct Context {
    Pool pool;
    std::vector<std::shared_ptr<CertificateChain>> authorities;
    std::shared_ptr<Identity> identity;
    std::vector<std::unique_ptr<CertificateHandle>> certificateHandles;
    std::unordered_map<void*, Snapshot> caLists;
    std::unordered_map<void*, Snapshot> caCerts;
    std::unordered_map<void*, std::unique_ptr<CertificateName>> names;
    explicit Context(std::size_t size) : pool{size} {}
};

using SslVerifyCallback = int (APS5_VABI *)(int, unsigned int, void**, int, void*);

struct Session {
    std::shared_ptr<Context> context;
    std::vector<std::shared_ptr<CertificateChain>> authorities;
    std::shared_ptr<Identity> identity;
    Random random;
    mbedtls_x509_crt_profile profile;
    mbedtls_ssl_config config;
    mbedtls_ssl_context ssl;
    explicit Session(std::shared_ptr<Context> owner) : context(std::move(owner)), profile(mbedtls_x509_crt_profile_default) {
        mbedtls_ssl_config_init(&config);
        mbedtls_ssl_init(&ssl);
    }
    ~Session() {
        PoolScope scope(context->pool);
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&config);
    }
};

struct SslConnection {
    int context;
    int socket;
    std::string host;
    SslVerifyCallback verifyCallback = nullptr;
    void* verifyArgument = nullptr;
    std::uint32_t verifyOptions = DefaultVerifyOptions;
    int minimumVersion = VersionNone;
    std::vector<std::string> protocols;
    std::vector<const char*> protocolList;
    std::unique_ptr<Session> session;
    bool closed = false;
    bool connecting = false;
    std::vector<std::uint8_t> peeked;
    std::mutex io;
};

struct Runtime {
    std::mutex mutex;
    std::unordered_map<int, std::shared_ptr<Context>> contexts;
    std::unordered_map<int, std::shared_ptr<SslConnection>> connections;
    unsigned nextHandle = 1;
    Runtime() {
        if (mbedtls_platform_set_calloc_free(PoolCalloc, PoolFree) != 0)
            throw std::runtime_error("SSL allocator initialization failed");
    }
};

Runtime& State() {
    static auto* runtime = new Runtime;
    return *runtime;
}

Context& GetContext(int handle) {
    const auto found = State().contexts.find(handle);
    if (found == State().contexts.end()) throw std::invalid_argument("Invalid SSL context");
    return *found->second;
}

SslConnection& RequireConnection(const char* function, int sslConnectionId) {
    const auto connection = State().connections.find(sslConnectionId);
    if (connection == State().connections.end()) throw std::invalid_argument(std::string(function) + ": unknown connection");
    if (!State().contexts.contains(connection->second->context)) {
        throw std::invalid_argument(std::string(function) + ": the connection's context was terminated");
    }
    return *connection->second;
}

std::shared_ptr<SslConnection> ShareConnection(const char* function, int sslConnectionId) {
    std::lock_guard lock(State().mutex);
    RequireConnection(function, sslConnectionId);
    return State().connections.at(sslConnectionId);
}

struct Input {
    Block bytes;
    std::size_t size;
};

Input CopyInput(const SceSsl::Data& data) {
    if (!data.ptr || !data.size) throw std::invalid_argument("Empty SSL certificate/key data");
    auto bytes = Allocate(Add(data.size, 1));
    std::memcpy(bytes.get(), data.ptr, data.size);
    auto size = data.size;
    std::size_t first = 0;
    while (first < size && (bytes.get()[first] == ' ' || bytes.get()[first] == '\r' || bytes.get()[first] == '\n' || bytes.get()[first] == '\t')) ++first;
    const bool pem = first < size && bytes.get()[first] == '-';
    if (pem) {
        if (bytes.get()[size - 1] != 0) ++size;
        if (std::memchr(bytes.get(), 0, size - 1)) throw std::invalid_argument("Embedded null in SSL PEM data");
    } else {
        auto* position = bytes.get();
        std::size_t length = 0;
        CheckBackend(mbedtls_asn1_get_tag(&position, bytes.get() + size, &length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE),
            "Invalid SSL DER sequence");
        if (length != static_cast<std::size_t>(bytes.get() + size - position)) throw std::invalid_argument("Trailing SSL DER data");
    }
    return {std::move(bytes), size};
}

std::shared_ptr<CertificateChain> ParseCertificate(const SceSsl::Data& data) {
    auto chain = std::make_shared<CertificateChain>();
    const auto input = CopyInput(data);
    CheckBackend(mbedtls_x509_crt_parse(&chain->root, input.bytes.get(), input.size), "Invalid SSL certificate chain");
    return chain;
}

std::size_t CertificateCount(const Context& context) {
    std::size_t count = 0;
    for (const auto& chain : context.authorities) count = Add(count, chain->handles.size());
    return count;
}

Pool& HostPool() {
    static auto* pool = new Pool(std::numeric_limits<std::size_t>::max() / 2);
    return *pool;
}

std::shared_ptr<CertificateChain> LoadSystemRoots() {
    PoolScope scope(HostPool());
    auto chain = std::make_shared<CertificateChain>();
#ifdef _WIN32
    if (const HCERTSTORE store = CertOpenSystemStoreW(0, L"ROOT")) {
        for (PCCERT_CONTEXT entry = CertEnumCertificatesInStore(store, nullptr); entry; entry = CertEnumCertificatesInStore(store, entry)) {
            if (entry->dwCertEncodingType & X509_ASN_ENCODING) mbedtls_x509_crt_parse_der(&chain->root, entry->pbCertEncoded, entry->cbCertEncoded);
        }
        CertCloseStore(store, 0);
    }
#else
    for (const char* path : {"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem",
             "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/cert.pem"}) {
        std::ifstream file(path, std::ios::binary);
        if (!file) continue;
        std::string bundle((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        if (bundle.empty()) continue;
        if (mbedtls_x509_crt_parse(&chain->root, reinterpret_cast<const unsigned char*>(bundle.c_str()), bundle.size() + 1) >= 0 &&
            chain->root.raw.len) {
            break;
        }
        chain = std::make_shared<CertificateChain>();
    }
#endif
    return chain;
}

const CertificateChain& SystemRoots() {
    static const auto roots = LoadSystemRoots();
    return *roots;
}

bool SameName(const mbedtls_x509_buf& left, const mbedtls_x509_buf& right) {
    return left.len == right.len && std::memcmp(left.p, right.p, left.len) == 0;
}

int AddCandidate(mbedtls_x509_crt*& candidates, const mbedtls_x509_crt& authority) {
    if (!candidates) {
        candidates = static_cast<mbedtls_x509_crt*>(mbedtls_calloc(1, sizeof(mbedtls_x509_crt)));
        if (!candidates) return MBEDTLS_ERR_X509_ALLOC_FAILED;
        mbedtls_x509_crt_init(candidates);
    }
    return mbedtls_x509_crt_parse_der(candidates, authority.raw.p, authority.raw.len);
}

int TrustedCandidates(void* parameter, const mbedtls_x509_crt* child, mbedtls_x509_crt** result) {
    const auto& session = *static_cast<const Session*>(parameter);
    mbedtls_x509_crt* candidates = nullptr;
    auto collect = [&](const mbedtls_x509_crt* authority) {
        for (; authority && authority->raw.len; authority = authority->next) {
            if (!SameName(authority->subject_raw, child->issuer_raw)) continue;
            if (const int error = AddCandidate(candidates, *authority); error != 0) return error;
        }
        return 0;
    };
    int error = 0;
    for (const auto& chain : session.authorities) {
        if ((error = collect(&chain->root)) != 0) break;
    }
    if (error == 0) error = collect(&SystemRoots().root);
    if (error != 0) {
        if (candidates) {
            mbedtls_x509_crt_free(candidates);
            mbedtls_free(candidates);
        }
        return error;
    }
    *result = candidates;
    return 0;
}

int TransportSend(void* parameter, const unsigned char* buffer, std::size_t length) {
    const int socket = *static_cast<const int*>(parameter);
    auto result = sceNetSend(socket, buffer, length, 0);
    if (result == NetErrorBadDescriptor) {
        result = send_nid_postfix(socket, buffer, length, GuestNoSignal);
        if (result < 0) return *__error_nid_postfix() == GuestEagain ? MBEDTLS_ERR_SSL_WANT_WRITE : MBEDTLS_ERR_NET_SEND_FAILED;
    }
    if (result == NetErrorAgain) return MBEDTLS_ERR_SSL_WANT_WRITE;
    if (result < 0) return MBEDTLS_ERR_NET_SEND_FAILED;
    return static_cast<int>(result);
}

int TransportReceive(void* parameter, unsigned char* buffer, std::size_t length) {
    const int socket = *static_cast<const int*>(parameter);
    auto result = sceNetRecv(socket, buffer, length, 0);
    if (result == NetErrorBadDescriptor) {
        result = recv_nid_postfix(socket, buffer, length, 0);
        if (result < 0) return *__error_nid_postfix() == GuestEagain ? MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_NET_RECV_FAILED;
    }
    if (result == NetErrorAgain) return MBEDTLS_ERR_SSL_WANT_READ;
    if (result < 0) return MBEDTLS_ERR_NET_RECV_FAILED;
    return static_cast<int>(result);
}

[[noreturn]] void BackendFailure(const char* function, int error) {
    if (currentPool && currentPool->exhausted) throw std::bad_alloc();
    char text[160]{};
    mbedtls_strerror(error, text, sizeof(text));
    throw std::runtime_error(std::string(function) + ": " + text + " (console error code unknown)");
}

std::uint32_t AllowedFailures(std::uint32_t options) {
    std::uint32_t allowed = 0;
    if (!(options & VerifyCommonName)) allowed |= MBEDTLS_X509_BADCERT_CN_MISMATCH;
    if (!(options & VerifyNotAfter)) allowed |= MBEDTLS_X509_BADCERT_EXPIRED;
    if (!(options & VerifyNotBefore)) allowed |= MBEDTLS_X509_BADCERT_FUTURE;
    if (!(options & VerifyKnownCa)) allowed |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
    return allowed;
}

void CheckVerifyOption(const char* function, std::uint32_t option) {
    if (option & ~VerifyOptions) throw std::invalid_argument(std::string(function) + ": unknown verification option");
}

SslConnection& RequireIdle(const char* function, int sslConnectionId) {
    auto& connection = RequireConnection(function, sslConnectionId);
    if (connection.session || connection.closed || connection.connecting) {
        throw std::invalid_argument(std::string(function) + ": the connection was already started");
    }
    return connection;
}

Session& RequireSession(const char* function, SslConnection& connection) {
    if (!connection.session) {
        throw std::invalid_argument(std::string(function) + (connection.closed ? ": the connection was closed" : ": the connection is not connected"));
    }
    return *connection.session;
}

const mbedtls_x509_crt& RequireCertificate(Context& context, void* certificate) {
    for (const auto& handle : context.certificateHandles) {
        if (handle.get() != certificate) continue;
        if (handle->owner.expired()) throw std::invalid_argument("SSL certificate was unloaded");
        return *handle->certificate;
    }
    throw std::invalid_argument("Unknown SSL certificate");
}

CertificateName& RequireName(Context& context, void* name) {
    const auto found = context.names.find(name);
    if (found == context.names.end()) throw std::invalid_argument("Unknown SSL certificate name");
    return *found->second;
}

void* CreateName(int sslCtxId, void* certificate, bool subject) {
    std::lock_guard lock(State().mutex);
    auto& context = GetContext(sslCtxId);
    const auto& source = RequireCertificate(context, certificate);
    auto name = std::make_unique<CertificateName>();
    for (const auto* entry = subject ? &source.subject : &source.issuer; entry && entry->oid.p; entry = entry->next) {
        char oid[128]{};
        const int length = mbedtls_oid_get_numeric_string(oid, sizeof(oid), &entry->oid);
        if (length < 0) throw std::invalid_argument("SSL certificate name has an unprintable OID");
        name->entries.push_back({std::string(oid, static_cast<std::size_t>(length)), {entry->val.p, entry->val.p + entry->val.len}});
    }
    void* handle = name.get();
    context.names.emplace(handle, std::move(name));
    return handle;
}

int ReadRecord(const char* function, SslConnection& connection, std::uint8_t* buffer, std::size_t length) {
    auto& session = RequireSession(function, connection);
    PoolScope scope(session.context->pool);
    const int result = mbedtls_ssl_read(&session.ssl, buffer, length);
    if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return 0;
    if (result < 0) BackendFailure(function, result);
    return result;
}

}

extern "C" {

int APS5_VABI sceSslInit_nid_postfix(std::uint64_t poolSize) {
    auto& state = State();
    std::lock_guard lock(state.mutex);
    if (state.nextHandle > static_cast<unsigned>(std::numeric_limits<int>::max())) throw std::overflow_error("SSL context handles exhausted");
    const auto handle = static_cast<int>(state.nextHandle);
    state.contexts.emplace(handle, std::make_shared<Context>(poolSize));
    ++state.nextHandle;
    return handle;
}

int APS5_VABI sceSslTerm_nid_postfix(int sslCtxId) {
    auto& state = State();
    std::lock_guard lock(state.mutex);
    state.contexts.erase(sslCtxId);
    return 0;
}

int APS5_VABI sceSslGetMemoryPoolStats(int sslCtxId, SceSsl::MemoryPoolStats* stats) {
    if (!stats) return static_cast<int>(0x8095F007);
    auto& state = State();
    std::lock_guard lock(state.mutex);
    const auto found = state.contexts.find(sslCtxId);
    if (found == state.contexts.end()) {
        std::memset(stats, 0, sizeof(*stats));
        return static_cast<int>(0x8095F006);
    }
    const auto& pool = found->second->pool;
    *stats = {pool.size, pool.peak, pool.current, 0};
    return 0;
}

int APS5_VABI sceSslLoadCert(int sslCtxId, int caCertNum, SceSsl::Data** caList, SceSsl::Data* cert, SceSsl::Data* privateKey) {
    if (caCertNum < 0 || (caCertNum && !caList) || (!!cert != !!privateKey))
        throw std::invalid_argument("Invalid SSL certificate load arguments");
    auto& state = State();
    std::lock_guard lock(state.mutex);
    auto& context = GetContext(sslCtxId);
    PoolScope scope(context.pool);
    std::vector<std::shared_ptr<CertificateChain>> authorities;
    std::vector<std::unique_ptr<CertificateHandle>> handles;
    for (int index = 0; index < caCertNum; ++index) {
        if (!caList[index]) throw std::invalid_argument("Missing SSL certificate descriptor");
        auto chain = ParseCertificate(*caList[index]);
        for (auto* entry = &chain->root; entry; entry = entry->next) {
            auto handle = std::make_unique<CertificateHandle>(CertificateHandle{chain, entry});
            chain->handles.push_back(handle.get());
            handles.push_back(std::move(handle));
        }
        authorities.push_back(std::move(chain));
    }
    std::shared_ptr<Identity> identity;
    if (cert) {
        identity = std::make_shared<Identity>();
        identity->chain = ParseCertificate(*cert);
        const auto key = CopyInput(*privateKey);
        Random random;
        random.Seed();
        CheckBackend(mbedtls_pk_parse_key(&identity->key.key, key.bytes.get(), key.size, nullptr, 0,
            mbedtls_ctr_drbg_random, &random.drbg), "Invalid SSL private key");
        CheckBackend(mbedtls_pk_check_pair(&identity->chain->root.pk, &identity->key.key, mbedtls_ctr_drbg_random, &random.drbg),
            "SSL client certificate and private key do not match");
    }
    context.authorities.reserve(Add(context.authorities.size(), authorities.size()));
    context.certificateHandles.reserve(Add(context.certificateHandles.size(), handles.size()));
    for (auto& chain : authorities) context.authorities.push_back(std::move(chain));
    for (auto& handle : handles) context.certificateHandles.push_back(std::move(handle));
    if (identity) context.identity = std::move(identity);
    return 0;
}

int APS5_VABI sceSslUnloadCert(int sslCtxId) {
    auto& state = State();
    std::lock_guard lock(state.mutex);
    auto& context = GetContext(sslCtxId);
    context.authorities.clear();
    context.identity.reset();
    return 0;
}

int APS5_VABI sceSslGetCaList(int sslCtxId, SceSsl::CaList* output) {
    if (!output) return ErrorInvalidArg;
    auto& state = State();
    std::lock_guard lock(state.mutex);
    auto& context = GetContext(sslCtxId);
    PoolScope scope(context.pool);
    const auto count = CertificateCount(context);
    if (!count) {
        *output = {};
        return ErrorNotFound;
    }
    if (count > static_cast<std::size_t>(std::numeric_limits<int>::max())) throw std::length_error("Too many SSL authorities");
    Snapshot snapshot{Allocate(count * sizeof(void*)), context.authorities, count};
    auto** pointers = reinterpret_cast<void**>(snapshot.data.get());
    std::size_t index = 0;
    for (const auto& chain : snapshot.certificates) for (auto* handle : chain->handles) pointers[index++] = handle;
    context.caLists.emplace(pointers, std::move(snapshot));
    *output = {pointers, static_cast<int>(count)};
    return 0;
}

int APS5_VABI sceSslFreeCaList(int sslCtxId, SceSsl::CaList* list) {
    if (!list) return ErrorInvalidArg;
    auto& state = State();
    std::lock_guard lock(state.mutex);
    auto& context = GetContext(sslCtxId);
    if (!list->certs && list->num == 0) return 0;
    const auto found = context.caLists.find(list->certs);
    if (found == context.caLists.end() || list->num < 0 || static_cast<std::size_t>(list->num) != found->second.count)
        throw std::invalid_argument("Invalid SSL CA list allocation");
    context.caLists.erase(found);
    *list = {};
    return 0;
}

int APS5_VABI sceSslGetCaCerts(int sslCtxId, SceSsl::CaCerts* output) {
    if (!output) return ErrorInvalidArg;
    auto& state = State();
    std::lock_guard lock(state.mutex);
    const auto found = state.contexts.find(sslCtxId);
    if (found == state.contexts.end()) {
        *output = {};
        return ErrorNotFound;
    }
    auto& context = *found->second;
    PoolScope scope(context.pool);
    const auto count = CertificateCount(context);
    if (!count) {
        *output = {};
        return ErrorNotFound;
    }
    if (count > std::numeric_limits<std::size_t>::max() / sizeof(SceSsl::Data)) throw std::length_error("Too many SSL authorities");
    auto total = count * sizeof(SceSsl::Data);
    for (const auto& chain : context.authorities)
        for (auto* entry = &chain->root; entry; entry = entry->next) total = Add(total, entry->raw.len);
    Snapshot snapshot{Allocate(total), {}, count};
    auto* data = reinterpret_cast<SceSsl::Data*>(snapshot.data.get());
    auto* next = snapshot.data.get() + count * sizeof(SceSsl::Data);
    std::size_t index = 0;
    for (const auto& chain : context.authorities) {
        for (auto* entry = &chain->root; entry; entry = entry->next) {
            data[index++] = {next, entry->raw.len};
            std::memcpy(next, entry->raw.p, entry->raw.len);
            next += entry->raw.len;
        }
    }
    context.caCerts.emplace(data, std::move(snapshot));
    *output = {data, count, data};
    return 0;
}

int APS5_VABI sceSslFreeCaCerts(int sslCtxId, SceSsl::CaCerts* certificates) {
    if (!certificates) return ErrorInvalidArg;
    auto& state = State();
    std::lock_guard lock(state.mutex);
    const auto found = state.contexts.find(sslCtxId);
    if (found != state.contexts.end()) {
        auto& snapshots = found->second->caCerts;
        const auto allocation = snapshots.find(certificates->pool);
        if (allocation != snapshots.end()) {
            if (certificates->certs != certificates->pool || certificates->num != allocation->second.count)
                throw std::invalid_argument("Invalid SSL CA certificate allocation");
            snapshots.erase(allocation);
        }
    }
    *certificates = {};
    return 0;
}

int APS5_VABI sceSslCreateConnection(int sslCtxId, int sockId, const char* host) {
    if (!host) throw std::invalid_argument("sceSslCreateConnection: null host");
    std::lock_guard lock(State().mutex);
    if (!State().contexts.contains(sslCtxId)) return ErrorInvalidId;
    auto& state = State();
    if (state.nextHandle > static_cast<unsigned>(std::numeric_limits<int>::max())) throw std::overflow_error("SSL connection handles exhausted");
    const auto id = static_cast<int>(state.nextHandle);
    auto connection = std::make_shared<SslConnection>();
    connection->context = sslCtxId;
    connection->socket = sockId;
    connection->host = host;
    state.connections.emplace(id, std::move(connection));
    ++state.nextHandle;
    return id;
}

int APS5_VABI sceSslDeleteConnection(int sslConnectionId) {
    std::lock_guard lock(State().mutex);
    if (!State().connections.erase(sslConnectionId)) throw std::invalid_argument("sceSslDeleteConnection: unknown connection");
    return 0;
}

int APS5_VABI sceSslSetVerifyCallback(int sslConnectionId, SslVerifyCallback cbfunc, void* userArg) {
    std::lock_guard lock(State().mutex);
    SslConnection& connection = RequireConnection(__func__, sslConnectionId);
    connection.verifyCallback = cbfunc;
    connection.verifyArgument = userArg;
    return 0;
}

int APS5_VABI sceSslEnableVerifyOption(int sslConnectionId, std::uint32_t option) {
    CheckVerifyOption(__func__, option);
    std::lock_guard lock(State().mutex);
    RequireIdle(__func__, sslConnectionId).verifyOptions |= option;
    return 0;
}

int APS5_VABI sceSslDisableVerifyOption(int sslConnectionId, std::uint32_t option) {
    CheckVerifyOption(__func__, option);
    std::lock_guard lock(State().mutex);
    RequireIdle(__func__, sslConnectionId).verifyOptions &= ~option;
    return 0;
}

int APS5_VABI sceSslSetMinSslVersion(int sslConnectionId, int version) {
    if (version < VersionNone || version > VersionTls12) throw std::invalid_argument("sceSslSetMinSslVersion: unknown version");
    std::lock_guard lock(State().mutex);
    RequireIdle(__func__, sslConnectionId).minimumVersion = version;
    return 0;
}

int APS5_VABI sceSslSetAlpn(int sslConnectionId, const char* proto) {
    std::vector<std::string> protocols;
    if (proto) {
        const auto* wire = reinterpret_cast<const std::uint8_t*>(proto);
        const auto size = std::strlen(proto);
        for (std::size_t offset = 0; offset < size;) {
            const std::size_t length = wire[offset++];
            if (!length || length > size - offset) throw std::invalid_argument("sceSslSetAlpn: malformed protocol list");
            protocols.emplace_back(proto + offset, length);
            offset += length;
        }
    }
    std::lock_guard lock(State().mutex);
    auto& connection = RequireIdle(__func__, sslConnectionId);
    connection.protocols = std::move(protocols);
    connection.protocolList.clear();
    for (const auto& protocol : connection.protocols) connection.protocolList.push_back(protocol.c_str());
    if (!connection.protocolList.empty()) connection.protocolList.push_back(nullptr);
    return 0;
}

const char* APS5_VABI sceSslGetAlpnSelected(int sslConnectionId) {
    const auto connection = ShareConnection(__func__, sslConnectionId);
    std::lock_guard io(connection->io);
    return connection->session ? mbedtls_ssl_get_alpn_protocol(&connection->session->ssl) : nullptr;
}

int APS5_VABI sceSslConnect(int sslConnectionId) {
    std::shared_ptr<SslConnection> connection;
    std::unique_ptr<Session> session;
    std::uint32_t options;
    {
        std::lock_guard lock(State().mutex);
        auto& current = RequireIdle(__func__, sslConnectionId);
        if (current.verifyCallback) NotImplemented_nid_no_patch("sceSslConnect: verification callback");
        connection = State().connections.at(sslConnectionId);
        const auto& context = State().contexts.at(current.context);
        session = std::make_unique<Session>(context);
        session->authorities = context->authorities;
        session->identity = context->identity;
        options = current.verifyOptions;
        current.connecting = true;
    }
    struct Connecting {
        SslConnection& connection;
        ~Connecting() {
            std::lock_guard lock(State().mutex);
            connection.connecting = false;
        }
    } connecting{*connection};
    std::lock_guard io(connection->io);
    SystemRoots();
    PoolScope scope(session->context->pool);
    session->random.Seed();
    auto check = [](int error) {
        if (error != 0) BackendFailure("sceSslConnect", error);
    };
    check(mbedtls_ssl_config_defaults(&session->config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT));
    mbedtls_ssl_conf_rng(&session->config, mbedtls_ctr_drbg_random, &session->random.drbg);
    mbedtls_ssl_conf_authmode(&session->config, options & VerifyServer ? MBEDTLS_SSL_VERIFY_OPTIONAL : MBEDTLS_SSL_VERIFY_NONE);
    if (!(options & VerifyNotSha1)) session->profile.allowed_mds |= MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1);
    mbedtls_ssl_conf_cert_profile(&session->config, &session->profile);
    mbedtls_ssl_conf_ca_cb(&session->config, TrustedCandidates, session.get());
    if (session->identity) check(mbedtls_ssl_conf_own_cert(&session->config, &session->identity->chain->root, &session->identity->key.key));
    if (!connection->protocolList.empty()) check(mbedtls_ssl_conf_alpn_protocols(&session->config, connection->protocolList.data()));
    check(mbedtls_ssl_setup(&session->ssl, &session->config));
    check(mbedtls_ssl_set_hostname(&session->ssl, connection->host.c_str()));
    mbedtls_ssl_set_bio(&session->ssl, &connection->socket, TransportSend, TransportReceive, nullptr);
    check(mbedtls_ssl_handshake(&session->ssl));
    const auto failures = mbedtls_ssl_get_verify_result(&session->ssl);
    if ((options & VerifyServer) && (failures & ~AllowedFailures(options))) {
        char text[512]{};
        mbedtls_x509_crt_verify_info(text, sizeof(text), "", failures & ~AllowedFailures(options));
        throw std::runtime_error(std::string("sceSslConnect: server certificate rejected (console error code unknown): ") + text);
    }
    connection->session = std::move(session);
    return 0;
}

int APS5_VABI sceSslRead(int sslConnectionId, void* buf, size_t len, int flags) {
    const auto connection = ShareConnection(__func__, sslConnectionId);
    if (flags != 0 && flags != ReadPartial && flags != ReadPeek) throw std::invalid_argument("sceSslRead: unknown flags");
    if (!buf && len) throw std::invalid_argument("sceSslRead: null buffer");
    if (len > static_cast<std::size_t>(std::numeric_limits<int>::max())) throw std::invalid_argument("sceSslRead: length does not fit the result");
    std::lock_guard io(connection->io);
    RequireSession(__func__, *connection);
    const GuestArena::HostWrite destination(len == 0 ? nullptr : buf, len);
    if (!destination.Open()) throw std::invalid_argument("sceSslRead: buffer is not writable");
    auto* output = static_cast<std::uint8_t*>(buf);
    auto& peeked = connection->peeked;
    if (flags == ReadPeek) {
        if (peeked.empty() && len) {
            peeked.resize(len);
            peeked.resize(static_cast<std::size_t>(ReadRecord(__func__, *connection, peeked.data(), len)));
        }
        const auto count = std::min(len, peeked.size());
        std::memcpy(output, peeked.data(), count);
        return static_cast<int>(count);
    }
    std::size_t total = std::min(len, peeked.size());
    std::memcpy(output, peeked.data(), total);
    peeked.erase(peeked.begin(), peeked.begin() + static_cast<std::ptrdiff_t>(total));
    while (total < len && !(total && flags == ReadPartial)) {
        const int count = ReadRecord(__func__, *connection, output + total, len - total);
        if (count == 0) break;
        total += static_cast<std::size_t>(count);
    }
    return static_cast<int>(total);
}

int APS5_VABI sceSslWrite(int sslConnectionId, void* buf, size_t len, int flags) {
    const auto connection = ShareConnection(__func__, sslConnectionId);
    if (flags != 0) throw std::invalid_argument("sceSslWrite: unknown flags");
    if (!buf && len) throw std::invalid_argument("sceSslWrite: null buffer");
    if (len > static_cast<std::size_t>(std::numeric_limits<int>::max())) throw std::invalid_argument("sceSslWrite: length does not fit the result");
    std::lock_guard io(connection->io);
    auto& session = RequireSession(__func__, *connection);
    PoolScope scope(session.context->pool);
    const auto* input = static_cast<const std::uint8_t*>(buf);
    for (std::size_t written = 0; written < len;) {
        const int result = mbedtls_ssl_write(&session.ssl, input + written, len - written);
        if (result < 0) BackendFailure(__func__, result);
        written += static_cast<std::size_t>(result);
    }
    return static_cast<int>(len);
}

int APS5_VABI sceSslClose(int sslConnectionId) {
    const auto connection = ShareConnection(__func__, sslConnectionId);
    std::lock_guard io(connection->io);
    auto& session = RequireSession(__func__, *connection);
    {
        PoolScope scope(session.context->pool);
        const int result = mbedtls_ssl_close_notify(&session.ssl);
        if (result != 0) BackendFailure(__func__, result);
    }
    connection->session.reset();
    connection->peeked.clear();
    connection->closed = true;
    return 0;
}

void* APS5_VABI sceSslGetSubjectName(int sslCtxId, void* sslCert) {
    return CreateName(sslCtxId, sslCert, true);
}

void* APS5_VABI sceSslGetIssuerName(int sslCtxId, void* sslCert) {
    return CreateName(sslCtxId, sslCert, false);
}

int APS5_VABI sceSslGetNameEntryCount(int sslCtxId, void* certName) {
    std::lock_guard lock(State().mutex);
    const auto count = RequireName(GetContext(sslCtxId), certName).entries.size();
    if (count > static_cast<std::size_t>(std::numeric_limits<int>::max())) throw std::length_error("Too many SSL name entries");
    return static_cast<int>(count);
}

int APS5_VABI sceSslGetNameEntryInfo(int sslCtxId, void* certName, int entryNum, char* oidname, std::size_t maxOidnameLen,
    std::uint8_t* value, std::size_t maxValueLen, std::size_t* valueLen) {
    std::lock_guard lock(State().mutex);
    const auto& name = RequireName(GetContext(sslCtxId), certName);
    if (entryNum < 0 || static_cast<std::size_t>(entryNum) >= name.entries.size()) throw std::invalid_argument("sceSslGetNameEntryInfo: entry out of range");
    if (!oidname || !value || !valueLen) throw std::invalid_argument("sceSslGetNameEntryInfo: null output");
    const auto& entry = name.entries[static_cast<std::size_t>(entryNum)];
    if (entry.oid.size() >= maxOidnameLen || entry.value.size() > maxValueLen) throw std::length_error("sceSslGetNameEntryInfo: output buffer too small");
    std::memcpy(oidname, entry.oid.c_str(), entry.oid.size() + 1);
    std::memcpy(value, entry.value.data(), entry.value.size());
    *valueLen = entry.value.size();
    return 0;
}

int APS5_VABI sceSslFreeSslCertName(int sslCtxId, void* certName) {
    std::lock_guard lock(State().mutex);
    auto& context = GetContext(sslCtxId);
    RequireName(context, certName);
    context.names.erase(certName);
    return 0;
}

int APS5_VABI sceSslGetSerialNumber(int sslCtxId, void* sslCert, std::uint8_t* sboData, std::size_t* sboLen) {
    if (!sboData || !sboLen) throw std::invalid_argument("sceSslGetSerialNumber: null output");
    std::lock_guard lock(State().mutex);
    const auto& serial = RequireCertificate(GetContext(sslCtxId), sslCert).serial;
    if (serial.len > *sboLen) throw std::length_error("sceSslGetSerialNumber: output buffer too small");
    std::memcpy(sboData, serial.p, serial.len);
    *sboLen = serial.len;
    return 0;
}

int APS5_VABI sceSslGetPem(void) {
    NotImplemented_nid_no_patch(__func__);
    return 0;
}

}
