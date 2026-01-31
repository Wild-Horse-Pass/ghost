// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gsp/gsp.h>
#include <gsp/gsp_auth.h>
#include <gsp/gsp_wallet.h>
#include <gsp/gsp_ws.h>

#include <blockfilter.h>
#include <chain.h>
#include <chainparams.h>
#include <httpserver.h>
#include <index/blockfilterindex.h>
#include <logging.h>
#include <netaddress.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <primitives/block.h>
#include <random.h>
#include <rpc/protocol.h>
#include <serialize.h>
#include <streams.h>
#include <univalue.h>
#include <util/time.h>
#include <util/strencodings.h>
#include <validation.h>
#include <validationinterface.h>

namespace gsp {

/**
 * GSP Notification Handler - Receives validation events and pushes to WebSocket clients.
 * Implements CValidationInterface to get notified of new blocks, transactions, etc.
 */
class GspNotificationHandler : public CValidationInterface {
public:
    explicit GspNotificationHandler(WsServer* ws_server) : m_ws_server(ws_server) {}

protected:
    void UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload) override
    {
        // Don't send notifications during initial sync
        if (fInitialDownload || !m_ws_server) return;

        if (pindexNew) {
            LogPrintf("GSP: New block tip at height %d, notifying WebSocket clients\n", pindexNew->nHeight);
            m_ws_server->NotifyNewBlock(pindexNew->GetBlockHash().GetHex(), pindexNew->nHeight);
        }
    }

    void BlockConnected(ChainstateRole role, const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override
    {
        // Only notify for the active chainstate
        if (role != ChainstateRole::NORMAL || !m_ws_server) return;

        // In a full implementation, scan the block for transactions relevant to
        // subscribed wallets and send balance/payment notifications
        LogPrintf("GSP: Block %s connected at height %d\n",
                  pindex->GetBlockHash().GetHex().substr(0, 16), pindex->nHeight);
    }

    void TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t mempool_sequence) override
    {
        // In a full implementation, check if this transaction is relevant to
        // any subscribed wallets and send payment notifications
        if (!m_ws_server) return;

        // Note: We don't log every mempool tx as it would be too noisy
    }

private:
    WsServer* m_ws_server;
};

// Implementation class
class GspServer::Impl {
public:
    std::unique_ptr<JwtManager> jwt;
    std::unique_ptr<WalletRegistry> registry;
    std::unique_ptr<WsServer> ws_server;
    std::unique_ptr<AuthRateLimiter> rate_limiter;
    std::unique_ptr<GspNotificationHandler> notification_handler;
};

GspServer::GspServer(node::NodeContext& node, const GspConfig& config)
    : m_node(node)
    , m_config(config)
    , m_impl(std::make_unique<Impl>())
{
}

GspServer::~GspServer()
{
    Stop();
}

bool GspServer::Start()
{
    if (m_running.load()) {
        return true; // Already running
    }

    LogPrintf("GSP: Starting Ghost Service Protocol server on port %d\n", m_config.port);

    // Create data directory if it doesn't exist
    if (!fs::exists(m_config.data_dir)) {
        fs::create_directories(m_config.data_dir);
    }

    // Initialize JWT manager
    std::string jwt_secret = m_config.jwt_secret;
    if (jwt_secret.empty()) {
        // Generate a random secret
        std::vector<unsigned char> secret(32);
        GetStrongRandBytes(secret);
        jwt_secret = HexStr(secret);
        LogPrintf("GSP: Generated new JWT secret\n");
    }
    m_impl->jwt = std::make_unique<JwtManager>(jwt_secret);

    // Initialize wallet registry
    m_impl->registry = std::make_unique<WalletRegistry>(m_config.data_dir);
    if (!m_impl->registry->Initialize()) {
        LogPrintf("GSP: Failed to initialize wallet registry\n");
        return false;
    }
    LogPrintf("GSP: Wallet registry initialized with %d wallets\n",
              m_impl->registry->GetWalletCount());

    // Initialize rate limiter
    if (m_config.rate_limit_enabled) {
        m_impl->rate_limiter = std::make_unique<AuthRateLimiter>();
    }

    // Register HTTP handlers
    // Note: In a full implementation, these would be registered with the HTTP server
    // For now, we define the handler patterns
    RegisterHTTPHandler("/gsp/health", true,
        [this](HTTPRequest* req, const std::string&) -> bool {
            return HandleHealthHTTP(req);
        });

    RegisterHTTPHandler("/gsp/api/v1/info", true,
        [this](HTTPRequest* req, const std::string&) -> bool {
            return HandleInfoHTTP(req);
        });

    RegisterHTTPHandler("/gsp/api/v1/register", true,
        [this](HTTPRequest* req, const std::string&) -> bool {
            return HandleRegisterHTTP(req);
        });

    RegisterHTTPHandler("/gsp/api/v1/session", true,
        [this](HTTPRequest* req, const std::string&) -> bool {
            return HandleSessionHTTP(req);
        });

    // BIP-157/158 privacy-preserving filter endpoints
    RegisterHTTPHandler("/gsp/api/v1/filters/headers", true,
        [this](HTTPRequest* req, const std::string&) -> bool {
            return HandleFilterHeadersHTTP(req);
        });

    // Batch filter download: /gsp/api/v1/filters/batch?start=N&count=M
    RegisterHTTPHandler("/gsp/api/v1/filters/batch", true,
        [this](HTTPRequest* req, const std::string&) -> bool {
            return HandleFilterBatchHTTP(req);
        });

    // Note: Filter by height and block by hash require path parameter parsing
    // These are handled via a pattern-matching handler
    RegisterHTTPHandler("/gsp/api/v1/filters", false,
        [this](HTTPRequest* req, const std::string& path) -> bool {
            // Parse height from path: /gsp/api/v1/filters/:height
            std::string height_str = path.substr(path.rfind('/') + 1);
            try {
                int height = std::stoi(height_str);
                return HandleFilterHTTP(req, height);
            } catch (const std::exception&) {
                req->WriteReply(HTTP_BAD_REQUEST, "Invalid height parameter");
                return true;
            }
        });

    RegisterHTTPHandler("/gsp/api/v1/block", false,
        [this](HTTPRequest* req, const std::string& path) -> bool {
            // Parse hash from path: /gsp/api/v1/block/:hash
            std::string hash = path.substr(path.rfind('/') + 1);
            return HandleBlockHTTP(req, hash);
        });

    // Initialize WebSocket server
    m_impl->ws_server = std::make_unique<WsServer>(
        m_node,
        *m_impl->jwt,
        *m_impl->registry,
        m_config.port,
        m_config.max_connections
    );

    if (!m_impl->ws_server->Start()) {
        LogPrintf("GSP: Failed to start WebSocket server\n");
        return false;
    }

    // Register for validation events (new blocks, transactions)
    if (m_node.validation_signals) {
        m_impl->notification_handler = std::make_unique<GspNotificationHandler>(m_impl->ws_server.get());
        m_node.validation_signals->RegisterValidationInterface(m_impl->notification_handler.get());
        LogPrintf("GSP: Registered validation interface for push notifications\n");
    }

    m_start_time = GetTime();
    m_running.store(true);
    LogPrintf("GSP: Server started successfully\n");
    return true;
}

void GspServer::Stop()
{
    if (!m_running.load()) {
        return;
    }

    LogPrintf("GSP: Stopping server...\n");

    // Unregister validation interface first
    if (m_impl->notification_handler && m_node.validation_signals) {
        m_node.validation_signals->UnregisterValidationInterface(m_impl->notification_handler.get());
        m_impl->notification_handler.reset();
        LogPrintf("GSP: Unregistered validation interface\n");
    }

    // Stop WebSocket server
    if (m_impl->ws_server) {
        m_impl->ws_server->Stop();
    }

    // Unregister HTTP handlers
    UnregisterHTTPHandler("/gsp/health", true);
    UnregisterHTTPHandler("/gsp/api/v1/info", true);
    UnregisterHTTPHandler("/gsp/api/v1/register", true);
    UnregisterHTTPHandler("/gsp/api/v1/session", true);
    UnregisterHTTPHandler("/gsp/api/v1/filters/headers", true);
    UnregisterHTTPHandler("/gsp/api/v1/filters/batch", true);
    UnregisterHTTPHandler("/gsp/api/v1/filters", false);
    UnregisterHTTPHandler("/gsp/api/v1/block", false);

    m_running.store(false);
    LogPrintf("GSP: Server stopped\n");
}

void GspServer::Interrupt()
{
    if (m_impl->ws_server) {
        m_impl->ws_server->Interrupt();
    }
}

uint32_t GspServer::GetRegisteredWalletCount() const
{
    if (m_impl->registry) {
        return m_impl->registry->GetWalletCount();
    }
    return 0;
}

GspServer::ServerInfo GspServer::GetServerInfo() const
{
    ServerInfo info;
    info.protocol_version = GSP_VERSION;
    info.network = Params().GetChainTypeString();
    info.connections = GetConnectionCount();
    info.registered_wallets = GetRegisteredWalletCount();

    // Determine sync status from chainman
    if (m_node.chainman) {
        LOCK(cs_main);
        const CBlockIndex* tip = m_node.chainman->ActiveChain().Tip();
        if (tip) {
            // Check if we're synced (tip time within last hour)
            int64_t tip_time = tip->GetBlockTime();
            int64_t now = GetTime();
            if (now - tip_time < 3600) {
                info.sync_status = "synced";
            } else {
                info.sync_status = "syncing";
            }
        } else {
            info.sync_status = "initializing";
        }
    } else {
        info.sync_status = "unknown";
    }

    info.uptime_secs = m_start_time > 0 ? GetTime() - m_start_time : 0;
    return info;
}

// HTTP Handler implementations using HTTPRequest wrapper
bool GspServer::HandleHealthHTTP(HTTPRequest* req)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("status", "ok");
    result.pushKV("version", GSP_VERSION);
    req->WriteHeader("Content-Type", "application/json");
    req->WriteReply(HTTP_OK, result.write());
    return true;
}

bool GspServer::HandleInfoHTTP(HTTPRequest* req)
{
    ServerInfo info = GetServerInfo();

    UniValue result(UniValue::VOBJ);
    result.pushKV("protocol_version", info.protocol_version);
    result.pushKV("network", info.network);
    result.pushKV("connections", (int)info.connections);
    result.pushKV("registered_wallets", (int)info.registered_wallets);
    result.pushKV("sync_status", info.sync_status);
    result.pushKV("uptime_secs", (int64_t)info.uptime_secs);

    req->WriteHeader("Content-Type", "application/json");
    req->WriteReply(HTTP_OK, result.write());
    return true;
}

bool GspServer::HandleRegisterHTTP(HTTPRequest* req)
{
    if (req->GetRequestMethod() != HTTPRequest::POST) {
        req->WriteReply(HTTP_BAD_METHOD, "POST required");
        return true;
    }

    // Rate limit by IP
    if (m_impl->rate_limiter) {
        std::string ip = req->GetPeer().ToStringAddr();
        if (!m_impl->rate_limiter->Allow(ip, 10, 3600)) { // 10 per hour
            UniValue error(UniValue::VOBJ);
            error.pushKV("error", "rate_limit_exceeded");
            error.pushKV("message", "Too many registration attempts");
            req->WriteHeader("Content-Type", "application/json");
            req->WriteReply(429, error.write());
            return true;
        }
    }

    // Parse request body
    std::string body = req->ReadBody();
    UniValue params;
    if (!params.read(body)) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "invalid_json");
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_BAD_REQUEST, error.write());
        return true;
    }

    // Extract and verify WalletProof
    if (!params.exists("pubkey") || !params.exists("signature") ||
        !params.exists("challenge") || !params.exists("timestamp")) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "missing_fields");
        error.pushKV("message", "Required: pubkey, signature, challenge, timestamp");
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_BAD_REQUEST, error.write());
        return true;
    }

    WalletProof proof;
    // Parse pubkey
    std::vector<unsigned char> pubkey_bytes = ParseHex(params["pubkey"].get_str());
    proof.pubkey.Set(pubkey_bytes.begin(), pubkey_bytes.end());
    if (!proof.pubkey.IsValid()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "invalid_pubkey");
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_BAD_REQUEST, error.write());
        return true;
    }

    proof.challenge = params["challenge"].get_str();
    proof.signature = ParseHex(params["signature"].get_str());
    proof.timestamp = params["timestamp"].getInt<int64_t>();

    // Verify timestamp
    if (!proof.IsTimestampValid()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "invalid_timestamp");
        error.pushKV("message", "Timestamp out of acceptable range");
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_BAD_REQUEST, error.write());
        return true;
    }

    // Verify signature
    if (!proof.Verify()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "invalid_signature");
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_BAD_REQUEST, error.write());
        return true;
    }

    // Register wallet
    std::string label = params.exists("label") ? params["label"].get_str() : "";
    auto wallet_id = m_impl->registry->RegisterWallet(proof.pubkey, label);

    if (!wallet_id) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "registration_failed");
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_INTERNAL_SERVER_ERROR, error.write());
        return true;
    }

    // Create initial session token
    std::string token = m_impl->jwt->CreateToken(*wallet_id);

    UniValue result(UniValue::VOBJ);
    result.pushKV("wallet_id", *wallet_id);
    result.pushKV("token", token);
    result.pushKV("expires_in", 86400);

    req->WriteHeader("Content-Type", "application/json");
    req->WriteReply(HTTP_OK, result.write());
    return true;
}

bool GspServer::HandleSessionHTTP(HTTPRequest* req)
{
    if (req->GetRequestMethod() != HTTPRequest::POST) {
        req->WriteReply(HTTP_BAD_METHOD, "POST required");
        return true;
    }

    // Rate limit by IP
    if (m_impl->rate_limiter) {
        std::string ip = req->GetPeer().ToStringAddr();
        if (!m_impl->rate_limiter->Allow(ip, 30, 3600)) { // 30 per hour
            UniValue error(UniValue::VOBJ);
            error.pushKV("error", "rate_limit_exceeded");
            req->WriteHeader("Content-Type", "application/json");
            req->WriteReply(429, error.write());
            return true;
        }
    }

    // Parse request body
    std::string body = req->ReadBody();
    UniValue params;
    if (!params.read(body)) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "invalid_json");
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_BAD_REQUEST, error.write());
        return true;
    }

    // Verify WalletProof for existing wallet
    if (!params.exists("wallet_id") || !params.exists("signature") ||
        !params.exists("challenge") || !params.exists("timestamp")) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "missing_fields");
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_BAD_REQUEST, error.write());
        return true;
    }

    std::string wallet_id = params["wallet_id"].get_str();

    // Check if wallet is registered
    auto wallet = m_impl->registry->GetWallet(wallet_id);
    if (!wallet || !wallet->active) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "wallet_not_found");
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_NOT_FOUND, error.write());
        return true;
    }

    WalletProof proof;
    proof.pubkey = wallet->pubkey;
    proof.challenge = params["challenge"].get_str();
    proof.signature = ParseHex(params["signature"].get_str());
    proof.timestamp = params["timestamp"].getInt<int64_t>();

    if (!proof.IsTimestampValid() || !proof.Verify()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "invalid_proof");
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_UNAUTHORIZED, error.write());
        return true;
    }

    // Update last seen
    m_impl->registry->UpdateLastSeen(wallet_id);

    // Create session token
    std::string token = m_impl->jwt->CreateToken(wallet_id);

    UniValue result(UniValue::VOBJ);
    result.pushKV("token", token);
    result.pushKV("expires_in", 86400);

    req->WriteHeader("Content-Type", "application/json");
    req->WriteReply(HTTP_OK, result.write());
    return true;
}

bool GspServer::HandleFilterHTTP(HTTPRequest* req, int height)
{
    if (!m_node.chainman) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "node_not_ready");
        error.pushKV("message", "Chain manager not initialized");
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_SERVICE_UNAVAILABLE, error.write());
        return true;
    }

    // Get the basic filter index
    BlockFilterIndex* filter_index = GetBlockFilterIndex(BlockFilterType::BASIC);
    if (!filter_index) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "filter_index_not_enabled");
        error.pushKV("message", "Block filter index not enabled. Start node with -blockfilterindex=basic");
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_SERVICE_UNAVAILABLE, error.write());
        return true;
    }

    // Get block at height
    const CBlockIndex* block_index;
    {
        LOCK(cs_main);
        block_index = m_node.chainman->ActiveChain()[height];
        if (!block_index) {
            UniValue error(UniValue::VOBJ);
            error.pushKV("error", "block_not_found");
            error.pushKV("message", "Block not found at height " + std::to_string(height));
            req->WriteHeader("Content-Type", "application/json");
            req->WriteReply(HTTP_NOT_FOUND, error.write());
            return true;
        }
    }

    // Look up the filter
    BlockFilter filter;
    if (!filter_index->LookupFilter(block_index, filter)) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "filter_not_found");
        if (!filter_index->BlockUntilSyncedToCurrentChain()) {
            error.pushKV("message", "Block filters still being indexed");
        } else {
            error.pushKV("message", "Filter not found (index may be corrupted)");
        }
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_NOT_FOUND, error.write());
        return true;
    }

    // Look up the filter header
    uint256 filter_header;
    if (!filter_index->LookupFilterHeader(block_index, filter_header)) {
        filter_header.SetNull();
    }

    // Return the filter data
    UniValue result(UniValue::VOBJ);
    result.pushKV("height", height);
    result.pushKV("block_hash", block_index->GetBlockHash().GetHex());
    result.pushKV("filter", HexStr(filter.GetEncodedFilter()));
    result.pushKV("filter_header", filter_header.GetHex());
    result.pushKV("filter_type", "basic");

    req->WriteHeader("Content-Type", "application/json");
    req->WriteReply(HTTP_OK, result.write());
    return true;
}

bool GspServer::HandleFilterBatchHTTP(HTTPRequest* req)
{
    // Batch filter download for efficient light wallet sync
    // Query params: start=N&count=M (max 100 filters per request)

    if (!m_node.chainman) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "node_not_ready");
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_SERVICE_UNAVAILABLE, error.write());
        return true;
    }

    BlockFilterIndex* filter_index = GetBlockFilterIndex(BlockFilterType::BASIC);
    if (!filter_index) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "filter_index_not_enabled");
        error.pushKV("message", "Block filter index not enabled. Start node with -blockfilterindex=basic");
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_SERVICE_UNAVAILABLE, error.write());
        return true;
    }

    // Parse query parameters from URI
    // URI format: /gsp/api/v1/filters/batch?start=N&count=M
    std::string uri = req->GetURI();
    int start_height = 0;
    int count = 10; // Default batch size
    const int max_batch = 100; // Maximum filters per request

    size_t query_pos = uri.find('?');
    if (query_pos != std::string::npos) {
        std::string query = uri.substr(query_pos + 1);
        // Simple query string parsing
        size_t pos = 0;
        while (pos < query.size()) {
            size_t eq = query.find('=', pos);
            if (eq == std::string::npos) break;
            size_t amp = query.find('&', eq);
            if (amp == std::string::npos) amp = query.size();

            std::string key = query.substr(pos, eq - pos);
            std::string value = query.substr(eq + 1, amp - eq - 1);

            if (key == "start") {
                try { start_height = std::stoi(value); } catch (...) {}
            } else if (key == "count") {
                try { count = std::stoi(value); } catch (...) {}
            }
            pos = amp + 1;
        }
    }

    // Validate parameters
    if (start_height < 0) start_height = 0;
    if (count <= 0) count = 10;
    if (count > max_batch) count = max_batch;

    // Get current chain tip height
    int tip_height;
    {
        LOCK(cs_main);
        tip_height = m_node.chainman->ActiveChain().Height();
    }

    if (start_height > tip_height) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "invalid_range");
        error.pushKV("message", "Start height exceeds chain tip");
        error.pushKV("tip_height", tip_height);
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_BAD_REQUEST, error.write());
        return true;
    }

    // Collect filters
    UniValue filters(UniValue::VARR);
    {
        LOCK(cs_main);
        for (int h = start_height; h < start_height + count && h <= tip_height; ++h) {
            const CBlockIndex* block_index = m_node.chainman->ActiveChain()[h];
            if (!block_index) continue;

            BlockFilter filter;
            if (!filter_index->LookupFilter(block_index, filter)) continue;

            uint256 filter_header;
            filter_index->LookupFilterHeader(block_index, filter_header);

            UniValue filter_obj(UniValue::VOBJ);
            filter_obj.pushKV("height", h);
            filter_obj.pushKV("block_hash", block_index->GetBlockHash().GetHex());
            filter_obj.pushKV("filter", HexStr(filter.GetEncodedFilter()));
            filter_obj.pushKV("filter_header", filter_header.GetHex());
            filters.push_back(filter_obj);
        }
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("filter_type", "basic");
    result.pushKV("start", start_height);
    result.pushKV("count", (int)filters.size());
    result.pushKV("tip_height", tip_height);
    result.pushKV("filters", filters);

    req->WriteHeader("Content-Type", "application/json");
    req->WriteReply(HTTP_OK, result.write());
    return true;
}

bool GspServer::HandleFilterHeadersHTTP(HTTPRequest* req)
{
    if (!m_node.chainman) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "node_not_ready");
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_SERVICE_UNAVAILABLE, error.write());
        return true;
    }

    BlockFilterIndex* filter_index = GetBlockFilterIndex(BlockFilterType::BASIC);
    if (!filter_index) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "filter_index_not_enabled");
        error.pushKV("message", "Block filter index not enabled");
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_SERVICE_UNAVAILABLE, error.write());
        return true;
    }

    // Get current chain tip height
    int tip_height;
    {
        LOCK(cs_main);
        tip_height = m_node.chainman->ActiveChain().Height();
    }

    // Return checkpoint headers (every 1000 blocks per BIP-157)
    UniValue headers(UniValue::VARR);
    {
        LOCK(cs_main);
        for (int h = 0; h <= tip_height; h += CFCHECKPT_INTERVAL) {
            const CBlockIndex* block_index = m_node.chainman->ActiveChain()[h];
            if (!block_index) continue;

            uint256 filter_header;
            if (filter_index->LookupFilterHeader(block_index, filter_header)) {
                UniValue header_obj(UniValue::VOBJ);
                header_obj.pushKV("height", h);
                header_obj.pushKV("block_hash", block_index->GetBlockHash().GetHex());
                header_obj.pushKV("filter_header", filter_header.GetHex());
                headers.push_back(header_obj);
            }
        }
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("filter_type", "basic");
    result.pushKV("tip_height", tip_height);
    result.pushKV("checkpoint_interval", CFCHECKPT_INTERVAL);
    result.pushKV("headers", headers);

    req->WriteHeader("Content-Type", "application/json");
    req->WriteReply(HTTP_OK, result.write());
    return true;
}

bool GspServer::HandleBlockHTTP(HTTPRequest* req, const std::string& hash_str)
{
    if (!m_node.chainman) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "node_not_ready");
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_SERVICE_UNAVAILABLE, error.write());
        return true;
    }

    // Parse block hash
    auto block_hash = uint256::FromHex(hash_str);
    if (!block_hash) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "invalid_hash");
        error.pushKV("message", "Invalid block hash format");
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_BAD_REQUEST, error.write());
        return true;
    }

    // Find block index
    const CBlockIndex* block_index;
    {
        LOCK(cs_main);
        block_index = m_node.chainman->m_blockman.LookupBlockIndex(*block_hash);
        if (!block_index) {
            UniValue error(UniValue::VOBJ);
            error.pushKV("error", "block_not_found");
            req->WriteHeader("Content-Type", "application/json");
            req->WriteReply(HTTP_NOT_FOUND, error.write());
            return true;
        }
    }

    // Read block from disk
    CBlock block;
    {
        LOCK(cs_main);
        if (!m_node.chainman->m_blockman.ReadBlock(block, *block_index)) {
            UniValue error(UniValue::VOBJ);
            error.pushKV("error", "block_read_failed");
            error.pushKV("message", "Failed to read block from disk");
            req->WriteHeader("Content-Type", "application/json");
            req->WriteReply(HTTP_INTERNAL_SERVER_ERROR, error.write());
            return true;
        }
    }

    // Serialize block to hex
    DataStream ss;
    ss << TX_WITH_WITNESS(block);

    UniValue result(UniValue::VOBJ);
    result.pushKV("hash", block_hash->GetHex());
    result.pushKV("height", block_index->nHeight);
    result.pushKV("block", HexStr(ss));
    result.pushKV("size", (int)ss.size());

    req->WriteHeader("Content-Type", "application/json");
    req->WriteReply(HTTP_OK, result.write());
    return true;
}

} // namespace gsp
