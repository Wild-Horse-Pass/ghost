// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gsp/gsp_ws.h>
#include <gsp/gsp_auth.h>
#include <gsp/gsp_wallet.h>

#include <blockfilter.h>
#include <chain.h>
#include <chainparams.h>
#include <index/blockfilterindex.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <primitives/block.h>
#include <serialize.h>
#include <streams.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <validation.h>

#include <map>
#include <mutex>
#include <thread>

namespace gsp {

std::string WsMessageTypeToString(WsMessageType type)
{
    switch (type) {
    case WsMessageType::Authenticate: return "Authenticate";
    case WsMessageType::GetBalance: return "GetBalance";
    case WsMessageType::GetUtxos: return "GetUtxos";
    case WsMessageType::GetGhostLocks: return "GetGhostLocks";
    case WsMessageType::GetTransactions: return "GetTransactions";
    case WsMessageType::GetBlockFilter: return "GetBlockFilter";
    case WsMessageType::GetBlock: return "GetBlock";
    case WsMessageType::SubscribeBalance: return "SubscribeBalance";
    case WsMessageType::SubscribePayments: return "SubscribePayments";
    case WsMessageType::SubscribeGhostLocks: return "SubscribeGhostLocks";
    case WsMessageType::Unsubscribe: return "Unsubscribe";
    case WsMessageType::Ping: return "Ping";
    case WsMessageType::AuthResult: return "AuthResult";
    case WsMessageType::BalanceResult: return "BalanceResult";
    case WsMessageType::UtxosResult: return "UtxosResult";
    case WsMessageType::GhostLocksResult: return "GhostLocksResult";
    case WsMessageType::TransactionsResult: return "TransactionsResult";
    case WsMessageType::BlockFilterResult: return "BlockFilterResult";
    case WsMessageType::BlockResult: return "BlockResult";
    case WsMessageType::SubscribeResult: return "SubscribeResult";
    case WsMessageType::UnsubscribeResult: return "UnsubscribeResult";
    case WsMessageType::Pong: return "Pong";
    case WsMessageType::BalanceUpdate: return "BalanceUpdate";
    case WsMessageType::PaymentReceived: return "PaymentReceived";
    case WsMessageType::GhostLockUpdate: return "GhostLockUpdate";
    case WsMessageType::NewBlock: return "NewBlock";
    case WsMessageType::Error: return "Error";
    }
    return "Unknown";
}

// WebSocket server implementation
class WsServer::Impl {
public:
    std::atomic<bool> running{false};
    std::mutex connections_mutex;
    std::map<uint64_t, WsConnection> connections;
    std::atomic<uint64_t> next_conn_id{1};
    std::thread accept_thread;

    // For mapping wallet_id to connection IDs
    std::mutex wallet_connections_mutex;
    std::multimap<std::string, uint64_t> wallet_connections;
};

WsServer::WsServer(node::NodeContext& node,
                   JwtManager& jwt,
                   WalletRegistry& registry,
                   uint16_t port,
                   uint32_t max_connections)
    : m_node(node)
    , m_jwt(jwt)
    , m_registry(registry)
    , m_port(port)
    , m_max_connections(max_connections)
    , m_impl(std::make_unique<Impl>())
{
}

WsServer::~WsServer()
{
    Stop();
}

bool WsServer::Start()
{
    if (m_impl->running.load()) {
        return true;
    }

    LogPrintf("GSP WS: Starting WebSocket server on port %d\n", m_port);

    // In a full implementation, this would:
    // 1. Create a WebSocket server using libevent
    // 2. Start accepting connections
    // 3. Handle WebSocket upgrade requests

    m_impl->running.store(true);
    LogPrintf("GSP WS: Server started\n");
    return true;
}

void WsServer::Stop()
{
    if (!m_impl->running.load()) {
        return;
    }

    LogPrintf("GSP WS: Stopping server...\n");
    m_impl->running.store(false);

    // Close all connections
    {
        std::lock_guard<std::mutex> lock(m_impl->connections_mutex);
        m_impl->connections.clear();
    }

    m_connection_count.store(0);
    LogPrintf("GSP WS: Server stopped\n");
}

void WsServer::Interrupt()
{
    m_impl->running.store(false);
}

void WsServer::Broadcast(WsMessageType sub_type, const std::string& message)
{
    std::lock_guard<std::mutex> lock(m_impl->connections_mutex);

    for (auto& [id, conn] : m_impl->connections) {
        if (conn.subscriptions.count(sub_type)) {
            // In a full implementation, send message via WebSocket
            LogPrintf("GSP WS: Broadcasting %s to connection %llu\n",
                      WsMessageTypeToString(sub_type), id);
        }
    }
}

void WsServer::SendToWallet(const std::string& wallet_id,
                            WsMessageType type,
                            const std::string& message)
{
    std::lock_guard<std::mutex> lock(m_impl->wallet_connections_mutex);

    auto range = m_impl->wallet_connections.equal_range(wallet_id);
    for (auto it = range.first; it != range.second; ++it) {
        // In a full implementation, send message via WebSocket
        LogPrintf("GSP WS: Sending %s to wallet %s (conn %llu)\n",
                  WsMessageTypeToString(type), wallet_id, it->second);
    }
}

void WsServer::NotifyNewBlock(const std::string& block_hash, int height)
{
    UniValue payload(UniValue::VOBJ);
    payload.pushKV("block_hash", block_hash);
    payload.pushKV("height", height);

    UniValue msg(UniValue::VOBJ);
    msg.pushKV("type", (int)WsMessageType::NewBlock);
    msg.pushKV("payload", payload);

    Broadcast(WsMessageType::SubscribeBalance, msg.write());
}

void WsServer::NotifyBalanceChange(const std::string& wallet_id,
                                   int64_t confirmed,
                                   int64_t unconfirmed)
{
    UniValue payload(UniValue::VOBJ);
    payload.pushKV("wallet_id", wallet_id);
    payload.pushKV("confirmed", confirmed);
    payload.pushKV("unconfirmed", unconfirmed);

    UniValue msg(UniValue::VOBJ);
    msg.pushKV("type", (int)WsMessageType::BalanceUpdate);
    msg.pushKV("payload", payload);

    SendToWallet(wallet_id, WsMessageType::BalanceUpdate, msg.write());
}

void WsServer::NotifyGhostLockChange(const std::string& wallet_id,
                                     const std::string& lock_id,
                                     const std::string& state)
{
    UniValue payload(UniValue::VOBJ);
    payload.pushKV("wallet_id", wallet_id);
    payload.pushKV("lock_id", lock_id);
    payload.pushKV("state", state);

    UniValue msg(UniValue::VOBJ);
    msg.pushKV("type", (int)WsMessageType::GhostLockUpdate);
    msg.pushKV("payload", payload);

    SendToWallet(wallet_id, WsMessageType::GhostLockUpdate, msg.write());
}

// Message handlers

std::string WsServer::HandleAuthenticate(WsConnection& conn, const std::string& payload)
{
    UniValue params;
    if (!params.read(payload)) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "invalid_json");
        return error.write();
    }

    if (!params.exists("token")) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "missing_token");
        return error.write();
    }

    std::string token = params["token"].get_str();
    auto wallet_id = m_jwt.VerifyToken(token);

    if (!wallet_id) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "invalid_token");
        return error.write();
    }

    // Check if wallet is active
    if (!m_registry.IsActive(*wallet_id)) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "wallet_not_active");
        return error.write();
    }

    // Associate connection with wallet
    conn.wallet_id = *wallet_id;

    {
        std::lock_guard<std::mutex> lock(m_impl->wallet_connections_mutex);
        m_impl->wallet_connections.insert({*wallet_id, conn.id});
    }

    m_registry.UpdateLastSeen(*wallet_id);

    UniValue result(UniValue::VOBJ);
    result.pushKV("type", (int)WsMessageType::AuthResult);
    result.pushKV("success", true);
    result.pushKV("wallet_id", *wallet_id);

    return result.write();
}

std::string WsServer::HandleGetBalance(WsConnection& conn, const std::string& payload)
{
    if (conn.wallet_id.empty()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "not_authenticated");
        return error.write();
    }

    // In a full implementation, query the UTXO set for the wallet's addresses
    // For now, return a placeholder

    UniValue result(UniValue::VOBJ);
    result.pushKV("type", (int)WsMessageType::BalanceResult);
    result.pushKV("confirmed", 0);
    result.pushKV("unconfirmed", 0);
    result.pushKV("locked", 0);

    return result.write();
}

std::string WsServer::HandleGetUtxos(WsConnection& conn, const std::string& payload)
{
    if (conn.wallet_id.empty()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "not_authenticated");
        return error.write();
    }

    // In a full implementation, query UTXOs for the wallet's addresses
    UniValue utxos(UniValue::VARR);

    UniValue result(UniValue::VOBJ);
    result.pushKV("type", (int)WsMessageType::UtxosResult);
    result.pushKV("utxos", utxos);

    return result.write();
}

std::string WsServer::HandleGetGhostLocks(WsConnection& conn, const std::string& payload)
{
    if (conn.wallet_id.empty()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "not_authenticated");
        return error.write();
    }

    // Ghost Locks are queried via BIP-157/158 filters on the client side
    // This endpoint is deprecated in favor of filter-based queries
    UniValue result(UniValue::VOBJ);
    result.pushKV("type", (int)WsMessageType::GhostLocksResult);
    result.pushKV("message", "Use block filters for privacy-preserving Ghost Lock queries");

    return result.write();
}

std::string WsServer::HandleGetTransactions(WsConnection& conn, const std::string& payload)
{
    if (conn.wallet_id.empty()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "not_authenticated");
        return error.write();
    }

    // Transactions should be retrieved via block filters for privacy
    UniValue txs(UniValue::VARR);

    UniValue result(UniValue::VOBJ);
    result.pushKV("type", (int)WsMessageType::TransactionsResult);
    result.pushKV("transactions", txs);

    return result.write();
}

std::string WsServer::HandleGetBlockFilter(WsConnection& conn, const std::string& payload)
{
    // This endpoint doesn't require authentication - filters are public

    UniValue params;
    if (!params.read(payload)) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "invalid_json");
        return error.write();
    }

    if (!params.exists("height")) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "missing_height");
        return error.write();
    }

    int height = params["height"].getInt<int>();

    // Get the block filter from the index
    if (!m_node.chainman) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "node_not_ready");
        return error.write();
    }

    // Get the basic filter index
    BlockFilterIndex* filter_index = GetBlockFilterIndex(BlockFilterType::BASIC);
    if (!filter_index) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "filter_index_not_enabled");
        error.pushKV("message", "Block filter index not enabled. Start node with -blockfilterindex=basic");
        return error.write();
    }

    // Get block at height
    const CBlockIndex* block_index;
    {
        LOCK(cs_main);
        block_index = m_node.chainman->ActiveChain()[height];
        if (!block_index) {
            UniValue error(UniValue::VOBJ);
            error.pushKV("type", (int)WsMessageType::Error);
            error.pushKV("error", "block_not_found");
            error.pushKV("message", "Block not found at height " + std::to_string(height));
            return error.write();
        }
    }

    // Look up the filter
    BlockFilter filter;
    if (!filter_index->LookupFilter(block_index, filter)) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "filter_not_found");
        if (!filter_index->BlockUntilSyncedToCurrentChain()) {
            error.pushKV("message", "Block filters still being indexed");
        } else {
            error.pushKV("message", "Filter not found");
        }
        return error.write();
    }

    // Look up the filter header
    uint256 filter_header;
    if (!filter_index->LookupFilterHeader(block_index, filter_header)) {
        filter_header.SetNull();
    }

    // Return the filter data
    UniValue result(UniValue::VOBJ);
    result.pushKV("type", (int)WsMessageType::BlockFilterResult);
    result.pushKV("height", height);
    result.pushKV("block_hash", block_index->GetBlockHash().GetHex());
    result.pushKV("filter", HexStr(filter.GetEncodedFilter()));
    result.pushKV("filter_header", filter_header.GetHex());
    result.pushKV("filter_type", "basic");

    return result.write();
}

std::string WsServer::HandleGetBlock(WsConnection& conn, const std::string& payload)
{
    // This endpoint doesn't require authentication - blocks are public

    UniValue params;
    if (!params.read(payload)) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "invalid_json");
        return error.write();
    }

    if (!params.exists("hash")) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "missing_hash");
        return error.write();
    }

    std::string hash_str = params["hash"].get_str();

    if (!m_node.chainman) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "node_not_ready");
        return error.write();
    }

    // Parse block hash
    auto block_hash = uint256::FromHex(hash_str);
    if (!block_hash) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "invalid_hash");
        error.pushKV("message", "Invalid block hash format");
        return error.write();
    }

    // Find block index
    const CBlockIndex* block_index;
    {
        LOCK(cs_main);
        block_index = m_node.chainman->m_blockman.LookupBlockIndex(*block_hash);
        if (!block_index) {
            UniValue error(UniValue::VOBJ);
            error.pushKV("type", (int)WsMessageType::Error);
            error.pushKV("error", "block_not_found");
            return error.write();
        }
    }

    // Read block from disk
    CBlock block;
    {
        LOCK(cs_main);
        if (!m_node.chainman->m_blockman.ReadBlock(block, *block_index)) {
            UniValue error(UniValue::VOBJ);
            error.pushKV("type", (int)WsMessageType::Error);
            error.pushKV("error", "block_read_failed");
            error.pushKV("message", "Failed to read block from disk");
            return error.write();
        }
    }

    // Serialize block to hex
    DataStream ss;
    ss << TX_WITH_WITNESS(block);

    UniValue result(UniValue::VOBJ);
    result.pushKV("type", (int)WsMessageType::BlockResult);
    result.pushKV("hash", block_hash->GetHex());
    result.pushKV("height", block_index->nHeight);
    result.pushKV("block", HexStr(ss));
    result.pushKV("size", (int)ss.size());

    return result.write();
}

std::string WsServer::HandleSubscribe(WsConnection& conn, WsMessageType sub_type)
{
    if (conn.wallet_id.empty()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "not_authenticated");
        return error.write();
    }

    conn.subscriptions.insert(sub_type);

    UniValue result(UniValue::VOBJ);
    result.pushKV("type", (int)WsMessageType::SubscribeResult);
    result.pushKV("success", true);
    result.pushKV("subscription", WsMessageTypeToString(sub_type));

    return result.write();
}

std::string WsServer::HandleUnsubscribe(WsConnection& conn, WsMessageType sub_type)
{
    conn.subscriptions.erase(sub_type);

    UniValue result(UniValue::VOBJ);
    result.pushKV("type", (int)WsMessageType::UnsubscribeResult);
    result.pushKV("success", true);
    result.pushKV("subscription", WsMessageTypeToString(sub_type));

    return result.write();
}

// Message dispatch - routes incoming messages to appropriate handlers
std::string DispatchMessage(WsServer& server, WsConnection& conn, const std::string& message)
{
    UniValue msg;
    if (!msg.read(message)) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "invalid_json");
        error.pushKV("message", "Could not parse message as JSON");
        return error.write();
    }

    if (!msg.exists("type")) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "missing_type");
        error.pushKV("message", "Message must include 'type' field");
        return error.write();
    }

    int type_int = msg["type"].getInt<int>();
    WsMessageType type = static_cast<WsMessageType>(type_int);

    // Extract payload (defaults to empty object if not present)
    std::string payload = "{}";
    if (msg.exists("payload")) {
        payload = msg["payload"].write();
    }

    // Extract request ID for response correlation
    std::string request_id;
    if (msg.exists("id")) {
        request_id = msg["id"].get_str();
    }

    // Update last activity
    conn.last_activity = GetTime();

    // Dispatch to appropriate handler
    std::string response;
    switch (type) {
    case WsMessageType::Authenticate:
        response = server.HandleAuthenticate(conn, payload);
        break;
    case WsMessageType::GetBalance:
        response = server.HandleGetBalance(conn, payload);
        break;
    case WsMessageType::GetUtxos:
        response = server.HandleGetUtxos(conn, payload);
        break;
    case WsMessageType::GetGhostLocks:
        response = server.HandleGetGhostLocks(conn, payload);
        break;
    case WsMessageType::GetTransactions:
        response = server.HandleGetTransactions(conn, payload);
        break;
    case WsMessageType::GetBlockFilter:
        response = server.HandleGetBlockFilter(conn, payload);
        break;
    case WsMessageType::GetBlock:
        response = server.HandleGetBlock(conn, payload);
        break;
    case WsMessageType::SubscribeBalance:
        response = server.HandleSubscribe(conn, WsMessageType::SubscribeBalance);
        break;
    case WsMessageType::SubscribePayments:
        response = server.HandleSubscribe(conn, WsMessageType::SubscribePayments);
        break;
    case WsMessageType::SubscribeGhostLocks:
        response = server.HandleSubscribe(conn, WsMessageType::SubscribeGhostLocks);
        break;
    case WsMessageType::Unsubscribe:
        if (msg.exists("subscription")) {
            int sub_type = msg["subscription"].getInt<int>();
            response = server.HandleUnsubscribe(conn, static_cast<WsMessageType>(sub_type));
        } else {
            UniValue error(UniValue::VOBJ);
            error.pushKV("type", (int)WsMessageType::Error);
            error.pushKV("error", "missing_subscription");
            response = error.write();
        }
        break;
    case WsMessageType::Ping:
        {
            UniValue pong(UniValue::VOBJ);
            pong.pushKV("type", (int)WsMessageType::Pong);
            pong.pushKV("timestamp", GetTime());
            response = pong.write();
        }
        break;
    default:
        {
            UniValue error(UniValue::VOBJ);
            error.pushKV("type", (int)WsMessageType::Error);
            error.pushKV("error", "unknown_message_type");
            error.pushKV("message", "Unknown message type: " + std::to_string(type_int));
            response = error.write();
        }
        break;
    }

    // Add request ID to response if present
    if (!request_id.empty()) {
        UniValue resp_obj;
        if (resp_obj.read(response)) {
            resp_obj.pushKV("id", request_id);
            response = resp_obj.write();
        }
    }

    return response;
}

// Connection management helpers
uint64_t CreateConnection(WsServer::Impl& impl, const std::string& remote_addr)
{
    std::lock_guard<std::mutex> lock(impl.connections_mutex);

    WsConnection conn;
    conn.id = impl.next_conn_id.fetch_add(1);
    conn.connected_at = GetTime();
    conn.last_activity = conn.connected_at;
    conn.remote_addr = remote_addr;

    impl.connections[conn.id] = conn;
    return conn.id;
}

void RemoveConnection(WsServer::Impl& impl, uint64_t conn_id)
{
    std::lock_guard<std::mutex> lock(impl.connections_mutex);

    auto it = impl.connections.find(conn_id);
    if (it != impl.connections.end()) {
        // Remove from wallet_connections if authenticated
        if (!it->second.wallet_id.empty()) {
            std::lock_guard<std::mutex> wallet_lock(impl.wallet_connections_mutex);
            auto range = impl.wallet_connections.equal_range(it->second.wallet_id);
            for (auto wit = range.first; wit != range.second;) {
                if (wit->second == conn_id) {
                    wit = impl.wallet_connections.erase(wit);
                } else {
                    ++wit;
                }
            }
        }
        impl.connections.erase(it);
    }
}

WsConnection* GetConnection(WsServer::Impl& impl, uint64_t conn_id)
{
    std::lock_guard<std::mutex> lock(impl.connections_mutex);
    auto it = impl.connections.find(conn_id);
    if (it != impl.connections.end()) {
        return &it->second;
    }
    return nullptr;
}

} // namespace gsp
